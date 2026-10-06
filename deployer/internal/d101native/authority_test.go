package d101native

import (
	"bytes"
	"context"
	"encoding/json"
	"opensamguk-deployer/internal/d101custody"
	"strings"
	"testing"
	"time"
)

type native9HeldFixture struct {
	ref    RawRef
	wire   []byte
	source *native9OriginalFixture
}

func (h *native9HeldFixture) Original() []byte  { return bytes.Clone(h.wire) }
func (h *native9HeldFixture) Reference() RawRef { return h.ref }
func (h *native9HeldFixture) Recheck(context.Context) error {
	if h.source.changed {
		return ErrUnavailable
	}
	return nil
}
func (h *native9HeldFixture) Close() error { h.source.closed++; return nil }

type native9OriginalFixture struct {
	originals    map[RawRef][]byte
	changed      bool
	held, closed int
}

func (s *native9OriginalFixture) HoldOriginal(_ context.Context, r RawRef) (HeldOriginal, error) {
	wire, ok := s.originals[r]
	if !ok {
		return nil, ErrUnavailable
	}
	s.held++
	return &native9HeldFixture{r, wire, s}, nil
}

type native9SemanticFixture struct {
	observation CurrentObservation
	changed     bool
	checks      int
	images      FiveImages
}

func (s *native9SemanticFixture) AuthenticateCurrent(_ context.Context, e CurrentEvidence) (CurrentObservation, error) {
	if len(e.Originals) == 0 {
		return CurrentObservation{}, ErrUnavailable
	}
	s.observation.ObservedAt = time.Now()
	return s.observation, nil
}
func (s *native9SemanticFixture) RecheckCurrent(context.Context, CurrentEvidence, CurrentObservation) error {
	s.checks++
	if s.changed {
		return ErrUnavailable
	}
	return nil
}
func (s *native9SemanticFixture) AuthenticatePublic(_ context.Context, _ *VerifiedCurrent, pub RelaySessionBinding, _ Process) error {
	if pub.ImageDigests != s.images || s.changed {
		return ErrUnavailable
	}
	return nil
}
func (s *native9SemanticFixture) RecheckPublic(context.Context, *VerifiedCurrent, RelaySessionBinding, Process) error {
	if s.changed {
		return ErrUnavailable
	}
	return nil
}
func native9CurrentFixture(t *testing.T, last uint64) (*CurrentVerifier, *native9OriginalFixture, *native9SemanticFixture) {
	t.Helper()
	f := native9NewFixture(t, last)
	r := f.binding.PreAcquisitionApprovalRef
	expected := CurrentExpected{Binding: f.binding, IssuerOrigin: r, IssuerCustody: r, PurposeApproval: r, SourceConfinement: r, CompleteWriterInventory: r, ActualRootCapture: r, WriterIDs: []string{"writer-a"}, FreshFor: time.Second}
	for i, ref := range f.refs {
		expected.Records = append(expected.Records, RecordPins{ref, f.pins})
		_ = i
	}
	originals := &native9OriginalFixture{originals: f.originals}
	source := &native9SemanticFixture{observation: CurrentObservation{OperationID: f.binding.OperationID, TargetFingerprint: f.binding.TargetFingerprint, PublicationRevision: f.binding.PublicationRevision, Keeper: f.binding.Keeper, Root: f.binding.Keeper.Process, RootCapture: r, Writers: []WriterObservation{{ID: "writer-a", Original: r, Closure: r, RestartBarrier: r}}}}
	v, err := NewCurrentVerifier(expected, originals, source)
	if err != nil {
		t.Fatal(err)
	}
	return v, originals, source
}
func TestNative9CurrentRequiresActualSourceAndWholeWriters(t *testing.T) {
	for _, name := range []string{"actual-source", "missing-source", "typed-nil-source", "incomplete-writers", "root-object-change", "held-original-change", "original-cutoff", "concurrent-use"} {
		t.Run(name, func(t *testing.T) {
			v, originals, source := native9CurrentFixture(t, 13)
			want := name == "actual-source"
			switch name {
			case "missing-source":
				v.semantics = nil
			case "typed-nil-source":
				var absent *native9SemanticFixture
				v.semantics = absent
			case "incomplete-writers":
				source.observation.Writers = nil
			case "root-object-change":
				source.changed = true
			case "held-original-change":
				originals.changed = true
			case "original-cutoff":
				v.expected.Binding.OriginalCutoffUnix = time.Now().Unix()
			case "concurrent-use":
				v.busy.Store(true)
			}
			used := false
			err := v.Consume(context.Background(), func(a *VerifiedCurrent) error {
				used = true
				seq, ok := a.Sequence()
				if !ok || seq != 13 || !a.Physical() {
					t.Fatal("wrong verified phase")
				}
				return nil
			})
			if (err == nil) != want || used != want {
				t.Fatalf("consumption err=%v used=%v", err, used)
			}
			if originals.held != originals.closed {
				t.Fatal("owned original handles leaked")
			}
		})
	}
	t.Run("mutation-after-use", func(t *testing.T) {
		v, originals, _ := native9CurrentFixture(t, 13)
		if v.Consume(context.Background(), func(*VerifiedCurrent) error { originals.changed = true; return nil }) == nil {
			t.Fatal("post-use mutation hidden")
		}
		if originals.held != originals.closed {
			t.Fatal("post failure handles leaked")
		}
	})
}
func TestNative9PhaseScopedAuthorityNoFutureReceiptCycle(t *testing.T) {
	for _, last := range []uint64{0, 9, 10, 11, 12, 13} {
		v, _, _ := native9CurrentFixture(t, last)
		if v.Consume(context.Background(), func(a *VerifiedCurrent) error {
			seq, _ := a.Sequence()
			if seq != last {
				t.Fatal("wrong phase")
			}
			if last < 13 && a.Physical() {
				t.Fatal("issuer success declared physical authority")
			}
			return nil
		}) != nil {
			t.Fatalf("phase %d required future originals", last)
		}
	}
}
func TestNative9ReaderBridgeMissingSourceDeny(t *testing.T) {
	old := ReviewedReaderFactory
	defer func() { ReviewedReaderFactory = old }()
	ReviewedReaderFactory = nil
	if _, err := OpenActualReader(context.Background(), d101custody.Original{}); err == nil {
		t.Fatal("missing actual reader source accepted")
	}
}

func TestNative9PublicProjectionRequiresActualPeerImagesAndPhysicalPhase(t *testing.T) {
	for _, name := range []string{"physical-public", "wrong-peer", "image-scope", "issuer-only", "source-change"} {
		t.Run(name, func(t *testing.T) {
			last := uint64(13)
			if name == "issuer-only" {
				last = 11
			}
			v, originals, source := native9CurrentFixture(t, last)
			b := v.expected.Binding
			image := "sha256:" + strings.Repeat("a", 64)
			source.images = FiveImages{image, image, image, image, image}
			pub := RelaySessionBinding{SchemaVersion: 1, LeafKind: "RELAY_SESSION_BINDING", OperationID: b.OperationID, TargetFingerprint: b.TargetFingerprint, PublicationRevision: b.PublicationRevision, OriginalCutoffUnix: b.OriginalCutoffUnix, KeeperProcess: b.Keeper.Process, KeeperBirthNonce: b.Keeper.BirthNonce, Peer: b.Keeper.Process, ImageDigests: source.images, PhysicalPhaseSHA256: strings.Repeat("f", 64), KeeperSessionSHA256: v.expected.Records[8].Original.SHA256, ApprovedPlanSHA256: b.PreAcquisitionApprovalRef.SHA256, ExecutionReceiptSHA256: b.PreAcquisitionApprovalRef.SHA256}
			if last == 13 {
				pub.PhysicalPhaseSHA256 = v.expected.Records[13].Original.SHA256
			}
			if name == "image-scope" {
				pub.ImageDigests.GameAPI = "sha256:" + strings.Repeat("f", 64)
			}
			if name == "source-change" {
				source.changed = true
			}
			peer := pub.Peer
			if name == "wrong-peer" {
				peer.StartTicks++
			}
			f := native9NewFixture(t, 0)
			wire := f.sign(t, &pub)
			used := false
			err := v.ConsumePublic(context.Background(), wire, v.expected.Records[0].Signature, peer, func(*VerifiedCurrent, *RelaySessionBinding) error { used = true; return nil })
			want := name == "physical-public"
			if (err == nil) != want || used != want {
				t.Fatalf("public route used=%v err=%v", used, err)
			}
			if originals.held != originals.closed {
				t.Fatal("public route leaked originals")
			}
			body, _ := json.Marshal(pub)
			if bytes.Contains(body, []byte("previousOriginalRef")) || bytes.Contains(body, []byte("/fixture/actual-original")) {
				t.Fatal("private authority leaked through public schema")
			}
		})
	}
}
