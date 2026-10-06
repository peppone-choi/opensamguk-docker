package d101native

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101freeze"
	"reflect"
	"sync/atomic"
	"time"
)

// Expected inputs originate outside the files being consumed. All real actor,
// purpose, key custody, source, replica and lifecycle sources remain mandatory.
type RecordPins struct {
	Original  RawRef
	Signature SignaturePins
}
type CurrentExpected struct {
	Binding                                                         PreBinding
	Records                                                         []RecordPins
	IssuerOrigin, IssuerCustody, PurposeApproval, SourceConfinement RawRef
	CompleteWriterInventory, ActualRootCapture                      RawRef
	WriterIDs                                                       []string
	FreshFor                                                        time.Duration
}
type HeldOriginal interface {
	Original() []byte
	Reference() RawRef
	Recheck(context.Context) error
	Close() error
}
type NativeOriginalSource interface {
	HoldOriginal(context.Context, RawRef) (HeldOriginal, error)
}
type WriterObservation struct {
	ID                                string
	Original, Closure, RestartBarrier RawRef
}
type CurrentObservation struct {
	OperationID, TargetFingerprint, PublicationRevision string
	Keeper                                              Keeper
	ObservedAt                                          time.Time
	Writers                                             []WriterObservation
	Root                                                Process
	RootCapture                                         RawRef
}
type CurrentEvidence struct {
	Expected  CurrentExpected
	Records   []Unverified
	Originals map[RawRef][]byte
}

// Implementations authenticate actual original provenance and all live sources,
// including full inherited OFD ownership. Signature/stat/time labels alone do
// not implement this interface. No positive source is installed by this package.
type CurrentSemanticSource interface {
	AuthenticateCurrent(context.Context, CurrentEvidence) (CurrentObservation, error)
	RecheckCurrent(context.Context, CurrentEvidence, CurrentObservation) error
}
type PublicSemanticSource interface {
	AuthenticatePublic(context.Context, *VerifiedCurrent, RelaySessionBinding, Process) error
	RecheckPublic(context.Context, *VerifiedCurrent, RelaySessionBinding, Process) error
}
type CurrentVerifier struct {
	expected  CurrentExpected
	originals NativeOriginalSource
	semantics CurrentSemanticSource
	busy      atomic.Bool
}
type VerifiedCurrent struct {
	binding     PreBinding
	records     []Unverified
	observation CurrentObservation
}

func (v *VerifiedCurrent) Binding() (PreBinding, bool) {
	if v == nil {
		return PreBinding{}, false
	}
	return v.binding, true
}
func (v *VerifiedCurrent) Physical() bool { return v != nil && len(v.records) >= 14 }
func (v *VerifiedCurrent) Sequence() (uint64, bool) {
	if v == nil || len(v.records) == 0 {
		return 0, false
	}
	return uint64(len(v.records) - 1), true
}
func (v *VerifiedCurrent) Original(sequence uint64) []byte {
	if v == nil || sequence >= uint64(len(v.records)) {
		return nil
	}
	return v.records[sequence].Original()
}
func Missing(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return r.IsNil()
	}
	return false
}
func cloneExpected(e CurrentExpected) CurrentExpected {
	e.Records = append([]RecordPins(nil), e.Records...)
	for i := range e.Records {
		e.Records[i].Signature.SPKIDER = bytes.Clone(e.Records[i].Signature.SPKIDER)
	}
	e.WriterIDs = append([]string(nil), e.WriterIDs...)
	return e
}
func NewCurrentVerifier(e CurrentExpected, n NativeOriginalSource, s CurrentSemanticSource) (*CurrentVerifier, error) {
	if Missing(n) || Missing(s) || !ValidBinding(e.Binding) || len(e.Records) == 0 || len(e.Records) > 15 || e.FreshFor <= 0 || len(e.WriterIDs) == 0 || len(e.WriterIDs) > 256 {
		return nil, ErrUnavailable
	}
	for _, r := range []RawRef{e.IssuerOrigin, e.IssuerCustody, e.PurposeApproval, e.SourceConfinement, e.CompleteWriterInventory, e.ActualRootCapture} {
		if !ValidRef(r) {
			return nil, ErrUnavailable
		}
	}
	seen := map[string]bool{}
	for _, id := range e.WriterIDs {
		if id == "" || seen[id] {
			return nil, ErrUnavailable
		}
		seen[id] = true
	}
	for _, r := range e.Records {
		if !ValidRef(r.Original) || r.Signature.Domain != NativeAuthorityDomain || r.Signature.KeyID == "" || Hash(r.Signature.SPKIDER) != e.Binding.IssuerSPKISHA256 {
			return nil, ErrUnavailable
		}
	}
	return &CurrentVerifier{expected: cloneExpected(e), originals: n, semantics: s}, nil
}
func equalBinding(a, b PreBinding) bool { return a == b }
func VerifyChain(records []Unverified, refs []RawRef, binding PreBinding) error {
	if len(records) == 0 || len(records) > 15 || len(records) != len(refs) {
		return ErrUnavailable
	}
	indices := map[string]int{}
	for i, r := range refs {
		if !ValidRef(r) || Hash(records[i].original) != r.SHA256 || uint64(len(records[i].original)) != r.Bytes {
			return ErrUnavailable
		}
		if _, ok := indices[r.SHA256]; ok {
			return ErrUnavailable
		}
		indices[r.SHA256] = i
	}
	for i, u := range records {
		h, ok := HeaderOf(u.record)
		if !ok || h.Sequence != uint64(i) || !equalBinding(h.Binding, binding) {
			return ErrUnavailable
		}
		if i > 0 && (h.PreviousOriginalRef != refs[i-1] || h.AcquisitionRef != refs[0]) {
			return ErrUnavailable
		}
		for _, r := range References(u.record) {
			if n, known := indices[r.SHA256]; known && n >= i {
				return ErrUnavailable
			}
		}
		if i >= 10 {
			var p PlanHeader
			switch x := u.record.(type) {
			case *FinalBound:
				p = x.Header
			case *IssuerRunning:
				p = x.Header
			case *IssuerDone:
				p = x.Header
			case *PhysicalRunning:
				p = x.Header.Plan
			case *Released:
				p = x.Header.Plan
			case *RecoveredRelease:
				p = x.Header.Plan
			}
			if p.FreezeOriginalRef != refs[9] {
				return ErrUnavailable
			}
			if i > 10 {
				first := records[10].record.(*FinalBound)
				if p.ApprovedFinalPlanRef != first.Header.ApprovedFinalPlanRef {
					return ErrUnavailable
				}
			}
		}
		if i >= 13 {
			done := records[12].record.(*IssuerDone)
			var p PhysicalHeader
			switch x := u.record.(type) {
			case *PhysicalRunning:
				p = x.Header
			case *Released:
				p = x.Header
			case *RecoveredRelease:
				p = x.Header
			}
			if p.IssuerDoneRef != refs[12] || p.ExecutionReceiptRef != done.ExecutionReceiptRef {
				return ErrUnavailable
			}
		}
	}
	if len(records) > 9 {
		f := records[9].record.(*Freeze)
		actual := []RawRef{f.InventoryRef, f.ConsoleAdmissionRef, f.RootAdmissionRef, f.TurnFlushRef, f.PublisherRef, f.PostgresAdmissionRef, f.OldServicesRef, f.KeeperSessionRef}
		for i, x := range actual {
			if x != refs[i+1] {
				return ErrUnavailable
			}
		}
	}
	return nil
}
func observationMatches(e CurrentExpected, o CurrentObservation, now time.Time) bool {
	b := e.Binding
	if o.OperationID != b.OperationID || o.TargetFingerprint != b.TargetFingerprint || o.PublicationRevision != b.PublicationRevision || o.Keeper != b.Keeper || o.RootCapture != e.ActualRootCapture || !ValidProcess(o.Root) || o.ObservedAt.IsZero() || o.ObservedAt.After(now) || now.Sub(o.ObservedAt) >= e.FreshFor || now.Unix() >= b.OriginalCutoffUnix || len(o.Writers) != len(e.WriterIDs) {
		return false
	}
	want := map[string]bool{}
	for _, id := range e.WriterIDs {
		want[id] = true
	}
	for _, w := range o.Writers {
		if !want[w.ID] || !ValidRef(w.Original) || !ValidRef(w.Closure) || !ValidRef(w.RestartBarrier) {
			return false
		}
		delete(want, w.ID)
	}
	return len(want) == 0
}

// No mutex is held during I/O/authentication or user code. Atomic reservation
// denies concurrent uses; existing consumers perform their own actual CAS.
func (v *CurrentVerifier) Consume(ctx context.Context, use func(*VerifiedCurrent) error) error {
	if v == nil || ctx == nil || ctx.Err() != nil || use == nil || Missing(v.originals) || Missing(v.semantics) || !v.busy.CompareAndSwap(false, true) {
		return ErrUnavailable
	}
	defer v.busy.Store(false)
	e := cloneExpected(v.expected)
	if time.Now().Unix() >= e.Binding.OriginalCutoffUnix {
		return ErrUnavailable
	}
	held := []HeldOriginal{}
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			_ = held[i].Close()
		}
	}()
	originals := map[RawRef][]byte{}
	hold := func(r RawRef) error {
		if _, exists := originals[r]; exists {
			return nil
		}
		if !ValidRef(r) {
			return ErrUnavailable
		}
		h, err := v.originals.HoldOriginal(ctx, r)
		if err != nil || Missing(h) {
			return ErrUnavailable
		}
		held = append(held, h)
		raw := h.Original()
		if h.Reference() != r || uint64(len(raw)) != r.Bytes || Hash(raw) != r.SHA256 || h.Recheck(ctx) != nil {
			return ErrUnavailable
		}
		originals[r] = bytes.Clone(raw)
		return nil
	}
	records := make([]Unverified, 0, len(e.Records))
	refs := make([]RawRef, 0, len(e.Records))
	for _, p := range e.Records {
		if hold(p.Original) != nil {
			return ErrUnavailable
		}
		u, err := Decode(originals[p.Original], p.Signature)
		if err != nil {
			return ErrUnavailable
		}
		records = append(records, u)
		refs = append(refs, p.Original)
	}
	if VerifyChain(records, refs, e.Binding) != nil {
		return ErrUnavailable
	}
	for _, u := range records {
		for _, r := range References(u.record) {
			if hold(r) != nil {
				return ErrUnavailable
			}
		}
	}
	for _, r := range []RawRef{e.IssuerOrigin, e.IssuerCustody, e.PurposeApproval, e.SourceConfinement, e.CompleteWriterInventory, e.ActualRootCapture} {
		if hold(r) != nil {
			return ErrUnavailable
		}
	}
	evidence := CurrentEvidence{e, records, originals}
	obs, err := v.semantics.AuthenticateCurrent(ctx, evidence)
	check := func() error {
		if ctx.Err() != nil || !observationMatches(e, obs, time.Now()) {
			return ErrUnavailable
		}
		for _, h := range held {
			if h.Recheck(ctx) != nil {
				return ErrUnavailable
			}
		}
		if v.semantics.RecheckCurrent(ctx, evidence, obs) != nil || ctx.Err() != nil || !observationMatches(e, obs, time.Now()) {
			return ErrUnavailable
		}
		for _, h := range held {
			if h.Recheck(ctx) != nil {
				return ErrUnavailable
			}
		}
		return nil
	}
	if err != nil || check() != nil {
		return ErrUnavailable
	}
	verified := &VerifiedCurrent{e.Binding, records, obs}
	if err = use(verified); err != nil {
		return err
	}
	return check()
}

// A runtime certificate is authenticated against an actual physical lease;
// decoding a public file never supplies a connected-peer issuer by itself.
func (v *CurrentVerifier) ConsumePublic(ctx context.Context, wire []byte, pins SignaturePins, peer Process, use func(*VerifiedCurrent, *RelaySessionBinding) error) error {
	if use == nil || v == nil {
		return ErrUnavailable
	}
	source, ok := v.semantics.(PublicSemanticSource)
	if !ok || Missing(source) {
		return ErrUnavailable
	}
	u, err := Decode(wire, pins)
	if err != nil {
		return err
	}
	pub, ok := u.record.(*RelaySessionBinding)
	if !ok || pub.Peer != peer {
		return ErrUnavailable
	}
	return v.Consume(ctx, func(current *VerifiedCurrent) error {
		b := current.binding
		if !current.Physical() || pub.OperationID != b.OperationID || pub.TargetFingerprint != b.TargetFingerprint || pub.PublicationRevision != b.PublicationRevision || pub.OriginalCutoffUnix != b.OriginalCutoffUnix || pub.KeeperProcess != b.Keeper.Process || pub.KeeperBirthNonce != b.Keeper.BirthNonce || pub.PhysicalPhaseSHA256 != Hash(current.records[13].original) || pub.KeeperSessionSHA256 != Hash(current.records[8].original) {
			return ErrUnavailable
		}
		done := current.records[12].record.(*IssuerDone)
		plan := current.records[10].record.(*FinalBound)
		if pub.ApprovedPlanSHA256 != plan.Header.ApprovedFinalPlanRef.SHA256 || pub.ExecutionReceiptSHA256 != done.ExecutionReceiptRef.SHA256 {
			return ErrUnavailable
		}
		if source.AuthenticatePublic(ctx, current, *pub, peer) != nil || source.RecheckPublic(ctx, current, *pub, peer) != nil {
			return ErrUnavailable
		}
		if err := use(current, pub); err != nil {
			return err
		}
		return source.RecheckPublic(ctx, current, *pub, peer)
	})
}

func (v *VerifiedCurrent) ObservedAt() time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.observation.ObservedAt
}

// Shared C3 bridge is installed by the same approved real input bundle as the
// host/main consumers. Reader exact7 and original14 do not carry these inputs.
// The factory remains nil until actual source/custody/purpose approval exists.
type ReaderInput struct {
	InstallationSHA           string
	Binding                   PreBinding
	FreezeSHA                 string
	Directory                 string
	ParentDevice, ParentInode uint64
	LockPins                  d101freeze.ProductionLockPins
	Source                    ReaderCurrentSource
}
type ReaderCurrentSource interface {
	CurrentReader(context.Context, *os.File, d101freeze.UnverifiedProductionLock, time.Time) (*CurrentVerifier, error)
	RecheckReader(context.Context, ReaderInput) error
}
type ReaderFactory interface {
	OpenReader(context.Context, d101custody.Original) (*ReaderInput, error)
	RecheckReaderInstallation(context.Context, d101custody.Original, ReaderInput) error
}

var ReviewedReaderFactory ReaderFactory

func OpenActualReader(ctx context.Context, original d101custody.Original) (*ReaderInput, error) {
	if ctx == nil || ctx.Err() != nil || Missing(ReviewedReaderFactory) {
		return nil, ErrUnavailable
	}
	input, err := ReviewedReaderFactory.OpenReader(ctx, original)
	if err != nil || input == nil || input.InstallationSHA != original.SHA256 || !ValidBinding(input.Binding) || !ValidSHA(input.FreezeSHA) || !filepath.IsAbs(input.Directory) || filepath.Clean(input.Directory) != input.Directory || input.ParentDevice == 0 || input.ParentInode == 0 || input.LockPins.Inode == 0 || Missing(input.Source) || ReviewedReaderFactory.RecheckReaderInstallation(ctx, original, *input) != nil || input.Source.RecheckReader(ctx, *input) != nil {
		return nil, ErrUnavailable
	}
	copy := *input
	return &copy, nil
}

// Exactly the existing current8 wire, derived only inside the actual current
// consumer. A whole-source failure produces no successful empty projection.
func CollectReaderCurrent(ctx context.Context, input ReaderInput, descriptor *os.File, started time.Time, lock d101freeze.UnverifiedProductionLock) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || descriptor == nil || descriptor.Fd() != 9 || Missing(input.Source) || started.IsZero() || input.Source.RecheckReader(ctx, input) != nil {
		return nil, ErrUnavailable
	}
	current, err := input.Source.CurrentReader(ctx, descriptor, lock, started)
	if err != nil || current == nil {
		return nil, ErrUnavailable
	}
	var wire []byte
	err = current.Consume(ctx, func(actual *VerifiedCurrent) error {
		b, ok := actual.Binding()
		seq, ok2 := actual.Sequence()
		observed := actual.ObservedAt()
		if !ok || !ok2 || seq != 13 || b != input.Binding || Hash(actual.Original(9)) != input.FreezeSHA || observed.Before(started) || observed.After(time.Now()) {
			return ErrUnavailable
		}
		var e error
		wire, e = json.Marshal(struct {
			ObservedAt             string `json:"observedAt"`
			ServerID               string `json:"serverId"`
			OperationID            string `json:"operationId"`
			TargetFingerprint      string `json:"targetFingerprint"`
			PublicationState       string `json:"publicationState"`
			PublicationRevision    string `json:"publicationRevision"`
			WriterFreezeReceiptSHA string `json:"writerFreezeReceiptSha256"`
			WriterFreezeHeld       bool   `json:"writerFreezeHeld"`
		}{observed.UTC().Format(time.RFC3339Nano), "pep", b.OperationID, b.TargetFingerprint, "VERIFYING", b.PublicationRevision, input.FreezeSHA, true})
		return e
	})
	if err != nil || ctx.Err() != nil || input.Source.RecheckReader(ctx, input) != nil {
		return nil, ErrUnavailable
	}
	return wire, nil
}
