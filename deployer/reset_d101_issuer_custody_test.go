package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"opensamguk-deployer/internal/d101operatorauth"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func resetD101IssuerLedgerTestDirectory(t *testing.T) (*os.File, resetD101IssuerDirectoryPin) {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(path, 0700) != nil {
		t.Fatal("fixture directory")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	pin := resetD101IssuerDirectoryPin{uint64(stat.Dev), uint64(stat.Ino)}
	dir, err := openResetD101IssuerDirectory(path, pin, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	return dir, pin
}

func TestIssuerLedgerExclusiveOriginalSurvivesNewWriterAndRejectsMutation(t *testing.T) {
	for _, name := range []string{"same-name-replay", "symlink", "hardlink", "wrong-mode", "content-mutation", "oversize"} {
		t.Run(name, func(t *testing.T) {
			dir, _ := resetD101IssuerLedgerTestDirectory(t)
			uid := uint32(os.Getuid())
			wire := []byte("synthetic-private-original")
			if name == "oversize" {
				if writeResetD101IssuerExclusive(dir, "entry", bytes.Repeat([]byte{'a'}, (64<<10)+1), uid) == nil {
					t.Fatal("oversize")
				}
				return
			}
			if writeResetD101IssuerExclusive(dir, "entry", wire, uid) != nil || requireResetD101IssuerOwnedOriginal(dir, "entry", wire, uid) != nil {
				t.Fatal("durable original")
			}
			path := filepath.Join(dir.Name(), "entry")
			switch name {
			case "same-name-replay":
				// A fresh writer, without process flags, sees the durable O_EXCL guard.
				other, err := os.Open(dir.Name())
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				if writeResetD101IssuerExclusive(other, "entry", []byte("replacement"), uid) == nil || requireResetD101IssuerOwnedOriginal(dir, "entry", wire, uid) != nil {
					t.Fatal("durable replay replaced original")
				}
				return
			case "symlink":
				if os.Remove(path) != nil || os.Symlink("outside", path) != nil {
					t.Fatal("fixture symlink")
				}
			case "hardlink":
				if os.Link(path, filepath.Join(dir.Name(), "alias")) != nil {
					t.Fatal("fixture link")
				}
			case "wrong-mode":
				if os.Chmod(path, 0600) != nil {
					t.Fatal("fixture mode")
				}
			case "content-mutation":
				if os.Chmod(path, 0600) != nil || os.WriteFile(path, []byte("mutated"), 0600) != nil || os.Chmod(path, 0400) != nil {
					t.Fatal("fixture mutation")
				}
			}
			if requireResetD101IssuerOwnedOriginal(dir, "entry", wire, uid) == nil {
				t.Fatal("mutated native original was accepted")
			}
		})
	}
}

func TestIssuerLedgerDirectoryAndBudgetRejectUnknownOrOverflow(t *testing.T) {
	for _, name := range []string{"pin-drift", "parent-symlink", "unknown-child", "cap-full", "reserve-overflow"} {
		t.Run(name, func(t *testing.T) {
			root, pin := resetD101IssuerLedgerTestDirectory(t)
			uid := uint32(os.Getuid())
			if name == "pin-drift" {
				pin.inode++
				if dir, err := openResetD101IssuerDirectory(root.Name(), pin, uid); err == nil {
					dir.Close()
					t.Fatal("wrong parent inode")
				}
				return
			}
			if name == "parent-symlink" {
				alias := filepath.Join(t.TempDir(), "alias")
				if os.Symlink(root.Name(), alias) != nil {
					t.Fatal("fixture symlink")
				}
				if dir, err := openResetD101IssuerDirectory(alias, pin, uid); err == nil {
					dir.Close()
					t.Fatal("aliased namespace")
				}
				return
			}
			oncePath := filepath.Join(root.Name(), ".once")
			if os.Mkdir(oncePath, 0700) != nil {
				t.Fatal("fixture once")
			}
			once, err := os.Open(oncePath)
			if err != nil {
				t.Fatal(err)
			}
			defer once.Close()
			cap, reserve := uint64(1<<30), uint64(10<<30)
			switch name {
			case "unknown-child":
				if os.Mkdir(filepath.Join(root.Name(), "unapproved"), 0700) != nil {
					t.Fatal("fixture")
				}
			case "cap-full":
				cap = 1
			case "reserve-overflow":
				reserve = ^uint64(0)
			}
			if resetD101IssuerLedgerBudget(root, once, cap, reserve, uid) == nil {
				t.Fatal("unknown/budget unsafe namespace accepted")
			}
		})
	}
}

func TestNativeIssuerEmitterMissingOpaqueInputsNeverCapturesOrSigns(t *testing.T) {
	if emitter, err := newResetD101NativeIssuerEmission(resetD101NativeIssuerEmissionInputs{}); err == nil || emitter != nil {
		t.Fatal("missing native semantic/key/output inputs registered")
	}
	var emitter *resetD101NativeIssuerEmission
	if emitter.IssueAndRetain(context.Background(), nil, d101operatorauth.TechnicalIssuance{}) == nil || emitter.AuthenticateAvailability(context.Background(), nil, d101operatorauth.ReviewedPolicy{}) == nil {
		t.Fatal("missing opaque/native inputs accepted")
	}
}
func TestNativeIssuerRoleEnvelopeUsesExistingRoleDomainAndRejectsRootKey(t *testing.T) {
	for _, name := range []string{"approval", "receipt", "unknown-role", "root-key", "wrong-public-key", "changed-unsigned", "cross-role-domain", "corrupt-envelope"} {
		t.Run(name, func(t *testing.T) {
			// Public deterministic synthetic crypto fixture, never native signing.
			private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, ed25519.SeedSize))
			spki, err := x509.MarshalPKIXPublicKey(private.Public())
			if err != nil {
				t.Fatal(err)
			}
			issuer := d101operatorauth.IssuerPins{Role: d101operatorauth.ApprovalIssuerRole, PublicKeySPKI: spki, PublicKeySPKISHA256: resetD101OriginalSHA(spki)}
			key := resetD101SigningKey{keyID: "synthetic-issuer", publicKeySpkiSHA: issuer.PublicKeySPKISHA256, private: private}
			defer key.close()
			root := strings.Repeat("f", 64)
			unsigned := []byte(`{"synthetic":"frozen unsigned"}`)
			if name == "receipt" {
				issuer.Role = d101operatorauth.ApprovedReceiptIssuerRole
			}
			if name == "unknown-role" {
				issuer.Role = "QUERY"
			}
			if name == "root-key" {
				root = issuer.PublicKeySPKISHA256
			}
			if name == "wrong-public-key" {
				issuer.PublicKeySPKISHA256 = strings.Repeat("e", 64)
			}
			wire, err := signResetD101IssuerRoleEnvelope(&key, issuer, root, unsigned)
			if name == "unknown-role" || name == "root-key" || name == "wrong-public-key" {
				if err == nil || wire != nil {
					t.Fatal("unapproved role/root/mismatched key signed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if name == "changed-unsigned" {
				unsigned = append(unsigned, ' ')
			}
			if name == "cross-role-domain" {
				issuer.Role = d101operatorauth.ApprovedReceiptIssuerRole
			}
			if name == "corrupt-envelope" {
				var env resetD101SignedHostOriginal
				if json.Unmarshal(wire, &env) != nil {
					t.Fatal("fixture")
				}
				env.SignatureBase64url = "invalid"
				wire, _ = json.Marshal(env)
			}
			err = verifyResetD101IssuerRoleEnvelope(wire, unsigned, issuer, root)
			if (err == nil) != (name == "approval" || name == "receipt") {
				t.Fatal("exact existing role/domain/frozen bytes verification")
			}
		})
	}
}
func TestNativeIssuerEmissionRetentionPreservesAndRejectsNativeReplacement(t *testing.T) {
	for _, name := range []string{"retained", "existing", "same-byte-replaced"} {
		t.Run(name, func(t *testing.T) {
			dir, _ := resetD101IssuerLedgerTestDirectory(t)
			uid := uint32(os.Getuid())
			op := strings.Repeat("a", 32)
			wire := []byte("synthetic retained envelope")
			if name == "existing" {
				if err := os.WriteFile(filepath.Join(dir.Name(), op+".json"), []byte("preserved"), 0400); err != nil {
					t.Fatal(err)
				}
			}
			o, err := writeResetD101IssuerEmissionHeld(context.Background(), dir, op, wire, uid)
			if name == "existing" {
				if err == nil || o.file != nil {
					t.Fatal("overwrite accepted")
				}
				b, _ := os.ReadFile(filepath.Join(dir.Name(), op+".json"))
				if string(b) != "preserved" {
					t.Fatal("old envelope changed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer o.file.Close()
			if name == "same-byte-replaced" {
				path := filepath.Join(dir.Name(), op+".json")
				if os.Rename(path, path+".old") != nil || os.WriteFile(path, wire, 0400) != nil {
					t.Fatal("fixture replacement")
				}
			}
			if (recheckResetD101PreparedHeldOriginal(o, uid) == nil) != (name == "retained") {
				t.Fatal("native descriptor replacement result")
			}
		})
	}
}

type resetD101IssuerSnapshotMutationFixture struct{ mutate bool }

func (s resetD101IssuerSnapshotMutationFixture) CaptureAuthenticatedUnsigned(context.Context, d101operatorauth.TechnicalIssuance) (resetD101IssuerSemanticSnapshot, error) {
	return resetD101IssuerSemanticSnapshot{}, errResetExecutionEvidence
}
func (s resetD101IssuerSnapshotMutationFixture) RecheckAuthenticatedUnsigned(_ context.Context, _ d101operatorauth.TechnicalIssuance, v resetD101IssuerSemanticSnapshot) error {
	if s.mutate {
		v.Original13["synthetic"][0] = 'X'
	}
	return nil
}
func TestNativeIssuerSemanticRecheckRejectsSnapshotMutation(t *testing.T) {
	for _, mutate := range []bool{false, true} {
		name := "unchanged"
		if mutate {
			name = "mutated"
		}
		t.Run(name, func(t *testing.T) {
			// Private snapshot-copy seam only, zero issuance stays unavailable in
			// the production factory/emitter; this fixture grants no authority.
			s := &resetD101IssuerEmissionSemanticSource{actual: resetD101IssuerSnapshotMutationFixture{mutate: mutate}, frozen: resetD101IssuerSemanticSnapshot{Original13: map[string][]byte{"synthetic": []byte("original")}}, captured: true}
			err := s.RecheckAuthenticatedUnsigned(context.Background(), d101operatorauth.TechnicalIssuance{}, s.frozen)
			if (err == nil) == mutate || string(s.frozen.Original13["synthetic"]) != "original" {
				t.Fatal("callback mutation accepted or frozen input changed")
			}
		})
	}
}

// Portable retained-descriptor fixture only. It never supplies installed native
// authority, a CurrentOperator/TechnicalIssuance, a private key or a signature.
func resetD101IssuerRetainedEmissionFixture(t *testing.T) (*resetD101NativeIssuerEmission, *resetD101IssuerRetainedEmission) {
	t.Helper()
	op := strings.Repeat("a", 32)
	e := &resetD101NativeIssuerEmission{attempted: true}
	e.inputs.policy.Scope.OperationID = op
	r := &resetD101IssuerRetainedEmission{semantic: &resetD101IssuerEmissionSemanticSource{
		actual: resetD101IssuerSnapshotMutationFixture{}, captured: true,
		frozen: resetD101IssuerSemanticSnapshot{Original13: map[string][]byte{"synthetic": []byte("original")}},
	}}
	for i := 0; i < 3; i++ {
		dir, pin := resetD101IssuerLedgerTestDirectory(t)
		r.dirs = append(r.dirs, dir)
		o, err := writeResetD101IssuerEmissionHeld(context.Background(), dir, op, []byte("synthetic output "+string(rune('a'+i))), uint32(os.Getuid()))
		if err != nil {
			t.Fatal(err)
		}
		r.held = append(r.held, o)
		output := resetD101IssuerEmissionOutput{directory: dir.Name(), pin: pin}
		switch i {
		case 0:
			e.inputs.origin = output
		case 1:
			e.inputs.attestation = output
		case 2:
			e.inputs.provenance = output
		}
	}
	e.retained = r
	e.inputs.verifyRetained = func(_ context.Context, _ *os.File, _ d101operatorauth.TechnicalIssuance, _ resetD101IssuerSemanticSnapshot, a, b, c []byte) error {
		for i, wire := range [][]byte{a, b, c} {
			if !bytes.Equal(wire, r.held[i].wire) {
				return errResetExecutionEvidence
			}
		}
		return nil
	}
	t.Cleanup(func() { _ = e.CloseRetained() })
	return e, r
}

func resetD101IssuerRetainedFixtureNative(context.Context, *os.File, string) error {
	// Private pure seam; never wired to the production AuthenticateRetained.
	return nil
}

func requireResetD101IssuerRetainedFixtureClosed(t *testing.T, e *resetD101NativeIssuerEmission, r *resetD101IssuerRetainedEmission) {
	t.Helper()
	if e.retained != nil || !e.stopped.Load() {
		t.Fatal("failed/released custody remained available")
	}
	for _, o := range r.held {
		if _, err := o.file.Stat(); err == nil {
			t.Fatal("output descriptor remained open")
		}
	}
	for _, d := range r.dirs {
		if _, err := d.Stat(); err == nil {
			t.Fatal("directory descriptor remained open")
		}
	}
}

func TestNativeIssuerRetainedOutputsPreserveDescriptorsUntilClosure(t *testing.T) {
	e, r := resetD101IssuerRetainedEmissionFixture(t)
	var descriptors []uintptr
	for _, o := range r.held {
		descriptors = append(descriptors, o.file.Fd())
	}
	for _, phase := range []string{"issuer-emission-retained", "issuer-release"} {
		if e.authenticateRetainedWithNative(context.Background(), nil, e.inputs.policy.Scope.OperationID, phase, uint32(os.Getuid()), resetD101IssuerRetainedFixtureNative) != nil {
			t.Fatal("portable same-descriptor conjunction refused")
		}
		for i, o := range r.held {
			if o.file.Fd() != descriptors[i] || recheckResetD101PreparedHeldOriginal(o, uint32(os.Getuid())) != nil {
				t.Fatal("emission/release reopened or replaced original descriptor")
			}
		}
	}
	if e.CloseRetained() != nil {
		t.Fatal("final descriptor closure")
	}
	requireResetD101IssuerRetainedFixtureClosed(t, e, r)
	for _, o := range r.held {
		wire, err := os.ReadFile(o.file.Name())
		if err != nil || !bytes.Equal(wire, o.wire) {
			t.Fatal("closure changed durable original")
		}
	}
	if e.authenticateRetainedWithNative(context.Background(), nil, e.inputs.policy.Scope.OperationID, "issuer-release", uint32(os.Getuid()), resetD101IssuerRetainedFixtureNative) == nil {
		t.Fatal("release replay accepted")
	}
}

func TestNativeIssuerRetainedOutputsRejectPostEmissionDrift(t *testing.T) {
	for _, name := range []string{"origin-samebytes-replace", "attestation-samebytes-replace", "provenance-samebytes-replace", "directory-replace", "closed-descriptor", "content-mutation"} {
		t.Run(name, func(t *testing.T) {
			e, r := resetD101IssuerRetainedEmissionFixture(t)
			op, uid := e.inputs.policy.Scope.OperationID, uint32(os.Getuid())
			if e.authenticateRetainedWithNative(context.Background(), nil, op, "issuer-emission-retained", uid, resetD101IssuerRetainedFixtureNative) != nil {
				t.Fatal("pre-mutation fixture")
			}
			i := 0
			if name == "attestation-samebytes-replace" {
				i = 1
			} else if name == "provenance-samebytes-replace" {
				i = 2
			}
			path := r.held[i].file.Name()
			switch name {
			case "directory-replace":
				if os.Rename(r.dirs[0].Name(), r.dirs[0].Name()+".old") != nil || os.Mkdir(r.dirs[0].Name(), 0700) != nil || os.WriteFile(path, r.held[0].wire, 0400) != nil {
					t.Fatal("fixture directory replacement")
				}
			case "closed-descriptor":
				if r.held[0].file.Close() != nil {
					t.Fatal("fixture close")
				}
			case "content-mutation":
				if os.Chmod(path, 0600) != nil || os.WriteFile(path, []byte("mutated original"), 0600) != nil || os.Chmod(path, 0400) != nil {
					t.Fatal("fixture mutation")
				}
			default:
				if os.Rename(path, path+".old") != nil || os.WriteFile(path, r.held[i].wire, 0400) != nil {
					t.Fatal("fixture same-byte replacement")
				}
			}
			if e.authenticateRetainedWithNative(context.Background(), nil, op, "issuer-release", uid, resetD101IssuerRetainedFixtureNative) == nil {
				t.Fatal("post-emission native drift released")
			}
			requireResetD101IssuerRetainedFixtureClosed(t, e, r)
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("denial removed partial/original")
			}
		})
	}
}

func TestNativeIssuerRetainedReleaseRequiresActualConjunction(t *testing.T) {
	for _, name := range []string{"native-before-denied", "native-after-denied", "native-missing", "verifier-denied", "verifier-mutation", "semantic-mutation", "cancelled", "wrong-operation", "unknown-phase"} {
		t.Run(name, func(t *testing.T) {
			e, r := resetD101IssuerRetainedEmissionFixture(t)
			op, phase := e.inputs.policy.Scope.OperationID, "issuer-release"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			native := resetD101IssuerRetainedFixtureNative
			switch name {
			case "native-before-denied", "native-after-denied":
				native = func(_ context.Context, _ *os.File, phase string) error {
					if name == "native-before-denied" || strings.HasSuffix(phase, "-after") {
						return errResetExecutionEvidence
					}
					return nil
				}
			case "native-missing":
				native = nil
			case "verifier-denied", "verifier-mutation":
				e.inputs.verifyRetained = func(_ context.Context, _ *os.File, _ d101operatorauth.TechnicalIssuance, v resetD101IssuerSemanticSnapshot, _, _, _ []byte) error {
					if name == "verifier-denied" {
						return errResetExecutionEvidence
					}
					v.Original13["synthetic"][0] = 'X'
					return nil
				}
			case "semantic-mutation":
				r.semantic.actual = resetD101IssuerSnapshotMutationFixture{mutate: true}
			case "cancelled":
				cancel()
			case "wrong-operation":
				op = strings.Repeat("b", 32)
			case "unknown-phase":
				phase = "issuer-pre-ready"
			}
			if e.authenticateRetainedWithNative(ctx, nil, op, phase, uint32(os.Getuid()), native) == nil {
				t.Fatal("missing/failed actual conjunction released")
			}
			requireResetD101IssuerRetainedFixtureClosed(t, e, r)
			for _, o := range r.held {
				wire, err := os.ReadFile(o.file.Name())
				if err != nil || !bytes.Equal(wire, o.wire) {
					t.Fatal("failed release removed or rewrote original")
				}
			}
		})
	}
}

func TestNativeIssuerRetainedAuthenticationRejectsAbsentNativeAuthority(t *testing.T) {
	var absent *resetD101NativeIssuerEmission
	if absent.AuthenticateRetained(context.Background(), nil, strings.Repeat("a", 32), "issuer-release") == nil {
		t.Fatal("nil emitter granted native authority")
	}
	e, r := resetD101IssuerRetainedEmissionFixture(t)
	if e.AuthenticateRetained(context.Background(), nil, e.inputs.policy.Scope.OperationID, "issuer-release") == nil {
		t.Fatal("portable descriptors replaced actual Linux/source/key/FD9 authority")
	}
	requireResetD101IssuerRetainedFixtureClosed(t, e, r)
}

func TestNativeIssuerRetainedConcurrentClosureStopsActiveAuthentication(t *testing.T) {
	e, r := resetD101IssuerRetainedEmissionFixture(t)
	entered, resume := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- e.authenticateRetainedWithNative(context.Background(), nil, e.inputs.policy.Scope.OperationID, "issuer-release", uint32(os.Getuid()), func(context.Context, *os.File, string) error {
			close(entered)
			<-resume
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(resume)
		t.Fatal("fixture authentication did not enter")
	}
	// A second caller must not wait behind the native callback or approve a
	// release. The active owner observes stopped and closes its own actual FDs.
	if e.CloseRetained() == nil {
		close(resume)
		t.Fatal("busy closure claimed completed release")
	}
	close(resume)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("active authentication ignored terminal stop")
		}
	case <-time.After(time.Second):
		t.Fatal("active owner did not return its descriptors")
	}
	requireResetD101IssuerRetainedFixtureClosed(t, e, r)
}
