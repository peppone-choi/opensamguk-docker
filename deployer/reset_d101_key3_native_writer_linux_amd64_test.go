//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Actual kernel filesystem tests, isolated tmp root, public deterministic
// entropy. No actual authority provider is installed; no production /etc path,
// crypto/rand, key signing/activation/install or service operation is invoked.
type key3EntropyObservation struct {
	reader         *bytes.Reader
	trace          *[]string
	reads          int
	bytes          int
	durableMissing bool
}

func (r *key3EntropyObservation) Read(b []byte) (int, error) {
	if r.reads == 0 {
		for _, required := range []string{"intent-file-fsync", "intent-parent-fsync", "once-parent-fsync"} {
			found := false
			for _, event := range *r.trace {
				if event == required {
					found = true
				}
			}
			if !found {
				r.durableMissing = true
				return 0, io.ErrUnexpectedEOF
			}
		}
	}
	r.reads++
	n, err := r.reader.Read(b)
	r.bytes += n
	return n, err
}

type key3KernelFixture struct {
	tree    *resetD101Key3NativeTree
	session *resetD101Key3AuthenticatedSession
	binding resetD101Key3NativeInitializationBinding
	trace   []string
	entropy *key3EntropyObservation
	checks  resetD101Key3KernelChecks
	invalid bool
}

func newKey3KernelFixture(t *testing.T) *key3KernelFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("actual Linux/amd64 UID0 kernel fixture NOT_RUN; no positive authority claimed")
	}
	if resetD101ReviewedKey3CeremonySource != nil || resetD101ReviewedKey3NativeInitializationSource != nil {
		t.Fatal("fixture found production authority provider installed")
	}
	base := t.TempDir()
	if os.Chmod(base, 0700) != nil {
		t.Fatal("isolated root unavailable")
	}
	for _, name := range []string{".once", "keys", "key-public"} {
		if os.Mkdir(filepath.Join(base, name), 0700) != nil {
			t.Fatal("isolated parents unavailable")
		}
	}
	tree := &resetD101Key3NativeTree{}
	var err error
	tree.base, err = tree.holdDirectory(nil, "", base, nil)
	if err != nil {
		t.Fatal("isolated root FD unavailable")
	}
	for _, entry := range []struct {
		name   string
		target **resetD101Key3HeldDirectory
	}{{".once", &tree.onceParent}, {"keys", &tree.keysParent}, {"key-public", &tree.publicParent}} {
		*entry.target, err = tree.holdDirectory(tree.base, entry.name, filepath.Join(base, entry.name), nil)
		if err != nil {
			tree.close()
			t.Fatal("isolated parent FD unavailable")
		}
	}
	t.Cleanup(tree.close)
	_, expected, _ := key3PublicFixture(t)
	expected.Card.ValidFromUnix = time.Now().Unix() - 10
	expected.Card.ValidUntilUnix = time.Now().Unix() + 60
	wire, err := json.Marshal(expected.Card)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	expected.CardSHA = resetD101OriginalSHA(wire)
	f := &key3KernelFixture{tree: tree, session: &resetD101Key3AuthenticatedSession{expected: expected}}
	f.binding = resetD101Key3NativeInitializationBinding{ceremonySHA: expected.CardSHA, executionScopeSHA: strings.Repeat("d", 64), hostInstanceID: expected.Card.HostInstanceID, sourceSHA: expected.Card.InitializerSourceSHA, binarySHA: expected.Card.InitializerBinarySHA256, observedAt: time.Now()}
	f.checks.guard = func(ctx context.Context) error {
		if ctx == nil || ctx.Err() != nil || f.invalid || !validResetD101Key3Card(f.session.expected.Card, time.Now()) {
			return errResetExecutionEvidence
		}
		return nil
	}
	f.checks.after = func(event string) { f.trace = append(f.trace, event) }
	f.entropy = &key3EntropyObservation{reader: bytes.NewReader(key3PublicEntropy()), trace: &f.trace}
	return f
}
func (f *key3KernelFixture) run() resetD101Key3NativeInitializationOutcome {
	// Required bytes=1 is public fixture data, not a production capacity policy.
	return writeResetD101Key3Kernel(context.Background(), f.tree, f.session, f.binding, 1, f.entropy, f.checks)
}
func key3FixtureNames(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal("fixture namespace unavailable")
	}
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
func TestKey3NativeWriterOnceDurableBeforeFirstEntropy(t *testing.T) {
	for _, name := range []string{"actual-durable-order", "intent-write-failure", "intent-fsync-failure", "once-parent-fsync-failure"} {
		t.Run(name, func(t *testing.T) {
			f := newKey3KernelFixture(t)
			failAt := map[string]string{"intent-write-failure": "before-write-intent", "intent-fsync-failure": "before-intent-file-fsync", "once-parent-fsync-failure": "before-once-parent-fsync"}[name]
			f.checks.before = func(event string) error {
				if event == failAt {
					return syscall.EIO
				}
				return nil
			}
			out := f.run()
			if !out.attempted {
				t.Fatal("owned once mkdir not recorded as attempted")
			}
			if name == "actual-durable-order" {
				if !out.complete || out.err != nil || f.entropy.durableMissing || f.entropy.bytes != len(key3PublicEntropy()) {
					t.Fatal("entropy preceded actual durable once or complete failed")
				}
			} else if out.complete || out.err == nil || f.entropy.reads != 0 {
				t.Fatal("failed durable once reached entropy/success")
			}
			if _, err := os.Stat(filepath.Join(f.tree.onceParent.file.Name(), "key3-initialize")); err != nil {
				t.Fatal("attempt claim lost after failure")
			}
		})
	}
}
func TestKey3NativeWriterDistinct3HeldReadbackAndPublicProvenance(t *testing.T) {
	f := newKey3KernelFixture(t)
	out := f.run()
	if out.err != nil || !out.complete {
		t.Fatal("kernel fixture failed")
	}
	manifestPath := filepath.Join(f.tree.publicParent.file.Name(), "key3-generation.json")
	wire, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal("manifest unavailable")
	}
	var manifest resetD101Key3GeneratedPublicManifest
	if decodeResetPrivateJSON(wire, &manifest) != nil || manifest.Kind != "KEY3_GENERATION_UNOBSERVED" || len(manifest.Roles) != 3 || manifest.CeremonyCardSHA256 != f.session.expected.CardSHA {
		t.Fatal("public data provenance mismatch")
	}
	// No private original bodies/seed/envelope/private path can occur in public.
	for _, forbidden := range []string{"privateKeyPkcs8Base64url", "privateNativePin", f.tree.keysParent.file.Name(), "public fixture human", "public fixture custodian", "public fixture retention"} {
		if bytes.Contains(wire, []byte(forbidden)) {
			t.Fatal("private data appeared in public manifest")
		}
	}
	seen := map[string]bool{}
	for _, role := range manifest.Roles {
		t.Run(role.Role, func(t *testing.T) {
			if seen[role.CustodyID] || seen[role.KeyID] || seen[role.PublicSPKISHA256] {
				t.Fatal("fixture keys/custody not distinct")
			}
			seen[role.CustodyID] = true
			seen[role.KeyID] = true
			seen[role.PublicSPKISHA256] = true
			parent := filepath.Join(f.tree.keysParent.file.Name(), role.Role)
			private := filepath.Join(parent, role.CustodyID+".json")
			b, err := os.ReadFile(private)
			if err != nil || resetD101OriginalSHA(b) != role.EnvelopeSHA256 {
				t.Fatal("private held bytes mismatch")
			}
			clear(b)
			key, err := readResetD101SigningKey(resetD101SigningKeyPins{parent, role.CustodyID, role.EnvelopeSHA256, role.KeyID, role.PublicSPKISHA256})
			if err != nil {
				t.Fatal("existing production UID0 reader rejected fixture")
			}
			key.close()
			info, err := os.Stat(private)
			if err != nil || !resetD101Key3OutputMetadata(info, 0400, int(info.Size())) {
				t.Fatal("private owner/mode/nlink mismatch")
			}
			pubPath := filepath.Join(f.tree.publicParent.file.Name(), role.Role+".spki")
			pub, err := os.ReadFile(pubPath)
			if err != nil || len(pub) != 44 || resetD101OriginalSHA(pub) != role.PublicSPKISHA256 {
				t.Fatal("public DER mismatch")
			}
			// Existing ancestor seam is restricted to this isolated tmp fixture. The
			// production /etc ancestor/UID rules are unchanged; every held fixture FD
			// still must match its actual owner/mode/inode and pathname.
			held, err := openResetD101NativeInputWithAncestors(context.Background(), pubPath, role.PublicNativePin, 0444, 0, func(path string, uid uint32) error {
				if uid != 0 || filepath.Dir(path) != f.tree.publicParent.file.Name() {
					return errResetExecutionEvidence
				}
				return f.tree.recheck()
			})
			if err != nil {
				t.Fatal("manifest public native parent pin became stale during creation")
			}
			held.close()
		})
	}
	completionPath := filepath.Join(f.tree.onceParent.file.Name(), "key3-initialize", "complete.json")
	completeWire, err := os.ReadFile(completionPath)
	if err != nil {
		t.Fatal("completion unavailable")
	}
	var completion resetD101Key3CompleteReceipt
	if decodeResetPrivateJSON(completeWire, &completion) != nil || completion.Kind != "KEY3_COMPLETE_UNOBSERVED" || completion.ManifestSHA256 != resetD101OriginalSHA(wire) {
		t.Fatal("completion/public whole bytes not bound")
	}
	if f.tree.recheck() != nil {
		t.Fatal("held kernel state changed")
	}
	if resetD101ReviewedKey3CeremonySource != nil || resetD101ReviewedKey3NativeInitializationSource != nil {
		t.Fatal("fixture activated an actual authority")
	}
}
func TestKey3NativeWriterPartialNeverRetriesOrAdopts(t *testing.T) {
	for _, name := range []string{"partial-private", "partial-public", "different-card-after-once", "same-card-after-once", "missing-role-after-partial", "existing-role", "existing-public", "existing-manifest"} {
		t.Run(name, func(t *testing.T) {
			f := newKey3KernelFixture(t)
			switch name {
			case "existing-role":
				if os.Mkdir(filepath.Join(f.tree.keysParent.file.Name(), "root-purpose"), 0700) != nil {
					t.Fatal("fixture conflict failed")
				}
			case "existing-public":
				if os.WriteFile(filepath.Join(f.tree.publicParent.file.Name(), "root-purpose.spki"), []byte("retained public fixture"), 0444) != nil {
					t.Fatal("fixture conflict failed")
				}
			case "existing-manifest":
				if os.WriteFile(filepath.Join(f.tree.publicParent.file.Name(), "key3-generation.json"), []byte("retained public fixture"), 0444) != nil {
					t.Fatal("fixture conflict failed")
				}
			default:
				failAt := "before-write-private-approval-issuer"
				if name == "partial-public" {
					failAt = "before-write-public-approval-issuer"
				}
				f.checks.before = func(event string) error {
					if event == failAt {
						return syscall.EIO
					}
					return nil
				}
				first := f.run()
				if !first.attempted || first.complete || first.err == nil {
					t.Fatal("partial fixture promoted to success")
				}
				if name == "different-card-after-once" {
					f.session.expected.CardSHA = strings.Repeat("e", 64)
					f.session.expected.Card.CeremonyID = strings.Repeat("e", 32)
				}
				f.checks.before = nil
			}
			before := f.entropy.reads
			oldFiles := len(f.tree.files)
			keys := key3FixtureNames(t, f.tree.keysParent.file.Name())
			pub := key3FixtureNames(t, f.tree.publicParent.file.Name())
			next := f.run()
			if next.attempted || next.complete || next.err == nil || f.entropy.reads != before || len(f.tree.files) != oldFiles || strings.Join(keys, ",") != strings.Join(key3FixtureNames(t, f.tree.keysParent.file.Name()), ",") || strings.Join(pub, ",") != strings.Join(key3FixtureNames(t, f.tree.publicParent.file.Name()), ",") {
				t.Fatal("retry/adoption/overwrite/fill-missing changed retained state")
			}
		})
	}
}
func TestKey3NativeWriterRejectsPathInodeModeAndCapacityMutation(t *testing.T) {
	for _, name := range []string{"symlink-role", "symlink-public", "foreign-mode", "foreign-owner", "linked-private", "parent-replacement", "created-file-replacement", "readback-tamper", "duplicate-custody", "duplicate-spki", "capacity-unavailable"} {
		t.Run(name, func(t *testing.T) {
			f := newKey3KernelFixture(t)
			mutated := false
			switch name {
			case "symlink-role":
				if os.Symlink(f.tree.publicParent.file.Name(), filepath.Join(f.tree.keysParent.file.Name(), "root-purpose")) != nil {
					t.Fatal("fixture symlink failed")
				}
			case "symlink-public":
				if os.Symlink(f.tree.keysParent.file.Name(), filepath.Join(f.tree.publicParent.file.Name(), "root-purpose.spki")) != nil {
					t.Fatal("fixture symlink failed")
				}
			case "foreign-mode":
				if os.Chmod(f.tree.keysParent.file.Name(), 0770) != nil {
					t.Fatal("fixture mode failed")
				}
			case "foreign-owner":
				if os.Chown(f.tree.keysParent.file.Name(), 1, -1) != nil {
					t.Fatal("fixture owner mutation failed")
				}
			case "duplicate-custody":
				b := key3PublicEntropy()
				copy(b[48:64], b[:16])
				f.entropy.reader = bytes.NewReader(b)
			case "duplicate-spki":
				b := key3PublicEntropy()
				copy(b[64:96], b[16:48])
				f.entropy.reader = bytes.NewReader(b)
			case "capacity-unavailable":
				out := writeResetD101Key3Kernel(context.Background(), f.tree, f.session, f.binding, ^uint64(0), f.entropy, f.checks)
				if out.attempted || out.complete || out.err == nil || f.entropy.reads != 0 {
					t.Fatal("unavailable capacity admitted")
				}
				return
			default:
				f.checks.before = func(event string) error {
					if mutated {
						return nil
					}
					if name == "parent-replacement" && event == "before-entropy" {
						mutated = true
						old := f.tree.keysParent.file.Name()
						if os.Rename(old, old+"-retained") != nil || os.Mkdir(old, 0700) != nil {
							t.Fatal("fixture parent replacement failed")
						}
					}
					if (name == "created-file-replacement" || name == "readback-tamper" || name == "linked-private") && event == "before-private-root-purpose-file-fsync" {
						mutated = true
						target := f.tree.files[len(f.tree.files)-1].file.Name()
						if name == "linked-private" {
							if os.Link(target, target+".linked") != nil {
								t.Fatal("fixture hardlink failed")
							}
						} else if name == "created-file-replacement" {
							if os.Rename(target, target+"-retained") != nil || os.WriteFile(target, []byte("replacement public fixture"), 0400) != nil {
								t.Fatal("fixture file replacement failed")
							}
						} else {
							if os.WriteFile(target, []byte("tampered public fixture"), 0400) != nil {
								t.Fatal("fixture readback mutation failed")
							}
						}
					}
					return nil
				}
			}
			out := f.run()
			if out.complete || out.err == nil {
				t.Fatal("native mutation was promoted to success")
			}
			if name == "parent-replacement" && f.entropy.reads != 0 {
				t.Fatal("replaced parent reached entropy")
			}
		})
	}
}
func TestKey3NativeWriterAuthAndWindowFailureRetainsAttempt(t *testing.T) {
	for _, name := range []string{"missing-guard", "source-before-once", "window-before-once", "source-after-once", "window-after-entropy", "source-after-completion"} {
		t.Run(name, func(t *testing.T) {
			f := newKey3KernelFixture(t)
			switch name {
			case "missing-guard":
				f.checks.guard = nil
			case "source-before-once":
				f.invalid = true
			case "window-before-once":
				f.session.expected.Card.ValidUntilUnix = time.Now().Unix()
			default:
				f.checks.after = func(event string) {
					f.trace = append(f.trace, event)
					if name == "source-after-once" && event == "once-parent-fsync" {
						f.invalid = true
					}
					if name == "window-after-entropy" && event == "private-root-purpose-file-fsync" {
						f.session.expected.Card.ValidUntilUnix = time.Now().Unix()
					}
					if name == "source-after-completion" && event == "completion-parent-fsync" {
						f.invalid = true
					}
				}
			}
			out := f.run()
			if out.complete || out.err == nil {
				t.Fatal("lost actual-source/window guard admitted")
			}
			before := name == "missing-guard" || name == "source-before-once" || name == "window-before-once"
			if before && (out.attempted || f.entropy.reads != 0) {
				t.Fatal("missing guard reached namespace or entropy")
			}
			if !before && !out.attempted {
				t.Fatal("partial lost attempted receipt")
			}
			if name == "source-after-once" && f.entropy.reads != 0 {
				t.Fatal("post-once lost source reached entropy")
			}
			if name == "source-after-completion" {
				if _, err := os.Stat(filepath.Join(f.tree.onceParent.file.Name(), "key3-initialize", "complete.json")); err != nil {
					t.Fatal("durable completion lost on late source failure")
				}
			}
		})
	}
}
