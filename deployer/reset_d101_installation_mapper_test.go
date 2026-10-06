package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101custody"
)

type installationMapperDenyCurrent struct{}

func (installationMapperDenyCurrent) CaptureAfter(context.Context, resetExecutionPhaseBinding, time.Time) (resetD101CurrentFreezeCapture, error) {
	return resetD101CurrentFreezeCapture{}, errResetExecutionEvidence
}

type installationMapperDenyRecovery struct{}

func (installationMapperDenyRecovery) ReadClosure(context.Context, string, string) ([]byte, error) {
	return nil, errResetExecutionEvidence
}
func (installationMapperDenyRecovery) VerifyRecovery(context.Context, resetD101RecoveryBinding) error {
	return errResetExecutionEvidence
}
func (installationMapperDenyRecovery) ReadDatabase(context.Context, string, string) (resetD101RestoredDatabaseObservation, error) {
	return resetD101RestoredDatabaseObservation{}, errResetExecutionEvidence
}

func installationMapperStructuralFixture(t *testing.T) (resetD101FixedInstallation, resetD101ProvenanceReaderInstallation, d101custody.Original, d101custody.NativeFilePin) {
	t.Helper()
	op := strings.Repeat("a", 32)
	dirs := map[string]string{}
	files := map[string]string{}
	for _, id := range resetD101HostOriginalIDs {
		dirs[id] = filepath.Join("/synthetic-installation", id)
		files[id] = filepath.Join(dirs[id], op+".json")
	}
	key := resetD101SigningKeyPins{KeyID: "synthetic-key"}
	p := resetD101FixedInstallation{
		authority:  resetD101HostAuthorityPins{OperationID: op, ApprovalIntentSHA: strings.Repeat("b", 64), ManifestDirectory: "/synthetic-installation/manifest", ClockDirectory: "/synthetic-installation/clock", OriginalDirectories: dirs, SigningKey: key},
		provenance: resetD101ApprovedReceiptPins{OperationID: op, ApprovalIntentSHA: strings.Repeat("b", 64), OriginalDirectories: cloneResetD101Strings(dirs), RootKey: key},
		current:    resetD101CurrentFreezePins{operationID: op, supplier: installationMapperDenyCurrent{}},
		preStop:    resetD101PreStopNativeInstallation{sourceSHA: strings.Repeat("c", 40), parentDevice: 1, parentInode: 2, verify: func(context.Context, resetD101PreStopNativeBinding) error { return errResetExecutionEvidence }},
		candidate:  resetD101CandidateInstallation{OperationID: op, IntentSHA: strings.Repeat("b", 64), SelectedEnvelopeDirectory: "/synthetic-installation/selected", ProducerIdentity: "synthetic-key"},
		upstream:   func(context.Context, *resetD101HostEvidence) error { return errResetExecutionEvidence },
		evidence:   func(context.Context, *resetD101HostEvidence) error { return errResetExecutionEvidence },
		recovery:   installationMapperDenyRecovery{},
	}
	record := resetD101ProvenanceReaderInstallation{1, "D101_NATIVE_READER_BINDINGS_V1", filepath.Join(p.authority.ManifestDirectory, op+".json"), filepath.Join(p.authority.ClockDirectory, op+".json"), files, "/synthetic-installation/token.json", filepath.Join(p.candidate.SelectedEnvelopeDirectory, op+".json")}
	wire, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	original := d101custody.Original{Bytes: wire, SHA256: resetD101OriginalSHA(wire)}
	pin := d101custody.NativeFilePin{SHA256: original.SHA256, Snapshot: d101custody.PrivateSnapshot{Device: 1, Inode: 3, ByteLength: uint64(len(wire)), ModifiedAtUnixNano: 1}, OwnerUID: 0, FileMode: 0400, LinkCount: 1, ParentSnapshot: d101custody.PrivateSnapshot{Device: 1, Inode: 4, ModifiedAtUnixNano: 1}, ParentOwnerUID: 0, ParentMode: 0700}
	p.readerSHA = original.SHA256
	p.provenance.ReaderInstallationSHA = original.SHA256
	p.readerPin = pin
	return p, record, original, pin
}
func TestInstallationMapperExistingExact7AndNativePinsStayIndependent(t *testing.T) {
	for _, mode := range []string{"control", "file-pin", "parent-pin", "wrong-sha", "body-drift", "missing-original", "unknown-original", "rebind-original", "alias-original", "manifest-drift", "clock-drift", "selected-drift", "relative-token", "alias-token", "native-mode", "native-links"} {
		t.Run(mode, func(t *testing.T) {
			p, record, original, pin := installationMapperStructuralFixture(t)
			switch mode {
			case "file-pin":
				pin.Snapshot.Inode++
			case "parent-pin":
				pin.ParentSnapshot.Inode++
			case "wrong-sha":
				p.readerSHA = strings.Repeat("f", 64)
			case "body-drift":
				original.Bytes = append(original.Bytes, ' ')
			case "missing-original":
				delete(record.OriginalFiles, "approvalReceipt")
			case "unknown-original":
				record.OriginalFiles["unknown"] = "/synthetic-installation/unknown.json"
			case "rebind-original":
				record.OriginalFiles["approvalReceipt"] = "/synthetic-installation/other.json"
			case "alias-original":
				record.OriginalFiles["approvalReceipt"] = record.OriginalFiles["combinedCiReceipt"]
			case "manifest-drift":
				record.ManifestFile = "/synthetic-installation/other.json"
			case "clock-drift":
				record.ClockFile = "/synthetic-installation/other.json"
			case "selected-drift":
				record.SelectedEnvelopeFile = "/synthetic-installation/other.json"
			case "relative-token":
				record.RootTokenFile = "relative.json"
			case "alias-token":
				record.RootTokenFile = record.OriginalFiles["approvalReceipt"]
			case "native-mode":
				pin.FileMode = 0600
				p.readerPin = pin
			case "native-links":
				pin.LinkCount = 2
				p.readerPin = pin
			}
			if mode != "control" && mode != "file-pin" && mode != "parent-pin" && mode != "wrong-sha" && mode != "body-drift" && mode != "native-mode" && mode != "native-links" {
				wire, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				original = d101custody.Original{Bytes: wire, SHA256: resetD101OriginalSHA(wire)}
				pin.SHA256 = original.SHA256
				pin.Snapshot.ByteLength = uint64(len(wire))
				p.readerSHA = original.SHA256
				p.readerPin = pin
				p.provenance.ReaderInstallationSHA = original.SHA256
			}
			err := requireResetD101FixedReaderMapping(original, pin, p)
			if (mode == "control") != (err == nil) {
				t.Fatal("structural-only binding result", mode, err)
			}
		})
	}
}
func TestInstallationMapperMissingAuthenticatorsCannotReadOrActivate(t *testing.T) {
	for _, mode := range []string{"nil-installation", "upstream", "evidence", "current", "pre-stop", "recovery", "typed-nil-recovery", "cancelled", "nil-context", "nil-reader"} {
		t.Run(mode, func(t *testing.T) {
			p, _, original, pin := installationMapperStructuralFixture(t)
			input := &p
			ctx := context.Background()
			switch mode {
			case "nil-installation":
				input = nil
			case "upstream":
				p.upstream = nil
			case "evidence":
				p.evidence = nil
			case "current":
				p.current.supplier = nil
			case "pre-stop":
				p.preStop.verify = nil
			case "recovery":
				p.recovery = nil
			case "typed-nil-recovery":
				p.recovery = (*installationMapperDenyRecovery)(nil)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			}
			calls := 0
			read := resetD101CurrentFreezeReader(func(string, int64) (d101custody.Original, d101custody.NativeFilePin, error) {
				calls++
				return original, pin, nil
			})
			if mode == "nil-reader" {
				read = nil
			}
			sources, err := mapResetD101FixedInstallationWithSources(ctx, config{}, original, pin, input, read, time.Now, 0)
			if !errors.Is(err, errResetD101InstallationNotSupplied) || calls != 0 {
				t.Fatal("missing producer was adopted", mode, err, calls)
			}
			if sources.purposeAuthority != nil || sources.phaseSource != nil || sources.candidatePipeline != nil || sources.preStopNativeInstallation != nil || sources.recoveryClosureReader != nil || sources.recoveryVerifier != nil || sources.recoveryDatabaseSource != nil || sources.seedMaterialInputs != nil {
				t.Fatal("partial mapped sources escaped")
			}
		})
	}
}
func TestInstallationMapperChangedReaderDeniedBeforeTypedAuthorityConstruction(t *testing.T) {
	p, _, original, pin := installationMapperStructuralFixture(t)
	calls := 0
	read := func(string, int64) (d101custody.Original, d101custody.NativeFilePin, error) {
		calls++
		changed := original
		changed.Bytes = append([]byte(nil), original.Bytes...)
		changed.Bytes = append(changed.Bytes, ' ')
		return changed, pin, nil
	}
	sources, err := mapResetD101FixedInstallationWithSources(context.Background(), config{}, original, pin, &p, read, time.Now, 0)
	if err == nil || calls != 1 || sources.purposeAuthority != nil {
		t.Fatal("drift reached authority construction", err, calls)
	}
}
