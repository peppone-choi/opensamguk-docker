package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func resetD101SpaceInventoryFixture(t *testing.T) (resetD101SpaceInventoryPins, resetD101SpaceBudgetInventory, resetD101SpaceBudgetVerifier, func(string) (uint64, resetSpaceObservation, error)) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plan, _, _ := resetEvidenceFixture(t)
	pins := resetD101SpaceInventoryPins{BudgetDirectory: filepath.Join(root, "budget"), OperationID: plan.OperationID, TargetFingerprint: plan.TargetFingerprint, AppSourceSHA: plan.AppSourceSHA, DockerSourceSHA: strings.Repeat("a", 40), OldImageDigests: plan.OldImageDigests, NewImageDigests: plan.NewImageDigests, SourceDirectories: map[string]string{}, FilesystemPaths: map[string]string{}, ProducerIdentity: "synthetic-space-fixture"}
	if os.Mkdir(pins.BudgetDirectory, 0700) != nil {
		t.Fatal("fixture budget")
	}
	budget := resetD101SpaceBudgetInventory{1, "D101_SPACE_BUDGET_INVENTORY_V1", pins.OperationID, pins.TargetFingerprint, pins.AppSourceSHA, pins.DockerSourceSHA, pins.OldImageDigests, pins.NewImageDigests, resetSpaceBudget{resetBudgetNumber(100), resetBudgetNumber(200), resetBudgetNumber(300), resetBudgetNumber(400), resetBudgetNumber(50), resetBudgetNumber(10)}, map[string]resetD101SpaceSourceReference{}}
	originals := map[string][]byte{}
	for _, id := range resetD101SpaceSourceIDs {
		dir := filepath.Join(root, "source-"+id)
		if os.Mkdir(dir, 0700) != nil {
			t.Fatal("fixture source")
		}
		pins.SourceDirectories[id] = dir
		wire := []byte(`{"syntheticAllocationInventory":"` + id + `"}`)
		originals[id] = wire
		if os.WriteFile(filepath.Join(dir, pins.OperationID+".json"), wire, 0400) != nil {
			t.Fatal("fixture source original")
		}
		budget.SourceReferences[id] = resetD101SpaceSourceReference{id, resetD101OriginalSHA(wire), uint64(len(wire))}
	}
	for _, id := range resetD101SpaceFilesystemIDs {
		path := filepath.Join(root, "fs-"+id)
		if os.Mkdir(path, 0700) != nil {
			t.Fatal("fixture fs")
		}
		pins.FilesystemPaths[id] = path
	}
	wire, err := json.Marshal(budget)
	if err != nil {
		t.Fatal(err)
	}
	pins.BudgetSHA = resetD101OriginalSHA(wire)
	if os.WriteFile(filepath.Join(pins.BudgetDirectory, pins.OperationID+".json"), wire, 0400) != nil {
		t.Fatal("fixture budget original")
	}
	verify := func(ctx context.Context, evidence resetD101SpaceBudgetEvidence) error {
		if ctx.Err() != nil || !bytes.Equal(evidence.BudgetOriginal(), wire) {
			return errResetExecutionEvidence
		}
		for id, original := range originals {
			observed, err := evidence.SourceOriginal(id)
			if err != nil || !bytes.Equal(original, observed) {
				return errResetExecutionEvidence
			}
		}
		return nil
	}
	observe := func(path string) (uint64, resetSpaceObservation, error) {
		var stat syscall.Stat_t
		if syscall.Stat(path, &stat) != nil {
			return 0, resetSpaceObservation{}, errResetExecutionEvidence
		}
		return uint64(stat.Dev), resetSpaceObservation{resetBudgetNumber(resetDiskReserveBytes + 1000), resetBudgetNumber(60)}, nil
	}
	return pins, budget, verify, observe
}

func TestSpaceInventoryPreIntentLeafUsesActualFilesystemIdentityAndExactBudget(t *testing.T) {
	pins, budget, verify, observe := resetD101SpaceInventoryFixture(t)
	wire, sha, err := produceResetD101HostSpaceCollectionWithSources(context.Background(), pins, verify, uint32(os.Getuid()), observe, time.Now)
	if err != nil {
		t.Fatal("synthetic bound inventory refused", err)
	}
	value, err := decodeResetD101HostSpaceCollection(wire, sha, pins, budget, time.Now())
	if err != nil || value.RequiredBytes != resetDiskReserveBytes+1000 || value.RequiredInodes != 60 {
		t.Fatal("budget changed", err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(wire, &fields) != nil || len(fields) != 18 || len(fields["approvalIntentSha256"]) != 0 || len(fields["deploymentCardSha256"]) != 0 {
		t.Fatal("pre-intent leaf changed DAG")
	}
	// Independent actual Statfs/Stat read on a fixture directory. It does not
	// claim the production host has adequate capacity or a verified budget.
	device, actual, err := observeResetFilesystem(pins.FilesystemPaths["servers"])
	if err != nil || device == 0 || actual.AvailableBytes == nil || actual.AvailableInodes == nil {
		t.Fatal("actual fixture statfs unavailable", err)
	}
}

func TestSpaceInventoryMissingVerifierOrSourcesProducesNoObservation(t *testing.T) {
	for _, mode := range []string{"verifier", "rejected-bounds", "missing-source", "wrong-source", "cancelled", "future-intent"} {
		t.Run(mode, func(t *testing.T) {
			pins, _, verify, observer := resetD101SpaceInventoryFixture(t)
			ctx := context.Background()
			switch mode {
			case "verifier":
				verify = nil
			case "rejected-bounds":
				verify = func(context.Context, resetD101SpaceBudgetEvidence) error {
					return errors.New("synthetic rejected upper bounds")
				}
			case "missing-source":
				delete(pins.SourceDirectories, "backup")
			case "wrong-source":
				path := filepath.Join(pins.SourceDirectories["backup"], pins.OperationID+".json")
				if os.Remove(path) != nil || os.WriteFile(path, []byte("different"), 0400) != nil {
					t.Fatal("fixture replace")
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "future-intent":
				path := filepath.Join(pins.BudgetDirectory, pins.OperationID+".json")
				wire, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var root map[string]any
				_ = json.Unmarshal(wire, &root)
				root["approvalIntentSha256"] = strings.Repeat("b", 64)
				wire, _ = json.Marshal(root)
				pins.BudgetSHA = resetD101OriginalSHA(wire)
				if os.Remove(path) != nil || os.WriteFile(path, wire, 0400) != nil {
					t.Fatal("fixture replace")
				}
			}
			calls := 0
			observe := func(path string) (uint64, resetSpaceObservation, error) { calls++; return observer(path) }
			wire, sha, err := produceResetD101HostSpaceCollectionWithSources(ctx, pins, verify, uint32(os.Getuid()), observe, time.Now)
			if err == nil || wire != nil || sha != "" || calls != 0 {
				t.Fatal("missing source released inventory")
			}
		})
	}
}

func TestSpaceInventoryRejectsCapacityDeviceCustodyAndSourceDrift(t *testing.T) {
	for _, mode := range []string{"bytes", "inodes", "device", "nil-bytes", "symlink", "writable", "source-drift"} {
		t.Run(mode, func(t *testing.T) {
			pins, _, verify, observer := resetD101SpaceInventoryFixture(t)
			switch mode {
			case "symlink":
				path := pins.FilesystemPaths["servers"] + "-alias"
				if os.Symlink(pins.FilesystemPaths["servers"], path) != nil {
					t.Fatal("fixture alias")
				}
				pins.FilesystemPaths["servers"] = path
			case "writable":
				if os.Chmod(pins.FilesystemPaths["servers"], 0777) != nil {
					t.Fatal("fixture mode")
				}
			}
			observe := func(path string) (uint64, resetSpaceObservation, error) {
				device, space, err := observer(path)
				switch mode {
				case "bytes":
					space.AvailableBytes = resetBudgetNumber(resetDiskReserveBytes + 999)
				case "inodes":
					space.AvailableInodes = resetBudgetNumber(59)
				case "device":
					device++
				case "nil-bytes":
					space.AvailableBytes = nil
				case "source-drift":
					source := filepath.Join(pins.SourceDirectories["backup"], pins.OperationID+".json")
					if os.Remove(source) != nil || os.WriteFile(source, []byte("drift"), 0400) != nil {
						t.Fatal("fixture drift")
					}
				}
				return device, space, err
			}
			wire, sha, err := produceResetD101HostSpaceCollectionWithSources(context.Background(), pins, verify, uint32(os.Getuid()), observe, time.Now)
			if err == nil || wire != nil || sha != "" {
				t.Fatal("unobserved inventory released")
			}
		})
	}
}

func TestSpaceInventoryDecoderRejectsForgedStageBudgetAndDevice(t *testing.T) {
	pins, budget, verify, observe := resetD101SpaceInventoryFixture(t)
	wire, _, err := produceResetD101HostSpaceCollectionWithSources(context.Background(), pins, verify, uint32(os.Getuid()), observe, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"stage", "scope", "required-bytes", "required-inodes", "budget", "future", "other-device", "unknown", "duplicate", "null"} {
		t.Run(mode, func(t *testing.T) {
			var fields map[string]any
			if json.Unmarshal(wire, &fields) != nil {
				t.Fatal("fixture")
			}
			switch mode {
			case "stage":
				fields["stage"] = "AFTER_BACKUP"
			case "scope":
				fields["scope"] = "APPROVED"
			case "required-bytes":
				fields["requiredBytes"] = float64(resetDiskReserveBytes)
			case "required-inodes":
				fields["requiredInodes"] = float64(0)
			case "budget":
				fields["spaceBudget"].(map[string]any)["RecoveryBytes"] = float64(0)
			case "future":
				fields["observedAtUtc"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			case "other-device":
				fields["filesystemObservations"].(map[string]any)["dockerDataRoot"].(map[string]any)["device"] = "1"
			case "unknown":
				fields["approvalIntentSha256"] = strings.Repeat("f", 64)
			case "null":
				fields["spaceBudget"].(map[string]any)["InodeReserve"] = nil
			}
			changed, _ := json.Marshal(fields)
			if mode == "duplicate" {
				changed = []byte(strings.Replace(string(changed), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1))
			}
			if _, err := decodeResetD101HostSpaceCollection(changed, resetD101OriginalSHA(changed), pins, budget, time.Now()); err == nil {
				t.Fatal("forged inventory accepted")
			}
		})
	}
}
