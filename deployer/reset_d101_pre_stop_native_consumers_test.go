package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestR2PreStopNativeLinkedPreflightRequiresExactProofKey(t *testing.T) {
	plan, receipt, now := resetEvidenceFixture(t)
	wire, _ := json.Marshal(receipt)
	if decodeResetPrivateJSON(wire, &resetPreflightReceipt{}) != nil || validateResetPreflight(receipt, plan, receipt.ApprovalPlanSHA, now) != nil {
		t.Fatal("legacy absent field changed")
	}
	plan.ApprovalIntentSHA = strings.Repeat("a", 64)
	if validateResetPreflight(receipt, plan, receipt.ApprovalPlanSHA, now) == nil {
		t.Fatal("linked receipt omitted native proof")
	}
	receipt.PreStopNativeProofSHA = strings.Repeat("f", 64)
	wire, _ = json.Marshal(receipt)
	if decodeResetPrivateJSON(wire, &resetPreflightReceipt{}) != nil || validateResetPreflight(receipt, plan, receipt.ApprovalPlanSHA, now) != nil {
		t.Fatal("exact linked proof data refused")
	}
	for _, mode := range []string{"null", "empty", "number", "alias", "duplicate", "trailing", "legacy-proof"} {
		t.Run(mode, func(t *testing.T) {
			changed := string(wire)
			proof := `"preStopNativeProofSha256":"` + receipt.PreStopNativeProofSHA + `"`
			switch mode {
			case "null":
				changed = strings.Replace(changed, proof, `"preStopNativeProofSha256":null`, 1)
			case "empty":
				changed = strings.Replace(changed, proof, `"preStopNativeProofSha256":""`, 1)
			case "number":
				changed = strings.Replace(changed, proof, `"preStopNativeProofSha256":7`, 1)
			case "alias":
				changed = strings.Replace(changed, "preStopNativeProofSha256", "PreStopNativeProofSha256", 1)
			case "duplicate":
				changed = strings.Replace(changed, proof, proof+","+proof, 1)
			case "trailing":
				changed += "{}"
			case "legacy-proof":
				plan.ApprovalIntentSHA = ""
				if validateResetPreflight(receipt, plan, receipt.ApprovalPlanSHA, now) == nil {
					t.Fatal("proof broadened legacy admission")
				}
				return
			}
			if decodeResetPrivateJSON([]byte(changed), &resetPreflightReceipt{}) == nil {
				t.Fatal("nonexact proof field accepted")
			}
		})
	}
}

func TestR2PreStopNativeMissingSourcesDenyOwningInvokerAndClosure(t *testing.T) {
	body, intent, plan, planSHA, _, _ := r2PreStopNativeFixture(t, time.Now().UTC().Add(-time.Minute))
	calls := 0
	cfg := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	if _, err := cfg.runResetD101PreStopNativeCapture(context.Background(), body.OperationID, intent.SHA, planSHA, "unverified"); err == nil || calls != 0 {
		t.Fatal("missing fixed producer reached execution")
	}
	_, closure, _ := recoveryFixture(t)
	if cfg.requireResetD101RecoveryPreSQL(context.Background(), durableOperationRecord{}, resetExecutionEvidence{Plan: plan}, intent, closure, uint32(os.Getuid())) == nil || calls != 0 {
		t.Fatal("missing actual restored SQL reached closure")
	}
}

func TestR2PreStopNativeCanonicalNullableRecoveryRetainsOriginalNulls(t *testing.T) {
	for _, mode := range []string{"both-null", "generation-null", "scenario-null"} {
		t.Run(mode, func(t *testing.T) {
			_, result, now := recoveryFixture(t)
			wire, _ := base64.RawURLEncoding.DecodeString(result.OldCanonicalRegistryBytesBase64url)
			var registry resetD101NullableOldCanonicalRegistry
			_ = json.Unmarshal(wire, &registry)
			if mode != "scenario-null" {
				registry.Generation = nil
			}
			if mode != "generation-null" {
				registry.ScenarioCode = nil
			}
			wire, _ = json.Marshal(registry)
			result.OldCanonicalRegistryBytesBase64url = base64.RawURLEncoding.EncodeToString(wire)
			result.OldRegistryReceiptSHA = resetD101OriginalSHA(wire)
			if validateResetD101RecoverySnapshots(result, now.Add(-time.Second), now) != nil {
				t.Fatal("nullable original refused")
			}
			var decoded resetD101NullableOldCanonicalRegistry
			if decodeResetD101RecoverySnapshot(result.OldCanonicalRegistryBytesBase64url, result.OldRegistryReceiptSHA, &decoded) != nil || (mode != "scenario-null" && decoded.Generation != nil) || (mode != "generation-null" && decoded.ScenarioCode != nil) {
				t.Fatal("null replaced")
			}
			// A null canonical field does not relax actual restored world matching.
			result.OldGeneration++
			if validateResetD101RecoverySnapshots(result, now.Add(-time.Second), now) == nil {
				t.Fatal("world mismatch hidden by canonical null")
			}
		})
	}
}

func TestR2PreStopNativeCanonicalRecoveryRejectsMissingTypeAndNonnullMismatch(t *testing.T) {
	for _, mode := range []string{"missing-generation", "missing-scenario", "generation-string", "scenario-number", "generation-mismatch", "scenario-mismatch", "duplicate", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			_, result, now := recoveryFixture(t)
			wire, _ := base64.RawURLEncoding.DecodeString(result.OldCanonicalRegistryBytesBase64url)
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(wire, &fields)
			switch mode {
			case "missing-generation":
				delete(fields, "generation")
			case "missing-scenario":
				delete(fields, "scenarioCode")
			case "generation-string":
				fields["generation"] = json.RawMessage(`"9"`)
			case "scenario-number":
				fields["scenarioCode"] = json.RawMessage(`9`)
			case "generation-mismatch":
				fields["generation"] = json.RawMessage(`8`)
			case "scenario-mismatch":
				fields["scenarioCode"] = json.RawMessage(`"scenario_3190"`)
			case "unknown":
				fields["trusted"] = json.RawMessage(`true`)
			}
			wire, _ = json.Marshal(fields)
			if mode == "duplicate" {
				wire = []byte(strings.Replace(string(wire), `"generation":9`, `"generation":9,"generation":9`, 1))
			}
			result.OldCanonicalRegistryBytesBase64url = base64.RawURLEncoding.EncodeToString(wire)
			result.OldRegistryReceiptSHA = resetD101OriginalSHA(wire)
			if validateResetD101RecoverySnapshots(result, now.Add(-time.Second), now) == nil {
				t.Fatal("nonexact/mismatched canonical accepted")
			}
		})
	}
}

func TestR2PreStopNativeCustodyChangeDeniesBeforeActualRunner(t *testing.T) {
	for _, mode := range []string{"parent-rename", "leaf-replace", "leaf-hardlink", "parent-mode"} {
		t.Run(mode, func(t *testing.T) {
			body, _, _, _, _, _ := r2PreStopNativeFixture(t, time.Now().UTC().Add(-time.Minute))
			directory := r2FixtureDirectory(t)
			stream, err := openResetD101PreStopNativeStreamWithLeafOpener(directory, body.OperationID, body, uint32(os.Getuid()), r2FixtureLeafOpener)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.ClosePreservingPartial()
			if stream.AppendNonCommand(r2FixtureFrameNow(body.Observations[0])) != nil || stream.QueueGuard(r2FixtureFrameNow(body.Observations[1])) != nil {
				t.Fatal("fixture stream")
			}
			path := filepath.Join(directory, body.OperationID+".json")
			switch mode {
			case "parent-rename":
				if os.Rename(directory, directory+"-retained") != nil || os.Mkdir(directory, 0700) != nil {
					t.Fatal("fixture rename")
				}
			case "leaf-replace":
				if os.Rename(path, path+".retained") != nil || os.WriteFile(path, []byte("{}"), 0400) != nil {
					t.Fatal("fixture replace")
				}
			case "leaf-hardlink":
				if os.Link(path, path+".linked") != nil {
					t.Fatal("fixture hardlink")
				}
			case "parent-mode":
				if os.Chmod(directory, 0750) != nil {
					t.Fatal("fixture mode")
				}
			}
			ctx := context.WithValue(context.Background(), resetD101PreStopStreamContextKey{}, stream)
			ctx = context.WithValue(ctx, resetD101OldWorldPhysicalContextKey{}, true)
			calls := 0
			cfg := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
			if _, err := cfg.runServerDockerContext(ctx, "start", "--attach", strings.Repeat("a", 64)); err == nil || calls != 0 {
				t.Fatal("changed custody reached runner")
			}
			if stream.file == nil {
				t.Fatal("original issuing descriptor lost before close")
			}
		})
	}
}

func TestR2PreStopNativeSlotRejectsMissingParentAndSymlink(t *testing.T) {
	body, _, _, _, _, _ := r2PreStopNativeFixture(t, time.Now().UTC().Add(-time.Minute))
	directory := r2FixtureDirectory(t)
	missing := filepath.Join(directory, "not-installed")
	if _, err := openResetD101PreStopNativeStreamWithLeafOpener(missing, body.OperationID, body, uint32(os.Getuid()), r2FixtureLeafOpener); err == nil {
		t.Fatal("missing parent auto-installed")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("missing parent changed")
	}
	target := filepath.Join(directory, "retained-target")
	if os.WriteFile(target, []byte("retained"), 0400) != nil || os.Symlink(target, filepath.Join(directory, body.OperationID+".json")) != nil {
		t.Fatal("fixture symlink")
	}
	if _, err := openResetD101PreStopNativeStreamWithLeafOpener(directory, body.OperationID, body, uint32(os.Getuid()), r2FixtureLeafOpener); err == nil {
		t.Fatal("symlink issuing slot accepted")
	}
	if _, _, err := readResetD101PreStopNativeFileWithLeafOpener(directory, body.OperationID, uint32(os.Getuid()), r2FixtureLeafOpener); err == nil {
		t.Fatal("symlink reader accepted")
	}
	wire, err := os.ReadFile(target)
	if err != nil || string(wire) != "retained" {
		t.Fatal("symlink target changed")
	}
}

func TestR2PreStopNativeActualSQLTupleCannotUseNullableCanonicalFallback(t *testing.T) {
	old, _, _ := oldWorldCaptureFixture()
	restored, _, _ := restoredDatabaseFixture()
	if requireResetD101RestoredMatchesObservedOld(restored, old) != nil {
		t.Fatal("same actual old SQL tuple refused")
	}
	for _, mode := range []string{"generation", "scenario", "tick", "world"} {
		t.Run(mode, func(t *testing.T) {
			changed := restored
			switch mode {
			case "generation":
				changed.GenerationRaw = "0"
			case "scenario":
				changed.ScenarioCode = "scenario_3190"
			case "tick":
				changed.TickSeconds = 3600
			case "world":
				changed.WorldID = 2
			}
			if requireResetD101RestoredMatchesObservedOld(changed, old) == nil {
				t.Fatal("actual SQL tuple mismatch accepted")
			}
		})
	}
}
