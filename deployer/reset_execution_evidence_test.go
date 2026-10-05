package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resetEvidenceFixture(t *testing.T) (resetApprovalPlan, resetPreflightReceipt, time.Time) {
	t.Helper()
	now := time.Unix(1791162000, 0)
	target := resetDigestFixture(t, map[string]string{"game-api": "sha256:" + strings.Repeat("a", 64), "game-engine": "sha256:" + strings.Repeat("b", 64), "web-game": "sha256:" + strings.Repeat("c", 64)})
	target.ScenarioCode = "scenario_3190"
	target.Updates["SCENARIO_CODE"] = "scenario_3190"
	target.Generation = 0
	target.Updates["SERVER_GENERATION"] = "0"
	target.StorageImageDigests = map[string]string{"game-postgres": "sha256:" + strings.Repeat("d", 64), "game-redis": "sha256:" + strings.Repeat("e", 64)}
	for key, value := range map[string]string{"SERVER_NAME": "빼섭", "RESET_MAXGENERAL": "50", "RESET_FIRST_TURN": "immediate", "SCENARIO_LOOKUP_DIR": "", "RESET_TURNTERM": "60", "RESET_EXTEND": "1", "RESET_BLOCK_GENERAL_CREATE": "1", "RESET_NPCMODE": "0", "RESET_SHOW_IMG_LEVEL": "3"} {
		target.Updates[key] = value
	}
	normalized, normalizeErr := normalizeResetLifecycleTarget(target)
	if normalizeErr != nil {
		t.Fatal(normalizeErr)
	}
	target = normalized
	pin := "sha256:" + strings.Repeat("a", 64)
	pins := map[string]string{"game-api": pin, "game-engine": pin, "web-game": pin, "game-postgres": pin, "game-redis": pin}
	value := uint64(100)
	plan := resetApprovalPlan{Version: 1, ServerID: "pep", WorldID: 1, OperationID: strings.Repeat("a", 32),
		TargetFingerprint: resetRequestFingerprint("pep", target), Target: target, AppSourceSHA: target.Updates["IMAGE_TAG"],
		OldImageDigests: pins, NewImageDigests: pins, WindowOpensAtUnix: now.Unix() - 60, DestructiveCutoffUnix: now.Unix() + 300, RecoveryDeadlineUnix: now.Unix() + 3600,
		ApprovalReceiptSHA: strings.Repeat("b", 64), CombinedCIReceiptSHA: strings.Repeat("b", 64), SelectedSourceReceiptSHA: strings.Repeat("b", 64),
		IsolatedSeedTickReceiptSHA: strings.Repeat("b", 64), WriterFreezeReceiptSHA: strings.Repeat("b", 64), SpaceInventoryReceiptSHA: strings.Repeat("b", 64),
		SpaceBudget: resetSpaceBudget{&value, &value, &value, &value, &value, &value}}
	// Use the target's exact digests, including distinct service digests.
	plan.NewImageDigests = map[string]string{}
	for key, val := range pins {
		plan.NewImageDigests[key] = val
	}
	for key, val := range target.ImageDigests {
		plan.NewImageDigests[key] = val
	}
	for key, val := range target.StorageImageDigests {
		plan.NewImageDigests[key] = val
	}
	falseValue := false
	zero, space, inodes := uint64(0), resetDiskReserveBytes+200, uint64(200)
	ids := map[string]string{}
	for index, service := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		ids[service] = strings.Repeat(string(rune('a'+index)), 64)
	}
	receipt := resetPreflightReceipt{Version: 1, ServerID: "pep", WorldID: 1, OperationID: plan.OperationID, TargetFingerprint: plan.TargetFingerprint,
		ApprovalPlanSHA: strings.Repeat("c", 64), AppSourceSHA: plan.AppSourceSHA, NewImageDigests: plan.NewImageDigests, OldImageDigests: plan.OldImageDigests,
		ObservedAtUnix: now.Unix() - 1, ExpiresAtUnix: now.Unix() + 20, PublicationState: "VERIFYING", PublicationRevision: "2",
		WriterFreezeReceiptSHA: plan.WriterFreezeReceiptSHA, DrainReceiptSHA: strings.Repeat("d", 64), BackupManifestSHA: strings.Repeat("e", 64),
		BackupRetainUntilUnix: now.Unix() + 7*24*60*60, RestoreVerified: &falseValue, FilesystemDevice: &value, AvailableBytes: &space, AvailableInodes: &inodes,
		UnfinishedTemporaryBytes: &value, RemainingNewFileCount: &value, StoppedContainerIDs: ids, DatabaseClientCount: &zero}
	return plan, receipt, now
}

func TestResetEvidencePlanIdentityWindowAndUnknownFailClosed(t *testing.T) {
	plan, _, now := resetEvidenceFixture(t)
	if err := validateResetApprovalPlan(plan, plan.OperationID, plan.Target, now); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*resetApprovalPlan){
		"wrong-world":       func(p *resetApprovalPlan) { p.WorldID = 2 },
		"wrong-server":      func(p *resetApprovalPlan) { p.ServerID = "uni" },
		"wrong-operation":   func(p *resetApprovalPlan) { p.OperationID = strings.Repeat("b", 32) },
		"wrong-fingerprint": func(p *resetApprovalPlan) { p.TargetFingerprint = strings.Repeat("b", 64) },
		"source-mismatch":   func(p *resetApprovalPlan) { p.AppSourceSHA = strings.Repeat("f", 40) },
		"missing-approval":  func(p *resetApprovalPlan) { p.ApprovalReceiptSHA = "" },
		"missing-bound":     func(p *resetApprovalPlan) { p.SpaceBudget.RecoveryBytes = nil },
		"not-open":          func(p *resetApprovalPlan) { p.WindowOpensAtUnix = now.Unix() + 1 },
		"at-cutoff":         func(p *resetApprovalPlan) { p.DestructiveCutoffUnix = now.Unix() },
		"deadline-order":    func(p *resetApprovalPlan) { p.RecoveryDeadlineUnix = p.DestructiveCutoffUnix },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := plan
			change(&bad)
			if validateResetApprovalPlan(bad, plan.OperationID, plan.Target, now) == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
}

func TestResetEvidencePreflightIdentityFreshnessAndReserves(t *testing.T) {
	plan, receipt, now := resetEvidenceFixture(t)
	if err := validateResetPreflight(receipt, plan, receipt.ApprovalPlanSHA, now); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*resetPreflightReceipt){
		"future":                 func(r *resetPreflightReceipt) { r.ObservedAtUnix = now.Unix() + 1 },
		"age-boundary":           func(r *resetPreflightReceipt) { r.ObservedAtUnix = now.Add(-resetPreflightMaxAge).Unix() },
		"expired":                func(r *resetPreflightReceipt) { r.ExpiresAtUnix = now.Unix() },
		"too-long":               func(r *resetPreflightReceipt) { r.ExpiresAtUnix = r.ObservedAtUnix + 31 },
		"late-cutoff":            func(r *resetPreflightReceipt) { r.ExpiresAtUnix = plan.DestructiveCutoffUnix + 1 },
		"wrong-plan":             func(r *resetPreflightReceipt) { r.ApprovalPlanSHA = strings.Repeat("d", 64) },
		"public":                 func(r *resetPreflightReceipt) { r.PublicationState = "PUBLIC" },
		"overflow-revision":      func(r *resetPreflightReceipt) { r.PublicationRevision = "9223372036854775808" },
		"noncanonical-revision":  func(r *resetPreflightReceipt) { r.PublicationRevision = "02" },
		"missing-drain":          func(r *resetPreflightReceipt) { r.DrainReceiptSHA = "" },
		"missing-database-count": func(r *resetPreflightReceipt) { r.DatabaseClientCount = nil },
		"active-database":        func(r *resetPreflightReceipt) { v := uint64(1); r.DatabaseClientCount = &v },
		"missing-restore-status": func(r *resetPreflightReceipt) { r.RestoreVerified = nil },
		"invented-restore":       func(r *resetPreflightReceipt) { v := true; r.RestoreVerified = &v },
		"short-retention":        func(r *resetPreflightReceipt) { r.BackupRetainUntilUnix = now.Unix() + 1 },
		"space-short":            func(r *resetPreflightReceipt) { v := resetDiskReserveBytes; r.AvailableBytes = &v },
		"missing-inodes":         func(r *resetPreflightReceipt) { r.AvailableInodes = nil },
		"missing-device":         func(r *resetPreflightReceipt) { r.FilesystemDevice = nil },
		"unknown-container":      func(r *resetPreflightReceipt) { r.StoppedContainerIDs = nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := receipt
			change(&bad)
			if validateResetPreflight(bad, plan, receipt.ApprovalPlanSHA, now) == nil {
				t.Fatal("invalid preflight accepted")
			}
		})
	}
	// Every later phase evaluates the clock again; earlier success grants no late deletion.
	if validateResetPreflight(receipt, plan, receipt.ApprovalPlanSHA, now.Add(21*time.Second)) == nil {
		t.Fatal("expired later phase accepted")
	}
}

func TestResetPrivateEvidenceExactBytesAndCustody(t *testing.T) {
	const operation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cases := []string{"valid", "hash-mismatch", "unknown-key", "duplicate-key", "nested-duplicate", "trailing", "writable-file", "public-directory", "wrong-owner", "symlink", "hardlink", "oversize"}
	for _, mode := range cases {
		t.Run(mode, func(t *testing.T) {
			// Darwin's /var path is a symlink. Resolve only the owned fixture root.
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			wire := []byte("{\"version\":1}")
			switch mode {
			case "unknown-key":
				wire = []byte("{\"version\":1,\"unexpected\":true}")
			case "duplicate-key":
				wire = []byte("{\"version\":1,\"version\":2}")
			case "nested-duplicate":
				wire = []byte("{\"version\":1,\"target\":{\"generation\":0,\"generation\":1}}")
			case "trailing":
				wire = []byte("{\"version\":1} {}")
			case "oversize":
				wire = []byte(strings.Repeat(" ", resetEvidenceMaxBytes+1))
			}
			path := filepath.Join(dir, operation+".json")
			if err := os.WriteFile(path, wire, 0400); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(wire)
			expected := hex.EncodeToString(sum[:])
			uid := uint32(os.Getuid())
			switch mode {
			case "hash-mismatch":
				expected = strings.Repeat("a", 64)
			case "writable-file":
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "public-directory":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				uid++
			case "symlink":
				if err := os.Rename(path, path+".actual"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".actual", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".second"); err != nil {
					t.Fatal(err)
				}
			}
			var plan resetApprovalPlan
			err = readResetPrivateEvidence(dir, operation, expected, uid, &plan)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("mode=%s error=%v", mode, err)
			}
		})
	}
}

func TestResetEvidenceDuplicateJSONValidator(t *testing.T) {
	for _, wire := range []string{"{}", "{\"a\":[1,{\"b\":2}]}"} {
		if !json.Valid([]byte(wire)) || rejectResetDuplicateJSONKeys([]byte(wire)) != nil {
			t.Fatal("valid JSON refused")
		}
	}
	for _, wire := range []string{"{\"a\":1,\"a\":2}", "{\"a\":{\"b\":1,\"b\":2}}", "{\"a\":1} {}", "{\"a\":}"} {
		if rejectResetDuplicateJSONKeys([]byte(wire)) == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}
