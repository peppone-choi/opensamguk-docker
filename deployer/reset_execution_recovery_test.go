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

// Real custody/coordinator/store with synthetic approval and backup bytes.
// Positive results mean one claim, never physical restore or operating success.
func resetD101RecoveryFixture(t *testing.T) (config, *operationLease, lifecycleJournal, uint32) {
	t.Helper()
	cfg, uid, op := resetD101IssuerFixture(t)
	journal, _, err := cfg.readLifecycleJournal()
	if err != nil {
		t.Fatal(err)
	}
	record, _ := cfg.lifecycleOperationStore.Lookup(op)
	evidence, err := cfg.readResetExecutionEvidenceWithCustodyUID(op, *journal.ResetTarget, journal.ResetExecution.Evidence, record.CreatedAt, uid)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := cfg.d101PurposeAuthority(context.Background(), op, record.D101IntentSHA)
	if err != nil {
		t.Fatal(err)
	}
	_, wires, budget, pins, _ := resetRecoveryBackupFixture(t)
	cfg.composeDir = filepath.Join(cfg.serversDir, "stack")
	backupDir := filepath.Join(cfg.composeDir, "backups", "pep", op)
	if os.MkdirAll(backupDir, 0700) != nil {
		t.Fatal("fixture backup directory")
	}
	evidence.Preflight.BackupManifestSHA = writeResetRecoveryBackupFixture(t, backupDir, wires)
	evidence.Plan.SpaceBudget.BackupBytes = budget.BackupBytes
	evidence.Plan.SpaceBudget.RecoveryBytes = budget.RecoveryBytes
	evidence.Plan.OldImageDigests = pins
	intent := authority.Intent.Intent
	intent.SpaceBudget = evidence.Plan.SpaceBudget
	intent.OldImageDigests = pins
	intentWire, _ := json.Marshal(intent)
	intentSHA := resetD101OriginalSHA(intentWire)
	decoded, err := decodeResetApprovalIntent(intentWire, intentSHA)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Plan.ApprovalIntentSHA = intentSHA
	planWire, _ := json.Marshal(evidence.Plan)
	evidence.Preflight.ApprovalPlanSHA = resetD101OriginalSHA(planWire)
	evidence.Preflight.OldImageDigests = pins
	space := resetDiskReserveBytes + 2*1024*1024
	evidence.Preflight.AvailableBytes = &space
	preflightWire, _ := json.Marshal(evidence.Preflight)
	refs := resetExecutionEvidenceRefs{resetD101OriginalSHA(planWire), resetD101OriginalSHA(preflightWire)}
	journal.ResetExecution.Evidence = refs
	fingerprint, err := resetExecutionRequestFingerprint("pep", *journal.ResetTarget, refs)
	if err != nil {
		t.Fatal(err)
	}
	journal.ResetExecution.RequestFingerprint = fingerprint
	previous := ""
	for i := range journal.ResetExecution.Attestations {
		a := &journal.ResetExecution.Attestations[i]
		a.PreviousSHA = previous
		a.SHA = resetExecutionAttestationSHA(*journal.ResetExecution, *a)
		previous = a.SHA
	}
	record.Status = lifecycleJobRecoveryRequired
	record.RequestFingerprint = fingerprint
	record.D101IntentSHA = intentSHA
	cfg.lifecycleOperationStore.operations[op] = record
	prepare, _ := json.Marshal(struct {
		SchemaVersion     int    `json:"schemaVersion"`
		ApprovalIntentSHA string `json:"approvalIntentSha256"`
		IntentBytes       string `json:"approvalIntentBytesBase64url"`
	}{1, intentSHA, base64.RawURLEncoding.EncodeToString(intentWire)})
	for leaf, wire := range map[string][]byte{".deployer-reset-intents": intentWire, ".deployer-reset-approvals": planWire, ".deployer-reset-preflights": preflightWire, ".deployer-reset-prepare-bodies": prepare} {
		if os.Remove(filepath.Join(cfg.serversDir, leaf, op+".json")) != nil || writeResetImmutablePrivateBytesWithUID(filepath.Join(cfg.serversDir, leaf), op, resetD101OriginalSHA(wire), wire, uid) != nil {
			t.Fatal("fixture original custody")
		}
	}
	if cfg.writeLifecycleJournalRecord(journal) != nil || os.Mkdir(filepath.Join(cfg.serversDir, ".deployer-reset-recovery-claims"), 0700) != nil {
		t.Fatal("fixture recovery custody")
	}
	cfg.d101PurposeAuthority = func(context.Context, string, string) (resetD101VerifiedPurposeAuthority, error) {
		a := authority
		a.Intent = decoded
		a.ClockObservedAt = time.Now()
		return a, nil
	}
	cfg.d101RecoveryVerifier = func(context.Context, resetD101RecoveryBinding) error { return nil }
	cfg.operations = newOperationCoordinator("", cfg.lifecycleJournalFile, nil)
	lease, err := cfg.operations.beginRecovery()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Done)
	return cfg, lease, journal, uid
}

func TestResetD101RecoveryClaimPinsOriginalOperationAndNeverReplays(t *testing.T) {
	cfg, lease, journal, uid := resetD101RecoveryFixture(t)
	before, _ := cfg.lifecycleOperationStore.Lookup(journal.OperationID)
	journalBefore, _ := os.ReadFile(cfg.lifecycleJournalFile)
	binding, err := cfg.claimResetD101RecoveryAttemptWithCustodyUID(lease, journal, uid)
	if err != nil {
		t.Fatal("synthetic owned claim refused", err)
	}
	wire, err := readResetPrivateCustody(filepath.Join(cfg.serversDir, ".deployer-reset-recovery-claims"), journal.OperationID, uid)
	var claim resetD101RecoveryClaim
	if err != nil || decodeResetPrivateJSON(wire, &claim) != nil || claim.Attempt != 1 || claim.OperationID != before.OperationID || claim.ApprovalIntentSHA != before.D101IntentSHA ||
		claim.AcceptedAtUTC != before.CreatedAt.UTC().Format(time.RFC3339Nano) || claim.BackupManifestSHA != binding.backup.manifestSHA ||
		claim.DestructiveCutoffUnix != binding.evidence.Plan.DestructiveCutoffUnix || claim.RecoveryDeadlineUnix != binding.evidence.Plan.RecoveryDeadlineUnix {
		t.Fatal("claim renewed or changed original binding")
	}
	if _, err := cfg.claimResetD101RecoveryAttemptWithCustodyUID(lease, journal, uid); err == nil {
		t.Fatal("recovery attempt replayed")
	}
	after, _ := cfg.lifecycleOperationStore.Lookup(journal.OperationID)
	journalAfter, _ := os.ReadFile(cfg.lifecycleJournalFile)
	if before != after || string(journalBefore) != string(journalAfter) || !cfg.operations.closed {
		t.Fatal("claim helper settled/opened physical operation")
	}
}

func TestResetD101RecoveryRefusesUnownedLeaseMissingSourceAndChangedBindings(t *testing.T) {
	for _, mode := range []string{"nil-lease", "dispatch-lease", "open", "no-journal-pending", "different-active", "different-maintenance-op", "succeeded", "running", "no-intent", "wrong-operation", "changed-journal", "missing-authority", "missing-verifier", "verifier-refusal", "verifier-changed-record", "verifier-changed-card", "stale-clock", "changed-backup", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			cfg, lease, journal, uid := resetD101RecoveryFixture(t)
			record, _ := cfg.lifecycleOperationStore.Lookup(journal.OperationID)
			switch mode {
			case "nil-lease":
				lease = nil
			case "dispatch-lease":
				lease.jobID = strings.Repeat("b", 32)
			case "open":
				cfg.operations.closed = false
			case "no-journal-pending":
				cfg.operations.journalPending = false
			case "different-active":
				cfg.operations.active = &operationLease{}
			case "different-maintenance-op":
				cfg.operations.maintenanceLease = &maintenanceAdmissionLease{operationID: strings.Repeat("b", 32)}
			case "succeeded":
				record.Status = lifecycleJobSucceeded
				cfg.lifecycleOperationStore.operations[journal.OperationID] = record
			case "running":
				record.Status = lifecycleJobRunning
				cfg.lifecycleOperationStore.operations[journal.OperationID] = record
			case "no-intent":
				record.D101IntentSHA = ""
				cfg.lifecycleOperationStore.operations[journal.OperationID] = record
			case "wrong-operation":
				journal.OperationID = strings.Repeat("b", 32)
			case "changed-journal":
				journal.Stage = lifecycleJournalStageEnv
			case "missing-authority":
				cfg.d101PurposeAuthority = nil
			case "missing-verifier":
				cfg.d101RecoveryVerifier = nil
			case "verifier-refusal":
				cfg.d101RecoveryVerifier = func(context.Context, resetD101RecoveryBinding) error { return errResetExecutionEvidence }
			case "verifier-changed-record":
				cfg.d101RecoveryVerifier = func(context.Context, resetD101RecoveryBinding) error {
					record.Status = lifecycleJobSucceeded
					cfg.lifecycleOperationStore.operations[record.OperationID] = record
					return nil
				}
			case "verifier-changed-card":
				source := cfg.d101PurposeAuthority
				changed := false
				cfg.d101PurposeAuthority = func(ctx context.Context, op, sha string) (resetD101VerifiedPurposeAuthority, error) {
					a, err := source(ctx, op, sha)
					if changed {
						a.DeploymentCardSHA = strings.Repeat("f", 64)
					}
					return a, err
				}
				cfg.d101RecoveryVerifier = func(context.Context, resetD101RecoveryBinding) error {
					changed = true
					return nil
				}
			case "stale-clock":
				source := cfg.d101PurposeAuthority
				cfg.d101PurposeAuthority = func(ctx context.Context, op, sha string) (resetD101VerifiedPurposeAuthority, error) {
					a, err := source(ctx, op, sha)
					a.ClockObservedAt = time.Now().Add(-resetPreflightMaxAge)
					return a, err
				}
			case "changed-backup":
				leaf := filepath.Join(cfg.composeDir, "backups", "pep", record.OperationID, "shared.env")
				_ = os.Remove(leaf)
				_ = os.WriteFile(leaf, []byte("changed"), 0400)
			case "cancelled":
				lease.cancel()
			}
			if _, err := cfg.claimResetD101RecoveryAttemptWithCustodyUID(lease, journal, uid); err == nil {
				t.Fatal("unqualified recovery claimed")
			}
			if stateFilePresent(filepath.Join(cfg.serversDir, ".deployer-reset-recovery-claims", record.OperationID+".json")) || !stateFilePresent(cfg.lifecycleJournalFile) {
				t.Fatal("refusal consumed attempt or cleared pending journal")
			}
		})
	}
}

func TestResetD101RecoveryAuthorityUsesOriginalRecoveryDeadlineWithoutNewGrant(t *testing.T) {
	cfg, _, journal, _ := resetD101RecoveryFixture(t)
	record, _ := cfg.lifecycleOperationStore.Lookup(journal.OperationID)
	authority, _ := cfg.d101PurposeAuthority(context.Background(), record.OperationID, record.D101IntentSHA)
	for _, test := range []struct {
		name    string
		unix    int64
		allowed bool
	}{
		{"before-window", authority.Intent.Intent.WindowOpensAtUnix - 1, false},
		{"after-original-destructive-cutoff", authority.Intent.Intent.DestructiveCutoffUnix + 1, true},
		{"recovery-deadline", authority.Intent.Intent.RecoveryDeadlineUnix, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Unix(test.unix, 0)
			a := authority
			a.ClockObservedAt = now
			_, err := requireResetD101RecoveryAuthority(a, record.OperationID, record.D101IntentSHA, now)
			if (err == nil) != test.allowed {
				t.Fatal("original recovery window not enforced")
			}
		})
	}
	if _, _, err := resetD101PurposeRoute("RECOVERY", record.OperationID); err == nil {
		t.Fatal("Root recovery invented Gateway grant route")
	}
}
