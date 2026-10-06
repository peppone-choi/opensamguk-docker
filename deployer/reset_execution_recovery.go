package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"
)

// Fixed approved host verifier, never request input or an env switch. It must
// actually rerun pg_restore --list, verify selected old metadata/settlement
// capture, retained old image availability, drain/freeze, space and host clock.
// Data-file checks below alone do not supply this producer. Production is nil.
type resetD101RecoveryVerifier func(context.Context, resetD101RecoveryBinding) error

type resetD101RecoveryBinding struct {
	operation         durableOperationRecord
	journal           lifecycleJournal
	evidence          resetExecutionEvidence
	intent            resetDecodedApprovalIntent
	backup            resetRecoveryBackup
	deploymentCardSHA string
	restoredDatabase  *resetD101RestoredDatabaseObservation // Actual source/native provenance, supplied before fixed closure signing.
}

type resetD101RecoveryClaim struct {
	SchemaVersion         int                        `json:"schemaVersion"`
	OperationID           string                     `json:"operationId"`
	ApprovalIntentSHA     string                     `json:"approvalIntentSha256"`
	DeploymentCardSHA     string                     `json:"deploymentCardSha256"`
	TargetFingerprint     string                     `json:"targetFingerprint"`
	RequestFingerprint    string                     `json:"rootRequestFingerprint"`
	Evidence              resetExecutionEvidenceRefs `json:"evidence"`
	AcceptedAtUTC         string                     `json:"acceptedAtUtc"`
	JournalSHA            string                     `json:"lifecycleJournalSha256"`
	BackupManifestSHA     string                     `json:"backupManifestSha256"`
	OldImageDigests       map[string]string          `json:"oldImageDigests"`
	DestructiveCutoffUnix int64                      `json:"destructiveCutoffUnix"`
	RecoveryDeadlineUnix  int64                      `json:"recoveryDeadlineUnix"`
	ClaimedAtUTC          string                     `json:"claimedAtUtc"`
	Attempt               int                        `json:"attempt"`
}

// Only the coordinator's closed recovery lease owns a pending D101 journal.
// A consumed dispatch lease, terminal success, helper or foreign operation can
// never acquire another destructive attempt through this path.
func (c config) requireResetD101RecoveryLease(lease *operationLease, journal lifecycleJournal) (durableOperationRecord, error) {
	if lease == nil || lease.coordinator == nil || lease.coordinator != c.operations || lease.ctx == nil || lease.Context().Err() != nil || lease.jobID != "" ||
		c.lifecycleOperationStore == nil || journal.Operation != "reset" || journal.OperationKind != lifecycleKindReset || journal.ServerID != "pep" ||
		journal.Project != "opensamguk-spep" || journal.ResetTarget == nil || journal.ResetExecution == nil || validateLifecycleResetExecution(journal) != nil {
		return durableOperationRecord{}, errResetExecutionEvidence
	}
	record, found := c.lifecycleOperationStore.Lookup(journal.OperationID)
	if !found || record.Kind != lifecycleKindReset || record.SubjectID != "pep" || record.Status != lifecycleJobRecoveryRequired ||
		!resetEvidenceSHA.MatchString(record.D101IntentSHA) || c.validateResetExecutionOperation(*journal.ResetExecution, journal.OperationID) != nil {
		return durableOperationRecord{}, errResetExecutionEvidence
	}
	current, exists, err := c.readLifecycleJournal()
	if err != nil || !exists || !reflect.DeepEqual(current, journal) {
		return durableOperationRecord{}, errResetExecutionEvidence
	}
	coordinator := lease.coordinator
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if !coordinator.closed || !coordinator.journalPending || coordinator.active != lease || coordinator.preparing != nil ||
		(coordinator.maintenanceLease != nil && coordinator.maintenanceLease.operationID != journal.OperationID) {
		return durableOperationRecord{}, errResetExecutionEvidence
	}
	return record, nil
}

// Root-only recovery uses the original approval's recovery deadline. QUERY
// proves current provenance/clock; no new Gateway mutation grant is invented.
func requireResetD101RecoveryAuthority(authority resetD101VerifiedPurposeAuthority, operationID, intentSHA string, now time.Time) (resetDecodedApprovalIntent, error) {
	intent, err := requireResetD101Authority(authority, resetD101PurposeGrantRequest{OperationID: operationID, ApprovalIntentSHA: intentSHA, Action: "QUERY"}, now)
	if err != nil || now.Unix() < intent.Intent.WindowOpensAtUnix || now.Unix() >= intent.Intent.RecoveryDeadlineUnix {
		return resetDecodedApprovalIntent{}, errResetExecutionEvidence
	}
	return intent, nil
}

// Claim only, not a live restore, metadata settlement or PUBLIC operation. The
// future fixed host restore calls this before its first mutation; no production
// invoker is connected. Existing maintenance repair still refuses D101 replay.
func (c config) claimResetD101RecoveryAttempt(lease *operationLease, journal lifecycleJournal) (resetD101RecoveryBinding, error) {
	return c.claimResetD101RecoveryAttemptWithCustodyUID(lease, journal, 0)
}

func (c config) claimResetD101RecoveryAttemptWithCustodyUID(lease *operationLease, journal lifecycleJournal, uid uint32) (resetD101RecoveryBinding, error) {
	closed := resetD101RecoveryBinding{}
	record, err := c.requireResetD101RecoveryLease(lease, journal)
	if err != nil || c.d101PurposeAuthority == nil || c.d101RecoveryVerifier == nil || !filepath.IsAbs(c.composeDir) {
		return closed, errResetExecutionEvidence
	}
	// Original plan/preflight are validated at the immutable first admission.
	// That read does not renew current recovery authority or clock freshness.
	evidence, err := c.readResetExecutionEvidenceWithCustodyUID(journal.OperationID, *journal.ResetTarget, journal.ResetExecution.Evidence, record.CreatedAt, uid)
	if err != nil || evidence.Plan.ApprovalIntentSHA != record.D101IntentSHA {
		return closed, errResetExecutionEvidence
	}
	ctx, cancel := context.WithDeadline(lease.Context(), time.Unix(evidence.Plan.RecoveryDeadlineUnix, 0))
	defer cancel()
	authority, err := c.d101PurposeAuthority(ctx, journal.OperationID, record.D101IntentSHA)
	if err != nil || ctx.Err() != nil {
		return closed, errResetExecutionEvidence
	}
	intent, err := requireResetD101RecoveryAuthority(authority, journal.OperationID, record.D101IntentSHA, time.Now())
	prepare, prepareErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), journal.OperationID, uid)
	if err != nil || prepareErr != nil || requireResetIntentPlan(intent, evidence.Plan) != nil ||
		requireResetD101PrepareBody(prepare, intent, resetD101OriginalSHA(prepare)) != nil {
		return closed, errResetExecutionEvidence
	}
	backup, err := verifyResetRecoveryBackup(ctx, filepath.Join(c.composeDir, "backups", "pep", journal.OperationID), evidence.Preflight.BackupManifestSHA, evidence.Plan.SpaceBudget, evidence.Plan.OldImageDigests, uid)
	if err != nil || c.requireResetD101PreStopBackup(ctx, evidence, uid) != nil {
		return closed, errResetExecutionEvidence
	}
	binding := resetD101RecoveryBinding{operation: record, journal: journal, evidence: evidence, intent: intent, backup: backup, deploymentCardSHA: authority.DeploymentCardSHA}
	if c.d101RecoveryVerifier(ctx, binding) != nil || ctx.Err() != nil {
		return closed, errResetExecutionEvidence
	}
	// Slow validation cannot outlive the original deadline or replace the owned
	// operation/journal. A fresh authority must be for this same immutable card.
	current, err := c.requireResetD101RecoveryLease(lease, journal)
	if err != nil || current != record {
		return closed, errResetExecutionEvidence
	}
	authority, err = c.d101PurposeAuthority(ctx, journal.OperationID, record.D101IntentSHA)
	if err != nil || authority.DeploymentCardSHA != binding.deploymentCardSHA {
		return closed, errResetExecutionEvidence
	}
	if _, err = requireResetD101RecoveryAuthority(authority, journal.OperationID, record.D101IntentSHA, time.Now()); err != nil || ctx.Err() != nil {
		return closed, errResetExecutionEvidence
	}
	journalWire, err := json.Marshal(journal)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	claim := resetD101RecoveryClaim{SchemaVersion: 1, OperationID: journal.OperationID, ApprovalIntentSHA: record.D101IntentSHA, DeploymentCardSHA: binding.deploymentCardSHA,
		TargetFingerprint: evidence.Plan.TargetFingerprint, RequestFingerprint: record.RequestFingerprint, Evidence: journal.ResetExecution.Evidence,
		AcceptedAtUTC: record.CreatedAt.UTC().Format(time.RFC3339Nano), JournalSHA: resetD101OriginalSHA(journalWire), BackupManifestSHA: backup.manifestSHA,
		OldImageDigests: evidence.Plan.OldImageDigests, DestructiveCutoffUnix: evidence.Plan.DestructiveCutoffUnix, RecoveryDeadlineUnix: evidence.Plan.RecoveryDeadlineUnix,
		ClaimedAtUTC: time.Now().UTC().Format(time.RFC3339Nano), Attempt: 1}
	wire, err := json.Marshal(claim)
	if err != nil || createResetImmutablePrivateBytes(filepath.Join(c.serversDir, ".deployer-reset-recovery-claims"), journal.OperationID, resetD101OriginalSHA(wire), wire, uid) != nil || ctx.Err() != nil {
		return closed, errResetExecutionEvidence
	}
	return binding, nil
}
