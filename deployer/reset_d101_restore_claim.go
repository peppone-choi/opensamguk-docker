package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

// A restore after terminal success owns a separate immutable attempt. It does
// not recreate the completed lifecycle journal or transition its Root record.
// The gate persists even if validation, claim publication or execution becomes
// UNKNOWN. No restart/retry/maintenance-open path clears it automatically.
func resetD101RestoreGatePath(marker string) string {
	if marker == "" {
		return ""
	}
	return marker + ".d101-restore1"
}

func (c *operationCoordinator) beginResetD101SucceededRestore(op string) (*operationLease, error) {
	return c.beginResetD101SucceededRestoreWithCustodyUID(op, 0)
}

// UID is only an isolated filesystem fixture seam, never request input.
func (c *operationCoordinator) beginResetD101SucceededRestoreWithCustodyUID(op string, uid uint32) (*operationLease, error) {
	if c == nil || !lifecycleJobIDRe.MatchString(op) || !filepath.IsAbs(c.markerPath) || !filepath.IsAbs(c.journalPath) {
		return nil, errResetExecutionEvidence
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	gate := resetD101RestoreGatePath(c.markerPath)
	parent := filepath.Dir(gate)
	resolved, pathErr := filepath.EvalSymlinks(parent)
	before, statErr := os.Lstat(parent)
	stat, statOK := resetPrivateFileStat(before)
	if pathErr != nil || resolved != parent || statErr != nil || !before.IsDir() || before.Mode().Perm()&0022 != 0 || !statOK || stat.Uid != uid {
		return nil, errResetExecutionEvidence
	}
	retainedSameOp := c.closed && c.maintenanceLease != nil && c.maintenanceLease.consumed && c.maintenanceLease.operationID == op
	if (c.closed && !retainedSameOp) || c.active != nil || c.preparing != nil || c.preparationSettlementPending || c.journalPending ||
		(c.maintenanceLease != nil && !retainedSameOp) || (stateFilePresent(c.markerPath) && !retainedSameOp) || stateFilePresent(c.journalPath) || stateFilePresent(gate) {
		return nil, errResetExecutionEvidence
	}
	// Exclusive durable gate before publishing an in-memory lease. Failure after
	// creating it remains closed; the original op is never admitted a second time.
	wire, _ := json.Marshal(struct {
		Kind string `json:"kind"`
		Op   string `json:"operationId"`
	}{"D101_RESTORE1_PENDING_V1", op})
	file, err := os.OpenFile(gate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		if stateFilePresent(gate) {
			c.closed = true
		}
		return nil, errResetExecutionEvidence
	}
	c.closed = true
	n, writeErr := file.Write(wire)
	syncErr := file.Sync()
	closeErr := file.Close()
	after, afterErr := os.Lstat(parent)
	afterStat, afterOK := resetPrivateFileStat(after)
	if writeErr != nil || n != len(wire) || syncErr != nil || closeErr != nil || afterErr != nil || !os.SameFile(before, after) ||
		!afterOK || afterStat.Uid != uid || after.Mode().Perm() != before.Mode().Perm() ||
		syncDirectory(parent) != nil || requireResetD101RestoreGate(gate, op, uid) != nil {
		return nil, errResetExecutionEvidence
	}
	ctx, cancel := context.WithCancel(context.Background())
	lease := &operationLease{coordinator: c, ctx: ctx, cancel: cancel}
	c.active = lease
	c.maintenanceLease = &maintenanceAdmissionLease{operationID: op, consumed: true}
	c.cond.Broadcast()
	return lease, nil
}

func requireResetD101RestoreGate(path, op string, uid uint32) error {
	if !filepath.IsAbs(path) || !lifecycleJobIDRe.MatchString(op) {
		return errResetExecutionEvidence
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	wire, err := readResetRecoverySmallFile(ctx, filepath.Dir(path), filepath.Base(path), 1024, uid)
	var value struct {
		Kind string `json:"kind"`
		Op   string `json:"operationId"`
	}
	if err != nil || requireResetIntentShape(wire, reflect.TypeOf(value)) != nil || decodeResetPrivateJSON(wire, &value) != nil ||
		value.Kind != "D101_RESTORE1_PENDING_V1" || value.Op != op {
		return errResetExecutionEvidence
	}
	return nil
}

type resetD101SucceededRestoreClaim struct {
	SchemaVersion               int               `json:"schemaVersion"`
	Kind                        string            `json:"kind"`
	OperationID                 string            `json:"operationId"`
	ApprovalIntentSHA           string            `json:"approvalIntentSha256"`
	DeploymentCardSHA           string            `json:"deploymentCardSha256"`
	TargetFingerprint           string            `json:"targetFingerprint"`
	VerifyingRevision           string            `json:"verifyingRevision"`
	GatewayPayloadSHA           string            `json:"gatewayPayloadSha256"`
	OriginalRootResultSHA       string            `json:"originalRootResultSha256"`
	OriginalRootRecordSHA       string            `json:"originalRootRecordSha256"`
	RecoveryBeginReceiptSHA     string            `json:"recoveryBeginReceiptSha256"`
	RecoveryBeginBytesBase64url string            `json:"recoveryBeginBytesBase64url"`
	BackupManifestSHA           string            `json:"backupManifestSha256"`
	ArchiveContainerID          string            `json:"archiveContainerId"`
	ArchiveImageID              string            `json:"archiveImageId"`
	ArchiveListOriginalSHA      string            `json:"archiveListOriginalSha256"`
	OldImageDigests             map[string]string `json:"oldImageDigests"`
	Attempt                     int               `json:"attempt"`
	ClaimedAtUTC                string            `json:"claimedAtUtc"`
	RecoveryDeadlineUnix        int64             `json:"recoveryDeadlineUnix"`
}

type resetD101SucceededRestore struct {
	lease    *operationLease
	binding  resetD101RecoveryBinding
	begin    resetD101CommittedRecoveryBegin
	root     []byte
	claim    []byte
	claimSHA string
	archive  resetD101RestoreArchiveObservation
}

// Production entry point for an installed fixed restore executor. Missing host
// verifier remains closed before acquiring a lease. This does not restore data,
// declare RECOVERED or expose a caller-controlled retry endpoint.
func (c config) claimResetD101SucceededRestore(ctx context.Context, op, intentSHA string) (resetD101SucceededRestore, error) {
	closed := resetD101SucceededRestore{}
	if ctx == nil || ctx.Err() != nil || c.operations == nil || c.lifecycleOperationStore == nil ||
		c.d101PurposeAuthority == nil || c.d101RecoveryVerifier == nil || !lifecycleJobIDRe.MatchString(op) || !resetEvidenceSHA.MatchString(intentSHA) {
		return closed, errResetExecutionEvidence
	}
	record, found := c.lifecycleOperationStore.Lookup(op)
	if !found || record.Status != lifecycleJobSucceeded || record.Kind != lifecycleKindReset || record.SubjectID != "pep" || record.D101IntentSHA != intentSHA {
		return closed, errResetExecutionEvidence
	}
	begin, err := c.readResetD101GatewayRecoveryBegin(ctx, op, intentSHA)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	root, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-results"), op, 0)
	result, resultErr := decodeResetD101ExecutionResult(root, resetD101OriginalSHA(root))
	if err != nil || resultErr != nil || result.Status != string(lifecycleJobSucceeded) || begin.value.RootResultReceiptSHA != resetD101OriginalSHA(root) {
		return closed, errResetExecutionEvidence
	}
	authority, err := c.d101PurposeAuthority(ctx, op, intentSHA)
	intent, authorityErr := requireResetD101RecoveryAuthority(authority, op, intentSHA, time.Now())
	if err != nil || authorityErr != nil {
		return closed, errResetExecutionEvidence
	}
	refs := resetExecutionEvidenceRefs{result.ApprovalPlanSHA, result.ExecutionReceiptSHA}
	evidence, err := c.readResetExecutionEvidence(op, intent.Target, refs, record.CreatedAt)
	if err != nil || requireResetD101ResultBinding(result, intent, evidence.Plan, evidence.Preflight, record, time.Now()) != nil ||
		c.requireResetD101ResultProofs(result, evidence.Plan, evidence.Preflight, record) != nil {
		return closed, errResetExecutionEvidence
	}
	lease, err := c.operations.beginResetD101SucceededRestore(op)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	// Release only the in-memory owner on any failure. Durable gate/claim/job
	// stay retained, blocking ordinary maintenance reopen and all replay.
	keepLease := false
	defer func() {
		if !keepLease {
			lease.Done()
		}
	}()
	bounded, cancel := context.WithDeadline(ctx, time.Unix(intent.Intent.RecoveryDeadlineUnix, 0))
	defer cancel()
	backup, err := verifyResetRecoveryBackup(bounded, filepath.Join(c.composeDir, "backups", "pep", op), evidence.Preflight.BackupManifestSHA, evidence.Plan.SpaceBudget, intent.Intent.OldImageDigests, 0)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	attempt := resetD101SucceededRestore{lease: lease, binding: resetD101RecoveryBinding{operation: record, evidence: evidence,
		intent: intent, backup: backup, deploymentCardSHA: authority.DeploymentCardSHA}, begin: begin, root: append([]byte(nil), root...)}
	guard := func(ctx context.Context) error { return c.requireResetD101SucceededRestore(ctx, attempt, false) }
	if guard(bounded) != nil || c.d101RecoveryVerifier(bounded, attempt.binding) != nil || guard(bounded) != nil {
		return closed, errResetExecutionEvidence
	}
	archive, err := c.observeResetD101RestoreArchive(bounded, attempt.binding, guard)
	if err != nil || guard(bounded) != nil {
		return closed, errResetExecutionEvidence
	}
	recordWire, err := json.Marshal(record)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	claim := resetD101SucceededRestoreClaim{SchemaVersion: 1, Kind: "D101_SUCCEEDED_RESTORE1_CLAIM_V1", OperationID: op,
		ApprovalIntentSHA: intentSHA, DeploymentCardSHA: authority.DeploymentCardSHA, TargetFingerprint: result.TargetFingerprint,
		VerifyingRevision: result.VerifyingRevision, GatewayPayloadSHA: result.GatewayPayloadSHA, OriginalRootResultSHA: resetD101OriginalSHA(root),
		OriginalRootRecordSHA: resetD101OriginalSHA(recordWire), RecoveryBeginReceiptSHA: begin.SHA(), RecoveryBeginBytesBase64url: base64.RawURLEncoding.EncodeToString(begin.Original()),
		BackupManifestSHA: backup.manifestSHA, ArchiveContainerID: archive.ContainerID, ArchiveImageID: archive.ImageID,
		ArchiveListOriginalSHA: archive.ListOriginalSHA, OldImageDigests: intent.Intent.OldImageDigests, Attempt: 1,
		ClaimedAtUTC: time.Now().UTC().Format(time.RFC3339Nano), RecoveryDeadlineUnix: intent.Intent.RecoveryDeadlineUnix}
	wire, err := json.Marshal(claim)
	if err != nil || createResetImmutablePrivateBytes(filepath.Join(c.serversDir, ".deployer-reset-restore1-claims"), op, resetD101OriginalSHA(wire), wire, 0) != nil {
		return closed, errResetExecutionEvidence
	}
	attempt.claim, attempt.claimSHA, attempt.archive = append([]byte(nil), wire...), resetD101OriginalSHA(wire), archive
	if c.requireResetD101SucceededRestore(bounded, attempt, true) != nil {
		return closed, errResetExecutionEvidence
	}
	keepLease = true
	return attempt, nil
}

// Fresh guard for every later physical restore command. No lifecycle journal
// is required or rewritten, and the completed Root status/result stay exact.
func (c config) requireResetD101SucceededRestore(ctx context.Context, attempt resetD101SucceededRestore, requireClaim bool) error {
	op := attempt.binding.operation.OperationID
	lease := attempt.lease
	if ctx == nil || ctx.Err() != nil || c.lifecycleOperationStore == nil || c.d101PurposeAuthority == nil || lease == nil ||
		lease.coordinator != c.operations || lease.ctx == nil || lease.Context().Err() != nil || lease.jobID != "" {
		return errResetExecutionEvidence
	}
	record, found := c.lifecycleOperationStore.Lookup(op)
	if !found || record != attempt.binding.operation || record.Status != lifecycleJobSucceeded {
		return errResetExecutionEvidence
	}
	coordinator := lease.coordinator
	coordinator.mu.Lock()
	owned := coordinator.closed && coordinator.active == lease && coordinator.preparing == nil && !coordinator.journalPending &&
		!stateFilePresent(coordinator.journalPath) && stateFilePresent(resetD101RestoreGatePath(coordinator.markerPath)) &&
		coordinator.maintenanceLease != nil && coordinator.maintenanceLease.consumed && coordinator.maintenanceLease.operationID == op && coordinator.maintenanceLease.jobID == ""
	coordinator.mu.Unlock()
	if !owned {
		return errResetExecutionEvidence
	}
	if requireResetD101RestoreGate(resetD101RestoreGatePath(coordinator.markerPath), op, 0) != nil {
		return errResetExecutionEvidence
	}
	root, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-results"), op, 0)
	if err != nil || !bytes.Equal(root, attempt.root) {
		return errResetExecutionEvidence
	}
	authority, err := c.d101PurposeAuthority(ctx, op, record.D101IntentSHA)
	intent, authorityErr := requireResetD101RecoveryAuthority(authority, op, record.D101IntentSHA, time.Now())
	if err != nil || authorityErr != nil || authority.DeploymentCardSHA != attempt.binding.deploymentCardSHA || !bytes.Equal(intent.originalBytes(), attempt.binding.intent.originalBytes()) {
		return errResetExecutionEvidence
	}
	begin, err := c.readResetD101GatewayRecoveryBegin(ctx, op, record.D101IntentSHA)
	if err != nil || begin.SHA() != attempt.begin.SHA() || !bytes.Equal(begin.Original(), attempt.begin.Original()) || !reflect.DeepEqual(begin.gateway, attempt.begin.gateway) {
		return errResetExecutionEvidence
	}
	if requireClaim {
		wire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-restore1-claims"), op, 0)
		if err != nil || !resetEvidenceSHA.MatchString(attempt.claimSHA) || resetD101OriginalSHA(wire) != attempt.claimSHA || !bytes.Equal(wire, attempt.claim) {
			return errResetExecutionEvidence
		}
	}
	return nil
}
