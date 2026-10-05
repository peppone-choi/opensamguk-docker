package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"
)

func resetD101OriginalSHA(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

// The actual original PREPARE request binds the gateway payload. A SHA label
// supplied by a result candidate cannot replace these immutable bytes.
func requireResetD101PrepareBody(body []byte, intent resetDecodedApprovalIntent, expectedSHA string) error {
	var prepare struct {
		SchemaVersion     int    `json:"schemaVersion"`
		ApprovalIntentSHA string `json:"approvalIntentSha256"`
		IntentBytes       string `json:"approvalIntentBytesBase64url"`
	}
	if len(body) == 0 || len(body) > resetEvidenceMaxBytes || !resetEvidenceSHA.MatchString(expectedSHA) ||
		resetD101OriginalSHA(body) != expectedSHA || requireResetIntentShape(body, reflect.TypeOf(prepare)) != nil ||
		decodeResetPrivateJSON(body, &prepare) != nil || prepare.SchemaVersion != 1 || prepare.ApprovalIntentSHA != intent.SHA {
		return errResetExecutionEvidence
	}
	original, err := base64.RawURLEncoding.Strict().DecodeString(prepare.IntentBytes)
	if err != nil || base64.RawURLEncoding.EncodeToString(original) != prepare.IntentBytes || !bytes.Equal(original, intent.originalBytes()) {
		return errResetExecutionEvidence
	}
	return nil
}

// Coordinator-only issuance: PREPARE originals are committed before a grant is
// returned. Directories must already be installed with the approved custody;
// this function never creates keys, trust or a success authority provider.
func (c config) issueResetD101PurposeGrant(ctx context.Context, request resetD101PurposeGrantRequest) (string, error) {
	grant, err := issueResetD101PurposeGrant(ctx, c.d101PurposeAuthority, request, time.Now)
	if err != nil || request.Action != "PREPARE" {
		return grant, err
	}
	authority, err := c.d101PurposeAuthority(ctx, request.OperationID, request.ApprovalIntentSHA)
	if err != nil || ctx.Err() != nil {
		return "", errResetExecutionEvidence
	}
	intent, err := requireResetD101Authority(authority, request, time.Now())
	if err != nil || requireResetD101PrepareBody(request.Body, intent, request.GatewayPayloadSHA) != nil ||
		writeResetImmutablePrivateBytes(filepath.Join(c.serversDir, ".deployer-reset-intents"), request.OperationID, intent.SHA, intent.originalBytes()) != nil ||
		writeResetImmutablePrivateBytes(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), request.OperationID, request.GatewayPayloadSHA, request.Body) != nil || ctx.Err() != nil {
		return "", errResetExecutionEvidence
	}
	if _, err := requireResetD101Authority(authority, request, time.Now()); err != nil {
		return "", errResetExecutionEvidence
	}
	return grant, nil
}

// Called after the new stack has been observed and before durable SUCCEEDED.
// Only the actual Docker/raw ADMIN collector can supply this production file.
func (c config) persistResetD101Runtime(ctx context.Context, binding resetExecutionPhaseBinding, appRepository string) (string, error) {
	observation, err := c.collectResetD101Runtime(ctx, binding, appRepository)
	if err != nil || ctx.Err() != nil {
		return "", errResetExecutionEvidence
	}
	wire, err := json.Marshal(observation)
	sha := resetD101OriginalSHA(wire)
	if err != nil || writeResetImmutablePrivateBytes(filepath.Join(c.serversDir, ".deployer-reset-runtime"), binding.OperationID, sha, wire) != nil || ctx.Err() != nil {
		return "", errResetExecutionEvidence
	}
	return sha, nil
}

// Receipt-only settlement of an ALREADY durable physical success. No Docker,
// env, registry, restart, down, up or mutable outcome transition occurs here.
// On refusal, the live lifecycle journal remains available for this same read
// and publication path; physical execution is never repeated.
func (c config) publishResetD101SucceededResult(ctx context.Context, operationID string) (string, error) {
	return c.publishResetD101SucceededResultWithCustodyUID(ctx, operationID, 0)
}

// UID injection belongs only to isolated file/store fixtures.
func (c config) publishResetD101SucceededResultWithCustodyUID(ctx context.Context, operationID string, uid uint32) (string, error) {
	if ctx == nil || ctx.Err() != nil || c.d101PurposeAuthority == nil || c.lifecycleOperationStore == nil || !lifecycleJobIDRe.MatchString(operationID) {
		return "", errResetExecutionEvidence
	}
	record, found := c.lifecycleOperationStore.Lookup(operationID)
	journal, exists, err := c.readLifecycleJournal()
	if err != nil || !exists || !found || journal.OperationID != operationID || journal.OperationKind != lifecycleKindReset ||
		journal.ResetTarget == nil || journal.ResetExecution == nil || journal.Stage != lifecycleJournalStageDown ||
		record.Kind != lifecycleKindReset || record.SubjectID != "pep" || record.Status != lifecycleJobSucceeded ||
		c.validateResetExecutionOperation(*journal.ResetExecution, operationID) != nil || len(journal.ResetExecution.Attestations) != 3 {
		return "", errResetExecutionEvidence
	}
	refs := journal.ResetExecution.Evidence
	evidence, err := c.readResetExecutionEvidenceWithCustodyUID(operationID, *journal.ResetTarget, refs, record.CreatedAt, uid)
	if err != nil || evidence.Plan.ApprovalIntentSHA == "" || record.D101IntentSHA != evidence.Plan.ApprovalIntentSHA {
		return "", errResetExecutionEvidence
	}
	authority, err := c.d101PurposeAuthority(ctx, operationID, evidence.Plan.ApprovalIntentSHA)
	request := resetD101PurposeGrantRequest{OperationID: operationID, ApprovalIntentSHA: evidence.Plan.ApprovalIntentSHA, Action: "QUERY"}
	if err != nil {
		return "", errResetExecutionEvidence
	}
	intent, err := requireResetD101Authority(authority, request, time.Now())
	prepare, prepareErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), operationID, uid)
	request.GatewayPayloadSHA = resetD101OriginalSHA(prepare)
	if err != nil || prepareErr != nil || requireResetD101PrepareBody(prepare, intent, request.GatewayPayloadSHA) != nil || requireResetIntentPlan(intent, evidence.Plan) != nil {
		return "", errResetExecutionEvidence
	}
	runtime, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-runtime"), operationID, uid)
	if err != nil {
		return "", errResetExecutionEvidence
	}
	runtimeSHA := resetD101OriginalSHA(runtime)
	journalWire, err := json.Marshal(journal.ResetExecution)
	journalSHA := resetD101OriginalSHA(journalWire)
	if err != nil || writeResetImmutablePrivateBytesWithUID(filepath.Join(c.serversDir, ".deployer-reset-execution-journals"), operationID, journalSHA, journalWire, uid) != nil {
		return "", errResetExecutionEvidence
	}
	result := resetD101ExecutionResult{SchemaVersion: 1, ServerID: "pep", WorldID: 1, OperationID: operationID, Kind: "reset", Status: "succeeded",
		Generation: 0, ScenarioCode: "scenario_3190", ServerName: "빼섭", ApprovalIntentSHA: intent.SHA, ApprovalPlanSHA: refs.ApprovalPlanSHA,
		ExecutionReceiptSHA: refs.ExecutionReceiptSHA, TargetFingerprint: evidence.Plan.TargetFingerprint, RootRequestFingerprint: record.RequestFingerprint,
		GatewayPayloadSHA: request.GatewayPayloadSHA, VerifyingRevision: evidence.Preflight.PublicationRevision, AppSourceSHA: evidence.Plan.AppSourceSHA,
		ImageDigests: evidence.Plan.NewImageDigests, AcceptedAtUTC: record.CreatedAt.UTC().Format(time.RFC3339Nano), CompletedAtUTC: record.UpdatedAt.UTC().Format(time.RFC3339Nano),
		ExecutionJournalSHA: &journalSHA, ActualRuntimeReceiptSHA: &runtimeSHA}
	wire, err := json.Marshal(result)
	sha := resetD101OriginalSHA(wire)
	if err != nil || requireResetD101ResultBinding(result, intent, evidence.Plan, evidence.Preflight, record, time.Now()) != nil ||
		c.requireResetD101ResultProofsWithCustodyUID(result, evidence.Plan, evidence.Preflight, record, uid) != nil {
		return "", errResetExecutionEvidence
	}
	if _, err := decodeResetD101ExecutionResult(wire, sha); err != nil {
		return "", errResetExecutionEvidence
	}
	current, currentFound := c.lifecycleOperationStore.Lookup(operationID)
	if !currentFound || current != record || ctx.Err() != nil {
		return "", errResetExecutionEvidence
	}
	if _, err := requireResetD101Authority(authority, request, time.Now()); err != nil {
		return "", errResetExecutionEvidence
	}
	if writeResetImmutablePrivateBytesWithUID(filepath.Join(c.serversDir, ".deployer-reset-results"), operationID, sha, wire, uid) != nil || ctx.Err() != nil {
		return "", errResetExecutionEvidence
	}
	current, currentFound = c.lifecycleOperationStore.Lookup(operationID)
	if !currentFound || current != record {
		return "", errResetExecutionEvidence
	}
	return sha, nil
}

// The caller owns the lifecycle lease. D101 success cannot clear its journal
// before receipt publication; legacy jobs keep their existing cleanup path.
func (c config) settleSucceededLifecycleJournal(ctx context.Context, operationID string) error {
	journal, exists, err := c.readLifecycleJournal()
	if err != nil {
		return err
	}
	if exists && journal.ResetExecution != nil {
		if journal.OperationID != operationID {
			return errResetExecutionEvidence
		}
		if _, err := c.publishResetD101SucceededResult(ctx, operationID); err != nil {
			return err
		}
	}
	return c.clearLifecycleJournal()
}
