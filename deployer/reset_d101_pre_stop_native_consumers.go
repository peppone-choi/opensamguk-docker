package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

func requireResetD101PreflightProofShape(wire []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(wire, &fields) != nil {
		return errResetExecutionEvidence
	}
	shape := reflect.TypeOf(resetPreflightReceipt{})
	allowed := make(map[string]bool)
	for n := 0; n < shape.NumField(); n++ {
		f := shape.Field(n)
		key := strings.Split(f.Tag.Get("json"), ",")[0]
		allowed[key] = true
		raw, exists := fields[key]
		if key == "preStopNativeProofSha256" && !exists {
			continue
		}
		if !exists || requireResetIntentShape(raw, f.Type) != nil {
			return errResetExecutionEvidence
		}
		if key == "preStopNativeProofSha256" {
			var sha string
			if json.Unmarshal(raw, &sha) != nil || !resetEvidenceSHA.MatchString(sha) {
				return errResetExecutionEvidence
			}
		}
	}
	for key := range fields {
		if !allowed[key] {
			return errResetExecutionEvidence
		}
	}
	return nil
}

// Read immutable preflight/plan at original admission time; prove native
// provenance now without re-aging the historical old SQL to current freshness.
func (c config) readResetD101PreStopProofForEvidence(ctx context.Context, evidence resetExecutionEvidence, uid uint32) (resetD101PreStopNativeOriginal, error) {
	closed := resetD101PreStopNativeOriginal{}
	if ctx == nil || ctx.Err() != nil || evidence.Plan.ApprovalIntentSHA == "" || !resetEvidenceSHA.MatchString(evidence.Preflight.PreStopNativeProofSHA) {
		return closed, errResetExecutionEvidence
	}
	op := evidence.Plan.OperationID
	intentWire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-intents"), op, uid)
	intent, intentErr := decodeResetApprovalIntent(intentWire, evidence.Plan.ApprovalIntentSHA)
	prepare, prepareErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), op, uid)
	gatewaySHA := resetD101OriginalSHA(prepare)
	if err != nil || intentErr != nil || prepareErr != nil || requireResetIntentPlan(intent, evidence.Plan) != nil || requireResetD101PrepareBody(prepare, intent, gatewaySHA) != nil {
		return closed, errResetExecutionEvidence
	}
	proof, err := c.readResetD101PreStopNativeProof(ctx, intent, evidence.Plan, evidence.Preflight.ApprovalPlanSHA, gatewaySHA, evidence.Preflight.PreStopNativeProofSHA, uid)
	completed, completedErr := resetD101PreStopUTC(proof.body.CollectorCompletedAtUTC)
	if err != nil || completedErr != nil || completed.After(time.Unix(evidence.Preflight.ObservedAtUnix, 0)) ||
		proof.body.VerifyingRevision != evidence.Preflight.PublicationRevision || proof.body.PostgresContainerID != evidence.Preflight.StoppedContainerIDs["game-postgres"] {
		return closed, errResetExecutionEvidence
	}
	intentAfter, intentAfterErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-intents"), op, uid)
	prepareAfter, prepareAfterErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), op, uid)
	var planAfter resetApprovalPlan
	if intentAfterErr != nil || prepareAfterErr != nil || !bytes.Equal(intentAfter, intentWire) || !bytes.Equal(prepareAfter, prepare) ||
		readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-approvals"), op, evidence.Preflight.ApprovalPlanSHA, uid, &planAfter) != nil ||
		!reflect.DeepEqual(planAfter, evidence.Plan) || ctx.Err() != nil {
		return closed, errResetExecutionEvidence
	}
	return proof, nil
}

// Both the retained static preproof and the actual backup are required. A
// backup-only verifier is not silently promoted to pre-stop authentication.
func (c config) requireResetD101PreStopBackup(ctx context.Context, evidence resetExecutionEvidence, uid uint32) error {
	if _, err := c.readResetD101PreStopProofForEvidence(ctx, evidence, uid); err != nil {
		return errResetExecutionEvidence
	}
	if _, err := verifyResetRecoveryBackup(ctx, filepath.Join(c.composeDir, "backups", "pep", evidence.Plan.OperationID), evidence.Preflight.BackupManifestSHA, evidence.Plan.SpaceBudget, evidence.Plan.OldImageDigests, uid); err != nil {
		return errResetExecutionEvidence
	}
	if _, err := c.readResetD101PreStopProofForEvidence(ctx, evidence, uid); err != nil {
		return errResetExecutionEvidence
	}
	return nil
}

// Fixed actual restore collector source, not request data/a result label. Its
// installation and native provenance must be supplied with the fixed recovery
// verifier. No new original slot, signing purpose or public body is introduced.
type resetD101RecoveryDatabaseSource func(context.Context, string, string) (resetD101RestoredDatabaseObservation, error)

func (c config) requireResetD101RecoveryPreSQL(ctx context.Context, record durableOperationRecord, evidence resetExecutionEvidence, intent resetDecodedApprovalIntent, closure resetD101RecoveryResult, uid uint32) error {
	if c.d101RecoveryDatabaseSource == nil || c.d101RecoveryVerifier == nil || ctx == nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	rootWire, rootErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-results"), record.OperationID, uid)
	root, rootDecodeErr := decodeResetD101ExecutionResult(rootWire, closure.OriginalRootResultSHA)
	var plan resetApprovalPlan
	var preflight resetPreflightReceipt
	if rootErr != nil || rootDecodeErr != nil || root.OperationID != record.OperationID || root.ApprovalIntentSHA != intent.SHA ||
		readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-approvals"), record.OperationID, root.ApprovalPlanSHA, uid, &plan) != nil ||
		readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-preflights"), record.OperationID, root.ExecutionReceiptSHA, uid, &preflight) != nil ||
		!reflect.DeepEqual(plan, evidence.Plan) || !reflect.DeepEqual(preflight, evidence.Preflight) {
		return errResetExecutionEvidence
	}
	proof, err := c.readResetD101PreStopProofForEvidence(ctx, evidence, uid)
	if err != nil || c.requireResetD101PreStopBackup(ctx, evidence, uid) != nil {
		return errResetExecutionEvidence
	}
	begin, err := c.readResetD101GatewayRecoveryBegin(ctx, record.OperationID, intent.SHA)
	if err != nil || begin.sha != closure.RecoveryBeginReceiptSHA {
		return errResetExecutionEvidence
	}
	database, err := c.d101RecoveryDatabaseSource(ctx, record.OperationID, closure.RestoredDatabaseReceiptSHA)
	database.original = bytes.Clone(database.original)
	if err != nil || ctx.Err() != nil || len(database.original) == 0 || resetD101OriginalSHA(database.original) != closure.RestoredDatabaseReceiptSHA || database.sha != closure.RestoredDatabaseReceiptSHA ||
		!resetEvidenceSHA.MatchString(database.postgresID) || !resetEvidenceSHA.MatchString(database.jobID) || database.postgresID == database.jobID ||
		!resetManifestDigest.MatchString(database.postgresImage) || !resetManifestDigest.MatchString(database.jobImage) {
		return errResetExecutionEvidence
	}
	actual, err := decodeResetD101RestoredDatabase(database.original, database.value.DatabaseName, database.value.DatabaseUser, database.value.ServerAddress, database.started, database.completed)
	started, e1 := resetD101RecoveryUTC(closure.StartedAtUTC)
	completed, e2 := resetD101RecoveryUTC(closure.CompletedAtUTC)
	generation, generationErr := strconv.ParseInt(actual.GenerationRaw, 10, 32)
	var world resetD101RestoredOldWorld
	if err != nil || e1 != nil || e2 != nil || generationErr != nil || database.started.Before(started) || database.completed.After(completed) || !reflect.DeepEqual(actual, database.value) ||
		requireResetD101RestoredMatchesObservedOld(actual, proof.old) != nil || decodeResetD101RecoverySnapshot(closure.RestoredOldWorldBytesBase64url, closure.OldWorldReceiptSHA, &world) != nil ||
		generation != int64(closure.OldGeneration) || actual.ScenarioCode != closure.OldScenarioCode || actual.TickSeconds != world.TickSeconds ||
		!bytes.Equal(begin.preReset.Original(), proof.canonical.Original()) || closure.OldRegistryReceiptSHA != resetD101OriginalSHA(proof.canonical.RegistryOriginal()) ||
		closure.OldPublicationReceiptSHA != resetD101OriginalSHA(proof.canonical.PublicationOriginal()) {
		return errResetExecutionEvidence
	}
	backup, err := verifyResetRecoveryBackup(ctx, filepath.Join(c.composeDir, "backups", "pep", record.OperationID), evidence.Preflight.BackupManifestSHA, evidence.Plan.SpaceBudget, intent.Intent.OldImageDigests, uid)
	if err != nil {
		return errResetExecutionEvidence
	}
	verifiedDatabase := database
	verifiedDatabase.original = bytes.Clone(database.original)
	binding := resetD101RecoveryBinding{operation: record, evidence: evidence, intent: intent, backup: backup, restoredDatabase: &verifiedDatabase}
	if c.d101RecoveryVerifier(ctx, binding) != nil {
		return errResetExecutionEvidence
	}
	after, err := c.d101RecoveryDatabaseSource(ctx, record.OperationID, closure.RestoredDatabaseReceiptSHA)
	if err != nil || !reflect.DeepEqual(after, database) || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	return nil
}
