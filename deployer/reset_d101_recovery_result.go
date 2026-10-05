package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

const resetD101RecoveryResultDomain = "OPENSAMGUK-D101-RECOVERY-RESULT-V1\n"

// Independent immutable closure; never overwrites the original Root RESULT.
type resetD101RecoveryResult struct {
	SchemaVersion                      int               `json:"schemaVersion"`
	Kind                               string            `json:"kind"`
	Status                             string            `json:"status"`
	ServerID                           string            `json:"serverId"`
	WorldID                            int               `json:"worldId"`
	OperationID                        string            `json:"operationId"`
	ApprovalIntentSHA                  string            `json:"approvalIntentSha256"`
	TargetFingerprint                  string            `json:"targetFingerprint"`
	GatewayPayloadSHA                  string            `json:"gatewayPayloadSha256"`
	VerifyingRevision                  string            `json:"verifyingRevision"`
	RecoveryBeginReceiptSHA            string            `json:"recoveryBeginReceiptSha256"`
	OriginalRootResultSHA              string            `json:"originalRootResultSha256"`
	BackupManifestSHA                  string            `json:"backupManifestSha256"`
	RecoveryClaimSHA                   string            `json:"recoveryClaimSha256"`
	RestoredDatabaseReceiptSHA         string            `json:"restoredDatabaseReceiptSha256"`
	RestoredRuntimeReceiptSHA          string            `json:"restoredRuntimeReceiptSha256"`
	RestoredSelectedMetadataReceiptSHA string            `json:"restoredSelectedMetadataReceiptSha256"`
	OldImageDigests                    map[string]string `json:"oldImageDigests"`
	RestoreAttempt                     int               `json:"restoreAttempt"`
	StartedAtUTC                       string            `json:"startedAtUtc"`
	CompletedAtUTC                     string            `json:"completedAtUtc"`
	RecoveryDeadlineUnix               int64             `json:"recoveryDeadlineUnix"`
	OldGeneration                      int               `json:"oldGeneration"`
	OldScenarioCode                    string            `json:"oldScenarioCode"`
	OldRegistryReceiptSHA              string            `json:"oldRegistryReceiptSha256"`
	OldPublicationReceiptSHA           string            `json:"oldPublicationReceiptSha256"`
	OldWorldReceiptSHA                 string            `json:"oldWorldReceiptSha256"`
	OldCanonicalRegistryBytesBase64url string            `json:"oldCanonicalRegistryBytesBase64url"`
	RestoredOldWorldBytesBase64url     string            `json:"restoredOldWorldBytesBase64url"`
}

// The fixed producer must verify committed same-op Gateway begin/CAS, exclusive
// immutable claim attempt1, actual backup/restore/runtime/selected old metadata,
// native original custody and deadline. No production producer is installed.
type resetD101RecoveryResultSource func(context.Context, string, string) (resetD101RecoveryResult, error)

func validateResetD101RecoveryResult(wire []byte, intent resetDecodedApprovalIntent, beginSHA string,
	now time.Time) (resetD101RecoveryResult, error) {
	var result resetD101RecoveryResult
	if len(wire) == 0 || len(wire) > 16*1024 || !utf8.Valid(wire) || requireResetIntentShape(wire, reflect.TypeOf(result)) != nil ||
		decodeResetPrivateJSON(wire, &result) != nil || result.SchemaVersion != 1 || result.Kind != "D101_RECOVERY_RESULT_V1" ||
		result.Status != "RECOVERED" || result.ServerID != "pep" || result.WorldID != 1 ||
		result.OperationID != intent.Intent.OperationID || result.ApprovalIntentSHA != intent.SHA ||
		result.TargetFingerprint != intent.Intent.TargetFingerprint || result.RecoveryBeginReceiptSHA != beginSHA ||
		!resetEvidenceSHA.MatchString(beginSHA) || result.RestoreAttempt != 1 || result.OldGeneration < 0 ||
		!regexp.MustCompile(`^scenario_[0-9]+$`).MatchString(result.OldScenarioCode) ||
		result.RecoveryDeadlineUnix != intent.Intent.RecoveryDeadlineUnix ||
		!validResetFiveImageDigests(result.OldImageDigests) ||
		!reflect.DeepEqual(result.OldImageDigests, intent.Intent.OldImageDigests) {
		return resetD101RecoveryResult{}, errResetExecutionEvidence
	}
	for _, sha := range []string{result.GatewayPayloadSHA, result.OriginalRootResultSHA, result.BackupManifestSHA,
		result.RecoveryClaimSHA, result.RestoredDatabaseReceiptSHA, result.RestoredRuntimeReceiptSHA,
		result.RestoredSelectedMetadataReceiptSHA, result.OldRegistryReceiptSHA, result.OldPublicationReceiptSHA, result.OldWorldReceiptSHA} {
		if !resetEvidenceSHA.MatchString(sha) {
			return resetD101RecoveryResult{}, errResetExecutionEvidence
		}
	}
	revision, revisionErr := strconv.ParseInt(result.VerifyingRevision, 10, 64)
	if revisionErr != nil || revision <= 0 || strconv.FormatInt(revision, 10) != result.VerifyingRevision {
		return resetD101RecoveryResult{}, errResetExecutionEvidence
	}
	started, err := resetD101RecoveryUTC(result.StartedAtUTC)
	completed, completedErr := resetD101RecoveryUTC(result.CompletedAtUTC)
	if err != nil || completedErr != nil || started.Unix() < intent.Intent.WindowOpensAtUnix ||
		completed.Before(started) || completed.After(now) || now.Sub(completed) >= resetPreflightMaxAge || completed.Unix() >= intent.Intent.RecoveryDeadlineUnix ||
		now.Unix() >= intent.Intent.RecoveryDeadlineUnix {
		return resetD101RecoveryResult{}, errResetExecutionEvidence
	}
	if validateResetD101RecoverySnapshots(result, started, completed) != nil {
		return resetD101RecoveryResult{}, errResetExecutionEvidence
	}
	return result, nil
}

// Read/sign only from the fixed actual closure producer. No mutation, approval
// renewal, caller result body, invented recovery attempt, or SUCCEEDED rewrite.
func issueResetD101RecoveryResult(ctx context.Context, authoritySource resetD101PurposeAuthoritySource,
	actualSource resetD101RecoveryResultSource, operationID, intentSHA, beginSHA string, clock func() time.Time) ([]byte, string, error) {
	return issueResetD101RecoveryResultWithKeyReader(ctx, authoritySource, actualSource, operationID, intentSHA, beginSHA, clock, readResetD101SigningKey)
}

func issueResetD101RecoveryResultWithKeyReader(ctx context.Context, authoritySource resetD101PurposeAuthoritySource,
	actualSource resetD101RecoveryResultSource, operationID, intentSHA, beginSHA string, clock func() time.Time,
	readKey func(resetD101SigningKeyPins) (resetD101SigningKey, error)) ([]byte, string, error) {
	if ctx == nil || ctx.Err() != nil || authoritySource == nil || actualSource == nil || clock == nil || readKey == nil ||
		!lifecycleJobIDRe.MatchString(operationID) || !resetEvidenceSHA.MatchString(intentSHA) || !resetEvidenceSHA.MatchString(beginSHA) {
		return nil, "", errResetExecutionEvidence
	}
	authority, err := authoritySource(ctx, operationID, intentSHA)
	now := clock()
	intent, scopeErr := requireResetD101Authority(authority, resetD101PurposeGrantRequest{
		OperationID: operationID, ApprovalIntentSHA: intentSHA, Action: "RECOVERY_CLOSE"}, now)
	if err != nil || scopeErr != nil {
		return nil, "", errResetExecutionEvidence
	}
	startedMonotonic := time.Now()
	ctx, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
	defer cancel()
	observation, err := actualSource(ctx, operationID, beginSHA)
	if err != nil || ctx.Err() != nil {
		return nil, "", errResetExecutionEvidence
	}
	wire, err := json.Marshal(observation)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	if _, err = validateResetD101RecoveryResult(wire, intent, beginSHA, clock()); err != nil {
		return nil, "", err
	}
	key, err := readKey(authority.KeyPins)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	defer key.close()
	signature, err := key.sign(resetD101RecoveryResultDomain, wire)
	if err != nil || ctx.Err() != nil {
		return nil, "", errResetExecutionEvidence
	}
	finished := clock()
	if finished.Before(now) || finished.Sub(now) >= resetPreflightMaxAge || time.Since(startedMonotonic) >= resetPreflightMaxAge {
		return nil, "", errResetExecutionEvidence
	}
	if _, err := requireResetD101Authority(authority, resetD101PurposeGrantRequest{
		OperationID: operationID, ApprovalIntentSHA: intentSHA, Action: "RECOVERY_CLOSE"}, finished); err != nil {
		return nil, "", err
	}
	return wire, key.keyID + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func resetD101RecoveryUTC(value string) (time.Time, error) {
	if !regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$`).MatchString(value) {
		return time.Time{}, errResetExecutionEvidence
	}
	return resetC4UTC(value)
}
