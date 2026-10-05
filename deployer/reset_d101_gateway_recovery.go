package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Committed Gateway original8, read under the existing authenticated QUERY.
// This is a same-op recovery prerequisite, not another mutation grant.
type resetD101RecoveryBeginOriginal struct {
	SchemaVersion        int    `json:"schemaVersion"`
	Kind                 string `json:"kind"`
	OperationID          string `json:"operationId"`
	VerifyingRevision    string `json:"verifyingRevision"`
	LastSafeState        string `json:"lastSafeState"`
	RootResultReceiptSHA string `json:"rootResultReceiptSha256"`
	FailureCode          string `json:"failureCode"`
	RequestBodySHA       string `json:"requestBodySha256"`
}
type resetD101CommittedRecoveryBegin struct {
	original        []byte
	sha             string
	gatewayOriginal []byte
	gateway         resetD101GatewayExecution
	value           resetD101RecoveryBeginOriginal
}

func (b resetD101CommittedRecoveryBegin) Original() []byte { return append([]byte(nil), b.original...) }
func (b resetD101CommittedRecoveryBegin) SHA() string      { return b.sha }

func decodeResetD101GatewayRecoveryBegin(wire []byte, intent resetDecodedApprovalIntent, evidence resetExecutionEvidence, binding resetExecutionPhaseBinding, gatewaySHA, rootResultSHA string, now time.Time) (resetD101CommittedRecoveryBegin, error) {
	closed := resetD101CommittedRecoveryBegin{}
	var fields map[string]json.RawMessage
	if len(wire) == 0 || len(wire) > 64*1024 || decodeResetPrivateJSON(wire, &fields) != nil || len(fields) != reflect.TypeOf(resetD101GatewayExecution{}).NumField()+2 {
		return closed, errResetExecutionEvidence
	}
	var encoded, beginSHA string
	if decodeResetPrivateJSON(fields["recoveryBeginReceiptBytesBase64url"], &encoded) != nil || decodeResetPrivateJSON(fields["recoveryBeginReceiptSha256"], &beginSHA) != nil || !resetEvidenceSHA.MatchString(beginSHA) || len(encoded) > 24*1024 {
		return closed, errResetExecutionEvidence
	}
	original, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	var begin resetD101RecoveryBeginOriginal
	if err != nil || len(original) == 0 || len(original) > 16*1024 || base64.RawURLEncoding.EncodeToString(original) != encoded || resetD101OriginalSHA(original) != beginSHA || requireResetIntentShape(original, reflect.TypeOf(begin)) != nil || decodeResetPrivateJSON(original, &begin) != nil {
		return closed, errResetExecutionEvidence
	}
	delete(fields, "recoveryBeginReceiptBytesBase64url")
	delete(fields, "recoveryBeginReceiptSha256")
	executionWire, err := json.Marshal(fields)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	value, err := decodeResetD101GatewayExecution(executionWire)
	fingerprint, fpErr := resetExecutionRequestFingerprint("pep", binding.Target, binding.Evidence)
	if err != nil || fpErr != nil || value.SchemaVersion != 1 || value.ServerID != "pep" || value.State != "RECOVERY_REQUIRED" || value.OperationID != binding.OperationID || value.OperationID != intent.Intent.OperationID || value.TargetFingerprint != intent.Intent.TargetFingerprint || value.ApprovalIntentSHA != intent.SHA || value.GatewayPayloadSHA != gatewaySHA || !resetEvidenceSHA.MatchString(gatewaySHA) || !resetEvidenceSHA.MatchString(rootResultSHA) || value.InitialPublicRevision != intent.Intent.InitialPublicRevision || value.VerifyingRevision != evidence.Preflight.PublicationRevision || value.RootRequestFingerprint == nil || *value.RootRequestFingerprint != fingerprint || value.PublishedRevision != nil || value.ValidationReceiptSHA != nil || requireResetIntentPlan(intent, evidence.Plan) != nil {
		return closed, errResetExecutionEvidence
	}
	revision, revisionErr := strconv.ParseInt(begin.VerifyingRevision, 10, 64)
	if revisionErr != nil || revision <= 0 || strconv.FormatInt(revision, 10) != begin.VerifyingRevision || begin.SchemaVersion != 1 || begin.Kind != "D101_RECOVERY_BEGIN_V1" || begin.OperationID != value.OperationID || begin.VerifyingRevision != value.VerifyingRevision || begin.RootResultReceiptSHA != rootResultSHA || !resetEvidenceSHA.MatchString(begin.RequestBodySHA) {
		return closed, errResetExecutionEvidence
	}
	if begin.LastSafeState != "DISPATCH_INTENT" && begin.LastSafeState != "REMOTE_SUCCEEDED" && begin.LastSafeState != "REGISTRY_SETTLED" {
		return closed, errResetExecutionEvidence
	}
	if begin.FailureCode != "RECOVERY_REQUIRED" && begin.FailureCode != "ROOT_FAILED" && begin.FailureCode != "ROOT_CANCELLED" {
		return closed, errResetExecutionEvidence
	}
	if value.RootResultReceiptSHA == nil {
		if begin.LastSafeState != "DISPATCH_INTENT" {
			return closed, errResetExecutionEvidence
		}
	} else if *value.RootResultReceiptSHA != rootResultSHA || begin.LastSafeState == "DISPATCH_INTENT" {
		return closed, errResetExecutionEvidence
	}
	created, err := resetC4UTC(value.CreatedAtUTC)
	updated, updatedErr := resetC4UTC(value.UpdatedAtUTC)
	if err != nil || updatedErr != nil || created.Unix() < intent.Intent.WindowOpensAtUnix || updated.Before(created) || updated.After(now) || now.Unix() >= intent.Intent.RecoveryDeadlineUnix {
		return closed, errResetExecutionEvidence
	}
	return resetD101CommittedRecoveryBegin{append([]byte(nil), original...), beginSHA, append([]byte(nil), wire...), value, begin}, nil
}

// Actual signed QUERY + existing private service credential; no caller body,
// hash-only BEGIN or live journal is used as the committed recovery source.
func (c config) readResetD101GatewayRecoveryBegin(ctx context.Context, op, intentSHA string) (resetD101CommittedRecoveryBegin, error) {
	closed := resetD101CommittedRecoveryBegin{}
	if ctx == nil || ctx.Err() != nil || c.d101PurposeAuthority == nil || c.lifecycleOperationStore == nil || !lifecycleJobIDRe.MatchString(op) || !resetEvidenceSHA.MatchString(intentSHA) {
		return closed, errResetExecutionEvidence
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	record, found := c.lifecycleOperationStore.Lookup(op)
	if !found || record.Kind != lifecycleKindReset || record.SubjectID != "pep" || record.D101IntentSHA != intentSHA || (record.Status != lifecycleJobSucceeded && record.Status != lifecycleJobRecoveryRequired) {
		return closed, errResetExecutionEvidence
	}
	origin, err := url.Parse(c.defaultGatewayAPIURL())
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") || origin.RawPath != "" || origin.ForceQuery || !resetPrivateGatewayHost(origin.Hostname()) {
		return closed, errResetExecutionEvidence
	}
	authority, err := c.d101PurposeAuthority(bounded, op, intentSHA)
	intent, scopeErr := requireResetD101RecoveryAuthority(authority, op, intentSHA, time.Now())
	if err != nil || scopeErr != nil {
		return closed, errResetExecutionEvidence
	}
	rootWire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-results"), op, 0)
	rootSHA := resetD101OriginalSHA(rootWire)
	rootResult, resultErr := decodeResetD101ExecutionResult(rootWire, rootSHA)
	if err != nil || resultErr != nil {
		return closed, errResetExecutionEvidence
	}
	refs := resetExecutionEvidenceRefs{rootResult.ApprovalPlanSHA, rootResult.ExecutionReceiptSHA}
	evidence, err := c.readResetExecutionEvidence(op, intent.Target, refs, record.CreatedAt)
	if err != nil || requireResetD101ResultBinding(rootResult, intent, evidence.Plan, evidence.Preflight, record, time.Now()) != nil {
		return closed, errResetExecutionEvidence
	}
	prepare, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), op, 0)
	gatewaySHA := resetD101OriginalSHA(prepare)
	if err != nil || requireResetD101PrepareBody(prepare, intent, gatewaySHA) != nil || rootResult.GatewayPayloadSHA != gatewaySHA {
		return closed, errResetExecutionEvidence
	}
	credentialWire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-gateway"), op, 0)
	var credential resetD101GatewayCredential
	if err != nil || requireResetIntentShape(credentialWire, reflect.TypeOf(credential)) != nil || decodeResetPrivateJSON(credentialWire, &credential) != nil || credential.Version != 1 || credential.OperationID != op || credential.ApprovalIntentSHA != intentSHA || credential.TargetFingerprint != intent.Intent.TargetFingerprint || credential.ExpiresAtUnix <= time.Now().Unix() || !validResetD101ServiceToken(credential.ServiceToken) {
		return closed, errResetExecutionEvidence
	}
	grant, err := c.issueResetD101PurposeGrant(bounded, resetD101PurposeGrantRequest{OperationID: op, ApprovalIntentSHA: intentSHA, GatewayPayloadSHA: gatewaySHA, Action: "QUERY"})
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	endpoint := strings.TrimRight(origin.String(), "/") + "/internal/d101/servers/pep/operations/" + op
	wire, cache, err := readResetD101GatewayQuery(bounded, endpoint, credential.ServiceToken, grant, 64*1024)
	binding := resetExecutionPhaseBinding{OperationID: op, Target: intent.Target, Evidence: refs, AcceptedAtUnix: record.CreatedAt.Unix(), Phase: "prepared"}
	observed, decodeErr := decodeResetD101GatewayRecoveryBegin(wire, intent, evidence, binding, gatewaySHA, rootSHA, time.Now())
	if err != nil || cache != "no-store" || decodeErr != nil {
		return closed, errResetExecutionEvidence
	}
	expectedFailure := "RECOVERY_REQUIRED"
	if rootResult.Status == string(lifecycleJobFailed) {
		expectedFailure = "ROOT_FAILED"
	} else if rootResult.Status == string(lifecycleJobCancelled) {
		expectedFailure = "ROOT_CANCELLED"
	}
	if observed.value.FailureCode != expectedFailure {
		return closed, errResetExecutionEvidence
	}
	rootAfter, rootErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-results"), op, 0)
	credentialAfter, credentialErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-gateway"), op, 0)
	current, exists := c.lifecycleOperationStore.Lookup(op)
	if rootErr != nil || credentialErr != nil || !bytes.Equal(rootWire, rootAfter) || !bytes.Equal(credentialWire, credentialAfter) || !exists || current != record || bounded.Err() != nil || credential.ExpiresAtUnix <= time.Now().Unix() {
		return closed, errResetExecutionEvidence
	}
	if _, err := requireResetD101RecoveryAuthority(authority, op, intentSHA, time.Now()); err != nil {
		return closed, errResetExecutionEvidence
	}
	return observed, nil
}
