package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// Fixed actual restore1 installation only, never a request result or env flag.
// Arguments are the operation and immutable closure SHA. Its producer must
// verify committed BEGIN, the exclusive claim and actual restore observations.
type resetD101RecoveryClosureReader func(context.Context, string, string) ([]byte, error)

func (c config) readResetD101RecoveryResult(ctx context.Context, op, expectedSHA string) ([]byte, string, error) {
	if ctx == nil || ctx.Err() != nil || c.d101RecoveryClosureReader == nil || c.d101RetainedRecovery == nil || c.lifecycleOperationStore == nil || !lifecycleJobIDRe.MatchString(op) || !resetEvidenceSHA.MatchString(expectedSHA) {
		return nil, "", errResetExecutionEvidence
	}
	record, found := c.lifecycleOperationStore.Lookup(op)
	if !found || record.Kind != lifecycleKindReset || record.SubjectID != "pep" || !resetEvidenceSHA.MatchString(record.D101IntentSHA) || (record.Status != lifecycleJobSucceeded && record.Status != lifecycleJobRecoveryRequired) {
		return nil, "", errResetExecutionEvidence
	}
	original, err := c.d101RecoveryClosureReader(ctx, op, expectedSHA)
	if err != nil || len(original) == 0 || len(original) > 16*1024 || ctx.Err() != nil {
		return nil, "", errResetExecutionEvidence
	}
	wire := append([]byte(nil), original...)
	var closure resetD101RecoveryResult
	if err != nil || len(wire) == 0 || len(wire) > 16*1024 || resetD101OriginalSHA(wire) != expectedSHA || requireResetIntentShape(wire, reflect.TypeOf(closure)) != nil || decodeResetPrivateJSON(wire, &closure) != nil || closure.OperationID != op || closure.ApprovalIntentSHA != record.D101IntentSHA {
		return nil, "", errResetExecutionEvidence
	}
	// Preserve and bind the original Root RESULT even after an actual successful
	// reset has finished and its live journal no longer exists. No status update,
	// fresh runtime interpretation or regeneration of that RESULT is performed.
	rootWire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-results"), op, 0)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	rootResult, err := decodeResetD101ExecutionResult(rootWire, closure.OriginalRootResultSHA)
	if err != nil || rootResult.OperationID != op || rootResult.ApprovalIntentSHA != record.D101IntentSHA || rootResult.VerifyingRevision != closure.VerifyingRevision || rootResult.GatewayPayloadSHA != closure.GatewayPayloadSHA || rootResult.TargetFingerprint != closure.TargetFingerprint {
		return nil, "", errResetExecutionEvidence
	}
	authority, err := c.resetD101RecoveryAuthority(ctx, op, record.D101IntentSHA, "QUERY")
	intent, scopeErr := requireResetD101RecoveryAuthority(authority, op, record.D101IntentSHA, time.Now())
	if err != nil || scopeErr != nil {
		return nil, "", errResetExecutionEvidence
	}
	var plan resetApprovalPlan
	var preflight resetPreflightReceipt
	if readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-approvals"), op, rootResult.ApprovalPlanSHA, 0, &plan) != nil || readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-preflights"), op, rootResult.ExecutionReceiptSHA, 0, &preflight) != nil || requireResetD101ResultBinding(rootResult, intent, plan, preflight, record, time.Now()) != nil || closure.BackupManifestSHA != preflight.BackupManifestSHA {
		return nil, "", errResetExecutionEvidence
	}
	evidence := resetExecutionEvidence{plan, preflight}
	if c.requireResetD101RecoveryPreSQL(ctx, record, evidence, intent, closure, 0) != nil {
		return nil, "", errResetExecutionEvidence
	}
	prepare, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), op, 0)
	if err != nil || requireResetD101PrepareBody(prepare, intent, closure.GatewayPayloadSHA) != nil {
		return nil, "", errResetExecutionEvidence
	}
	frozen := func(ctx context.Context, requestedOp, requestedBegin string) ([]byte, error) {
		if requestedOp != op || requestedBegin != closure.RecoveryBeginReceiptSHA || c.requireResetD101RecoveryPreSQL(ctx, record, evidence, intent, closure, 0) != nil {
			return nil, errResetExecutionEvidence
		}
		return append([]byte(nil), wire...), nil
	}
	closeAuthority := func(call context.Context, requestedOp, requestedIntent string) (resetD101VerifiedPurposeAuthority, error) {
		return c.resetD101RecoveryAuthority(call, requestedOp, requestedIntent, "RECOVERY_CLOSE")
	}
	signed, proof, err := issueResetD101RecoveryResultOriginalWithKeyReader(ctx, closeAuthority, frozen, op, record.D101IntentSHA, closure.RecoveryBeginReceiptSHA, time.Now, readResetD101SigningKey)
	after, afterErr := c.d101RecoveryClosureReader(ctx, op, expectedSHA)
	rootAfter, rootErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-results"), op, 0)
	current, exists := c.lifecycleOperationStore.Lookup(op)
	if err != nil || afterErr != nil || rootErr != nil || ctx.Err() != nil || !exists || current != record || !bytes.Equal(after, wire) || !bytes.Equal(rootAfter, rootWire) {
		return nil, "", errResetExecutionEvidence
	}
	if c.requireResetD101RecoveryPreSQL(ctx, record, evidence, intent, closure, 0) != nil {
		return nil, "", errResetExecutionEvidence
	}
	return signed, proof, nil
}

var resetD101RecoveryResultSlots = make(chan struct{}, 2)

func (c config) handleResetD101RecoveryResult(w http.ResponseWriter, r *http.Request, parts []string) {
	serveResetD101RecoveryResult(w, r, parts, c.readResetD101RecoveryResult)
}
func serveResetD101RecoveryResult(w http.ResponseWriter, r *http.Request, parts []string, read func(context.Context, string, string) ([]byte, string, error)) {
	w.Header().Set("Cache-Control", "no-store")
	if len(parts) != 3 || !lifecycleJobIDRe.MatchString(parts[0]) || parts[1] != "recovery-result" || !resetEvidenceSHA.MatchString(parts[2]) || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.Path != "/operations/"+strings.Join(parts, "/") || r.ContentLength != 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid recovery result identity"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "GET only"})
		return
	}
	select {
	case resetD101RecoveryResultSlots <- struct{}{}:
	default:
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "recovery result unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	type observed struct {
		wire  []byte
		proof string
		err   error
	}
	completed := make(chan observed, 1)
	go func() {
		// An uncancellable source keeps its slot; HTTP timeouts cannot grow readers.
		defer func() { <-resetD101RecoveryResultSlots }()
		if read == nil {
			completed <- observed{err: errResetExecutionEvidence}
			return
		}
		wire, proof, err := read(ctx, parts[0], parts[2])
		completed <- observed{wire, proof, err}
	}()
	select {
	case value := <-completed:
		proof := strings.Split(value.proof, ".")
		valid := len(proof) == 2 && resetD101KeyID.MatchString(proof[0])
		if valid {
			signature, err := base64.RawURLEncoding.Strict().DecodeString(proof[1])
			valid = err == nil && len(signature) == 64 && base64.RawURLEncoding.EncodeToString(signature) == proof[1]
		}
		if value.err != nil || ctx.Err() != nil || len(value.wire) == 0 || len(value.wire) > 16*1024 || resetD101OriginalSHA(value.wire) != parts[2] || !valid {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "recovery result unavailable"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-D101-Result-Proof", value.proof)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(value.wire)
	case <-ctx.Done():
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "recovery result unavailable"})
	}
}
