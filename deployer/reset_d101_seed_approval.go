package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// Read-only transport of the independent host's approved raw original. The
// existing QUERY grant authenticates these facts, never authorizes seed writes.
// Seed mutation remains owned by the physical Root lease and per-command guard.
type resetD101SeedApprovalMaterial struct {
	SchemaVersion          int    `json:"schemaVersion"`
	ApprovalIntentOriginal string `json:"approvalIntentOriginalBase64url"`
	PreparePayloadOriginal string `json:"preparePayloadOriginalBase64url"`
	PurposeGrant           string `json:"purposeGrant"`
}

func (c config) readResetD101SeedApproval(ctx context.Context, op, intentSHA string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || c.d101PurposeAuthority == nil || c.d101CandidatePipeline == nil || c.lifecycleOperationStore == nil || c.operations == nil || !lifecycleJobIDRe.MatchString(op) || !resetEvidenceSHA.MatchString(intentSHA) {
		return nil, errResetExecutionEvidence
	}
	record, found := c.lifecycleOperationStore.Lookup(op)
	if !found || record.Kind != lifecycleKindReset || record.SubjectID != "pep" || record.Status != lifecycleJobRunning || record.D101IntentSHA != intentSHA {
		return nil, errResetExecutionEvidence
	}
	authority, err := c.d101PurposeAuthority(ctx, op, intentSHA)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	intent, err := requireResetD101Authority(authority, resetD101PurposeGrantRequest{OperationID: op, ApprovalIntentSHA: intentSHA, Action: "DISPATCH_INTENT"}, time.Now())
	if err != nil {
		return nil, err
	}
	planBytes, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-approvals"), op, 0)
	if err != nil {
		return nil, err
	}
	preflightBytes, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-preflights"), op, 0)
	if err != nil {
		return nil, err
	}
	refs := resetExecutionEvidenceRefs{resetD101OriginalSHA(planBytes), resetD101OriginalSHA(preflightBytes)}
	evidence, err := c.readResetExecutionEvidence(op, intent.Target, refs, record.CreatedAt)
	if err != nil || requireResetIntentPlan(intent, evidence.Plan) != nil {
		return nil, errResetExecutionEvidence
	}
	binding := resetExecutionPhaseBinding{OperationID: op, Target: intent.Target, Evidence: refs, AcceptedAtUnix: record.CreatedAt.Unix(), Phase: "prepared"}
	c.operations.mu.Lock()
	lease := c.operations.active
	c.operations.mu.Unlock()
	if c.requireResetD101WorkerLease(lease, binding) != nil || c.observeResetD101GatewayDispatch(ctx, binding, evidence) != nil {
		return nil, errResetExecutionEvidence
	}
	server, err := c.serverTargetForID("pep")
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	admission, err := newResetD101CandidateAdmission(intent, evidence, binding, server)
	if err != nil || c.d101CandidatePipeline.requireAdmission(admission, authority) != nil {
		return nil, errResetExecutionEvidence
	}
	prepare, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), op, 0)
	if err != nil || requireResetD101PrepareBody(prepare, intent, resetD101OriginalSHA(prepare)) != nil {
		return nil, errResetExecutionEvidence
	}
	grant, err := c.issueResetD101PurposeGrant(ctx, resetD101PurposeGrantRequest{OperationID: op, ApprovalIntentSHA: intentSHA, GatewayPayloadSHA: resetD101OriginalSHA(prepare), Action: "QUERY"})
	current, exists := c.lifecycleOperationStore.Lookup(op)
	if err != nil || !exists || current != record || c.requireResetD101WorkerLease(lease, binding) != nil || ctx.Err() != nil || !time.Now().Before(admission.Cutoff()) {
		return nil, errResetExecutionEvidence
	}
	return json.Marshal(resetD101SeedApprovalMaterial{1, base64.RawURLEncoding.EncodeToString(intent.originalBytes()), base64.RawURLEncoding.EncodeToString(prepare), grant})
}

var resetD101SeedApprovalSlots = make(chan struct{}, 2)

func (c config) handleResetD101SeedApproval(w http.ResponseWriter, r *http.Request, parts []string) {
	serveResetD101SeedApproval(w, r, parts, c.readResetD101SeedApproval)
}
func serveResetD101SeedApproval(w http.ResponseWriter, r *http.Request, parts []string, read func(context.Context, string, string) ([]byte, error)) {
	w.Header().Set("Cache-Control", "no-store")
	if len(parts) != 3 || !lifecycleJobIDRe.MatchString(parts[0]) || parts[1] != "seed-approval" || !resetEvidenceSHA.MatchString(parts[2]) || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.Path != "/operations/"+strings.Join(parts, "/") || r.ContentLength != 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid seed source identity"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "GET only"})
		return
	}
	select {
	case resetD101SeedApprovalSlots <- struct{}{}:
	default:
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "seed source unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	type observed struct {
		wire []byte
		err  error
	}
	completed := make(chan observed, 1)
	go func() {
		defer func() { <-resetD101SeedApprovalSlots }()
		if read == nil {
			completed <- observed{err: errResetExecutionEvidence}
			return
		}
		wire, err := read(ctx, parts[0], parts[2])
		completed <- observed{wire, err}
	}()
	select {
	case value := <-completed:
		if value.err != nil || ctx.Err() != nil || len(value.wire) == 0 || len(value.wire) > 128*1024 {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "seed source unavailable"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(value.wire)
	case <-ctx.Done():
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "seed source unavailable"})
	}
}
