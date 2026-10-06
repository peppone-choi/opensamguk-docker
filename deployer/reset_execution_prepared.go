package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// This receipt describes one actual preparation. It grants no physical phase,
// changes no deadline and cannot replace the independently approved intent.
type resetD101PreparedProof struct {
	SchemaVersion          int               `json:"schemaVersion"`
	ServerID               string            `json:"serverId"`
	WorldID                int               `json:"worldId"`
	OperationID            string            `json:"operationId"`
	Phase                  string            `json:"phase"`
	ApprovalIntentSHA      string            `json:"approvalIntentSha256"`
	ApprovalPlanSHA        string            `json:"approvalPlanSha256"`
	ExecutionReceiptSHA    string            `json:"executionReceiptSha256"`
	TargetFingerprint      string            `json:"targetFingerprint"`
	RootRequestFingerprint string            `json:"rootRequestFingerprint"`
	GatewayPayloadSHA      string            `json:"gatewayPayloadSha256"`
	InitialPublicRevision  string            `json:"initialPublicRevision"`
	VerifyingRevision      string            `json:"verifyingRevision"`
	AppSourceSHA           string            `json:"appSourceSha"`
	ImageDigests           map[string]string `json:"imageDigests"`
	AcceptedAtUTC          string            `json:"acceptedAtUtc"`
	PreparedAtUTC          string            `json:"preparedAtUtc"`
	PreparedJournalSHA     string            `json:"preparedJournalSha256"`
	DestructiveCutoffUnix  int64             `json:"destructiveCutoffUnix"`
	RecoveryDeadlineUnix   int64             `json:"recoveryDeadlineUnix"`
}

func decodeResetD101PreparedProof(wire []byte) (resetD101PreparedProof, error) {
	var proof resetD101PreparedProof
	if len(wire) == 0 || len(wire) > resetD101ResultMaxBytes || requireResetIntentShape(wire, reflect.TypeOf(proof)) != nil ||
		decodeResetPrivateJSON(wire, &proof) != nil || proof.SchemaVersion != 1 || proof.ServerID != "pep" || proof.WorldID != 1 ||
		!lifecycleJobIDRe.MatchString(proof.OperationID) || proof.Phase != "prepared" || !gitSHA40.MatchString(proof.AppSourceSHA) ||
		!validResetFiveImageDigests(proof.ImageDigests) {
		return resetD101PreparedProof{}, errResetExecutionEvidence
	}
	for _, sha := range []string{proof.ApprovalIntentSHA, proof.ApprovalPlanSHA, proof.ExecutionReceiptSHA, proof.TargetFingerprint,
		proof.RootRequestFingerprint, proof.GatewayPayloadSHA, proof.PreparedJournalSHA} {
		if !resetEvidenceSHA.MatchString(sha) {
			return resetD101PreparedProof{}, errResetExecutionEvidence
		}
	}
	r, err := strconv.ParseInt(proof.InitialPublicRevision, 10, 64)
	v, vErr := strconv.ParseInt(proof.VerifyingRevision, 10, 64)
	a, aErr := resetC4UTC(proof.AcceptedAtUTC)
	p, pErr := resetC4UTC(proof.PreparedAtUTC)
	if err != nil || vErr != nil || r <= 0 || v <= r || strconv.FormatInt(r, 10) != proof.InitialPublicRevision ||
		strconv.FormatInt(v, 10) != proof.VerifyingRevision || aErr != nil || pErr != nil || p.Before(a) ||
		proof.DestructiveCutoffUnix <= p.Unix() || proof.RecoveryDeadlineUnix <= proof.DestructiveCutoffUnix {
		return resetD101PreparedProof{}, errResetExecutionEvidence
	}
	return proof, nil
}

// The caller already read actual immutable authority and evidence. Reserve is
// serialized with the published preparation; its first timestamp is never supplied
// by an HTTP caller. A committed but uncertain reservation remains pinned.
func (c config) reserveResetD101FirstAdmission(p *operationPreparation, target resetLifecycleTarget, refs resetExecutionEvidenceRefs, intentSHA string) (durableOperationRecord, bool, error) {
	fp, err := resetExecutionRequestFingerprint("pep", target, refs)
	if err != nil || p == nil || c.operations == nil || p.coordinator != c.operations || p.ctx == nil || p.Context().Err() != nil ||
		p.kind != lifecycleKindReset || p.subjectID != "pep" || p.fingerprint != fp || p.admissionErr != nil ||
		!lifecycleJobIDRe.MatchString(p.operationID) || !resetEvidenceSHA.MatchString(intentSHA) || c.lifecycleOperationStore == nil {
		return durableOperationRecord{}, false, errResetExecutionEvidence
	}
	coordinator := c.operations
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	lease := coordinator.maintenanceLease
	if !coordinator.closed || coordinator.preparing != p || coordinator.active != nil || coordinator.journalPending ||
		coordinator.preparationSettlementPending || p.Context().Err() != nil || lease == nil || lease.consumed || !secureEqual(lease.token, p.leaseAttempt) ||
		(lease.operationID != "" && lease.operationID != p.operationID) || stateFilePresent(c.lifecycleJournalFile) {
		return durableOperationRecord{}, false, errResetExecutionEvidence
	}
	want := durableOperationRecord{OperationID: p.operationID, Kind: lifecycleKindReset, SubjectID: "pep", RequestFingerprint: fp,
		Status: lifecycleJobPending, HTTPStatus: http.StatusAccepted, D101IntentSHA: intentSHA}
	record, replay, reserveErr := c.lifecycleOperationStore.Reserve(want)
	if reserveErr != nil {
		// Lookup can acknowledge a rename which committed before directory sync
		// failed. Never create a second operation or restart its preparation.
		if committed, exists := c.lifecycleOperationStore.Lookup(p.operationID); exists && committed.Kind == want.Kind &&
			committed.SubjectID == want.SubjectID && committed.RequestFingerprint == fp && committed.D101IntentSHA == intentSHA {
			lease.operationID = p.operationID
		}
		return durableOperationRecord{}, false, reserveErr
	}
	lease.operationID = p.operationID
	if record.Status != lifecycleJobPending || record.CreatedAt.IsZero() || !record.CreatedAt.Equal(record.UpdatedAt) {
		return durableOperationRecord{}, replay, errResetExecutionEvidence
	}
	return record, replay, nil
}

func (c config) requireResetD101Preparation(record durableOperationRecord) error {
	if c.operations == nil || c.lifecycleOperationStore == nil {
		return errResetExecutionEvidence
	}
	c.operations.mu.Lock()
	defer c.operations.mu.Unlock()
	p, lease := c.operations.preparing, c.operations.maintenanceLease
	if p == nil || p.coordinator != c.operations || p.ctx == nil || p.Context().Err() != nil || p.admissionErr != nil ||
		!c.operations.closed || c.operations.active != nil || c.operations.journalPending || c.operations.preparationSettlementPending ||
		lease == nil || lease.consumed || lease.operationID != record.OperationID || !secureEqual(lease.token, p.leaseAttempt) ||
		p.operationID != record.OperationID || p.kind != lifecycleKindReset || p.subjectID != "pep" || p.fingerprint != record.RequestFingerprint ||
		record.Kind != lifecycleKindReset || record.SubjectID != "pep" || record.Status != lifecycleJobPending || record.D101IntentSHA == "" {
		return errResetExecutionEvidence
	}
	current, found := c.lifecycleOperationStore.Lookup(record.OperationID)
	if !found || current != record {
		return errResetExecutionEvidence
	}
	return nil
}

// Root first admission and actual PREPARED precede Gateway dispatch. No pull,
// env write, journal advancement, down or up is permitted in this method.
func (c config) prepareResetD101Execution(p *operationPreparation, target resetLifecycleTarget, refs resetExecutionEvidenceRefs, source resetExecutionPhaseSource) (resetExecutionPhaseBinding, string, error) {
	var empty resetExecutionPhaseBinding
	if p == nil || p.ctx == nil || source == nil || c.d101PurposeAuthority == nil {
		return empty, "", errResetExecutionEvidence
	}
	admittedAt := time.Now()
	if c.lifecycleOperationStore != nil {
		if existing, found := c.lifecycleOperationStore.Lookup(p.operationID); found {
			admittedAt = existing.CreatedAt
		}
	}
	evidence, err := c.readResetExecutionEvidence(p.operationID, target, refs, admittedAt)
	if err != nil || evidence.Plan.ApprovalIntentSHA == "" || c.requireResetD101WorkerAuthority(p.Context(), evidence, evidence.Plan.ApprovalIntentSHA) != nil {
		return empty, "", errResetExecutionEvidence
	}
	record, replay, err := c.reserveResetD101FirstAdmission(p, target, refs, evidence.Plan.ApprovalIntentSHA)
	if err != nil {
		return empty, "", err
	}
	binding := resetExecutionPhaseBinding{OperationID: record.OperationID, Target: target, Evidence: refs, AcceptedAtUnix: record.CreatedAt.Unix(), Phase: "prepared"}
	if replay {
		// A failed first observation/commit is not rerun. Only the exact persisted
		// evidence may be read, inside its original freshness and cutoff.
		wire, _, err := c.readResetD101PreparedPhase(binding, record, evidence, 0)
		if err != nil || c.requireResetD101Preparation(record) != nil {
			return empty, "", errResetExecutionEvidence
		}
		proof, _ := decodeResetD101PreparedProof(wire)
		prepared, _ := resetC4UTC(proof.PreparedAtUTC)
		if time.Since(prepared) < 0 || time.Since(prepared) >= resetPreflightMaxAge {
			return empty, "", errResetExecutionEvidence
		}
		return binding, resetD101OriginalSHA(wire), nil
	}
	attestation, err := c.observeResetExecutionPhase(p.Context(), binding, source)
	if err != nil {
		return empty, "", err
	}
	chain, err := newResetExecutionJournal(binding, attestation)
	if err != nil || c.requireResetD101Preparation(record) != nil {
		return empty, "", errResetExecutionEvidence
	}
	sha, err := c.persistResetD101PreparedPhase(p.Context(), record, evidence, chain, 0)
	if err != nil {
		return empty, "", err
	}
	return binding, sha, nil
}

// UID injection is for isolated custody fixtures only, never configuration/input.
func (c config) persistResetD101PreparedPhase(ctx context.Context, record durableOperationRecord, evidence resetExecutionEvidence, chain resetExecutionJournal, uid uint32) (string, error) {
	if ctx == nil || ctx.Err() != nil || c.d101PurposeAuthority == nil || c.requireResetD101Preparation(record) != nil ||
		len(chain.Attestations) != 1 || validateResetExecutionJournal(chain, record.OperationID, evidence.Plan.Target) != nil ||
		chain.AcceptedAtUnix != record.CreatedAt.Unix() || chain.RequestFingerprint != record.RequestFingerprint ||
		chain.Evidence.ApprovalPlanSHA != evidence.Preflight.ApprovalPlanSHA {
		return "", errResetExecutionEvidence
	}
	authority, err := c.d101PurposeAuthority(ctx, record.OperationID, record.D101IntentSHA)
	request := resetD101PurposeGrantRequest{OperationID: record.OperationID, ApprovalIntentSHA: record.D101IntentSHA, Action: "DISPATCH_INTENT"}
	if err != nil {
		return "", errResetExecutionEvidence
	}
	intent, err := requireResetD101Authority(authority, request, time.Now())
	prepare, prepareErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), record.OperationID, uid)
	if err != nil || prepareErr != nil || requireResetIntentPlan(intent, evidence.Plan) != nil ||
		requireResetD101PrepareBody(prepare, intent, resetD101OriginalSHA(prepare)) != nil {
		return "", errResetExecutionEvidence
	}
	journalWire, err := json.Marshal(chain)
	if err != nil {
		return "", errResetExecutionEvidence
	}
	proof := resetD101PreparedProof{1, "pep", 1, record.OperationID, "prepared", record.D101IntentSHA, chain.Evidence.ApprovalPlanSHA,
		chain.Evidence.ExecutionReceiptSHA, evidence.Plan.TargetFingerprint, record.RequestFingerprint, resetD101OriginalSHA(prepare),
		intent.Intent.InitialPublicRevision, evidence.Preflight.PublicationRevision, evidence.Plan.AppSourceSHA, evidence.Plan.NewImageDigests,
		record.CreatedAt.UTC().Format(time.RFC3339Nano), chain.Attestations[0].Snapshot.ObservedAt.UTC().Format(time.RFC3339Nano),
		resetD101OriginalSHA(journalWire), evidence.Plan.DestructiveCutoffUnix, evidence.Plan.RecoveryDeadlineUnix}
	wire, err := json.Marshal(proof)
	if err != nil || requireResetD101PreparedBinding(proof, chain, intent, evidence, record, time.Now()) != nil {
		return "", errResetExecutionEvidence
	}
	if _, err := decodeResetD101PreparedProof(wire); err != nil {
		return "", err
	}
	if writeResetImmutablePrivateBytesWithUID(filepath.Join(c.serversDir, ".deployer-reset-prepared-phases"), record.OperationID, proof.PreparedJournalSHA, journalWire, uid) != nil ||
		ctx.Err() != nil || c.requireResetD101Preparation(record) != nil ||
		writeResetImmutablePrivateBytesWithUID(filepath.Join(c.serversDir, ".deployer-reset-prepared-proofs"), record.OperationID, resetD101OriginalSHA(wire), wire, uid) != nil {
		return "", errResetExecutionEvidence
	}
	if _, err := requireResetD101Authority(authority, request, time.Now()); err != nil || ctx.Err() != nil || c.requireResetD101Preparation(record) != nil {
		return "", errResetExecutionEvidence
	}
	return resetD101OriginalSHA(wire), nil
}

func requireResetD101PreparedBinding(proof resetD101PreparedProof, chain resetExecutionJournal, intent resetDecodedApprovalIntent, evidence resetExecutionEvidence, record durableOperationRecord, now time.Time) error {
	accepted, err := resetC4UTC(proof.AcceptedAtUTC)
	prepared, pErr := resetC4UTC(proof.PreparedAtUTC)
	if err != nil || pErr != nil || len(chain.Attestations) != 1 || validateResetExecutionJournal(chain, record.OperationID, evidence.Plan.Target) != nil ||
		chain.AcceptedAtUnix != record.CreatedAt.Unix() || chain.RequestFingerprint != record.RequestFingerprint ||
		!accepted.Equal(record.CreatedAt) || !prepared.Equal(chain.Attestations[0].Snapshot.ObservedAt) || prepared.After(now) ||
		chain.Attestations[0].StartedAt.Before(record.CreatedAt) ||
		record.Kind != lifecycleKindReset || record.SubjectID != "pep" || record.D101IntentSHA != intent.SHA ||
		proof.OperationID != record.OperationID || proof.ApprovalIntentSHA != record.D101IntentSHA ||
		proof.RootRequestFingerprint != record.RequestFingerprint || proof.TargetFingerprint != evidence.Plan.TargetFingerprint ||
		proof.InitialPublicRevision != intent.Intent.InitialPublicRevision || proof.VerifyingRevision != evidence.Preflight.PublicationRevision ||
		proof.AppSourceSHA != evidence.Plan.AppSourceSHA || !reflect.DeepEqual(proof.ImageDigests, evidence.Plan.NewImageDigests) ||
		proof.ApprovalPlanSHA != chain.Evidence.ApprovalPlanSHA || proof.ExecutionReceiptSHA != chain.Evidence.ExecutionReceiptSHA ||
		evidence.Preflight.ApprovalPlanSHA != proof.ApprovalPlanSHA || requireResetIntentPlan(intent, evidence.Plan) != nil ||
		proof.DestructiveCutoffUnix != evidence.Plan.DestructiveCutoffUnix || proof.RecoveryDeadlineUnix != evidence.Plan.RecoveryDeadlineUnix ||
		chain.Attestations[0].Snapshot.PublicationRevision != proof.VerifyingRevision ||
		chain.Attestations[0].Snapshot.WriterFreezeReceiptSHA != evidence.Plan.WriterFreezeReceiptSHA ||
		evidence.Preflight.FilesystemDevice == nil || chain.Attestations[0].Space.Device != *evidence.Preflight.FilesystemDevice {
		return errResetExecutionEvidence
	}
	return nil
}

func (c config) readResetD101PreparedPhase(binding resetExecutionPhaseBinding, record durableOperationRecord, evidence resetExecutionEvidence, uid uint32) ([]byte, resetExecutionJournal, error) {
	var chain resetExecutionJournal
	wire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepared-proofs"), binding.OperationID, uid)
	proof, decodeErr := decodeResetD101PreparedProof(wire)
	intentWire, intentErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-intents"), binding.OperationID, uid)
	intent, intentDecodeErr := decodeResetApprovalIntent(intentWire, record.D101IntentSHA)
	prepare, prepareErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), binding.OperationID, uid)
	if err != nil || decodeErr != nil || intentErr != nil || intentDecodeErr != nil || prepareErr != nil ||
		binding.Phase != "prepared" || binding.PreviousAttestationSHA != "" || record.CreatedAt.Unix() != binding.AcceptedAtUnix ||
		binding.Evidence != (resetExecutionEvidenceRefs{proof.ApprovalPlanSHA, proof.ExecutionReceiptSHA}) || !reflect.DeepEqual(binding.Target, evidence.Plan.Target) ||
		requireResetD101PrepareBody(prepare, intent, proof.GatewayPayloadSHA) != nil ||
		readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-prepared-phases"), binding.OperationID, proof.PreparedJournalSHA, uid, &chain) != nil ||
		requireResetD101PreparedBinding(proof, chain, intent, evidence, record, time.Now()) != nil {
		return nil, resetExecutionJournal{}, errResetExecutionEvidence
	}
	return wire, chain, nil
}

// Minted only after the production reader's authority, native original,
// persisted admission and whole phase binding checks. No raw-only constructor
// or request-selected domain exists. All parsed values belong to this read.
type resetD101PreparedSigningInput struct {
	original    []byte
	originalSHA string
	proof       resetD101PreparedProof
	authority   resetD101VerifiedPurposeAuthority
	request     resetD101PurposeGrantRequest
	chain       resetExecutionJournal
	evidence    resetExecutionEvidence
	record      durableOperationRecord
	validatedAt time.Time
}

func (c config) readResetD101PreparedProof(ctx context.Context, op, planSHA, preflightSHA string) ([]byte, string, error) {
	if ctx == nil || ctx.Err() != nil || c.d101PurposeAuthority == nil || c.lifecycleOperationStore == nil {
		return nil, "", errResetExecutionEvidence
	}
	record, found := c.lifecycleOperationStore.Lookup(op)
	if !found || c.requireResetD101Preparation(record) != nil {
		return nil, "", errResetExecutionEvidence
	}
	authority, err := c.d101PurposeAuthority(ctx, op, record.D101IntentSHA)
	request := resetD101PurposeGrantRequest{OperationID: op, ApprovalIntentSHA: record.D101IntentSHA, Action: "DISPATCH_INTENT"}
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	intent, err := requireResetD101Authority(authority, request, time.Now())
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	evidence, err := c.readResetExecutionEvidence(op, intent.Target, resetExecutionEvidenceRefs{planSHA, preflightSHA}, record.CreatedAt)
	if err != nil || validateResetApprovalPlan(evidence.Plan, op, intent.Target, time.Now()) != nil {
		return nil, "", errResetExecutionEvidence
	}
	binding := resetExecutionPhaseBinding{OperationID: op, Target: evidence.Plan.Target, Evidence: resetExecutionEvidenceRefs{planSHA, preflightSHA}, AcceptedAtUnix: record.CreatedAt.Unix(), Phase: "prepared"}
	wire, chain, err := c.readResetD101PreparedPhase(binding, record, evidence, 0)
	proof, _ := decodeResetD101PreparedProof(wire)
	prepared, pErr := resetC4UTC(proof.PreparedAtUTC)
	if err != nil || pErr != nil || ctx.Err() != nil || c.requireResetD101Preparation(record) != nil ||
		time.Since(prepared) < 0 || time.Since(prepared) >= resetPreflightMaxAge {
		return nil, "", errResetExecutionEvidence
	}
	key, err := readResetD101SigningKey(authority.KeyPins)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	defer key.close()
	input := &resetD101PreparedSigningInput{original: append([]byte(nil), wire...), originalSHA: resetD101OriginalSHA(wire), proof: proof,
		authority: authority, request: request, chain: chain, evidence: evidence, record: record, validatedAt: time.Now()}
	signature, err := key.signPrepared(ctx, input)
	if err != nil || ctx.Err() != nil || c.requireResetD101Preparation(record) != nil || time.Since(prepared) >= resetPreflightMaxAge {
		return nil, "", errResetExecutionEvidence
	}
	if _, err := requireResetD101Authority(authority, request, time.Now()); err != nil {
		return nil, "", errResetExecutionEvidence
	}
	return input.original, key.keyID + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func isResetD101PreparedPath(path string) bool { return strings.Contains(path, "/prepared-proof/") }

// Activation is distinct from preparation. Only the actual Gateway dispatch
// record allows this same preparation to consume its lease and start one worker.
// This helper is not exposed by a request-selectable source or legacy reset route.
func (c config) startResetD101PreparedWorker(p *operationPreparation, binding resetExecutionPhaseBinding, source resetExecutionPhaseSource) (string, error) {
	if p == nil || p.ctx == nil || source == nil || c.lifecycleJobs == nil || c.lifecycleOperationStore == nil ||
		p.operationID != binding.OperationID || binding.Phase != "prepared" || binding.PreviousAttestationSHA != "" {
		return "", errResetExecutionEvidence
	}
	record, found := c.lifecycleOperationStore.Lookup(binding.OperationID)
	if !found || record.CreatedAt.Unix() != binding.AcceptedAtUnix || c.requireResetD101Preparation(record) != nil {
		return "", errResetExecutionEvidence
	}
	evidence, err := c.readResetExecutionEvidence(binding.OperationID, binding.Target, binding.Evidence, record.CreatedAt)
	if err != nil || c.requireResetD101WorkerAuthority(p.Context(), evidence, record.D101IntentSHA) != nil {
		return "", errResetExecutionEvidence
	}
	if _, _, err := c.readResetD101PreparedPhase(binding, record, evidence, 0); err != nil {
		return "", err
	}
	if err := c.observeResetD101GatewayDispatch(p.Context(), binding, evidence); err != nil {
		return "", err
	}
	target, err := c.serverTargetForID("pep")
	if err != nil || c.requireResetD101Preparation(record) != nil {
		return "", errResetExecutionEvidence
	}
	jobID, replay, err := c.lifecycleJobs.reserveWithOperation(record.OperationID, record.RequestFingerprint, lifecycleKindReset)
	if err != nil {
		return "", err
	}
	if replay {
		return "", errResetExecutionEvidence
	}
	c.lifecycleJobs.bindOperationSubject(jobID, lifecycleKindReset, "pep")
	lease, err := c.beginPreparedLifecycle(p, jobID)
	if err != nil {
		c.lifecycleJobs.discard(jobID)
		return "", err
	}
	if err := c.startClaimedDurableLifecycleJob(lease, jobID, "D101 reset pep", record.OperationID, lifecycleKindReset, func(context.Context) (string, error) {
		return c.runResetD101PhysicalWorker(lease, target, binding, source)
	}); err != nil {
		// The lease is consumed even when RUNNING persistence is uncertain.
		// Keep admission closed for explicit settlement, never launch a retry.
		c.operations.markPreparationSettlementPending()
		lease.Done()
		return "", err
	}
	return jobID, nil
}

func (c config) handleResetD101PreparedProof(w http.ResponseWriter, r *http.Request, parts []string) {
	serveResetD101PreparedProof(w, r, parts, c.readResetD101PreparedProof)
}

func serveResetD101PreparedProof(w http.ResponseWriter, r *http.Request, parts []string, read func(context.Context, string, string, string) ([]byte, string, error)) {
	w.Header().Set("Cache-Control", "no-store")
	if len(parts) != 4 || !lifecycleJobIDRe.MatchString(parts[0]) || parts[1] != "prepared-proof" ||
		!resetEvidenceSHA.MatchString(parts[2]) || !resetEvidenceSHA.MatchString(parts[3]) || r.URL.RawQuery != "" ||
		r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Path != "/operations/"+strings.Join(parts, "/") || r.ContentLength != 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid prepared identity"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "GET only"})
		return
	}
	select {
	case resetD101ResultReadSlots <- struct{}{}:
	default:
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "prepared proof unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	type observation struct {
		wire  []byte
		proof string
		err   error
	}
	completed := make(chan observation, 1)
	go func() {
		defer func() { <-resetD101ResultReadSlots }()
		if read == nil {
			completed <- observation{err: errResetExecutionEvidence}
			return
		}
		wire, proof, err := read(ctx, parts[0], parts[2], parts[3])
		completed <- observation{wire, proof, err}
	}()
	var observed observation
	select {
	case observed = <-completed:
	case <-ctx.Done():
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "prepared proof unavailable"})
		return
	}
	proof, err := decodeResetD101PreparedProof(observed.wire)
	proofParts := strings.Split(observed.proof, ".")
	valid := len(proofParts) == 2 && resetD101KeyID.MatchString(proofParts[0])
	if valid {
		signature, err := base64.RawURLEncoding.Strict().DecodeString(proofParts[1])
		valid = err == nil && len(signature) == 64 && base64.RawURLEncoding.EncodeToString(signature) == proofParts[1]
	}
	if observed.err != nil || ctx.Err() != nil || err != nil || !valid || proof.OperationID != parts[0] || proof.ApprovalPlanSHA != parts[2] || proof.ExecutionReceiptSHA != parts[3] {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "prepared proof unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-D101-Prepared-Proof", observed.proof)
	w.Header().Set("X-D101-Prepared-Sha256", resetD101OriginalSHA(observed.wire))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(observed.wire)
}
