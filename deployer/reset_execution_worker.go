package main

import (
	"context"
	"time"
)

// A physical worker belongs to the already-promoted, consumed maintenance lease
// and first durable admission. A helper call or retained receipt cannot acquire
// execution authority. The ingress/coordinator provider remains a separate gate.
func (c config) requireResetD101WorkerLease(lease *operationLease, binding resetExecutionPhaseBinding) error {
	if lease == nil || lease.coordinator == nil || lease.coordinator != c.operations || lease.ctx == nil || lease.Context().Err() != nil || c.lifecycleOperationStore == nil {
		return errResetExecutionEvidence
	}
	record, found := c.lifecycleOperationStore.Lookup(binding.OperationID)
	fingerprint, err := resetExecutionRequestFingerprint("pep", binding.Target, binding.Evidence)
	if err != nil || !found || record.Kind != lifecycleKindReset || record.SubjectID != "pep" || record.Status != lifecycleJobRunning ||
		record.D101IntentSHA == "" || record.RequestFingerprint != fingerprint || record.CreatedAt.Unix() != binding.AcceptedAtUnix {
		return errResetExecutionEvidence
	}
	coordinator := lease.coordinator
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	admission := coordinator.maintenanceLease
	if !coordinator.closed || coordinator.active != lease || admission == nil || !admission.consumed ||
		admission.operationID != binding.OperationID || admission.jobID != lease.jobID {
		return errResetExecutionEvidence
	}
	return nil
}

// This is the D101 physical body for the durable lifecycle worker. The caller
// must have verified actual Gateway DISPATCH_INTENT before promoting its lease.
// No request-selectable phase source and no legacy automatic up retry is used.
// It does not settle Gateway canonical metadata or publish PUBLIC.
func (c config) runResetD101PhysicalWorker(lease *operationLease, target serverTarget, binding resetExecutionPhaseBinding, source resetExecutionPhaseSource) (string, error) {
	expectedTarget, targetErr := c.serverTargetForID("pep")
	if source == nil || c.d101PurposeAuthority == nil || target.ID != "pep" || target.Project != "opensamguk-spep" ||
		targetErr != nil || target != expectedTarget || !resetRuntimeRepository.MatchString("ghcr.io/"+c.ghcrOwner+"/opensamguk") ||
		binding.Phase != "prepared" || binding.PreviousAttestationSHA != "" || c.requireResetD101WorkerLease(lease, binding) != nil {
		return "", errResetExecutionEvidence
	}
	ctx := lease.Context()
	evidence, err := c.readResetExecutionEvidence(binding.OperationID, binding.Target, binding.Evidence, time.Unix(binding.AcceptedAtUnix, 0))
	record, found := c.lifecycleOperationStore.Lookup(binding.OperationID)
	if err != nil || !found || evidence.Plan.ApprovalIntentSHA != record.D101IntentSHA {
		return "", errResetExecutionEvidence
	}
	authority, err := c.d101PurposeAuthority(ctx, binding.OperationID, record.D101IntentSHA)
	request := resetD101PurposeGrantRequest{OperationID: binding.OperationID, ApprovalIntentSHA: record.D101IntentSHA, Action: "DISPATCH_INTENT"}
	if err != nil {
		return "", errResetExecutionEvidence
	}
	if _, err := requireResetD101Authority(authority, request, time.Now()); err != nil {
		return "", errResetExecutionEvidence
	}
	if err := c.observeResetD101GatewayDispatch(ctx, binding, evidence); err != nil {
		return "", err
	}
	// All original destructive work, including first new-stack startup, must
	// finish inside the original cutoff. Admission and retries never renew it.
	bounded, cancel := context.WithDeadline(ctx, time.Unix(evidence.Plan.DestructiveCutoffUnix, 0))
	defer cancel()
	// Reuse the preparation verified by Gateway before dispatch. Observing a
	// new initial phase here would break the signed first-admission chain.
	_, chain, err := c.readResetD101PreparedPhase(binding, record, evidence, 0)
	if err != nil {
		return "", err
	}
	if _, err := c.pullResetCandidate(bounded, target, binding.Target); err != nil {
		return "", err
	}
	if c.verifyResetCandidateStorageImages(bounded, binding.Target) != nil || c.requireResetD101WorkerLease(lease, binding) != nil {
		return "", errResetExecutionEvidence
	}
	binding.Phase, binding.PreviousAttestationSHA = "before-journal", chain.Attestations[0].SHA
	beforeJournal, err := c.observeResetExecutionPhase(bounded, binding, source)
	if err != nil {
		return "", err
	}
	chain, err = appendResetExecutionAttestation(chain, binding, beforeJournal)
	if err != nil {
		return "", err
	}
	if err := c.writeResetExecutionLifecycleJournal(target, binding.Target, binding.OperationID, chain); err != nil {
		return "", err
	}
	if bounded.Err() != nil || validateResetApprovalPlan(evidence.Plan, binding.OperationID, binding.Target, time.Now()) != nil {
		return "", errResetExecutionEvidence
	}
	if err := c.requireResetD101WorkerAuthority(bounded, evidence, record.D101IntentSHA); err != nil {
		return "", err
	}
	if err := c.observeResetD101GatewayDispatch(bounded, binding, evidence); err != nil {
		return "", err
	}
	if _, err := c.validateServerTarget(target); err != nil {
		return "", err
	}
	if err := applyResetLifecycleTarget(target.EnvFile, binding.Target); err != nil {
		return "", err
	}
	if err := c.advanceLifecycleJournal(lifecycleJournalStageEnv); err != nil {
		return "", err
	}
	binding.Phase, binding.PreviousAttestationSHA = "before-down", chain.Attestations[1].SHA
	if err := c.appendResetExecutionPhaseToJournal(bounded, binding, source); err != nil {
		return "", err
	}
	if c.requireResetD101WorkerLease(lease, binding) != nil || bounded.Err() != nil ||
		validateResetApprovalPlan(evidence.Plan, binding.OperationID, binding.Target, time.Now()) != nil {
		return "", errResetExecutionEvidence
	}
	if err := c.requireResetD101WorkerAuthority(bounded, evidence, record.D101IntentSHA); err != nil {
		return "", err
	}
	// The durable boundary precedes the command. An uncertain down outcome is
	// recovery-required; this worker never automatically repeats down or up.
	if err := c.observeResetD101GatewayDispatch(bounded, binding, evidence); err != nil {
		return "", err
	}
	if err := c.advanceLifecycleJournal(lifecycleJournalStageDown); err != nil {
		return "", err
	}
	if _, err := c.downServerStack(bounded, target.Project, target.EnvFile); err != nil {
		return "", err
	}
	if bounded.Err() != nil || validateResetApprovalPlan(evidence.Plan, binding.OperationID, binding.Target, time.Now()) != nil {
		return "", errResetExecutionEvidence
	}
	if err := c.requireResetD101WorkerAuthority(bounded, evidence, record.D101IntentSHA); err != nil {
		return "", err
	}
	if err := c.observeResetD101GatewayDispatch(bounded, binding, evidence); err != nil {
		return "", err
	}
	if _, err := c.upServerStack(bounded, target.Project, target.EnvFile); err != nil {
		return "", err
	}
	if _, err := c.persistResetD101Runtime(bounded, binding, "ghcr.io/"+c.ghcrOwner+"/opensamguk"); err != nil {
		return "", err
	}
	if bounded.Err() != nil || c.requireResetD101WorkerLease(lease, binding) != nil {
		return "", errResetExecutionEvidence
	}
	return "D101 physical runtime observed", nil
}

func (c config) requireResetD101WorkerAuthority(ctx context.Context, evidence resetExecutionEvidence, intentSHA string) error {
	if c.d101PurposeAuthority == nil || ctx == nil || ctx.Err() != nil || evidence.Plan.ApprovalIntentSHA != intentSHA {
		return errResetExecutionEvidence
	}
	request := resetD101PurposeGrantRequest{OperationID: evidence.Plan.OperationID, ApprovalIntentSHA: intentSHA, Action: "DISPATCH_INTENT"}
	authority, err := c.d101PurposeAuthority(ctx, request.OperationID, intentSHA)
	if err != nil {
		return errResetExecutionEvidence
	}
	intent, err := requireResetD101Authority(authority, request, time.Now())
	if err != nil || requireResetIntentPlan(intent, evidence.Plan) != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	return nil
}
