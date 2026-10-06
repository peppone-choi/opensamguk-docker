package main

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"time"
)

// This owns only pre-stop preparation/immutable plan custody. It is not Root
// PREPARED/first admission and cannot promote or consume the maintenance lease.
// Authenticated Gateway PREPARED and the actual current writer-freeze source
// must also pass before any old-world collector command is connected.
type resetD101PreStopPreparation struct {
	preparation  *operationPreparation
	lease        *maintenanceAdmissionLease
	caller       context.Context
	intent       resetDecodedApprovalIntent
	plan         resetApprovalPlan
	planSHA      string
	planOriginal []byte
}

func resetD101PreStopPreparationFingerprint(intentSHA, planSHA string) string {
	return resetD101OriginalSHA([]byte("D101_PRE_STOP_PREPARATION_V1\n" + intentSHA + "\n" + planSHA))
}

// Fixed callers supply independently reviewed original SHAs and the existing
// private maintenance lease. No HTTP route or request/config toggle is added.
// coordinator.prepare alone has no tombstone/first-admission side effects.
func (c config) beginResetD101PreStopPreparation(ctx context.Context, op, intentSHA, planSHA, leaseToken string) (*resetD101PreStopPreparation, error) {
	if ctx == nil || ctx.Err() != nil || c.operations == nil || c.lifecycleOperationStore == nil || c.d101PurposeAuthority == nil || !lifecycleJobIDRe.MatchString(op) || !resetEvidenceSHA.MatchString(intentSHA) || !resetEvidenceSHA.MatchString(planSHA) || leaseToken == "" {
		return nil, errResetExecutionEvidence
	}
	if _, exists := c.lifecycleOperationStore.Lookup(op); exists {
		return nil, errResetExecutionEvidence
	}
	authority, err := c.d101PurposeAuthority(ctx, op, intentSHA)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	intent, err := requireResetD101Authority(authority, resetD101PurposeGrantRequest{OperationID: op, ApprovalIntentSHA: intentSHA, Action: "QUERY"}, time.Now())
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	intentWire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-intents"), op, 0)
	if err != nil || !bytes.Equal(intentWire, intent.originalBytes()) {
		return nil, errResetExecutionEvidence
	}
	wire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-approvals"), op, 0)
	var plan resetApprovalPlan
	if err != nil || resetD101OriginalSHA(wire) != planSHA || requireResetIntentShape(wire, reflect.TypeOf(plan)) != nil || decodeResetPrivateJSON(wire, &plan) != nil || requireResetIntentPlan(intent, plan) != nil || validateResetApprovalPlan(plan, op, intent.Target, time.Now()) != nil {
		return nil, errResetExecutionEvidence
	}
	prep, err := c.operations.prepare(lifecycleKindReset, op, "pep", resetD101PreStopPreparationFingerprint(intentSHA, planSHA), leaseToken)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	s := &resetD101PreStopPreparation{preparation: prep, caller: ctx, intent: intent, plan: plan, planSHA: planSHA, planOriginal: bytes.Clone(wire)}
	c.operations.mu.Lock()
	s.lease = c.operations.maintenanceLease
	c.operations.mu.Unlock()
	if c.requireResetD101PreStopLeaseAndPlan(ctx, s) != nil {
		prep.complete(true)
		return nil, errResetExecutionEvidence
	}
	return s, nil
}

// The actual same unconsumed lease and serialized preparation are rechecked
// before/after native reads. This subset alone never authorizes a Docker command.
func (c config) requireResetD101PreStopLeaseAndPlan(ctx context.Context, s *resetD101PreStopPreparation) error {
	if ctx == nil || ctx.Err() != nil || s == nil || s.caller == nil || s.caller.Err() != nil || c.operations == nil || c.lifecycleOperationStore == nil || c.d101PurposeAuthority == nil || validateResetApprovalPlan(s.plan, s.intent.Intent.OperationID, s.intent.Target, time.Now()) != nil || requireResetIntentPlan(s.intent, s.plan) != nil || !resetEvidenceSHA.MatchString(s.planSHA) || resetD101OriginalSHA(s.planOriginal) != s.planSHA {
		return errResetExecutionEvidence
	}
	if c.requireResetD101PreStopLease(s) != nil {
		return errResetExecutionEvidence
	}
	authority, err := c.d101PurposeAuthority(ctx, s.intent.Intent.OperationID, s.intent.SHA)
	if err != nil {
		return errResetExecutionEvidence
	}
	current, err := requireResetD101Authority(authority, resetD101PurposeGrantRequest{OperationID: s.intent.Intent.OperationID, ApprovalIntentSHA: s.intent.SHA, Action: "QUERY"}, time.Now())
	if err != nil || !bytes.Equal(current.originalBytes(), s.intent.originalBytes()) {
		return errResetExecutionEvidence
	}
	intentWire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-intents"), s.intent.Intent.OperationID, 0)
	planWire, planErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-approvals"), s.intent.Intent.OperationID, 0)
	if err != nil || planErr != nil || !bytes.Equal(intentWire, s.intent.originalBytes()) || !bytes.Equal(planWire, s.planOriginal) || ctx.Err() != nil || s.caller.Err() != nil || validateResetApprovalPlan(s.plan, s.intent.Intent.OperationID, s.intent.Target, time.Now()) != nil || c.requireResetD101PreStopLease(s) != nil {
		return errResetExecutionEvidence
	}
	return nil
}
func (c config) requireResetD101PreStopLease(s *resetD101PreStopPreparation) error {
	if s == nil || s.preparation == nil || s.lease == nil || c.operations == nil || c.lifecycleOperationStore == nil {
		return errResetExecutionEvidence
	}
	if _, exists := c.lifecycleOperationStore.Lookup(s.intent.Intent.OperationID); exists {
		return errResetExecutionEvidence
	}
	c.operations.mu.Lock()
	defer c.operations.mu.Unlock()
	p := s.preparation
	lease := c.operations.maintenanceLease
	if !c.operations.closed || c.operations.active != nil || c.operations.preparing != p || c.operations.journalPending || c.operations.preparationSettlementPending || stateFilePresent(c.lifecycleJournalFile) || p.coordinator != c.operations || p.ctx == nil || p.Context().Err() != nil || p.admissionErr != nil || p.kind != lifecycleKindReset || p.subjectID != "pep" || p.operationID != s.intent.Intent.OperationID || p.fingerprint != resetD101PreStopPreparationFingerprint(s.intent.SHA, s.planSHA) || lease != s.lease || lease.consumed || lease.jobID != "" || !secureEqual(lease.token, p.leaseAttempt) || lease.operationID != "" && lease.operationID != p.operationID {
		return errResetExecutionEvidence
	}
	return nil
}
