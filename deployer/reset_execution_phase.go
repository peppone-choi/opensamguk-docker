package main

import (
	"context"
	"time"
)

// Persist this binding together with the journal before accepting a D101 worker.
// A later phase cannot choose a new initial receipt, operation or target.
type resetExecutionPhaseBinding struct {
	OperationID            string
	Target                 resetLifecycleTarget
	Evidence               resetExecutionEvidenceRefs
	AcceptedAtUnix         int64
	Phase                  string
	PreviousAttestationSHA string
}

// A configured source must freshly verify the canonical publication revision and
// the external writer freeze. A nil source fails closed; JSON flags alone are
// not a source implementation. Host issuance/wiring is still a separate gate.
type resetExecutionPhaseSnapshot struct {
	ObservedAt             time.Time
	ServerID               string
	OperationID            string
	TargetFingerprint      string
	PublicationState       string
	PublicationRevision    string
	WriterFreezeReceiptSHA string
	WriterFreezeHeld       bool
}

type resetExecutionPhaseSource func(context.Context, resetExecutionPhaseBinding) (resetExecutionPhaseSnapshot, error)

// The 30s initial receipt proves admission freshness once. Static backup/source
// custody is re-read by the SAME immutable SHA, not replaced by a reset retry.
// Live phase observations have their own deadline; the original window/cutoff
// is never renewed. The caller must persist both the initial binding and the
// subsequent attestation chain; without that wiring this is not executable.
func (c config) verifyResetExecutionPhase(ctx context.Context, binding resetExecutionPhaseBinding, source resetExecutionPhaseSource) error {
	now := time.Now()
	if source == nil || binding.AcceptedAtUnix <= 0 || time.Unix(binding.AcceptedAtUnix, 0).After(now) ||
		(binding.Phase != "prepared" && binding.Phase != "before-journal" && binding.Phase != "before-down") ||
		(binding.Phase != "prepared" && !resetEvidenceSHA.MatchString(binding.PreviousAttestationSHA)) {
		return errResetExecutionEvidence
	}
	// Read the static plan/receipt and validate initial freshness at persisted
	// admission time. Do not re-age the original preflight after a long pull.
	evidence, err := c.readResetExecutionEvidence(binding.OperationID, binding.Target, binding.Evidence, time.Unix(binding.AcceptedAtUnix, 0))
	if err != nil || validateResetApprovalPlan(evidence.Plan, binding.OperationID, binding.Target, now) != nil {
		return errResetExecutionEvidence
	}
	phaseDeadline := now.Add(resetPreflightMaxAge)
	cutoff := time.Unix(evidence.Plan.DestructiveCutoffUnix, 0)
	if cutoff.Before(phaseDeadline) {
		phaseDeadline = cutoff
	}
	phaseCtx, cancel := context.WithDeadline(ctx, phaseDeadline)
	defer cancel()
	current, err := source(phaseCtx, binding)
	if err != nil || validateResetPhaseSnapshot(current, evidence, binding, now, time.Now()) != nil {
		return errResetExecutionEvidence
	}
	if c.verifyResetStoppedContainers(phaseCtx, evidence) != nil || c.verifyResetLiveSpace(evidence) != nil {
		return errResetExecutionEvidence
	}
	if phaseCtx.Err() != nil || !time.Now().Before(phaseDeadline) ||
		time.Since(current.ObservedAt) >= resetPreflightMaxAge ||
		validateResetApprovalPlan(evidence.Plan, binding.OperationID, binding.Target, time.Now()) != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func validateResetPhaseSnapshot(current resetExecutionPhaseSnapshot, evidence resetExecutionEvidence, binding resetExecutionPhaseBinding, phaseStart, now time.Time) error {
	if current.ServerID != evidence.Plan.ServerID || current.OperationID != binding.OperationID ||
		current.TargetFingerprint != evidence.Plan.TargetFingerprint || current.PublicationState != "VERIFYING" ||
		current.PublicationRevision != evidence.Preflight.PublicationRevision || !current.WriterFreezeHeld ||
		current.WriterFreezeReceiptSHA != evidence.Plan.WriterFreezeReceiptSHA ||
		current.ObservedAt.After(now) || current.ObservedAt.Before(phaseStart) ||
		now.Sub(current.ObservedAt) >= resetPreflightMaxAge ||
		validateResetApprovalPlan(evidence.Plan, binding.OperationID, binding.Target, now) != nil {
		return errResetExecutionEvidence
	}
	return nil
}
