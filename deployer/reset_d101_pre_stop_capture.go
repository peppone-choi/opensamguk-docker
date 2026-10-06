package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strconv"
	"time"
)

// Bound in-process data only. Native old SQL/phase custody and mandatory
// stopped/preflight/backup/recovery consumers still precede any storage stop.
type resetD101PreStopOldWorldCapture struct {
	preparation *resetD101PreStopPreparation
	gateway     resetD101GatewayPreStopObservation
	freeze      resetExecutionPhaseSnapshot
	oldWorld    resetD101OldWorldObservation
	commands    []resetD101PreStopCommandObservation
}

type resetD101PreStopCommandObservation struct {
	gateway resetD101PreStopGatewayObservation
	freeze  resetExecutionPhaseSnapshot
}

// Each caller command obtains a new authenticated QUERY, local original/lease
// reads and current source observation. The post-stop phase guard is not used.
func (c config) observeResetD101PreStopCurrent(ctx context.Context, s *resetD101PreStopPreparation, gatewaySHA string) (resetD101PreStopGatewayObservation, resetExecutionPhaseSnapshot, error) {
	emptyGateway, emptySnapshot := resetD101PreStopGatewayObservation{}, resetExecutionPhaseSnapshot{}
	if ctx == nil || ctx.Err() != nil || s == nil || c.d101PhaseSource == nil {
		return emptyGateway, emptySnapshot, errResetExecutionEvidence
	}
	started := time.Now()
	deadline := started.Add(resetPreflightMaxAge)
	if cutoff := time.Unix(s.intent.Intent.DestructiveCutoffUnix, 0); cutoff.Before(deadline) {
		deadline = cutoff
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	gateway, err := c.readResetD101PreStopGateway(bounded, s, gatewaySHA)
	if err != nil {
		return emptyGateway, emptySnapshot, errResetExecutionEvidence
	}
	// Only source identity inputs are supplied here. There is no Root first
	// admission, acceptedAt, PREPARED proof or stopped/preflight evidence yet.
	binding := resetExecutionPhaseBinding{OperationID: s.intent.Intent.OperationID, Target: s.intent.Target, Evidence: resetExecutionEvidenceRefs{ApprovalPlanSHA: s.planSHA}}
	current, err := c.d101PhaseSource(bounded, binding)
	now := time.Now()
	if err != nil || bounded.Err() != nil || !now.Before(deadline) || c.requireResetD101PreStopLeaseAndPlan(bounded, s) != nil ||
		current.ServerID != "pep" || current.OperationID != s.intent.Intent.OperationID || current.TargetFingerprint != s.plan.TargetFingerprint ||
		current.PublicationState != "VERIFYING" || current.PublicationRevision != gateway.gateway.execution.VerifyingRevision ||
		current.WriterFreezeReceiptSHA != s.plan.WriterFreezeReceiptSHA || !resetEvidenceSHA.MatchString(current.WriterFreezeReceiptSHA) || !current.WriterFreezeHeld ||
		current.ObservedAt.Before(started) || current.ObservedAt.After(now) || now.Sub(current.ObservedAt) >= resetPreflightMaxAge ||
		gateway.publication.ObservedAt.Before(started) || gateway.publication.ObservedAt.After(now) || now.Sub(gateway.publication.ObservedAt) >= resetPreflightMaxAge {
		return emptyGateway, emptySnapshot, errResetExecutionEvidence
	}
	// Slow final native reads cannot carry a formerly fresh observation past
	// its original cutoff or age budget.
	now = time.Now()
	if bounded.Err() != nil || !now.Before(deadline) || now.Sub(current.ObservedAt) >= resetPreflightMaxAge || now.Sub(gateway.publication.ObservedAt) >= resetPreflightMaxAge || validateResetApprovalPlan(s.plan, s.intent.Intent.OperationID, s.intent.Target, now) != nil {
		return emptyGateway, emptySnapshot, errResetExecutionEvidence
	}
	return gateway, current, nil
}

// Existing C10 physical readonly collector, guarded at every actual command.
// No HTTP/config toggle registers the source or chooses installed PG inputs.
// Returned old SQL cannot authorize a stop until its native phase custody and
// mandatory downstream consumption have been connected by the owning invoker.
func (c config) captureResetD101PreStopOldWorld(ctx context.Context, s *resetD101PreStopPreparation, gatewaySHA string, input resetD101OldWorldCaptureInputs) (resetD101PreStopOldWorldCapture, error) {
	closed := resetD101PreStopOldWorldCapture{}
	initial, freeze, err := c.observeResetD101PreStopCurrent(ctx, s, gatewaySHA)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	canonical := initial.gateway.preReset
	if c.retainResetD101PreResetCapture(canonical) != nil {
		return closed, errResetExecutionEvidence
	}
	observations := []resetD101PreStopCommandObservation{{initial, freeze}}
	guard := func(ctx context.Context) error {
		current, snapshot, err := c.observeResetD101PreStopCurrent(ctx, s, gatewaySHA)
		if err != nil || !bytes.Equal(current.gateway.preReset.Original(), canonical.Original()) || current.gateway.execution.VerifyingRevision != initial.gateway.execution.VerifyingRevision {
			return errResetExecutionEvidence
		}
		native, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-pre-reset-originals"), s.intent.Intent.OperationID, 0)
		if err != nil || !bytes.Equal(native, canonical.Original()) || resetD101OriginalSHA(native) != canonical.sha || ctx.Err() != nil || c.requireResetD101PreStopLeaseAndPlan(ctx, s) != nil {
			return errResetExecutionEvidence
		}
		observations = append(observations, resetD101PreStopCommandObservation{current, snapshot})
		return nil
	}
	old, err := c.collectResetD101OldWorld(ctx, s.intent, input, guard)
	if err != nil || guard(ctx) != nil {
		return closed, errResetExecutionEvidence
	}
	generation, err := strconv.ParseInt(old.value.GenerationRaw, 10, 32)
	if err != nil || canonical.registry.Generation != nil && int64(*canonical.registry.Generation) != generation || canonical.registry.ScenarioCode != nil && *canonical.registry.ScenarioCode != old.value.ScenarioCode {
		return closed, errResetExecutionEvidence
	}
	return resetD101PreStopOldWorldCapture{s, initial.gateway, freeze, old, observations}, nil
}
