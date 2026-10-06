package main

import (
	"bytes"
	"context"
	"encoding/base64"
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
	nativeProof resetD101PreStopNativeOriginal
}

type resetD101PreStopCommandObservation struct {
	gateway   resetD101PreStopGatewayObservation
	freeze    resetExecutionPhaseSnapshot
	started   time.Time
	completed time.Time
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
	if ctx == nil || ctx.Err() != nil || s == nil || c.d101PreStopNativeInstallation == nil || c.d101PreStopNativeInstallation.verify == nil || input != c.d101PreStopNativeInstallation.oldInputs {
		return closed, errResetExecutionEvidence
	}
	started := time.Now().UTC()
	initial, freeze, err := c.observeResetD101PreStopCurrent(ctx, s, gatewaySHA)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	canonical := initial.gateway.preReset
	if c.retainResetD101PreResetCapture(canonical) != nil {
		return closed, errResetExecutionEvidence
	}
	directory := filepath.Join(c.serversDir, ".deployer-reset-old-world")
	dir, parentInfo, err := openResetD101NativeDirectory(directory, 0)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	parent, err := resetD101NativeSnapshot(parentInfo)
	dir.Close()
	binding := resetD101PreStopNativeBinding{intent: s.intent, plan: s.plan, planSHA: s.planSHA, gatewaySHA: gatewaySHA, parent: parent}
	if err != nil || c.requireResetD101PreStopProducer(ctx, binding) != nil || c.requireResetD101PreStopLeaseAndPlan(ctx, s) != nil {
		return closed, errResetExecutionEvidence
	}
	first := resetD101PreStopCommandObservation{gateway: initial, freeze: freeze, started: started, completed: time.Now().UTC()}
	frame, err := resetD101PreStopNativeFrameFromObservation(first)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	header := resetD101PreStopNativeBody{SchemaVersion: 1, OperationID: s.intent.Intent.OperationID, ApprovalIntentSHA: s.intent.SHA, ApprovalPlanSHA: s.planSHA,
		GatewayPayloadSHA: gatewaySHA, VerifyingRevision: initial.gateway.execution.VerifyingRevision, PreResetOriginalsBase64url: base64.RawURLEncoding.EncodeToString(canonical.Original()), PreResetOriginalsSHA: canonical.sha}
	stream, err := openResetD101PreStopNativeStream(directory, s.intent.Intent.OperationID, header, 0)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	defer stream.ClosePreservingPartial()
	if stream.AppendNonCommand(frame) != nil {
		return closed, errResetExecutionEvidence
	}
	ctx = context.WithValue(ctx, resetD101PreStopStreamContextKey{}, stream)
	observations := []resetD101PreStopCommandObservation{first}
	guard := func(ctx context.Context) error {
		started := time.Now().UTC()
		current, snapshot, err := c.observeResetD101PreStopCurrent(ctx, s, gatewaySHA)
		if err != nil || !bytes.Equal(current.gateway.preReset.Original(), canonical.Original()) || current.gateway.execution.VerifyingRevision != initial.gateway.execution.VerifyingRevision {
			return errResetExecutionEvidence
		}
		native, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-pre-reset-originals"), s.intent.Intent.OperationID, 0)
		if err != nil || !bytes.Equal(native, canonical.Original()) || resetD101OriginalSHA(native) != canonical.sha || ctx.Err() != nil || c.requireResetD101PreStopLeaseAndPlan(ctx, s) != nil {
			return errResetExecutionEvidence
		}
		parentInfo, parentErr := stream.directory.Stat()
		parent, pinErr := resetD101NativeSnapshot(parentInfo)
		binding.parent = parent
		if parentErr != nil || pinErr != nil || stream.checkCustody() != nil || c.requireResetD101PreStopProducer(ctx, binding) != nil {
			return errResetExecutionEvidence
		}
		observed := resetD101PreStopCommandObservation{gateway: current, freeze: snapshot, started: started, completed: time.Now().UTC()}
		frame, frameErr := resetD101PreStopNativeFrameFromObservation(observed)
		if frameErr != nil || stream.QueueGuard(frame) != nil {
			return errResetExecutionEvidence
		}
		observations = append(observations, observed)
		return nil
	}
	old, err := c.collectResetD101OldWorld(ctx, s.intent, input, guard)
	if err != nil || stream.FlushNonCommand() != nil || guard(ctx) != nil || stream.FlushNonCommand() != nil {
		return closed, errResetExecutionEvidence
	}
	generation, err := strconv.ParseInt(old.value.GenerationRaw, 10, 32)
	if err != nil || canonical.registry.Generation != nil && int64(*canonical.registry.Generation) != generation || canonical.registry.ScenarioCode != nil && *canonical.registry.ScenarioCode != old.value.ScenarioCode {
		return closed, errResetExecutionEvidence
	}
	body := header
	body.PostgresContainerID, body.PostgresImageID, body.JobContainerID, body.JobImageID = old.postgresID, old.postgresImage, old.jobID, old.jobImage
	body.CollectorStartedAtUTC, body.CollectorCompletedAtUTC = old.started.UTC().Format(time.RFC3339Nano), old.completed.UTC().Format(time.RFC3339Nano)
	body.OldWorldBytesBase64url, body.OldWorldSHA = base64.RawURLEncoding.EncodeToString(old.originalBytes()), old.sha
	body.CommandEvidence.SQLSHA, body.CommandEvidence.ProducerSourceSHA = resetD101OriginalSHA([]byte(resetD101OldWorldSQL)), c.d101PreStopNativeInstallation.sourceSHA
	if ctx.Err() != nil || c.requireResetD101PreStopLeaseAndPlan(ctx, s) != nil || stream.Finish(body) != nil {
		return closed, errResetExecutionEvidence
	}
	stream.ClosePreservingPartial()
	_, pin, err := readResetD101PreStopNativeFile(directory, s.intent.Intent.OperationID, 0)
	proof, proofErr := c.readResetD101PreStopNativeProof(ctx, s.intent, s.plan, s.planSHA, gatewaySHA, pin.SHA256, 0)
	if err != nil || proofErr != nil || c.requireResetD101PreStopLeaseAndPlan(ctx, s) != nil {
		return closed, errResetExecutionEvidence
	}
	return resetD101PreStopOldWorldCapture{preparation: s, gateway: initial.gateway, freeze: freeze, oldWorld: old, commands: observations, nativeProof: proof}, nil
}

// Owning fixed local invoker. Installed inputs select the physical old PG;
// request/env inputs cannot select source, sink, paths, images or a TRUE verifier.
// No ingress/main factory registers it while installation/current is absent.
func (c config) runResetD101PreStopNativeCapture(ctx context.Context, op, intentSHA, planSHA, leaseToken string) (resetD101PreStopNativeOriginal, error) {
	closed := resetD101PreStopNativeOriginal{}
	if ctx == nil || ctx.Err() != nil || c.d101PhaseSource == nil || c.d101PreStopNativeInstallation == nil || c.d101PreStopNativeInstallation.verify == nil {
		return closed, errResetExecutionEvidence
	}
	s, err := c.beginResetD101PreStopPreparation(ctx, op, intentSHA, planSHA, leaseToken)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	success := false
	defer func() { s.preparation.complete(success) }()
	prepare, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), op, 0)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	gatewaySHA := resetD101OriginalSHA(prepare)
	if requireResetD101PrepareBody(prepare, s.intent, gatewaySHA) != nil {
		return closed, errResetExecutionEvidence
	}
	capture, err := c.captureResetD101PreStopOldWorld(ctx, s, gatewaySHA, c.d101PreStopNativeInstallation.oldInputs)
	if err != nil || c.requireResetD101PreStopLeaseAndPlan(ctx, s) != nil {
		return closed, errResetExecutionEvidence
	}
	success = true
	return capture.nativeProof, nil
}
