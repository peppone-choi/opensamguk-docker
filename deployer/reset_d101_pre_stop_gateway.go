package main

import (
	"bytes"
	"context"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// Authenticated QUERY data and a separate current publication observation.
// These do not establish external writer exclusion or permit physical commands.
type resetD101PreStopGatewayObservation struct {
	gateway     resetD101GatewayPreStopObservation
	publication resetAdminPublicationObservation
}

// A private, unconsumed preparation replaces the post-dispatch durable record
// prerequisite. No preflight/stopped-container result is needed before old SQL.
// gatewaySHA is independently pinned before the response is read.
func (c config) readResetD101PreStopGateway(ctx context.Context, s *resetD101PreStopPreparation, gatewaySHA string) (resetD101PreStopGatewayObservation, error) {
	closed := resetD101PreStopGatewayObservation{}
	if ctx == nil || ctx.Err() != nil || s == nil || !resetEvidenceSHA.MatchString(gatewaySHA) || c.requireResetD101PreStopLeaseAndPlan(ctx, s) != nil {
		return closed, errResetExecutionEvidence
	}
	deadline := time.Now().Add(resetPreflightMaxAge)
	cutoff := time.Unix(s.intent.Intent.DestructiveCutoffUnix, 0)
	if cutoff.Before(deadline) {
		deadline = cutoff
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	origin, err := url.Parse(c.defaultGatewayAPIURL())
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") || origin.RawPath != "" || origin.ForceQuery || !resetPrivateGatewayHost(origin.Hostname()) {
		return closed, errResetExecutionEvidence
	}
	op := s.intent.Intent.OperationID
	prepareDirectory := filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies")
	prepare, err := readResetPrivateCustody(prepareDirectory, op, 0)
	if err != nil || requireResetD101PrepareBody(prepare, s.intent, gatewaySHA) != nil {
		return closed, errResetExecutionEvidence
	}
	credentialDirectory := filepath.Join(c.serversDir, ".deployer-reset-gateway")
	credentialWire, err := readResetPrivateCustody(credentialDirectory, op, 0)
	var credential resetD101GatewayCredential
	if err != nil || requireResetIntentShape(credentialWire, reflect.TypeOf(credential)) != nil || decodeResetPrivateJSON(credentialWire, &credential) != nil || credential.Version != 1 || credential.OperationID != op || credential.ApprovalIntentSHA != s.intent.SHA || credential.TargetFingerprint != s.intent.Intent.TargetFingerprint || credential.ExpiresAtUnix <= time.Now().Unix() || !validResetD101ServiceToken(credential.ServiceToken) {
		return closed, errResetExecutionEvidence
	}
	grant, err := c.issueResetD101PurposeGrant(bounded, resetD101PurposeGrantRequest{OperationID: op, ApprovalIntentSHA: s.intent.SHA, GatewayPayloadSHA: gatewaySHA, Action: "QUERY"})
	if err != nil || c.requireResetD101PreStopLeaseAndPlan(bounded, s) != nil {
		return closed, errResetExecutionEvidence
	}
	endpoint := strings.TrimRight(origin.String(), "/") + "/internal/d101/servers/pep/operations/" + op
	wire, cache, err := readResetD101GatewayQuery(bounded, endpoint, credential.ServiceToken, grant, 64*1024)
	gateway, decodeErr := decodeResetD101GatewayPreStop(wire, s.intent, gatewaySHA, time.Now())
	if err != nil || cache != "no-store" || decodeErr != nil {
		return closed, errResetExecutionEvidence
	}
	// This existing ADMIN credential/source observes VERIFYING independently of
	// the execution state. No downstream receipt or durable Root record is read.
	binding := resetExecutionPhaseBinding{OperationID: op, Target: s.intent.Target, Evidence: resetExecutionEvidenceRefs{ApprovalPlanSHA: s.planSHA}}
	adminDirectory := filepath.Join(c.serversDir, ".deployer-reset-admin")
	adminWire, err := readResetPrivateCustody(adminDirectory, op, 0)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	publication, err := c.observeResetD101Publication(bounded, binding, gateway.execution.VerifyingRevision)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	prepareAfter, prepareErr := readResetPrivateCustody(prepareDirectory, op, 0)
	credentialAfter, credentialErr := readResetPrivateCustody(credentialDirectory, op, 0)
	adminAfter, adminErr := readResetPrivateCustody(adminDirectory, op, 0)
	_, adminExpiryErr := readResetAdminCredential(adminDirectory, binding, time.Now(), 0)
	if prepareErr != nil || credentialErr != nil || adminErr != nil || adminExpiryErr != nil || !bytes.Equal(prepare, prepareAfter) || !bytes.Equal(credentialWire, credentialAfter) || !bytes.Equal(adminWire, adminAfter) || credential.ExpiresAtUnix <= time.Now().Unix() || bounded.Err() != nil || !time.Now().Before(deadline) || c.requireResetD101PreStopLeaseAndPlan(bounded, s) != nil {
		return closed, errResetExecutionEvidence
	}
	return resetD101PreStopGatewayObservation{gateway, publication}, nil
}
