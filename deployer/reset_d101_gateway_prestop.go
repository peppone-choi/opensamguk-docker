package main

import (
	"bytes"
	"strconv"
	"time"
)

// This is read-only Gateway QUERY data, not a writer-freeze, maintenance-lease,
// current-publication or physical-world proof. The C8 pre-stop owner supplies
// and rechecks those independent sources before using this observation.
type resetD101GatewayPreStopObservation struct {
	original  []byte
	execution resetD101GatewayExecution
	preReset  resetD101PreResetCapture
}

func (v resetD101GatewayPreStopObservation) Original() []byte { return bytes.Clone(v.original) }

// The expected intent and installed native prepare SHA come from the caller's
// independent custody. Neither is selected from the Gateway response body.
func decodeResetD101GatewayPreStop(wire []byte, intent resetDecodedApprovalIntent, gatewaySHA string, now time.Time) (resetD101GatewayPreStopObservation, error) {
	closed := resetD101GatewayPreStopObservation{}
	if now.IsZero() || !resetEvidenceSHA.MatchString(gatewaySHA) || !validResetD101OldWorldIntent(intent, now) {
		return closed, errResetExecutionEvidence
	}
	executionWire, capture, err := decodeResetD101GatewayQueryCapture(wire, false)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	value, err := decodeResetD101GatewayExecution(executionWire)
	if err != nil || value.SchemaVersion != 1 || value.ServerID != "pep" || value.State != "PREPARED" ||
		value.OperationID != intent.Intent.OperationID || value.ApprovalIntentSHA != intent.SHA ||
		value.TargetFingerprint != intent.Intent.TargetFingerprint || value.GatewayPayloadSHA != gatewaySHA ||
		value.InitialPublicRevision != intent.Intent.InitialPublicRevision ||
		value.PublishedRevision != nil || value.RootRequestFingerprint != nil ||
		value.RootResultReceiptSHA != nil || value.ValidationReceiptSHA != nil {
		return closed, errResetExecutionEvidence
	}
	initial, initialErr := strconv.ParseInt(value.InitialPublicRevision, 10, 64)
	verifying, verifyingErr := strconv.ParseInt(value.VerifyingRevision, 10, 64)
	created, createdErr := resetC4UTC(value.CreatedAtUTC)
	updated, updatedErr := resetC4UTC(value.UpdatedAtUTC)
	if initialErr != nil || verifyingErr != nil || initial <= 0 || verifying <= initial ||
		strconv.FormatInt(initial, 10) != value.InitialPublicRevision ||
		strconv.FormatInt(verifying, 10) != value.VerifyingRevision ||
		createdErr != nil || updatedErr != nil || created.Before(time.Unix(intent.Intent.WindowOpensAtUnix, 0)) ||
		updated.Before(created) || updated.After(now) ||
		!created.Before(time.Unix(intent.Intent.DestructiveCutoffUnix, 0)) ||
		!updated.Before(time.Unix(intent.Intent.DestructiveCutoffUnix, 0)) {
		return closed, errResetExecutionEvidence
	}
	return resetD101GatewayPreStopObservation{bytes.Clone(wire), value, capture}, nil
}
