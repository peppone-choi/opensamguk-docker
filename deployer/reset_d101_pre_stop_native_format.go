package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strconv"
	"time"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101evidencetransport"
)

// Generated local r2 capture only. Its shape/digests are not producer authority.
// HTTP bodies, old SQL15, signing purposes and recovery result keys are unchanged.
type resetD101PreStopNativeBody struct {
	SchemaVersion              int                                   `json:"schemaVersion"`
	OperationID                string                                `json:"operationId"`
	ApprovalIntentSHA          string                                `json:"approvalIntentSha256"`
	ApprovalPlanSHA            string                                `json:"approvalPlanSha256"`
	GatewayPayloadSHA          string                                `json:"gatewayPayloadSha256"`
	VerifyingRevision          string                                `json:"verifyingRevision"`
	PreResetOriginalsBase64url string                                `json:"preResetOriginalsBytesBase64url"`
	PreResetOriginalsSHA       string                                `json:"preResetOriginalsSha256"`
	PostgresContainerID        string                                `json:"postgresContainerId"`
	PostgresImageID            string                                `json:"postgresImageId"`
	JobContainerID             string                                `json:"jobContainerId"`
	JobImageID                 string                                `json:"jobImageId"`
	CollectorStartedAtUTC      string                                `json:"collectorStartedAtUtc"`
	CollectorCompletedAtUTC    string                                `json:"collectorCompletedAtUtc"`
	OldWorldBytesBase64url     string                                `json:"oldWorldBytesBase64url"`
	OldWorldSHA                string                                `json:"oldWorldSha256"`
	Observations               []resetD101PreStopNativeFrame         `json:"observations"`
	CommandEvidence            resetD101PreStopNativeCommandEvidence `json:"commandEvidence"`
}

type resetD101PreStopNativeFrame struct {
	StartedAtUTC       string                            `json:"startedAtUtc"`
	CompletedAtUTC     string                            `json:"completedAtUtc"`
	GatewayQueryBase64 string                            `json:"gatewayQueryBytesBase64url"`
	Publication        resetD101PreStopNativePublication `json:"publication"`
	Snapshot           resetD101PreStopNativeSnapshot    `json:"snapshot"`
	Invocation         *resetD101PreStopNativeInvocation `json:"invocation"`
}

type resetD101PreStopNativePublication struct {
	ObservedAtUTC string                `json:"observedAtUtc"`
	BodySHA       string                `json:"bodySha256"`
	Current       resetAdminPublication `json:"current"`
	BodyBase64    string                `json:"bodyBytesBase64url"`
}

type resetD101PreStopNativeSnapshot struct {
	ObservedAtUTC          string `json:"observedAt"`
	ServerID               string `json:"serverId"`
	OperationID            string `json:"operationId"`
	TargetFingerprint      string `json:"targetFingerprint"`
	PublicationState       string `json:"publicationState"`
	PublicationRevision    string `json:"publicationRevision"`
	WriterFreezeReceiptSHA string `json:"writerFreezeReceiptSha256"`
	WriterFreezeHeld       bool   `json:"writerFreezeHeld"`
}

type resetD101PreStopNativeInvocation struct {
	CommandID             string `json:"commandId"`
	ArgvSHA               string `json:"argvSha256"`
	StartedAtUTC          string `json:"startedAtUtc"`
	CompletedAtUTC        string `json:"completedAtUtc"`
	GuardObservationIndex int    `json:"guardObservationIndex"`
}

type resetD101PreStopNativeCommandEvidence struct {
	SQLSHA            string                             `json:"sqlSha256"`
	ProducerSourceSHA string                             `json:"producerSourceSha"`
	Invocations       []resetD101PreStopNativeInvocation `json:"invocations"`
}

type resetD101PreStopNativeOriginal struct {
	body      resetD101PreStopNativeBody
	old       resetD101OldWorldOriginal
	canonical resetD101PreResetCapture
	original  []byte
	sha       string
}

func (v resetD101PreStopNativeOriginal) Original() []byte { return bytes.Clone(v.original) }

func resetD101PreStopRaw(encoded, sha string, limit int) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > (limit*4+2)/3 || !resetEvidenceSHA.MatchString(sha) {
		return nil, errResetExecutionEvidence
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > limit || base64.RawURLEncoding.EncodeToString(raw) != encoded || resetD101OriginalSHA(raw) != sha {
		return nil, errResetExecutionEvidence
	}
	return raw, nil
}

func resetD101PreStopUTC(s string) (time.Time, error) {
	v, err := resetD101RecoveryUTC(s)
	if err != nil || v.UTC().Format(time.RFC3339Nano) != s {
		return time.Time{}, errResetExecutionEvidence
	}
	return v, nil
}

// Exact array elements must be checked explicitly; the intent shape helper
// checks nested objects but deliberately does not traverse slices.
func requireResetD101PreStopNativeShape(wire []byte) error {
	var body resetD101PreStopNativeBody
	if requireResetIntentShape(wire, reflect.TypeOf(body)) != nil {
		return errResetExecutionEvidence
	}
	var fields map[string]json.RawMessage
	if decodeResetPrivateJSON(wire, &fields) != nil {
		return errResetExecutionEvidence
	}
	var frames []json.RawMessage
	if decodeResetPrivateJSON(fields["observations"], &frames) != nil {
		return errResetExecutionEvidence
	}
	for _, frame := range frames {
		if requireResetD101NullableShape(frame, reflect.TypeOf(resetD101PreStopNativeFrame{}), map[string]bool{"invocation": true}, nil) != nil {
			return errResetExecutionEvidence
		}
	}
	var evidence map[string]json.RawMessage
	var invocations []json.RawMessage
	if decodeResetPrivateJSON(fields["commandEvidence"], &evidence) != nil || decodeResetPrivateJSON(evidence["invocations"], &invocations) != nil {
		return errResetExecutionEvidence
	}
	for _, invocation := range invocations {
		if requireResetIntentShape(invocation, reflect.TypeOf(resetD101PreStopNativeInvocation{})) != nil {
			return errResetExecutionEvidence
		}
	}
	return nil
}

// Independently supplied intent/plan/prepare/source pins are not selected from
// this body. Successful decoding still returns unverified physical data.
func decodeResetD101PreStopNative(wire []byte, sha string, intent resetDecodedApprovalIntent, plan resetApprovalPlan, planSHA, gatewaySHA, sourceSHA string) (resetD101PreStopNativeOriginal, error) {
	closed := resetD101PreStopNativeOriginal{}
	readAt := time.Now().UTC()
	var body resetD101PreStopNativeBody
	if len(wire) == 0 || uint64(len(wire)) > d101evidencetransport.OriginalMaxBytes || !utf8.Valid(wire) ||
		!resetEvidenceSHA.MatchString(sha) || resetD101OriginalSHA(wire) != sha || requireResetD101PreStopNativeShape(wire) != nil ||
		decodeResetPrivateJSON(wire, &body) != nil || body.SchemaVersion != 1 ||
		body.OperationID != intent.Intent.OperationID || body.ApprovalIntentSHA != intent.SHA ||
		!resetEvidenceSHA.MatchString(planSHA) || body.ApprovalPlanSHA != planSHA || requireResetIntentPlan(intent, plan) != nil ||
		!resetEvidenceSHA.MatchString(gatewaySHA) || body.GatewayPayloadSHA != gatewaySHA ||
		!gitSHA40.MatchString(sourceSHA) || body.CommandEvidence.ProducerSourceSHA != sourceSHA ||
		body.CommandEvidence.SQLSHA != resetD101OriginalSHA([]byte(resetD101OldWorldSQL)) ||
		!resetEvidenceSHA.MatchString(body.PostgresContainerID) || !resetEvidenceSHA.MatchString(body.JobContainerID) || body.JobContainerID == body.PostgresContainerID ||
		!resetManifestDigest.MatchString(body.PostgresImageID) || !resetManifestDigest.MatchString(body.JobImageID) {
		return closed, errResetExecutionEvidence
	}
	started, e1 := resetD101PreStopUTC(body.CollectorStartedAtUTC)
	completed, e2 := resetD101PreStopUTC(body.CollectorCompletedAtUTC)
	if e1 != nil || e2 != nil || completed.After(readAt) || completed.Before(started) || completed.Sub(started) >= resetPreflightMaxAge ||
		started.Unix() < intent.Intent.WindowOpensAtUnix || !completed.Before(time.Unix(intent.Intent.DestructiveCutoffUnix, 0)) {
		return closed, errResetExecutionEvidence
	}
	canonicalWire, err := resetD101PreStopRaw(body.PreResetOriginalsBase64url, body.PreResetOriginalsSHA, 16*1024)
	canonical, canonicalErr := decodeResetD101PreResetOriginal(canonicalWire, body.PreResetOriginalsSHA)
	oldWire, oldErr := resetD101PreStopRaw(body.OldWorldBytesBase64url, body.OldWorldSHA, 16*1024)
	var old resetD101OldWorldOriginal
	if err != nil || canonicalErr != nil || oldErr != nil || decodeResetPrivateJSON(oldWire, &old) != nil {
		return closed, errResetExecutionEvidence
	}
	old, err = decodeResetD101OldWorld(oldWire, old.DatabaseName, old.DatabaseUser, old.ServerAddress, started, completed)
	generation, generationErr := strconv.ParseInt(old.GenerationRaw, 10, 32)
	if err != nil || generationErr != nil || canonical.registry.Generation != nil && int64(*canonical.registry.Generation) != generation ||
		canonical.registry.ScenarioCode != nil && *canonical.registry.ScenarioCode != old.ScenarioCode {
		return closed, errResetExecutionEvidence
	}
	// Coverage of the independently pinned current 14-command collector, not
	// a new aggregate evidence cap. A changed collector requires exact review.
	if len(body.Observations) != 17 || len(body.CommandEvidence.Invocations) != 14 {
		return closed, errResetExecutionEvidence
	}
	sqlAt, sqlTimeErr := resetD101RecoveryUTC(old.ObservedAtUTC)
	if sqlTimeErr != nil {
		return closed, errResetExecutionEvidence
	}
	var previous time.Time
	for i, frame := range body.Observations {
		begin, e1 := resetD101PreStopUTC(frame.StartedAtUTC)
		end, e2 := resetD101PreStopUTC(frame.CompletedAtUTC)
		query, rawErr := base64.RawURLEncoding.Strict().DecodeString(frame.GatewayQueryBase64)
		if e1 != nil || e2 != nil || end.After(readAt) || end.Before(begin) || end.Sub(begin) >= resetPreflightMaxAge || begin.Before(previous) ||
			begin.Unix() < intent.Intent.WindowOpensAtUnix || !end.Before(time.Unix(intent.Intent.DestructiveCutoffUnix, 0)) ||
			rawErr != nil || len(query) == 0 || len(query) > 64*1024 || base64.RawURLEncoding.EncodeToString(query) != frame.GatewayQueryBase64 {
			return closed, errResetExecutionEvidence
		}
		gateway, err := decodeResetD101GatewayPreStop(query, intent, gatewaySHA, end)
		if err != nil || gateway.execution.VerifyingRevision != body.VerifyingRevision || !bytes.Equal(gateway.preReset.Original(), canonicalWire) {
			return closed, errResetExecutionEvidence
		}
		publicationRaw, rawErr := resetD101PreStopRaw(frame.Publication.BodyBase64, frame.Publication.BodySHA, 16*1024)
		publicationAt, atErr := resetD101PreStopUTC(frame.Publication.ObservedAtUTC)
		publication := resetAdminPublicationObservation{ObservedAt: publicationAt, BodySHA256: frame.Publication.BodySHA, Current: frame.Publication.Current, original: publicationRaw}
		binding := resetExecutionPhaseBinding{OperationID: body.OperationID, Target: intent.Target, Evidence: resetExecutionEvidenceRefs{ApprovalPlanSHA: planSHA}}
		observed, observedErr := resetD101PreStopUTC(frame.Snapshot.ObservedAtUTC)
		s := frame.Snapshot
		if rawErr != nil || atErr != nil || publicationAt.Before(begin) || publicationAt.After(end) || requireResetD101PublicationOriginal(publication, binding, body.VerifyingRevision) != nil ||
			observedErr != nil || observed.Before(begin) || observed.After(end) || s.ServerID != "pep" || s.OperationID != body.OperationID || s.TargetFingerprint != plan.TargetFingerprint ||
			s.PublicationState != "VERIFYING" || s.PublicationRevision != body.VerifyingRevision || s.WriterFreezeReceiptSHA != plan.WriterFreezeReceiptSHA || !s.WriterFreezeHeld {
			return closed, errResetExecutionEvidence
		}
		previous = end
		if i == 0 || i == 15 || i == 16 {
			if frame.Invocation != nil {
				return closed, errResetExecutionEvidence
			}
			continue
		}
		invocation := frame.Invocation
		if invocation == nil || invocation.GuardObservationIndex != i || invocation.CommandID == "" ||
			!resetEvidenceSHA.MatchString(invocation.ArgvSHA) || *invocation != body.CommandEvidence.Invocations[i-1] {
			return closed, errResetExecutionEvidence
		}
		commandStart, e1 := resetD101PreStopUTC(invocation.StartedAtUTC)
		commandEnd, e2 := resetD101PreStopUTC(invocation.CompletedAtUTC)
		if e1 != nil || e2 != nil || commandStart.Before(end) || commandEnd.Before(commandStart) || commandStart.Before(started) || commandEnd.After(completed) {
			return closed, errResetExecutionEvidence
		}
		if i == 8 && (invocation.CommandID != "docker:start:8" || sqlAt.Before(commandStart) || sqlAt.After(commandEnd)) {
			return closed, errResetExecutionEvidence
		}
		previous = commandEnd
	}
	return resetD101PreStopNativeOriginal{body, old, canonical, bytes.Clone(wire), sha}, nil
}
