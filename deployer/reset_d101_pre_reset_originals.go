package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Gateway captures these nullable canonical values before its PREPARE CAS.
// A null registry identity stays null; the actual frozen DB identity is separate.
type resetD101CapturedRegistry struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	GameAPIURL    string  `json:"gameApiUrl"`
	GameEngineURL string  `json:"gameEngineUrl"`
	DeployProject string  `json:"deployProject"`
	Generation    *int    `json:"generation"`
	ScenarioCode  *string `json:"scenarioCode"`
}
type resetD101CapturedPublication struct {
	State                string  `json:"state"`
	Revision             string  `json:"revision"`
	OperationID          *string `json:"operationId"`
	ExpectedGeneration   *int    `json:"expectedGeneration"`
	ExpectedScenarioCode *string `json:"expectedScenarioCode"`
	TargetFingerprint    *string `json:"targetFingerprint"`
}
type resetD101PreResetOriginal struct {
	SchemaVersion         int             `json:"schemaVersion"`
	Kind                  string          `json:"kind"`
	OperationID           string          `json:"operationId"`
	ApprovalIntentSHA     string          `json:"approvalIntentSha256"`
	TargetFingerprint     string          `json:"targetFingerprint"`
	GatewayPayloadSHA     string          `json:"gatewayPayloadSha256"`
	InitialPublicRevision string          `json:"initialPublicRevision"`
	OldRegistry           json.RawMessage `json:"oldRegistry"`
	OldPublication        json.RawMessage `json:"oldPublication"`
}
type resetD101PreResetCapture struct {
	original    []byte
	sha         string
	value       resetD101PreResetOriginal
	registry    resetD101CapturedRegistry
	publication resetD101CapturedPublication
}

func (v resetD101PreResetCapture) Original() []byte { return append([]byte(nil), v.original...) }
func (v resetD101PreResetCapture) RegistryOriginal() []byte {
	return append([]byte(nil), v.value.OldRegistry...)
}
func (v resetD101PreResetCapture) PublicationOriginal() []byte {
	return append([]byte(nil), v.value.OldPublication...)
}

// Local nullable shape checking does not relax the non-null intent/card rules.
func requireResetD101NullableShape(wire []byte, shape reflect.Type, nullable map[string]bool, rawObjects map[string]bool) error {
	var fields map[string]json.RawMessage
	if !utf8.Valid(wire) || decodeResetPrivateJSON(wire, &fields) != nil || len(fields) != shape.NumField() {
		return errResetExecutionEvidence
	}
	for i := 0; i < shape.NumField(); i++ {
		field := shape.Field(i)
		key := field.Tag.Get("json")
		raw, exists := fields[key]
		if !exists {
			return errResetExecutionEvidence
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			if !nullable[key] {
				return errResetExecutionEvidence
			}
			continue
		}
		if rawObjects[key] {
			var object map[string]json.RawMessage
			if decodeResetPrivateJSON(raw, &object) != nil || object == nil {
				return errResetExecutionEvidence
			}
			continue
		}
		kind := field.Type
		if kind.Kind() == reflect.Ptr {
			kind = kind.Elem()
		}
		if requireResetIntentShape(raw, kind) != nil {
			return errResetExecutionEvidence
		}
	}
	return nil
}
func decodeResetD101PreResetOriginal(wire []byte, sha string) (resetD101PreResetCapture, error) {
	closed := resetD101PreResetCapture{}
	var value resetD101PreResetOriginal
	if len(wire) == 0 || len(wire) > 16*1024 || !resetEvidenceSHA.MatchString(sha) || resetD101OriginalSHA(wire) != sha ||
		requireResetD101NullableShape(wire, reflect.TypeOf(value), nil, map[string]bool{"oldRegistry": true, "oldPublication": true}) != nil || decodeResetPrivateJSON(wire, &value) != nil {
		return closed, errResetExecutionEvidence
	}
	revision, err := strconv.ParseInt(value.InitialPublicRevision, 10, 64)
	if err != nil || revision <= 0 || strconv.FormatInt(revision, 10) != value.InitialPublicRevision || value.SchemaVersion != 1 || value.Kind != "D101_PRE_RESET_ORIGINALS_V1" ||
		!lifecycleJobIDRe.MatchString(value.OperationID) || !resetEvidenceSHA.MatchString(value.ApprovalIntentSHA) || !resetEvidenceSHA.MatchString(value.TargetFingerprint) || !resetEvidenceSHA.MatchString(value.GatewayPayloadSHA) {
		return closed, errResetExecutionEvidence
	}
	var registry resetD101CapturedRegistry
	var publication resetD101CapturedPublication
	if requireResetD101NullableShape(value.OldRegistry, reflect.TypeOf(registry), map[string]bool{"generation": true, "scenarioCode": true}, nil) != nil || decodeResetPrivateJSON(value.OldRegistry, &registry) != nil ||
		requireResetD101NullableShape(value.OldPublication, reflect.TypeOf(publication), map[string]bool{"operationId": true, "expectedGeneration": true, "expectedScenarioCode": true, "targetFingerprint": true}, nil) != nil || decodeResetPrivateJSON(value.OldPublication, &publication) != nil {
		return closed, errResetExecutionEvidence
	}
	if registry.ID != "pep" || strings.TrimSpace(registry.Name) == "" || strings.TrimSpace(registry.GameAPIURL) == "" || strings.TrimSpace(registry.GameEngineURL) == "" || strings.TrimSpace(registry.DeployProject) == "" ||
		(registry.Generation != nil && (*registry.Generation < 0 || *registry.Generation > 2147483647)) || (registry.ScenarioCode != nil && strings.TrimSpace(*registry.ScenarioCode) == "") || publication.State != "PUBLIC" || publication.Revision != value.InitialPublicRevision {
		return closed, errResetExecutionEvidence
	}
	anyTarget := publication.OperationID != nil || publication.ExpectedGeneration != nil || publication.ExpectedScenarioCode != nil || publication.TargetFingerprint != nil
	if anyTarget && (publication.OperationID == nil || publication.ExpectedGeneration == nil || publication.ExpectedScenarioCode == nil || publication.TargetFingerprint == nil ||
		!lifecycleJobIDRe.MatchString(*publication.OperationID) || *publication.ExpectedGeneration < 0 || *publication.ExpectedGeneration > 2147483647 || strings.TrimSpace(*publication.ExpectedScenarioCode) == "" || !resetEvidenceSHA.MatchString(*publication.TargetFingerprint)) {
		return closed, errResetExecutionEvidence
	}
	return resetD101PreResetCapture{append([]byte(nil), wire...), sha, value, registry, publication}, nil
}

// Normal QUERY is execution15 + capture2; recovery QUERY adds BEGIN2.
// Mutation replies still use the existing execution15 decoder.
func decodeResetD101GatewayQueryCapture(wire []byte, recovery bool) ([]byte, resetD101PreResetCapture, error) {
	closed := resetD101PreResetCapture{}
	var fields map[string]json.RawMessage
	count := reflect.TypeOf(resetD101GatewayExecution{}).NumField() + 2
	if recovery {
		count += 2
	}
	if len(wire) == 0 || len(wire) > 64*1024 || !utf8.Valid(wire) || decodeResetPrivateJSON(wire, &fields) != nil || len(fields) != count {
		return nil, closed, errResetExecutionEvidence
	}
	var encoded, sha string
	if decodeResetPrivateJSON(fields["preResetOriginalsBytesBase64url"], &encoded) != nil || decodeResetPrivateJSON(fields["preResetOriginalsSha256"], &sha) != nil || len(encoded) > 24*1024 {
		return nil, closed, errResetExecutionEvidence
	}
	original, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(original) != encoded {
		return nil, closed, errResetExecutionEvidence
	}
	capture, err := decodeResetD101PreResetOriginal(original, sha)
	if err != nil {
		return nil, closed, errResetExecutionEvidence
	}
	delete(fields, "preResetOriginalsBytesBase64url")
	delete(fields, "preResetOriginalsSha256")
	if recovery {
		if _, ok := fields["recoveryBeginReceiptBytesBase64url"]; !ok {
			return nil, closed, errResetExecutionEvidence
		}
		if _, ok := fields["recoveryBeginReceiptSha256"]; !ok {
			return nil, closed, errResetExecutionEvidence
		}
		delete(fields, "recoveryBeginReceiptBytesBase64url")
		delete(fields, "recoveryBeginReceiptSha256")
	}
	executionWire, err := json.Marshal(fields)
	value, decodeErr := decodeResetD101GatewayExecution(executionWire)
	if err != nil || decodeErr != nil || value.OperationID != capture.value.OperationID || value.ApprovalIntentSHA != capture.value.ApprovalIntentSHA || value.TargetFingerprint != capture.value.TargetFingerprint || value.GatewayPayloadSHA != capture.value.GatewayPayloadSHA || value.InitialPublicRevision != capture.value.InitialPublicRevision {
		return nil, closed, errResetExecutionEvidence
	}
	return executionWire, capture, nil
}

// The directory must already be installed under native private custody. Exact
// same-byte replay is allowed; a different original can never overwrite it.
func (c config) retainResetD101PreResetCapture(capture resetD101PreResetCapture) error {
	return c.retainResetD101PreResetCaptureWithCustodyUID(capture, 0)
}

// The UID seam is only for isolated file fixtures.
func (c config) retainResetD101PreResetCaptureWithCustodyUID(capture resetD101PreResetCapture, uid uint32) error {
	dir := filepath.Join(c.serversDir, ".deployer-reset-pre-reset-originals")
	if _, err := decodeResetD101PreResetOriginal(capture.original, capture.sha); err != nil {
		return errResetExecutionEvidence
	}
	return writeResetImmutablePrivateBytesWithUID(dir, capture.value.OperationID, capture.sha, capture.original, uid)
}
