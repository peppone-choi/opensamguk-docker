package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"time"
)

var resetD101KeyID = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)

// The approved host source must verify raw selected bytes, effective options,
// actual C4 producer output, independent approval provenance, deployment trust
// and current clock agreement. Custody/JSON hashes alone do not implement it.
// There is intentionally no success default or key-installing provider.
type resetD101PurposeAuthoritySource func(context.Context, string, string) (resetD101VerifiedPurposeAuthority, error)
type resetD101VerifiedPurposeAuthority struct {
	Intent                       resetDecodedApprovalIntent
	KeyPins                      resetD101SigningKeyPins
	DeploymentCardSHA            string
	ApprovedReceiptProvenanceSHA string
	ClockAgreementReceiptSHA     string
	ClockObservedAt              time.Time
}

type resetD101PurposeGrantClaims struct {
	SchemaVersion         int    `json:"schemaVersion"`
	KeyID                 string `json:"keyId"`
	Issuer                string `json:"issuer"`
	Subject               string `json:"subject"`
	Audience              string `json:"audience"`
	Purpose               string `json:"purpose"`
	Action                string `json:"action"`
	ServerID              string `json:"serverId"`
	OperationID           string `json:"operationId"`
	TargetFingerprint     string `json:"targetFingerprint"`
	ApprovalIntentSHA     string `json:"approvalIntentSha256"`
	GatewayPayloadSHA     string `json:"gatewayPayloadSha256"`
	InitialPublicRevision string `json:"initialPublicRevision"`
	Method                string `json:"method"`
	Path                  string `json:"path"`
	RequestBodySHA        string `json:"requestBodySha256"`
	IssuedAtUnix          int64  `json:"issuedAtUnix"`
	ExpiresAtUnix         int64  `json:"expiresAtUnix"`
	Nonce                 string `json:"nonce"`
}

type resetD101PurposeGrantRequest struct {
	OperationID       string
	ApprovalIntentSHA string
	GatewayPayloadSHA string
	Action            string
	Body              []byte
}

func resetD101PurposeRoute(action, op string) (string, string, error) {
	if !lifecycleJobIDRe.MatchString(op) {
		return "", "", errResetExecutionEvidence
	}
	base := "/internal/d101/servers/pep/operations/" + op
	switch action {
	case "PREPARE":
		return "POST", base + "/prepare", nil
	case "QUERY":
		return "GET", base, nil
	case "DISPATCH_INTENT":
		return "POST", base + "/dispatch-intent", nil
	case "SETTLE_REGISTRY":
		return "POST", base + "/terminal", nil
	}
	return "", "", errResetExecutionEvidence
}

func requireResetD101Authority(authority resetD101VerifiedPurposeAuthority, request resetD101PurposeGrantRequest, now time.Time) (resetDecodedApprovalIntent, error) {
	intent, err := decodeResetApprovalIntent(authority.Intent.originalBytes(), request.ApprovalIntentSHA)
	if err != nil || authority.Intent.SHA != request.ApprovalIntentSHA || intent.Intent.OperationID != request.OperationID ||
		!resetD101KeyID.MatchString(authority.KeyPins.KeyID) || !resetEvidenceSHA.MatchString(authority.KeyPins.PublicKeySpkiSHA) ||
		!resetEvidenceSHA.MatchString(authority.DeploymentCardSHA) || !resetEvidenceSHA.MatchString(authority.ApprovedReceiptProvenanceSHA) ||
		!resetEvidenceSHA.MatchString(authority.ClockAgreementReceiptSHA) || authority.ClockObservedAt.Unix() <= 0 ||
		authority.ClockObservedAt.After(now) || now.Sub(authority.ClockObservedAt) >= resetPreflightMaxAge {
		return resetDecodedApprovalIntent{}, errResetExecutionEvidence
	}
	switch request.Action {
	case "PREPARE", "DISPATCH_INTENT":
		if now.Unix() < intent.Intent.WindowOpensAtUnix || now.Unix() >= intent.Intent.DestructiveCutoffUnix {
			return resetDecodedApprovalIntent{}, errResetExecutionEvidence
		}
	case "SETTLE_REGISTRY":
		if now.Unix() < intent.Intent.WindowOpensAtUnix || now.Unix() >= intent.Intent.RecoveryDeadlineUnix {
			return resetDecodedApprovalIntent{}, errResetExecutionEvidence
		}
	case "QUERY":
	default:
		return resetDecodedApprovalIntent{}, errResetExecutionEvidence
	}
	return intent, nil
}

// A new nonce only produces short-lived purpose proof for the same durable op.
// It cannot renew approval, acceptedAt, physical phase evidence or a cutoff.
func issueResetD101PurposeGrant(ctx context.Context, source resetD101PurposeAuthoritySource, request resetD101PurposeGrantRequest, clock func() time.Time) (string, error) {
	return issueResetD101PurposeGrantWithKeyReader(ctx, source, request, clock, readResetD101SigningKey)
}

// Key-reader injection belongs only to isolated custody tests, never HTTP input.
func issueResetD101PurposeGrantWithKeyReader(ctx context.Context, source resetD101PurposeAuthoritySource, request resetD101PurposeGrantRequest, clock func() time.Time, readKey func(resetD101SigningKeyPins) (resetD101SigningKey, error)) (string, error) {
	if source == nil || clock == nil || readKey == nil || ctx == nil || ctx.Err() != nil || !resetEvidenceSHA.MatchString(request.ApprovalIntentSHA) ||
		!resetEvidenceSHA.MatchString(request.GatewayPayloadSHA) {
		return "", errResetExecutionEvidence
	}
	method, path, err := resetD101PurposeRoute(request.Action, request.OperationID)
	body := append([]byte(nil), request.Body...)
	limit := 16 * 1024
	if request.Action == "PREPARE" {
		limit = 64 * 1024
	}
	if err != nil || len(body) > limit || (request.Action == "QUERY" && len(body) != 0) {
		return "", errResetExecutionEvidence
	}
	bodySum := sha256.Sum256(body)
	bodySHA := hex.EncodeToString(bodySum[:])
	if request.Action == "PREPARE" && request.GatewayPayloadSHA != bodySHA {
		return "", errResetExecutionEvidence
	}
	authority, err := source(ctx, request.OperationID, request.ApprovalIntentSHA)
	if err != nil || ctx.Err() != nil {
		return "", errResetExecutionEvidence
	}
	now := clock()
	intent, err := requireResetD101Authority(authority, request, now)
	if err != nil || now.Unix() <= 0 {
		return "", errResetExecutionEvidence
	}
	if request.Action == "PREPARE" {
		var prepare struct {
			SchemaVersion     int    `json:"schemaVersion"`
			ApprovalIntentSHA string `json:"approvalIntentSha256"`
			IntentBytes       string `json:"approvalIntentBytesBase64url"`
		}
		if requireResetIntentShape(body, reflect.TypeOf(prepare)) != nil || decodeResetPrivateJSON(body, &prepare) != nil ||
			prepare.SchemaVersion != 1 || prepare.ApprovalIntentSHA != intent.SHA {
			return "", errResetExecutionEvidence
		}
		original, err := base64.RawURLEncoding.Strict().DecodeString(prepare.IntentBytes)
		if err != nil || base64.RawURLEncoding.EncodeToString(original) != prepare.IntentBytes || !bytes.Equal(original, intent.originalBytes()) {
			return "", errResetExecutionEvidence
		}
	}
	key, err := readKey(authority.KeyPins)
	if err != nil {
		return "", errResetExecutionEvidence
	}
	defer key.close()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", errResetExecutionEvidence
	}
	claims := resetD101PurposeGrantClaims{1, key.keyID, "opensamguk-root-issuer", "opensamguk-d101-root-executor",
		"opensamguk-gateway-d101-v1", "D101_PEP_RESET", request.Action, "pep", request.OperationID, intent.Intent.TargetFingerprint,
		request.ApprovalIntentSHA, request.GatewayPayloadSHA, intent.Intent.InitialPublicRevision, method, path, bodySHA,
		now.Unix(), now.Unix() + 60, hex.EncodeToString(nonce)}
	original, err := json.Marshal(claims)
	if err != nil || len(original) > 4096 {
		return "", errResetExecutionEvidence
	}
	signature, err := key.sign("OPENSAMGUK-D101-GRANT-V1\n", original)
	if err != nil {
		return "", errResetExecutionEvidence
	}
	completed := clock()
	if ctx.Err() != nil || completed.Before(now) || completed.Unix() >= claims.ExpiresAtUnix {
		return "", errResetExecutionEvidence
	}
	if _, err := requireResetD101Authority(authority, request, completed); err != nil {
		return "", errResetExecutionEvidence
	}
	return base64.RawURLEncoding.EncodeToString(original) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
