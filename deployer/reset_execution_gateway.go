package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode"
)

// The host supplies an existing internal service credential under fixed private
// custody. This is not a minted ADMIN JWT or a request-selectable credential.
type resetD101GatewayCredential struct {
	Version           int    `json:"version"`
	OperationID       string `json:"operationId"`
	ApprovalIntentSHA string `json:"approvalIntentSha256"`
	TargetFingerprint string `json:"targetFingerprint"`
	ExpiresAtUnix     int64  `json:"expiresAtUnix"`
	ServiceToken      string `json:"serviceToken"`
}

var resetD101GatewayReadSlots = make(chan struct{}, 2)

type resetD101GatewayExecution struct {
	SchemaVersion          int     `json:"schemaVersion"`
	ServerID               string  `json:"serverId"`
	OperationID            string  `json:"operationId"`
	State                  string  `json:"state"`
	TargetFingerprint      string  `json:"targetFingerprint"`
	ApprovalIntentSHA      string  `json:"approvalIntentSha256"`
	GatewayPayloadSHA      string  `json:"gatewayPayloadSha256"`
	InitialPublicRevision  string  `json:"initialPublicRevision"`
	VerifyingRevision      string  `json:"verifyingRevision"`
	PublishedRevision      *string `json:"publishedRevision"`
	RootRequestFingerprint *string `json:"rootRequestFingerprint"`
	RootResultReceiptSHA   *string `json:"rootResultReceiptSha256"`
	ValidationReceiptSHA   *string `json:"validationReceiptSha256"`
	CreatedAtUTC           string  `json:"createdAtUtc"`
	UpdatedAtUTC           string  `json:"updatedAtUtc"`
}

func decodeResetD101GatewayExecution(wire []byte) (resetD101GatewayExecution, error) {
	var value resetD101GatewayExecution
	var fields map[string]json.RawMessage
	shape := reflect.TypeOf(value)
	if len(wire) == 0 || len(wire) > 16*1024 || json.Unmarshal(wire, &fields) != nil || len(fields) != shape.NumField() {
		return value, errResetExecutionEvidence
	}
	nullable := map[string]bool{"publishedRevision": true, "rootRequestFingerprint": true, "rootResultReceiptSha256": true, "validationReceiptSha256": true}
	for i := 0; i < shape.NumField(); i++ {
		field := shape.Field(i)
		raw, ok := fields[field.Tag.Get("json")]
		if !ok || (!nullable[field.Tag.Get("json")] && requireResetIntentShape(raw, field.Type) != nil) {
			return value, errResetExecutionEvidence
		}
	}
	if decodeResetPrivateJSON(wire, &value) != nil {
		return value, errResetExecutionEvidence
	}
	return value, nil
}

func decodeResetD101GatewayDispatch(wire []byte, intent resetDecodedApprovalIntent, evidence resetExecutionEvidence, binding resetExecutionPhaseBinding, gatewaySHA string, now time.Time) error {
	value, err := decodeResetD101GatewayExecution(wire)
	if err != nil {
		return errResetExecutionEvidence
	}
	fingerprint, err := resetExecutionRequestFingerprint("pep", binding.Target, binding.Evidence)
	if err != nil || value.SchemaVersion != 1 || value.ServerID != "pep" || value.State != "DISPATCH_INTENT" ||
		value.OperationID != binding.OperationID || value.OperationID != intent.Intent.OperationID || value.TargetFingerprint != intent.Intent.TargetFingerprint ||
		value.ApprovalIntentSHA != intent.SHA || value.GatewayPayloadSHA != gatewaySHA || !resetEvidenceSHA.MatchString(gatewaySHA) ||
		value.InitialPublicRevision != intent.Intent.InitialPublicRevision || value.VerifyingRevision != evidence.Preflight.PublicationRevision ||
		value.RootRequestFingerprint == nil || *value.RootRequestFingerprint != fingerprint || value.PublishedRevision != nil ||
		value.RootResultReceiptSHA != nil || value.ValidationReceiptSHA != nil || requireResetIntentPlan(intent, evidence.Plan) != nil {
		return errResetExecutionEvidence
	}
	created, err := resetC4UTC(value.CreatedAtUTC)
	updated, updatedErr := resetC4UTC(value.UpdatedAtUTC)
	if err != nil || updatedErr != nil || updated.Before(created) || updated.After(now) {
		return errResetExecutionEvidence
	}
	return nil
}

func getResetD101GatewayDispatch(ctx context.Context, endpoint, serviceToken, grant string, intent resetDecodedApprovalIntent, evidence resetExecutionEvidence, binding resetExecutionPhaseBinding, gatewaySHA string) error {
	wire, _, err := readResetD101GatewayQuery(ctx, endpoint, serviceToken, grant, 16*1024)
	if err != nil || decodeResetD101GatewayDispatch(wire, intent, evidence, binding, gatewaySHA, time.Now()) != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func readResetD101GatewayQuery(ctx context.Context, endpoint, serviceToken, grant string, limit int64) ([]byte, string, error) {
	if ctx == nil || ctx.Err() != nil || !validResetD101ServiceToken(serviceToken) || len(grant) == 0 || len(grant) > 8192 || limit <= 0 || limit > 64*1024 {
		return nil, "", errResetExecutionEvidence
	}
	select {
	case resetD101GatewayReadSlots <- struct{}{}:
	default:
		return nil, "", errResetExecutionEvidence
	}
	defer func() { <-resetD101GatewayReadSlots }()
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(bounded, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	req.Header.Set("Authorization", "Bearer "+serviceToken)
	req.Header.Set("X-D101-Grant", grant)
	req.Header.Set("Accept", "application/json")
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, "", errResetExecutionEvidence
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || bounded.Err() != nil || int64(len(wire)) > limit {
		return nil, "", errResetExecutionEvidence
	}
	return wire, response.Header.Get("Cache-Control"), nil
}

func validResetD101ServiceToken(token string) bool {
	return len(token) > 0 && len(token) <= 8192 && strings.TrimSpace(token) == token && strings.IndexFunc(token, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) < 0
}

// Observe the actual authenticated Gateway DISPATCH_INTENT. Immutable local
// plan/preflight files alone never establish this remote transaction state.
func (c config) observeResetD101GatewayDispatch(ctx context.Context, binding resetExecutionPhaseBinding, evidence resetExecutionEvidence) error {
	if c.d101PurposeAuthority == nil || ctx == nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	origin, err := url.Parse(c.defaultGatewayAPIURL())
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" ||
		(origin.Path != "" && origin.Path != "/") || origin.RawPath != "" || origin.ForceQuery || !resetPrivateGatewayHost(origin.Hostname()) {
		return errResetExecutionEvidence
	}
	authority, err := c.d101PurposeAuthority(ctx, binding.OperationID, evidence.Plan.ApprovalIntentSHA)
	if err != nil {
		return errResetExecutionEvidence
	}
	request := resetD101PurposeGrantRequest{OperationID: binding.OperationID, ApprovalIntentSHA: evidence.Plan.ApprovalIntentSHA, Action: "QUERY"}
	intent, err := requireResetD101Authority(authority, request, time.Now())
	if err != nil {
		return errResetExecutionEvidence
	}
	prepare, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), binding.OperationID, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	request.GatewayPayloadSHA = resetD101OriginalSHA(prepare)
	if requireResetD101PrepareBody(prepare, intent, request.GatewayPayloadSHA) != nil || requireResetIntentPlan(intent, evidence.Plan) != nil {
		return errResetExecutionEvidence
	}
	wire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-gateway"), binding.OperationID, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	var credential resetD101GatewayCredential
	if requireResetIntentShape(wire, reflect.TypeOf(credential)) != nil || decodeResetPrivateJSON(wire, &credential) != nil || credential.Version != 1 ||
		credential.OperationID != binding.OperationID || credential.ApprovalIntentSHA != intent.SHA || credential.TargetFingerprint != intent.Intent.TargetFingerprint ||
		credential.ExpiresAtUnix <= time.Now().Unix() || !validResetD101ServiceToken(credential.ServiceToken) {
		return errResetExecutionEvidence
	}
	grant, err := c.issueResetD101PurposeGrant(ctx, request)
	if err != nil {
		return errResetExecutionEvidence
	}
	endpoint := strings.TrimRight(origin.String(), "/") + "/internal/d101/servers/pep/operations/" + binding.OperationID
	if getResetD101GatewayDispatch(ctx, endpoint, credential.ServiceToken, grant, intent, evidence, binding, request.GatewayPayloadSHA) != nil ||
		ctx.Err() != nil || credential.ExpiresAtUnix <= time.Now().Unix() {
		return errResetExecutionEvidence
	}
	return nil
}
