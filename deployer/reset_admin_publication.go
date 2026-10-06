package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type resetAdminPublication struct {
	ServerID             string `json:"serverId"`
	SourceStatus         string `json:"sourceStatus"`
	State                string `json:"state"`
	Revision             string `json:"revision"`
	OperationID          string `json:"operationId"`
	ExpectedGeneration   *int   `json:"expectedGeneration"`
	ExpectedScenarioCode string `json:"expectedScenarioCode"`
	TargetFingerprint    string `json:"targetFingerprint"`
}
type resetAdminPublicationObservation struct {
	ObservedAt time.Time
	BodySHA256 string
	Current    resetAdminPublication
	original   []byte
}

// Keep the actual GET body, including its whitespace, independently of Current.
// Neither this original nor its digest establishes external writer authority.
func (v resetAdminPublicationObservation) Original() []byte { return bytes.Clone(v.original) }

func requireResetD101PublicationOriginal(v resetAdminPublicationObservation, binding resetExecutionPhaseBinding, revision string) error {
	var current resetAdminPublication
	if len(v.original) == 0 || len(v.original) > 16*1024 || !utf8.Valid(v.original) ||
		resetD101OriginalSHA(v.original) != v.BodySHA256 ||
		requireResetIntentShape(v.original, reflect.TypeOf(current)) != nil ||
		decodeResetPrivateJSON(v.original, &current) != nil ||
		validateResetAdminPublication(current, binding, revision) != nil ||
		!reflect.DeepEqual(current, v.Current) || v.ObservedAt.IsZero() {
		return errResetExecutionEvidence
	}
	return nil
}

// This proves the publisher's current stored target/revision only. It is not
// process-world/source/physical/tick/role/freeze evidence or a PUBLIC issuer.
func validateResetAdminPublication(value resetAdminPublication, binding resetExecutionPhaseBinding, expectedRevision string) error {
	revision, err := strconv.ParseInt(expectedRevision, 10, 64)
	if err != nil || revision <= 0 || strconv.FormatInt(revision, 10) != expectedRevision ||
		value.ServerID != "pep" || value.SourceStatus != "KNOWN" || value.State != "VERIFYING" ||
		value.Revision != expectedRevision || value.OperationID != binding.OperationID ||
		value.ExpectedGeneration == nil || *value.ExpectedGeneration != 0 || binding.Target.Generation != 0 ||
		value.ExpectedScenarioCode != "scenario_3190" || binding.Target.ScenarioCode != "scenario_3190" ||
		value.TargetFingerprint != resetRequestFingerprint("pep", binding.Target) || !lifecycleJobIDRe.MatchString(binding.OperationID) {
		return errResetExecutionEvidence
	}
	return nil
}
func getResetAdminPublication(ctx context.Context, endpoint, accessToken string, binding resetExecutionPhaseBinding, expectedRevision string) (resetAdminPublicationObservation, error) {
	if len(accessToken) > 8192 || !resetAdminJWTShape.MatchString(accessToken) {
		return resetAdminPublicationObservation{}, errResetExecutionEvidence
	}
	deadline, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(deadline, http.MethodGet, endpoint, nil)
	if err != nil {
		return resetAdminPublicationObservation{}, errResetExecutionEvidence
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Cache-Control", "no-store")
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return resetAdminPublicationObservation{}, errResetExecutionEvidence
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return resetAdminPublicationObservation{}, errResetExecutionEvidence
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, 16*1024+1))
	var value resetAdminPublication
	if err != nil || len(wire) > 16*1024 || !utf8.Valid(wire) || requireResetIntentShape(wire, reflect.TypeOf(value)) != nil || decodeResetPrivateJSON(wire, &value) != nil ||
		validateResetAdminPublication(value, binding, expectedRevision) != nil || deadline.Err() != nil {
		return resetAdminPublicationObservation{}, errResetExecutionEvidence
	}
	sum := sha256.Sum256(wire)
	return resetAdminPublicationObservation{ObservedAt: time.Now(), BodySHA256: hex.EncodeToString(sum[:]), Current: value, original: bytes.Clone(wire)}, nil
}

// No caller URL/query/role/header chooses the source. Existing gateway-api JWT
// authentication verifies ADMIN signature/audience/expiry. No token is minted.
// Worker/issuer wiring and the mandatory actual writer-freeze source are absent.
func (c config) observeResetD101Publication(ctx context.Context, binding resetExecutionPhaseBinding, expectedRevision string) (resetAdminPublicationObservation, error) {
	origin, err := url.Parse(c.defaultGatewayAPIURL())
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") ||
		origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") ||
		!resetPrivateGatewayHost(origin.Hostname()) {
		return resetAdminPublicationObservation{}, errResetExecutionEvidence
	}
	token, err := readResetAdminCredential(filepath.Join(c.serversDir, ".deployer-reset-admin"), binding, time.Now(), 0)
	if err != nil {
		return resetAdminPublicationObservation{}, errResetExecutionEvidence
	}
	return getResetAdminPublication(ctx, strings.TrimRight(origin.String(), "/")+"/admin/servers/pep/publication", token, binding, expectedRevision)
}
func resetPrivateGatewayHost(host string) bool {
	switch host {
	case "gateway-api", "opensamguk-gateway-api", "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}
