package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecoveryResultEndpointChecksIdentitySHAAndProofBeforeResponse(t *testing.T) {
	op := strings.Repeat("a", 32)
	wire := []byte("SYNTHETIC transport fixture only\n")
	sha := resetD101OriginalSHA(wire)
	path := "/operations/" + op + "/recovery-result/" + sha
	parts := []string{op, "recovery-result", sha}
	calls := 0
	proof := "synthetic-key." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	read := func(context.Context, string, string) ([]byte, string, error) { calls++; return wire, proof, nil }
	for _, request := range []*http.Request{httptest.NewRequest(http.MethodGet, path+"?path=other", nil), httptest.NewRequest(http.MethodGet, path, strings.NewReader("{}")), httptest.NewRequest(http.MethodPost, path, nil)} {
		response := httptest.NewRecorder()
		serveResetD101RecoveryResult(response, request, parts, read)
		if response.Code == http.StatusOK || calls != 0 || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("invalid request reached source")
		}
	}
	response := httptest.NewRecorder()
	serveResetD101RecoveryResult(response, httptest.NewRequest(http.MethodGet, path, nil), parts, read)
	if response.Code != http.StatusOK || response.Body.String() != string(wire) || response.Header().Get("X-D101-Result-Proof") != proof {
		t.Fatal("original transport changed")
	}
	for _, bad := range []func(context.Context, string, string) ([]byte, string, error){nil, func(context.Context, string, string) ([]byte, string, error) { return []byte("drift"), proof, nil }, func(context.Context, string, string) ([]byte, string, error) { return wire, "malformed", nil }} {
		response := httptest.NewRecorder()
		serveResetD101RecoveryResult(response, httptest.NewRequest(http.MethodGet, path, nil), parts, bad)
		if response.Code != http.StatusServiceUnavailable || response.Header().Get("X-D101-Result-Proof") != "" {
			t.Fatal("invalid source released proof")
		}
	}
}
func TestRecoveryResultMissingActualClosureInstallationCallsNoDocker(t *testing.T) {
	calls := 0
	c := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	if wire, proof, err := c.readResetD101RecoveryResult(context.Background(), strings.Repeat("a", 32), strings.Repeat("b", 64)); err == nil || wire != nil || proof != "" || calls != 0 {
		t.Fatal("missing restore observer became a result")
	}
}
