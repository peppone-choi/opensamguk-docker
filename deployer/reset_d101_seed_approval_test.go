package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSeedApprovalSourceWithoutCurrentInstallationOrWorkerNeverCallsDocker(t *testing.T) {
	calls := 0
	c := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	if wire, err := c.readResetD101SeedApproval(context.Background(), strings.Repeat("a", 32), strings.Repeat("b", 64)); err == nil || wire != nil || calls != 0 {
		t.Fatal("uninstalled source released approval")
	}
}
func TestSeedApprovalReadEndpointRejectsWrongIdentityBodyAndQueryBeforeSource(t *testing.T) {
	op := strings.Repeat("a", 32)
	sha := strings.Repeat("b", 64)
	path := "/operations/" + op + "/seed-approval/" + sha
	parts := []string{op, "seed-approval", sha}
	calls := 0
	read := func(context.Context, string, string) ([]byte, error) { calls++; return nil, errResetExecutionEvidence }
	for _, request := range []*http.Request{httptest.NewRequest(http.MethodGet, path+"?path=other", nil), httptest.NewRequest(http.MethodGet, path, strings.NewReader("{}")), httptest.NewRequest(http.MethodPost, path, nil)} {
		response := httptest.NewRecorder()
		serveResetD101SeedApproval(response, request, parts, read)
		if response.Code == http.StatusOK || calls != 0 || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("invalid request reached source")
		}
	}
	response := httptest.NewRecorder()
	serveResetD101SeedApproval(response, httptest.NewRequest(http.MethodGet, path, nil), parts, nil)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("nil producer accepted")
	}
}
