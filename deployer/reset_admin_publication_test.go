package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func resetAdminPublicationFixture(t *testing.T) (resetAdminPublication, resetExecutionPhaseBinding) {
	t.Helper()
	plan, receipt, accepted := resetEvidenceFixture(t)
	binding := resetExecutionPhaseBinding{OperationID: plan.OperationID, Target: plan.Target, AcceptedAtUnix: accepted.Unix(),
		Evidence: resetExecutionEvidenceRefs{receipt.ApprovalPlanSHA, strings.Repeat("d", 64)}}
	generation := 0
	return resetAdminPublication{"pep", "KNOWN", "VERIFYING", "2", plan.OperationID, &generation, "scenario_3190", plan.TargetFingerprint}, binding
}
func TestResetAdminPublicationFreshTargetRevisionAndZeroBinding(t *testing.T) {
	value, binding := resetAdminPublicationFixture(t)
	wire, _ := json.Marshal(value)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.RequestURI() != "/admin/servers/pep/publication" || r.Header.Get("Authorization") != "Bearer aaa.bbb.ccc" || r.Header.Get("Cache-Control") != "no-store" {
			t.Error("fixed target/auth/method/cache request changed")
		}
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	before := time.Now()
	observed, err := getResetAdminPublication(context.Background(), server.URL+"/admin/servers/pep/publication", "aaa.bbb.ccc", binding, "2")
	if err != nil || observed.Current.ExpectedGeneration == nil || *observed.Current.ExpectedGeneration != 0 || observed.BodySHA256 != resetPrivateWireSHA(wire) || observed.ObservedAt.Before(before) || calls != 1 {
		t.Fatal("fresh isolated source refused")
	}
}
func TestResetAdminPublicationUnknownOrChangedFieldsFailClosed(t *testing.T) {
	value, binding := resetAdminPublicationFixture(t)
	cases := map[string]func(*resetAdminPublication){
		"server":          func(v *resetAdminPublication) { v.ServerID = "uni" },
		"unknown":         func(v *resetAdminPublication) { v.SourceStatus = "UNKNOWN" },
		"public":          func(v *resetAdminPublication) { v.State = "PUBLIC" },
		"revision":        func(v *resetAdminPublication) { v.Revision = "3" },
		"operation":       func(v *resetAdminPublication) { v.OperationID = strings.Repeat("f", 32) },
		"generation-null": func(v *resetAdminPublication) { v.ExpectedGeneration = nil },
		"generation":      func(v *resetAdminPublication) { n := 1; v.ExpectedGeneration = &n },
		"scenario":        func(v *resetAdminPublication) { v.ExpectedScenarioCode = "3190" },
		"target":          func(v *resetAdminPublication) { v.TargetFingerprint = strings.Repeat("f", 64) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := value
			change(&bad)
			if validateResetAdminPublication(bad, binding, "2") == nil {
				t.Fatal("changed source accepted")
			}
		})
	}
	for _, revision := range []string{"0", "02", "+2", "9223372036854775808", ""} {
		if validateResetAdminPublication(value, binding, revision) == nil {
			t.Fatal("unknown/aliased revision accepted")
		}
	}
}
func TestResetAdminPublicationBoundedErrorsDoNotFallbackOrRetry(t *testing.T) {
	value, binding := resetAdminPublicationFixture(t)
	wire, _ := json.Marshal(value)
	for _, mode := range []string{"401", "403", "503", "redirect", "oversized", "missing-generation", "string-generation", "duplicate", "unknown-field", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				switch mode {
				case "401":
					w.WriteHeader(401)
				case "403":
					w.WriteHeader(403)
				case "503":
					w.WriteHeader(503)
				case "redirect":
					w.Header().Set("Location", "/different")
					w.WriteHeader(302)
				case "oversized":
					_, _ = w.Write([]byte(strings.Repeat("x", 16*1024+1)))
				case "missing-generation":
					var fields map[string]any
					_ = json.Unmarshal(wire, &fields)
					delete(fields, "expectedGeneration")
					_ = json.NewEncoder(w).Encode(fields)
				case "string-generation":
					_, _ = w.Write([]byte(strings.Replace(string(wire), `"expectedGeneration":0`, `"expectedGeneration":"0"`, 1)))
				case "duplicate":
					_, _ = w.Write([]byte(strings.TrimSuffix(string(wire), "}") + `,"state":"VERIFYING"}`))
				case "unknown-field":
					_, _ = w.Write([]byte(strings.TrimSuffix(string(wire), "}") + `,"token":"must-not-forward"}`))
				case "trailing":
					_, _ = w.Write(append(wire, []byte("{}")...))
				}
			}))
			defer server.Close()
			observed, err := getResetAdminPublication(context.Background(), server.URL+"/admin/servers/pep/publication", "aaa.bbb.ccc", binding, "2")
			if err == nil || observed.BodySHA256 != "" || calls != 1 {
				t.Fatal("unknown source projected, retried or normalized")
			}
		})
	}
	if resetPrivateGatewayHost("attacker.invalid") {
		t.Fatal("public source origin allowed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := getResetAdminPublication(ctx, "http://127.0.0.1:1", "aaa.bbb.ccc", binding, "2"); err == nil {
		t.Fatal("cancelled context became known")
	}
}
