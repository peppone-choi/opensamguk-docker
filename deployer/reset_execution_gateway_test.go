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

func resetD101GatewayDispatchFixture(t *testing.T) ([]byte, resetDecodedApprovalIntent, resetExecutionEvidence, resetExecutionPhaseBinding, string) {
	t.Helper()
	original, sha, plan := resetIntentFixture(t)
	intent, err := decodeResetApprovalIntent(original, sha)
	if err != nil {
		t.Fatal(err)
	}
	_, preflight, accepted := resetEvidenceFixture(t)
	preflight.TargetFingerprint = plan.TargetFingerprint
	binding := resetExecutionPhaseBinding{OperationID: plan.OperationID, Target: plan.Target, Evidence: resetExecutionEvidenceRefs{preflight.ApprovalPlanSHA, strings.Repeat("d", 64)}, AcceptedAtUnix: accepted.Unix(), Phase: "prepared"}
	fingerprint, err := resetExecutionRequestFingerprint("pep", plan.Target, binding.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	bodySHA := strings.Repeat("e", 64)
	value := resetD101GatewayExecution{SchemaVersion: 1, ServerID: "pep", OperationID: plan.OperationID, State: "DISPATCH_INTENT", TargetFingerprint: plan.TargetFingerprint,
		ApprovalIntentSHA: sha, GatewayPayloadSHA: bodySHA, InitialPublicRevision: "1", VerifyingRevision: "2", RootRequestFingerprint: &fingerprint,
		CreatedAtUTC: accepted.UTC().Format(time.RFC3339Nano), UpdatedAtUTC: accepted.Add(time.Second).UTC().Format(time.RFC3339Nano)}
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return wire, intent, resetExecutionEvidence{plan, preflight}, binding, bodySHA
}

func TestResetD101GatewayDispatchRequiresExactActualTransactionStateAndBindings(t *testing.T) {
	wire, intent, evidence, binding, bodySHA := resetD101GatewayDispatchFixture(t)
	if decodeResetD101GatewayDispatch(wire, intent, evidence, binding, bodySHA, time.Now()) != nil {
		t.Fatal("correct synthetic dispatch refused")
	}
	for _, mode := range []string{"prepared", "result-present", "published-present", "validation-present", "different-op", "different-intent", "different-prepare", "different-target", "different-root-request", "different-v", "different-r", "null-version", "alias", "duplicate", "future-time"} {
		t.Run(mode, func(t *testing.T) {
			var fields map[string]any
			if json.Unmarshal(wire, &fields) != nil {
				t.Fatal("fixture")
			}
			switch mode {
			case "prepared":
				fields["state"] = "PREPARED"
			case "result-present":
				fields["rootResultReceiptSha256"] = strings.Repeat("f", 64)
			case "published-present":
				fields["publishedRevision"] = "3"
			case "validation-present":
				fields["validationReceiptSha256"] = strings.Repeat("f", 64)
			case "different-op":
				fields["operationId"] = strings.Repeat("f", 32)
			case "different-intent":
				fields["approvalIntentSha256"] = strings.Repeat("f", 64)
			case "different-prepare":
				fields["gatewayPayloadSha256"] = strings.Repeat("f", 64)
			case "different-target":
				fields["targetFingerprint"] = strings.Repeat("f", 64)
			case "different-root-request":
				fields["rootRequestFingerprint"] = strings.Repeat("f", 64)
			case "different-v":
				fields["verifyingRevision"] = "3"
			case "different-r":
				fields["initialPublicRevision"] = "2"
			case "null-version":
				fields["schemaVersion"] = nil
			case "alias":
				fields["SchemaVersion"] = fields["schemaVersion"]
				delete(fields, "schemaVersion")
			case "future-time":
				fields["updatedAtUtc"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			}
			changed, _ := json.Marshal(fields)
			if mode == "duplicate" {
				changed = []byte(strings.Replace(string(changed), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1))
			}
			if decodeResetD101GatewayDispatch(changed, intent, evidence, binding, bodySHA, time.Now()) == nil {
				t.Fatal("changed or incomplete Gateway transaction accepted")
			}
		})
	}
}

func TestResetD101GatewayDispatchHTTPBoundsAndUsesExistingCredentialAndGrant(t *testing.T) {
	wire, intent, evidence, binding, bodySHA := resetD101GatewayDispatchFixture(t)
	path := "/internal/d101/servers/pep/operations/" + binding.OperationID
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != path || r.URL.RawQuery != "" || r.Method != "GET" || r.Header.Get("Authorization") != "Bearer synthetic-service" || r.Header.Get("X-D101-Grant") != "synthetic-purpose-proof" || r.ContentLength != 0 {
			t.Error("HTTP source changed route/auth/body")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	if getResetD101GatewayDispatch(context.Background(), server.URL+path, "synthetic-service", "synthetic-purpose-proof", intent, evidence, binding, bodySHA) != nil || calls != 1 {
		t.Fatal("bounded actual HTTP fixture failed")
	}
	for _, mode := range []string{"oversize", "redirect", "error-status", "wrong-state"} {
		t.Run(mode, func(t *testing.T) {
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "oversize":
					_, _ = w.Write([]byte(strings.Repeat("x", 16*1024+1)))
				case "redirect":
					http.Redirect(w, r, server.URL+path, http.StatusTemporaryRedirect)
				case "error-status":
					w.WriteHeader(http.StatusServiceUnavailable)
				case "wrong-state":
					_, _ = w.Write([]byte(strings.Replace(string(wire), "DISPATCH_INTENT", "PREPARED", 1)))
				}
			}))
			defer source.Close()
			if getResetD101GatewayDispatch(context.Background(), source.URL+path, "synthetic-service", "synthetic-purpose-proof", intent, evidence, binding, bodySHA) == nil {
				t.Fatal("unavailable HTTP state accepted")
			}
			if calls != 1 {
				t.Fatal("redirect followed")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if getResetD101GatewayDispatch(ctx, server.URL+path, "synthetic-service", "synthetic-purpose-proof", intent, evidence, binding, bodySHA) == nil || calls != 1 {
		t.Fatal("cancelled observation continued")
	}
	if getResetD101GatewayDispatch(context.Background(), server.URL+path, "synthetic\ncredential", "synthetic-purpose-proof", intent, evidence, binding, bodySHA) == nil || calls != 1 {
		t.Fatal("invalid credential sent")
	}
}
