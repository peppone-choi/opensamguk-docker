package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func resetD101ResultFixture(t *testing.T) (resetD101ExecutionResult, resetDecodedApprovalIntent, resetApprovalPlan, resetPreflightReceipt, durableOperationRecord, time.Time) {
	t.Helper()
	wire, sha, plan := resetIntentFixture(t)
	intent, err := decodeResetApprovalIntent(wire, sha)
	if err != nil {
		t.Fatal(err)
	}
	_, preflight, now := resetEvidenceFixture(t)
	preflight.TargetFingerprint = plan.TargetFingerprint
	refs := resetExecutionEvidenceRefs{preflight.ApprovalPlanSHA, strings.Repeat("d", 64)}
	fingerprint, err := resetExecutionRequestFingerprint("pep", plan.Target, refs)
	if err != nil {
		t.Fatal(err)
	}
	record := durableOperationRecord{OperationID: plan.OperationID, Kind: lifecycleKindReset, SubjectID: "pep", RequestFingerprint: fingerprint,
		Status: lifecycleJobSucceeded, CreatedAt: now.Add(-time.Second), UpdatedAt: now, HTTPStatus: 200, PublicMessage: "reset done"}
	journal, runtime := strings.Repeat("e", 64), strings.Repeat("f", 64)
	result := resetD101ExecutionResult{1, "pep", 1, plan.OperationID, "reset", "succeeded", 0, "scenario_3190", "빼섭", sha,
		refs.ApprovalPlanSHA, refs.ExecutionReceiptSHA, plan.TargetFingerprint, fingerprint, strings.Repeat("c", 64), "2", plan.AppSourceSHA,
		plan.NewImageDigests, record.CreatedAt.UTC().Format(time.RFC3339Nano), record.UpdatedAt.UTC().Format(time.RFC3339Nano), &journal, &runtime, nil}
	return result, intent, plan, preflight, record, now
}

func TestResetD101ResultBindsCurrentRecordAndRejectsChangedOutcome(t *testing.T) {
	result, intent, plan, preflight, record, now := resetD101ResultFixture(t)
	wire, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	decoded, err := decodeResetD101ExecutionResult(wire, hex.EncodeToString(sum[:]))
	if err != nil || requireResetD101ResultBinding(decoded, intent, plan, preflight, record, now) != nil {
		t.Fatal("correct result binding failed", err)
	}
	changes := map[string]func(*durableOperationRecord){
		"running":     func(r *durableOperationRecord) { r.Status = lifecycleJobRunning },
		"kind":        func(r *durableOperationRecord) { r.Kind = lifecycleKindCreate },
		"subject":     func(r *durableOperationRecord) { r.SubjectID = "other" },
		"operation":   func(r *durableOperationRecord) { r.OperationID = strings.Repeat("b", 32) },
		"fingerprint": func(r *durableOperationRecord) { r.RequestFingerprint = strings.Repeat("b", 64) },
		"accepted":    func(r *durableOperationRecord) { r.CreatedAt = r.CreatedAt.Add(time.Second) },
		"completed":   func(r *durableOperationRecord) { r.UpdatedAt = r.UpdatedAt.Add(time.Second) },
		"intent":      func(r *durableOperationRecord) { r.D101IntentSHA = strings.Repeat("b", 64) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			bad := record
			change(&bad)
			if requireResetD101ResultBinding(decoded, intent, plan, preflight, bad, now) == nil {
				t.Fatal("different durable record accepted")
			}
		})
	}
	if requireResetD101ResultBinding(decoded, intent, plan, preflight, record, now.Add(-time.Second)) == nil {
		t.Fatal("future completion accepted")
	}
	// Old completed results remain readable; a read never replaces acceptedAt.
	if requireResetD101ResultBinding(decoded, intent, plan, preflight, record, now.Add(24*time.Hour)) != nil {
		t.Fatal("completed receipt re-aged")
	}
}

func TestResetD101ResultStrictShapeAndSuccessRequiresPhysicalProofReferences(t *testing.T) {
	result, _, _, _, _, _ := resetD101ResultFixture(t)
	mutate := map[string]func(*resetD101ExecutionResult){
		"journal-missing":     func(r *resetD101ExecutionResult) { r.ExecutionJournalSHA = nil },
		"runtime-missing":     func(r *resetD101ExecutionResult) { r.ActualRuntimeReceiptSHA = nil },
		"failure-on-success":  func(r *resetD101ExecutionResult) { v := "WORKER_FAILED"; r.FailureCode = &v },
		"unknown-status":      func(r *resetD101ExecutionResult) { r.Status = "running" },
		"failed-without-code": func(r *resetD101ExecutionResult) { r.Status = "failed" },
	}
	for name, change := range mutate {
		t.Run(name, func(t *testing.T) {
			bad := result
			change(&bad)
			wire, _ := json.Marshal(bad)
			sum := sha256.Sum256(wire)
			if _, err := decodeResetD101ExecutionResult(wire, hex.EncodeToString(sum[:])); err == nil {
				t.Fatal("invalid success accepted")
			}
		})
	}
	wire, _ := json.Marshal(result)
	alias := strings.Replace(string(wire), `"schemaVersion"`, `"SchemaVersion"`, 1)
	sum := sha256.Sum256([]byte(alias))
	if _, err := decodeResetD101ExecutionResult([]byte(alias), hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("case alias accepted")
	}
	nulled := strings.Replace(string(wire), `"generation":0`, `"generation":null`, 1)
	sum = sha256.Sum256([]byte(nulled))
	if _, err := decodeResetD101ExecutionResult([]byte(nulled), hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("null generation accepted")
	}
}

func TestResetD101ResultHttpMissingAuthorityNeverReturnsCompletion(t *testing.T) {
	op, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	path := "/operations/" + op + "/execution-result/" + sha
	cfg := config{}
	recorder := httptest.NewRecorder()
	cfg.handleOperation(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	if recorder.Code != 503 || recorder.Header().Get("X-D101-Result-Proof") != "" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing authority produced result")
	}
	for _, route := range []string{path + "?x=1", path + "/", strings.Replace(path, "execution-result", "execution%2Dresult", 1)} {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, route, nil)
		serveResetD101ExecutionResult(recorder, req, strings.Split(strings.TrimPrefix(req.URL.Path, "/operations/"), "/"), nil)
		if recorder.Code != 400 {
			t.Fatalf("nonexact route accepted: %s status %d", route, recorder.Code)
		}
	}
}

func TestResetD101ResultHttpDeadlineRetainsSlotUntilReaderExits(t *testing.T) {
	op, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	path := "/operations/" + op + "/execution-result/" + sha
	release, started, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	read := func(context.Context, string, string) ([]byte, string, error) {
		close(started)
		<-release
		return nil, "", errResetExecutionEvidence
	}
	recorder := httptest.NewRecorder()
	go func() {
		serveResetD101ExecutionResult(recorder, httptest.NewRequest(http.MethodGet, path, nil), []string{op, "execution-result", sha}, read)
		close(done)
	}()
	<-started
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("HTTP deadline not bounded")
	}
	if recorder.Code != 503 || len(resetD101ResultReadSlots) != 1 {
		close(release)
		t.Fatal("expired reader released capacity early")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for len(resetD101ResultReadSlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(resetD101ResultReadSlots) != 0 {
		t.Fatal("reader slot leaked")
	}
}

func TestResetD101ResultCliExactRouteAndBoundedReply(t *testing.T) {
	op, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	path := "/operations/" + op + "/execution-result/" + sha
	if !isAuthenticatedHTTPRouteAllowed("GET", path) {
		t.Fatal("exact result route unavailable")
	}
	for _, bad := range []string{path + "?x=1", path + "/", strings.Replace(path, op, "pep", 1), strings.Replace(path, sha, "not-sha", 1)} {
		if isAuthenticatedHTTPRouteAllowed("GET", bad) {
			t.Fatal("nonexact result route allowed")
		}
	}
	if isAuthenticatedHTTPRouteAllowed("POST", path) {
		t.Fatal("result mutation route allowed")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", resetD101ResultMaxBytes+1))
	}))
	defer server.Close()
	cfg := config{token: "synthetic-service-token", localHTTPBaseURL: server.URL}
	var out, errors bytes.Buffer
	if code := authenticatedHTTPCommand(cfg, "GET", path, strings.NewReader(""), &out, &errors); code != 1 || out.Len() != 0 {
		t.Fatal("oversized result leaked partial output")
	}
}
