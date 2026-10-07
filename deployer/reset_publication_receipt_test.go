package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func resetPublicationReceiptFixture(t *testing.T) (resetPublicationReceipt, resetExecutionEvidence, durableOperationRecord, time.Time) {
	t.Helper()
	plan, _, execution := resetExecutionChainFixture(t, 3)
	_, preflight, _ := resetEvidenceFixture(t)
	issued := execution.Attestations[2].CompletedAt.Add(time.Second)
	generation := 0
	receipt := resetPublicationReceipt{Version: 1, ServerID: "pep", WorldID: 1, OperationID: plan.OperationID, Generation: &generation,
		ScenarioCode: "scenario_3190", TargetFingerprint: plan.TargetFingerprint, PublicationRevision: preflight.PublicationRevision,
		AppSourceSHA: plan.AppSourceSHA, ImageDigests: plan.NewImageDigests, SelectedSourceReceiptSHA: plan.SelectedSourceReceiptSHA,
		IsolatedSeedTickReceiptSHA: plan.IsolatedSeedTickReceiptSHA, ActualRuntimeReceiptSHA: strings.Repeat("e", 64),
		FirstTickReceiptSHA: strings.Repeat("f", 64), RoleValidationReceiptSHA: strings.Repeat("e", 64), BackupManifestSHA: preflight.BackupManifestSHA,
		IssuedAtUnix: issued.Unix(), ExpiresAtUnix: issued.Unix() + 30, Execution: execution}
	record := durableOperationRecord{OperationID: plan.OperationID, Kind: lifecycleKindReset, SubjectID: "pep",
		RequestFingerprint: execution.RequestFingerprint, Status: lifecycleJobSucceeded, CreatedAt: time.Unix(execution.AcceptedAtUnix, 0),
		UpdatedAt: issued}
	return receipt, resetExecutionEvidence{plan, preflight}, record, issued.Add(time.Second)
}

func TestResetPublicationReceiptCannotSubstituteSuccessForExactProof(t *testing.T) {
	receipt, evidence, record, now := resetPublicationReceiptFixture(t)
	if validateResetPublicationReceipt(receipt, evidence, record, now) != nil {
		t.Fatal("synthetic complete fixture refused")
	}
	clone := func() resetPublicationReceipt {
		wire, _ := json.Marshal(receipt)
		var value resetPublicationReceipt
		_ = json.Unmarshal(wire, &value)
		return value
	}
	cases := map[string]func(*resetPublicationReceipt){
		"world":              func(r *resetPublicationReceipt) { r.WorldID = 2 },
		"operation":          func(r *resetPublicationReceipt) { r.OperationID = strings.Repeat("e", 32) },
		"target":             func(r *resetPublicationReceipt) { r.TargetFingerprint = strings.Repeat("e", 64) },
		"generation":         func(r *resetPublicationReceipt) { generation := 1; r.Generation = &generation },
		"generation-missing": func(r *resetPublicationReceipt) { r.Generation = nil },
		"revision":           func(r *resetPublicationReceipt) { r.PublicationRevision = "3" },
		"app-source":         func(r *resetPublicationReceipt) { r.AppSourceSHA = strings.Repeat("e", 40) },
		"selected-bytes":     func(r *resetPublicationReceipt) { r.SelectedSourceReceiptSHA = strings.Repeat("e", 64) },
		"candidate-pin": func(r *resetPublicationReceipt) {
			r.ImageDigests["game-postgres"] = "sha256:" + strings.Repeat("f", 64)
		},
		"missing-first-tick": func(r *resetPublicationReceipt) { r.FirstTickReceiptSHA = "" },
		"missing-runtime":    func(r *resetPublicationReceipt) { r.ActualRuntimeReceiptSHA = "" },
		"missing-roles":      func(r *resetPublicationReceipt) { r.RoleValidationReceiptSHA = "" },
		"incomplete-phase":   func(r *resetPublicationReceipt) { r.Execution.Attestations = r.Execution.Attestations[:2] },
		"initial-proof":      func(r *resetPublicationReceipt) { r.Execution.Evidence.ExecutionReceiptSHA = strings.Repeat("f", 64) },
		"future":             func(r *resetPublicationReceipt) { r.IssuedAtUnix = now.Unix() + 1 },
		"expired":            func(r *resetPublicationReceipt) { r.ExpiresAtUnix = now.Unix() },
		"renewed-window":     func(r *resetPublicationReceipt) { r.ExpiresAtUnix = r.IssuedAtUnix + 31 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := clone()
			change(&bad)
			if validateResetPublicationReceipt(bad, evidence, record, now) == nil {
				t.Fatal("partial/mismatched proof accepted")
			}
		})
	}
	for _, status := range []lifecycleJobStatus{lifecycleJobPending, lifecycleJobRunning, lifecycleJobFailed, lifecycleJobRecoveryRequired} {
		bad := record
		bad.Status = status
		if validateResetPublicationReceipt(receipt, evidence, bad, now) == nil {
			t.Fatal("non-success operation became public receipt")
		}
	}
	record.RequestFingerprint = strings.Repeat("f", 64)
	if validateResetPublicationReceipt(receipt, evidence, record, now) == nil {
		t.Fatal("unbound durable identity accepted")
	}
}

func TestResetPublicationReceiptRetainsExactPrivateBytesAndRejectsTokenFields(t *testing.T) {
	cfg := configuredResetOperationTest(t)
	// The production custody reader rejects symlinked parent paths. macOS
	// temporary roots need their canonical path even in an isolated fixture.
	canonical, err := filepath.EvalSymlinks(cfg.serversDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.serversDir = canonical
	receipt, evidence, record, now := resetPublicationReceiptFixture(t)
	write := func(directory string, value any) string {
		t.Helper()
		directory = filepath.Join(cfg.serversDir, directory)
		if os.Mkdir(directory, 0700) != nil {
			t.Fatal("fixture dir")
		}
		wire, _ := json.MarshalIndent(value, "", "  ")
		wire = append(wire, '\n')
		if os.WriteFile(filepath.Join(directory, record.OperationID+".json"), wire, 0400) != nil {
			t.Fatal("fixture file")
		}
		sum := sha256.Sum256(wire)
		return hex.EncodeToString(sum[:])
	}
	planSHA := write(".deployer-reset-approvals", evidence.Plan)
	evidence.Preflight.ApprovalPlanSHA = planSHA
	preflightSHA := write(".deployer-reset-preflights", evidence.Preflight)
	receipt.Execution.Evidence = resetExecutionEvidenceRefs{planSHA, preflightSHA}
	receipt.Execution.RequestFingerprint, _ = resetExecutionRequestFingerprint("pep", evidence.Plan.Target, receipt.Execution.Evidence)
	previous := ""
	for i := range receipt.Execution.Attestations {
		a := &receipt.Execution.Attestations[i]
		a.PreviousSHA = previous
		a.SHA = resetExecutionAttestationSHA(receipt.Execution, *a)
		previous = a.SHA
	}
	record.RequestFingerprint = receipt.Execution.RequestFingerprint
	mustReserveOperation(t, cfg.lifecycleOperationStore, record)
	expected := write(".deployer-publication-receipts", receipt)
	wire, err := cfg.readResetPublicationReceiptWithCustodyUID(record.OperationID, expected, now, uint32(os.Getuid()))
	if err != nil || string(wire) != readFile(t, filepath.Join(cfg.serversDir, ".deployer-publication-receipts", record.OperationID+".json")) {
		t.Fatal("private byte custody changed or refused")
	}
	sum := sha256.Sum256(wire)
	if hex.EncodeToString(sum[:]) != expected {
		t.Fatal("projection hash replaced exact byte hash")
	}
	if _, err := cfg.readResetPublicationReceiptWithCustodyUID(record.OperationID, strings.Repeat("f", 64), now, uint32(os.Getuid())); err == nil {
		t.Fatal("wrong requested SHA accepted")
	}
	withToken := strings.Replace(string(wire), `"version": 1`, `"accessToken":"forbidden","version": 1`, 1)
	var decoded resetPublicationReceipt
	if decodeResetPrivateJSON([]byte(withToken), &decoded) == nil {
		t.Fatal("secret field entered allowlist")
	}
}

func TestResetPublicationReceiptRouteIsExactAuthorizedBoundedAndCacheless(t *testing.T) {
	cfg := testConfig(t)
	wire := []byte("{\"version\":1}\n")
	sum := sha256.Sum256(wire)
	sha := hex.EncodeToString(sum[:])
	op := strings.Repeat("a", 32)
	for _, mode := range []string{"valid", "alias", "query", "POST", "HEAD", "bad-auth", "missing", "overbody", "wrong-bytes"} {
		t.Run(mode, func(t *testing.T) {
			path := "/operations/" + op + "/validation-receipt/" + sha
			method := http.MethodGet
			token := "Bearer test-token"
			if mode == "alias" {
				path += "/"
			}
			if mode == "query" {
				path += "?path=/private"
			}
			if mode == "POST" {
				method = "POST"
			}
			if mode == "HEAD" {
				method = "HEAD"
			}
			if mode == "bad-auth" {
				token = "Bearer wrong"
			}
			calls := 0
			read := func(string, string, time.Time) ([]byte, error) {
				calls++
				if mode == "missing" {
					return nil, errResetExecutionEvidence
				}
				if mode == "overbody" {
					return make([]byte, resetEvidenceMaxBytes+1), nil
				}
				if mode == "wrong-bytes" {
					return []byte("{}"), nil
				}
				return wire, nil
			}
			handler := cfg.withAuth(func(w http.ResponseWriter, r *http.Request) {
				serveResetPublicationReceipt(w, r, strings.Split(strings.TrimPrefix(r.URL.Path, "/operations/"), "/"), read)
			})
			req := httptest.NewRequest(method, path, nil)
			req.Header.Set("Authorization", token)
			result := httptest.NewRecorder()
			handler(result, req)
			want := 200
			if mode == "alias" || mode == "query" {
				want = 400
			}
			if mode == "POST" || mode == "HEAD" {
				want = 405
			}
			if mode == "bad-auth" {
				want = 401
			}
			if mode == "missing" || mode == "overbody" || mode == "wrong-bytes" {
				want = 503
			}
			if result.Code != want {
				t.Fatalf("status %d want %d", result.Code, want)
			}
			if mode != "bad-auth" && result.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("receipt response is cacheable")
			}
			if mode == "valid" && result.Body.String() != string(wire) {
				t.Fatal("receipt bytes reserialized")
			}
			if want < 500 && want != 200 && calls != 0 {
				t.Fatal("invalid caller reached private source")
			}
		})
	}
}

func TestResetPublicationReceiptConcurrencyBusyHasNoQueue(t *testing.T) {
	wire := []byte("{}")
	sum := sha256.Sum256(wire)
	parts := []string{strings.Repeat("a", 32), "validation-receipt", hex.EncodeToString(sum[:])}
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	var wg sync.WaitGroup
	read := func(string, string, time.Time) ([]byte, error) { arrived <- struct{}{}; <-release; return wire, nil }
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveResetPublicationReceipt(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), parts, read)
		}()
	}
	<-arrived
	<-arrived
	called := false
	result := httptest.NewRecorder()
	serveResetPublicationReceipt(result, httptest.NewRequest("GET", "/", nil), parts, func(string, string, time.Time) ([]byte, error) { called = true; return nil, errors.New("unexpected") })
	if result.Code != 503 || called {
		t.Error("busy third request queued or reached source")
	}
	close(release)
	wg.Wait()
}
