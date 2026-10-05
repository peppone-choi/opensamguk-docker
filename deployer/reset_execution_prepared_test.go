package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Synthetic fixture: real private files/store/coordinator, no operating authority
// or Docker. The UID seam cannot be selected by configuration or HTTP input.
func resetD101PreparedFixture(t *testing.T) (config, uint32, *operationPreparation, resetExecutionEvidence, resetExecutionJournal, durableOperationRecord) {
	t.Helper()
	cfg, uid, op := resetD101IssuerFixture(t)
	live, _, _ := cfg.readLifecycleJournal()
	old := *live.ResetExecution
	if os.Remove(cfg.lifecycleJournalFile) != nil {
		t.Fatal("fixture journal removal")
	}
	for _, leaf := range []string{".deployer-reset-prepared-phases", ".deployer-reset-prepared-proofs"} {
		if os.Mkdir(filepath.Join(cfg.serversDir, leaf), 0700) != nil {
			t.Fatal("fixture private directory")
		}
	}
	var plan resetApprovalPlan
	var preflight resetPreflightReceipt
	if readResetPrivateEvidence(filepath.Join(cfg.serversDir, ".deployer-reset-approvals"), op, old.Evidence.ApprovalPlanSHA, uid, &plan) != nil ||
		readResetPrivateEvidence(filepath.Join(cfg.serversDir, ".deployer-reset-preflights"), op, old.Evidence.ExecutionReceiptSHA, uid, &preflight) != nil {
		t.Fatal("fixture source")
	}
	authority, _ := cfg.d101PurposeAuthority(context.Background(), op, plan.ApprovalIntentSHA)
	intentValue := authority.Intent.Intent
	accepted := time.Now().UTC().Truncate(time.Second).Add(-time.Second)
	plan.WindowOpensAtUnix, plan.DestructiveCutoffUnix, plan.RecoveryDeadlineUnix = accepted.Unix()-60, accepted.Unix()+300, accepted.Unix()+3600
	intentValue.WindowOpensAtUnix, intentValue.DestructiveCutoffUnix, intentValue.RecoveryDeadlineUnix = plan.WindowOpensAtUnix, plan.DestructiveCutoffUnix, plan.RecoveryDeadlineUnix
	intentWire, _ := json.Marshal(intentValue)
	intentSHA := resetD101OriginalSHA(intentWire)
	intent, err := decodeResetApprovalIntent(intentWire, intentSHA)
	if err != nil {
		t.Fatal(err)
	}
	plan.ApprovalIntentSHA = intentSHA
	planWire, _ := json.Marshal(plan)
	preflight.ApprovalPlanSHA = resetD101OriginalSHA(planWire)
	preflight.ObservedAtUnix, preflight.ExpiresAtUnix, preflight.BackupRetainUntilUnix = accepted.Unix()-1, accepted.Unix()+20, accepted.Unix()+7*24*3600
	preflightWire, _ := json.Marshal(preflight)
	prepare, _ := json.Marshal(struct {
		SchemaVersion int    `json:"schemaVersion"`
		IntentSHA     string `json:"approvalIntentSha256"`
		IntentBytes   string `json:"approvalIntentBytesBase64url"`
	}{1, intentSHA, base64.RawURLEncoding.EncodeToString(intentWire)})
	for leaf, wire := range map[string][]byte{".deployer-reset-intents": intentWire, ".deployer-reset-approvals": planWire, ".deployer-reset-preflights": preflightWire, ".deployer-reset-prepare-bodies": prepare} {
		if os.Remove(filepath.Join(cfg.serversDir, leaf, op+".json")) != nil ||
			writeResetImmutablePrivateBytesWithUID(filepath.Join(cfg.serversDir, leaf), op, resetD101OriginalSHA(wire), wire, uid) != nil {
			t.Fatal("fixture replace source")
		}
	}
	refs := resetExecutionEvidenceRefs{preflight.ApprovalPlanSHA, resetD101OriginalSHA(preflightWire)}
	fp, _ := resetExecutionRequestFingerprint("pep", plan.Target, refs)
	cfg.lifecycleOperationStore.operations = map[string]durableOperationRecord{}
	cfg.lifecycleOperationStore.now = func() time.Time { return accepted }
	cfg.operations = newOperationCoordinator("", "", nil)
	cfg.operations.closed = true
	cfg.operations.maintenanceLease = &maintenanceAdmissionLease{token: "synthetic-test-token"}
	p, err := cfg.operations.prepare(lifecycleKindReset, op, "pep", fp, "synthetic-test-token")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.complete(true) })
	authority.Intent = intent
	cfg.d101PurposeAuthority = func(context.Context, string, string) (resetD101VerifiedPurposeAuthority, error) {
		a := authority
		a.ClockObservedAt = time.Now()
		return a, nil
	}
	record, replay, err := cfg.reserveResetD101FirstAdmission(p, plan.Target, refs, intentSHA)
	if err != nil || replay {
		t.Fatal("fixture first admission", err)
	}
	binding := resetExecutionPhaseBinding{OperationID: op, Target: plan.Target, Evidence: refs, AcceptedAtUnix: record.CreatedAt.Unix(), Phase: "prepared"}
	a := old.Attestations[0]
	a.StartedAt, a.CompletedAt = accepted.Add(100*time.Millisecond), accepted.Add(300*time.Millisecond)
	a.Snapshot.ObservedAt = accepted.Add(200 * time.Millisecond)
	chain, err := newResetExecutionJournal(binding, a)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, uid, p, resetExecutionEvidence{plan, preflight}, chain, record
}

func TestResetD101PreparedPersistReplayAndWorkerShareFirstAdmission(t *testing.T) {
	cfg, uid, p, evidence, chain, record := resetD101PreparedFixture(t)
	sha, err := cfg.persistResetD101PreparedPhase(context.Background(), record, evidence, chain, uid)
	if err != nil {
		t.Fatal("synthetic prepared commit", err)
	}
	binding := resetExecutionPhaseBinding{OperationID: record.OperationID, Target: evidence.Plan.Target, Evidence: chain.Evidence, AcceptedAtUnix: record.CreatedAt.Unix(), Phase: "prepared"}
	wire, got, err := cfg.readResetD101PreparedPhase(binding, record, evidence, uid)
	if err != nil || resetD101OriginalSHA(wire) != sha || got.Attestations[0].SHA != chain.Attestations[0].SHA {
		t.Fatal("prepared bytes/chain changed", err)
	}
	proof, err := decodeResetD101PreparedProof(wire)
	if err != nil || proof.PreparedAtUTC != chain.Attestations[0].Snapshot.ObservedAt.UTC().Format(time.RFC3339Nano) || proof.AcceptedAtUTC != record.CreatedAt.UTC().Format(time.RFC3339Nano) {
		t.Fatal("proof renewed times")
	}
	leaf := filepath.Join(cfg.serversDir, ".deployer-reset-prepared-proofs", record.OperationID+".json")
	before, _ := os.Stat(leaf)
	cfg.lifecycleOperationStore.now = func() time.Time { return record.CreatedAt.Add(time.Hour) }
	replay, replayed, err := cfg.reserveResetD101FirstAdmission(p, evidence.Plan.Target, chain.Evidence, record.D101IntentSHA)
	second, secondErr := cfg.persistResetD101PreparedPhase(context.Background(), replay, evidence, chain, uid)
	after, _ := os.Stat(leaf)
	if err != nil || secondErr != nil || !replayed || replay != record || second != sha || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("replay renewed admission/phase/custody")
	}
	// Worker reads the SAME phase after promotion changes only current status.
	running := record
	running.Status = lifecycleJobRunning
	running.UpdatedAt = record.CreatedAt.Add(time.Second)
	if _, got, err := cfg.readResetD101PreparedPhase(binding, running, evidence, uid); err != nil || got.Attestations[0].SHA != chain.Attestations[0].SHA {
		t.Fatal("worker replaced initial preparation", err)
	}
	if stateFilePresent(cfg.lifecycleJournalFile) || cfg.operations.maintenanceLease.consumed {
		t.Fatal("prepared proof performed a physical phase")
	}
}

func TestResetD101PreparedAdmissionPinsLeaseAndRefusesOtherOperation(t *testing.T) {
	cfg, _, p, evidence, chain, record := resetD101PreparedFixture(t)
	if cfg.operations.maintenanceLease.operationID != record.OperationID {
		t.Fatal("first admission did not pin lease")
	}
	p.complete(true)
	other, err := cfg.operations.prepare(lifecycleKindReset, strings.Repeat("b", 32), "pep", record.RequestFingerprint, "synthetic-test-token")
	if err != nil {
		t.Fatal(err)
	}
	defer other.complete(true)
	if other.admissionErr == nil {
		t.Fatal("pinned lease admitted another operation")
	}
	if _, _, err := cfg.reserveResetD101FirstAdmission(other, evidence.Plan.Target, chain.Evidence, record.D101IntentSHA); err == nil {
		t.Fatal("other operation reserved")
	}
	if _, exists := cfg.lifecycleOperationStore.Lookup(other.operationID); exists {
		t.Fatal("refusal created a durable operation")
	}
}

func TestResetD101PreparedUnavailablePreservesAdmissionAndNoPhaseRetry(t *testing.T) {
	for _, mode := range []string{"unpublished", "consumed", "other-op", "cancelled", "authority", "stale-clock", "different-created-at", "different-intent", "different-phase", "missing-proof-dir"} {
		t.Run(mode, func(t *testing.T) {
			cfg, uid, p, evidence, chain, record := resetD101PreparedFixture(t)
			switch mode {
			case "unpublished":
				cfg.operations.preparing = nil
			case "consumed":
				cfg.operations.maintenanceLease.consumed = true
			case "other-op":
				cfg.operations.maintenanceLease.operationID = strings.Repeat("b", 32)
			case "cancelled":
				p.cancel()
			case "authority":
				cfg.d101PurposeAuthority = nil
			case "stale-clock":
				source := cfg.d101PurposeAuthority
				cfg.d101PurposeAuthority = func(ctx context.Context, op, sha string) (resetD101VerifiedPurposeAuthority, error) {
					a, err := source(ctx, op, sha)
					a.ClockObservedAt = time.Now().Add(-resetPreflightMaxAge)
					return a, err
				}
			case "different-created-at":
				chain.AcceptedAtUnix++
			case "different-intent":
				record.D101IntentSHA = strings.Repeat("b", 64)
			case "different-phase":
				chain.Attestations[0].Phase = "before-down"
			case "missing-proof-dir":
				_ = os.Remove(filepath.Join(cfg.serversDir, ".deployer-reset-prepared-proofs"))
			}
			before, _ := cfg.lifecycleOperationStore.Lookup(p.operationID)
			if _, err := cfg.persistResetD101PreparedPhase(context.Background(), record, evidence, chain, uid); err == nil {
				t.Fatal("invalid preparation published")
			}
			after, _ := cfg.lifecycleOperationStore.Lookup(p.operationID)
			if before != after || stateFilePresent(cfg.lifecycleJournalFile) {
				t.Fatal("refusal changed first admission or physical journal")
			}
		})
	}
	// Durable admission without a complete proof is retained, never inferred
	// from the static plan or turned into a new initial observation on replay.
	cfg, uid, p, evidence, chain, record := resetD101PreparedFixture(t)
	binding := resetExecutionPhaseBinding{OperationID: record.OperationID, Target: evidence.Plan.Target, Evidence: chain.Evidence, AcceptedAtUnix: record.CreatedAt.Unix(), Phase: "prepared"}
	if _, _, err := cfg.readResetD101PreparedPhase(binding, record, evidence, uid); err == nil {
		t.Fatal("missing actual preparation invented")
	}
	if replay, exists, err := cfg.reserveResetD101FirstAdmission(p, evidence.Plan.Target, chain.Evidence, record.D101IntentSHA); err != nil || !exists || replay != record {
		t.Fatal("failed first observation lost durable identity")
	}
}

func TestResetD101PreparedHttpExactIdentityAndSharedCapacity(t *testing.T) {
	cfg, uid, _, evidence, chain, record := resetD101PreparedFixture(t)
	if _, err := cfg.persistResetD101PreparedPhase(context.Background(), record, evidence, chain, uid); err != nil {
		t.Fatal(err)
	}
	wire, _ := readResetPrivateCustody(filepath.Join(cfg.serversDir, ".deployer-reset-prepared-proofs"), record.OperationID, uid)
	proof := "synthetic-test." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	parts := []string{record.OperationID, "prepared-proof", chain.Evidence.ApprovalPlanSHA, chain.Evidence.ExecutionReceiptSHA}
	path := "/operations/" + strings.Join(parts, "/")
	read := func(context.Context, string, string, string) ([]byte, string, error) { return wire, proof, nil }
	w := httptest.NewRecorder()
	serveResetD101PreparedProof(w, httptest.NewRequest(http.MethodGet, path, nil), parts, read)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), wire) || w.Header().Get("X-D101-Prepared-Sha256") != resetD101OriginalSHA(wire) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("prepared transport lost original bytes")
	}
	for _, mode := range []string{"post", "query", "empty-query", "body", "raw-path", "wrong-plan", "oversize", "signature", "missing-source"} {
		t.Run(mode, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			reader := read
			switch mode {
			case "post":
				r.Method = http.MethodPost
			case "query":
				r.URL.RawQuery = "x=1"
			case "empty-query":
				r.URL.ForceQuery = true
			case "body":
				r.ContentLength = 1
			case "raw-path":
				r.URL.RawPath = path
			case "wrong-plan":
				reader = func(context.Context, string, string, string) ([]byte, string, error) {
					changed, _ := decodeResetD101PreparedProof(wire)
					changed.ApprovalPlanSHA = strings.Repeat("f", 64)
					b, _ := json.Marshal(changed)
					return b, proof, nil
				}
			case "oversize":
				reader = func(context.Context, string, string, string) ([]byte, string, error) {
					return make([]byte, resetD101ResultMaxBytes+1), proof, nil
				}
			case "signature":
				reader = func(context.Context, string, string, string) ([]byte, string, error) { return wire, "bad", nil }
			case "missing-source":
				reader = nil
			}
			w := httptest.NewRecorder()
			serveResetD101PreparedProof(w, r, parts, reader)
			if w.Code == 200 || w.Header().Get("X-D101-Prepared-Proof") != "" {
				t.Fatal("invalid transport claimed preparation")
			}
		})
	}
	// Result and prepared readers share the same cap: queueing never starts.
	resetD101ResultReadSlots <- struct{}{}
	resetD101ResultReadSlots <- struct{}{}
	w = httptest.NewRecorder()
	serveResetD101PreparedProof(w, httptest.NewRequest(http.MethodGet, path, nil), parts, func(context.Context, string, string, string) ([]byte, string, error) {
		t.Fatal("busy read started")
		return nil, "", nil
	})
	<-resetD101ResultReadSlots
	<-resetD101ResultReadSlots
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("busy prepared route queued")
	}
}
