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
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Synthetic retained protocol originals only, never an actual host issuer.
// Production Linux readers remain unchanged. Portable tests can construct the
// same data, but cannot turn the unsupported production reader into authority.
func installResetD101LinkedFixtureProof(t *testing.T, cfg *config, uid uint32, intent resetDecodedApprovalIntent, plan resetApprovalPlan, prepare []byte, preflight *resetPreflightReceipt) {
	t.Helper()
	base := time.Unix(preflight.ObservedAtUnix, 0).UTC().Add(-10 * time.Second)
	body, _, _, _, _, sourceSHA := r2PreStopNativeFixture(t, base)
	body.OperationID, body.ApprovalIntentSHA = intent.Intent.OperationID, intent.SHA
	body.ApprovalPlanSHA, body.GatewayPayloadSHA = preflight.ApprovalPlanSHA, resetD101OriginalSHA(prepare)
	body.VerifyingRevision, body.PostgresContainerID = preflight.PublicationRevision, preflight.StoppedContainerIDs["game-postgres"]
	if body.PostgresContainerID == body.JobContainerID {
		body.JobContainerID = strings.Repeat("f", 64)
	}
	canonicalWire, _ := base64.RawURLEncoding.DecodeString(body.PreResetOriginalsBase64url)
	var canonical resetD101PreResetOriginal
	if json.Unmarshal(canonicalWire, &canonical) != nil {
		t.Fatal("synthetic canonical")
	}
	canonical.OperationID, canonical.ApprovalIntentSHA, canonical.TargetFingerprint = body.OperationID, intent.SHA, plan.TargetFingerprint
	canonical.GatewayPayloadSHA = body.GatewayPayloadSHA
	canonical.InitialPublicRevision = intent.Intent.InitialPublicRevision
	canonicalWire, _ = json.Marshal(canonical)
	body.PreResetOriginalsBase64url, body.PreResetOriginalsSHA = base64.RawURLEncoding.EncodeToString(canonicalWire), resetD101OriginalSHA(canonicalWire)
	for i := range body.Observations {
		frame := &body.Observations[i]
		query, _ := base64.RawURLEncoding.DecodeString(frame.GatewayQueryBase64)
		var fields map[string]json.RawMessage
		if json.Unmarshal(query, &fields) != nil {
			t.Fatal("synthetic QUERY")
		}
		for key, value := range map[string]string{"operationId": body.OperationID, "approvalIntentSha256": intent.SHA, "targetFingerprint": plan.TargetFingerprint,
			"gatewayPayloadSha256": body.GatewayPayloadSHA, "initialPublicRevision": intent.Intent.InitialPublicRevision, "verifyingRevision": body.VerifyingRevision,
			"preResetOriginalsBytesBase64url": body.PreResetOriginalsBase64url, "preResetOriginalsSha256": body.PreResetOriginalsSHA} {
			fields[key], _ = json.Marshal(value)
		}
		query, _ = json.Marshal(fields)
		frame.GatewayQueryBase64 = base64.RawURLEncoding.EncodeToString(query)
		frame.Publication.Current.OperationID, frame.Publication.Current.TargetFingerprint, frame.Publication.Current.Revision = body.OperationID, plan.TargetFingerprint, body.VerifyingRevision
		publicationWire, _ := json.Marshal(frame.Publication.Current)
		frame.Publication.BodyBase64, frame.Publication.BodySHA = base64.RawURLEncoding.EncodeToString(publicationWire), resetD101OriginalSHA(publicationWire)
		frame.Snapshot.OperationID, frame.Snapshot.TargetFingerprint, frame.Snapshot.PublicationRevision, frame.Snapshot.WriterFreezeReceiptSHA = body.OperationID, plan.TargetFingerprint, body.VerifyingRevision, plan.WriterFreezeReceiptSHA
	}
	wire, err := json.Marshal(body)
	proofSHA := resetD101OriginalSHA(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeResetD101PreStopNative(wire, proofSHA, intent, plan, preflight.ApprovalPlanSHA, body.GatewayPayloadSHA, sourceSHA); err != nil {
		t.Fatal("synthetic retained proof data", err)
	}
	for _, leaf := range []string{".deployer-reset-pre-reset-originals", ".deployer-reset-old-world"} {
		directory := filepath.Join(cfg.serversDir, leaf)
		if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
			t.Fatal("isolated fixture directory", err)
		}
		dir, _, err := openResetD101NativeDirectory(directory, uid)
		if err != nil {
			t.Fatal("isolated fixture directory custody")
		}
		dir.Close()
		retainResetD101FixtureOriginalHistory(t, filepath.Join(directory, body.OperationID+".json"), uid)
	}
	if writeResetImmutablePrivateBytesWithUID(filepath.Join(cfg.serversDir, ".deployer-reset-pre-reset-originals"), body.OperationID, body.PreResetOriginalsSHA, canonicalWire, uid) != nil {
		t.Fatal("isolated canonical custody")
	}
	directory := filepath.Join(cfg.serversDir, ".deployer-reset-old-world")
	file, err := os.OpenFile(filepath.Join(directory, body.OperationID+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		t.Fatal(err)
	}
	n, writeErr := file.Write(wire)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || n != len(wire) || syncErr != nil || closeErr != nil {
		t.Fatal("isolated retained data write")
	}
	parentFile, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	parentSyncErr, parentCloseErr := parentFile.Sync(), parentFile.Close()
	if parentSyncErr != nil || parentCloseErr != nil {
		t.Fatal("isolated directory sync")
	}
	parentInfo, err := os.Stat(directory)
	parent, statErr := resetD101NativeSnapshot(parentInfo)
	if err != nil || statErr != nil {
		t.Fatal("isolated parent pin")
	}
	planSHA, gatewaySHA := preflight.ApprovalPlanSHA, body.GatewayPayloadSHA
	cfg.d101PreStopNativeInstallation = &resetD101PreStopNativeInstallation{sourceSHA: sourceSHA, parentDevice: parent.Device, parentInode: parent.Inode,
		oldInputs: resetD101OldWorldCaptureInputs{PostgresContainerID: body.PostgresContainerID, Database: "game", User: "game"},
		verify: func(ctx context.Context, binding resetD101PreStopNativeBinding) error {
			// This is an isolated fixed-data expectation, not operating authority.
			if ctx == nil || ctx.Err() != nil || binding.intent.SHA != intent.SHA || binding.planSHA != planSHA || binding.gatewaySHA != gatewaySHA ||
				!reflect.DeepEqual(binding.plan, plan) || !bytes.Equal(binding.original.Original(), wire) || binding.nativePin.SHA256 != proofSHA ||
				binding.nativePin.OwnerUID != uid || binding.nativePin.ParentOwnerUID != uid || binding.parent.Device != parent.Device || binding.parent.Inode != parent.Inode {
				return errResetExecutionEvidence
			}
			return nil
		}}
	preflight.PreStopNativeProofSHA = proofSHA
}

// Only fixture construction may rebase its synthetic history. Keep previous
// bytes in a separate one-time test leaf; product originals/cleanup are intact.
func retainResetD101FixtureOriginalHistory(t *testing.T, path string, uid uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil || !resetD101NativeFileInfo(info, uid, false) {
		t.Fatal("unsafe synthetic history source")
	}
	history := path + ".fixture-history"
	if _, err := os.Lstat(history); !os.IsNotExist(err) {
		t.Fatal("synthetic history would overwrite previous bytes")
	}
	before, err := os.ReadFile(path)
	if err != nil || os.Rename(path, history) != nil {
		t.Fatal("synthetic history retention")
	}
	after, err := os.ReadFile(history)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("synthetic history bytes changed")
	}
}

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
	// A distinct (slightly narrower) synthetic window keeps the new history
	// separate even when the wall clock equals the fixed issuer fixture instant.
	plan.WindowOpensAtUnix, plan.DestructiveCutoffUnix, plan.RecoveryDeadlineUnix = accepted.Unix()-59, accepted.Unix()+300, accepted.Unix()+3600
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
	prepare, _ := json.Marshal(struct {
		SchemaVersion int    `json:"schemaVersion"`
		IntentSHA     string `json:"approvalIntentSha256"`
		IntentBytes   string `json:"approvalIntentBytesBase64url"`
	}{1, intentSHA, base64.RawURLEncoding.EncodeToString(intentWire)})
	installResetD101LinkedFixtureProof(t, &cfg, uid, intent, plan, prepare, &preflight)
	preflightWire, _ := json.Marshal(preflight)
	for leaf, wire := range map[string][]byte{".deployer-reset-intents": intentWire, ".deployer-reset-approvals": planWire, ".deployer-reset-preflights": preflightWire, ".deployer-reset-prepare-bodies": prepare} {
		retainResetD101FixtureOriginalHistory(t, filepath.Join(cfg.serversDir, leaf, op+".json"), uid)
		if writeResetImmutablePrivateBytesWithUID(filepath.Join(cfg.serversDir, leaf), op, resetD101OriginalSHA(wire), wire, uid) != nil {
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

func TestLinkedPreparedFixtureRetainsProofAndUsesProductionPlatformBoundary(t *testing.T) {
	cfg, uid, _, evidence, chain, record := resetD101PreparedFixture(t)
	if validateResetPreflight(evidence.Preflight, evidence.Plan, chain.Evidence.ApprovalPlanSHA, record.CreatedAt) != nil {
		t.Fatal("linked fixture has invalid preflight data")
	}
	path := filepath.Join(cfg.serversDir, ".deployer-reset-old-world", record.OperationID+".json")
	wire, err := os.ReadFile(path)
	if err != nil || resetD101OriginalSHA(wire) != evidence.Preflight.PreStopNativeProofSHA {
		t.Fatal("linked proof original/SHA missing")
	}
	for _, leaf := range []string{".deployer-reset-intents", ".deployer-reset-approvals", ".deployer-reset-preflights", ".deployer-reset-prepare-bodies", ".deployer-reset-pre-reset-originals", ".deployer-reset-old-world"} {
		originalPath := filepath.Join(cfg.serversDir, leaf, record.OperationID+".json")
		prior, priorErr := os.ReadFile(originalPath + ".fixture-history")
		current, currentErr := os.ReadFile(originalPath)
		if priorErr != nil || currentErr != nil || len(prior) == 0 || len(current) == 0 || bytes.Equal(prior, current) {
			t.Fatal("fixture history discarded or re-used as current", leaf)
		}
	}
	verified := 0
	source := cfg.d101PreStopNativeInstallation.verify
	cfg.d101PreStopNativeInstallation.verify = func(ctx context.Context, binding resetD101PreStopNativeBinding) error {
		verified++
		return source(ctx, binding)
	}
	got, err := cfg.readResetExecutionEvidenceWithCustodyUID(record.OperationID, evidence.Plan.Target, chain.Evidence, record.CreatedAt, uid)
	if runtime.GOOS == "linux" {
		if err != nil || !reflect.DeepEqual(got, evidence) || verified != 1 {
			t.Fatal("Linux native data reader refused linked fixture", err)
		}
	} else if err == nil || got.Plan.OperationID != "" || verified != 0 {
		t.Fatal("portable fixture bypassed unsupported production reader")
	}
	after, afterErr := os.ReadFile(path)
	current, found := cfg.lifecycleOperationStore.Lookup(record.OperationID)
	if afterErr != nil || !bytes.Equal(wire, after) || !found || current != record || !cfg.operations.closed || cfg.operations.maintenanceLease.consumed || stateFilePresent(cfg.lifecycleJournalFile) {
		t.Fatal("native data read advanced/discarded preparation")
	}
}

func TestLinkedPreparedFixtureMissingOrChangedProofCannotAdmit(t *testing.T) {
	for _, mode := range []string{"proof-sha-absent", "proof-sha-wrong", "proof-file-missing", "proof-partial", "proof-previous-history", "canonical-changed", "producer-missing"} {
		t.Run(mode, func(t *testing.T) {
			cfg, uid, _, evidence, chain, record := resetD101PreparedFixture(t)
			proofPath := filepath.Join(cfg.serversDir, ".deployer-reset-old-world", record.OperationID+".json")
			switch mode {
			case "proof-sha-absent":
				evidence.Preflight.PreStopNativeProofSHA = ""
			case "proof-sha-wrong":
				evidence.Preflight.PreStopNativeProofSHA = strings.Repeat("a", 64)
			case "proof-file-missing":
				if os.Rename(proofPath, proofPath+".retained") != nil {
					t.Fatal("fixture retain")
				}
			case "proof-partial":
				wire, err := os.ReadFile(proofPath)
				if err != nil || os.Rename(proofPath, proofPath+".retained") != nil || os.WriteFile(proofPath, wire[:len(wire)-1], 0400) != nil {
					t.Fatal("fixture partial")
				}
				evidence.Preflight.PreStopNativeProofSHA = resetD101OriginalSHA(wire[:len(wire)-1])
			case "proof-previous-history":
				prior, err := os.ReadFile(proofPath + ".fixture-history")
				if err != nil || os.Rename(proofPath, proofPath+".retained") != nil || os.WriteFile(proofPath, prior, 0400) != nil {
					t.Fatal("fixture previous-history substitution")
				}
				evidence.Preflight.PreStopNativeProofSHA = resetD101OriginalSHA(prior)
			case "canonical-changed":
				path := filepath.Join(cfg.serversDir, ".deployer-reset-pre-reset-originals", record.OperationID+".json")
				if os.Rename(path, path+".retained") != nil || os.WriteFile(path, []byte("{}"), 0400) != nil {
					t.Fatal("fixture canonical")
				}
			case "producer-missing":
				cfg.d101PreStopNativeInstallation = nil
			}
			preflightWire, _ := json.Marshal(evidence.Preflight)
			path := filepath.Join(cfg.serversDir, ".deployer-reset-preflights", record.OperationID+".json")
			if os.Rename(path, path+".retained") != nil || writeResetImmutablePrivateBytesWithUID(filepath.Dir(path), record.OperationID, resetD101OriginalSHA(preflightWire), preflightWire, uid) != nil {
				t.Fatal("fixture preflight")
			}
			refs := chain.Evidence
			refs.ExecutionReceiptSHA = resetD101OriginalSHA(preflightWire)
			if _, err := cfg.readResetExecutionEvidenceWithCustodyUID(record.OperationID, evidence.Plan.Target, refs, record.CreatedAt, uid); err == nil {
				t.Fatal("changed proof admitted")
			}
			current, found := cfg.lifecycleOperationStore.Lookup(record.OperationID)
			if !found || current != record || !cfg.operations.closed || cfg.operations.maintenanceLease.consumed || stateFilePresent(cfg.lifecycleJournalFile) {
				t.Fatal("refusal changed original preparation")
			}
		})
	}
}
