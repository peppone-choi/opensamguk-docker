package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every byte, authority and runtime here is synthetic isolated test evidence.
// The issuer is tested against real private file custody and the durable store;
// the Docker trap ensures settlement cannot perform any physical work.
func resetD101IssuerFixture(t *testing.T) (config, uint32, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	for _, leaf := range []string{".deployer-reset-intents", ".deployer-reset-prepare-bodies", ".deployer-reset-approvals", ".deployer-reset-preflights", ".deployer-reset-runtime", ".deployer-reset-execution-journals", ".deployer-reset-results"} {
		if os.Mkdir(filepath.Join(root, leaf), 0700) != nil {
			t.Fatal("private fixture directory")
		}
	}
	intentWire, intentSHA, plan := resetIntentFixture(t)
	intent, err := decodeResetApprovalIntent(intentWire, intentSHA)
	if err != nil {
		t.Fatal(err)
	}
	_, preflight, accepted := resetEvidenceFixture(t)
	preflight.TargetFingerprint = plan.TargetFingerprint
	planWire, _ := json.Marshal(plan)
	preflight.ApprovalPlanSHA = resetD101OriginalSHA(planWire)
	preflightWire, _ := json.Marshal(preflight)
	refs := resetExecutionEvidenceRefs{preflight.ApprovalPlanSHA, resetD101OriginalSHA(preflightWire)}
	fingerprint, err := resetExecutionRequestFingerprint("pep", plan.Target, refs)
	if err != nil {
		t.Fatal(err)
	}
	chain := resetExecutionJournal{}
	for i, phase := range []string{"prepared", "before-journal", "before-down"} {
		start := accepted.Add(time.Duration(i*2) * time.Second)
		binding := resetExecutionPhaseBinding{OperationID: plan.OperationID, Target: plan.Target, Evidence: refs, AcceptedAtUnix: accepted.Unix(), Phase: phase}
		if i > 0 {
			binding.PreviousAttestationSHA = chain.Attestations[i-1].SHA
		}
		a := resetExecutionAttestation{Phase: phase, PreviousSHA: binding.PreviousAttestationSHA, StartedAt: start, CompletedAt: start.Add(time.Second),
			Snapshot: resetExecutionPhaseSnapshot{ObservedAt: start, ServerID: "pep", OperationID: plan.OperationID, TargetFingerprint: plan.TargetFingerprint,
				PublicationState: "VERIFYING", PublicationRevision: "2", WriterFreezeReceiptSHA: plan.WriterFreezeReceiptSHA, WriterFreezeHeld: true},
			Space: resetExecutionSpaceSnapshot{Device: *preflight.FilesystemDevice, AvailableBytes: resetDiskReserveBytes + 1000, AvailableInodes: 100}}
		if i == 0 {
			chain, err = newResetExecutionJournal(binding, a)
		} else {
			chain, err = appendResetExecutionAttestation(chain, binding, a)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	store := mustOpenOperationStore(t, filepath.Join(root, durableOperationStoreFileName))
	store.now = func() time.Time { return accepted.Add(12 * time.Second) }
	mustReserveOperation(t, store, durableOperationRecord{OperationID: plan.OperationID, Kind: lifecycleKindReset, SubjectID: "pep", RequestFingerprint: fingerprint,
		Status: lifecycleJobSucceeded, HTTPStatus: 200, PublicMessage: durableOperationResetSucceededMessage, CreatedAt: accepted, UpdatedAt: accepted.Add(12 * time.Second), D101IntentSHA: intentSHA})
	cfg := config{serversDir: root, lifecycleOperationStore: store, lifecycleJournalFile: filepath.Join(root, ".deployer-lifecycle.json"),
		dockerRunnerContext: func(context.Context, ...string) (string, error) {
			t.Fatal("receipt settlement invoked Docker")
			return "", errResetExecutionEvidence
		}}
	cfg.d101PurposeAuthority = func(context.Context, string, string) (resetD101VerifiedPurposeAuthority, error) {
		return resetD101VerifiedPurposeAuthority{Intent: intent, KeyPins: resetD101SigningKeyPins{KeyID: "synthetic-test", PublicKeySpkiSHA: strings.Repeat("1", 64)},
			DeploymentCardSHA: strings.Repeat("2", 64), ApprovedReceiptProvenanceSHA: strings.Repeat("3", 64), ClockAgreementReceiptSHA: strings.Repeat("4", 64), ClockObservedAt: time.Now()}, nil
	}
	journal := lifecycleJournal{Version: lifecycleJournalVersion, Operation: "reset", OperationID: plan.OperationID, OperationKind: lifecycleKindReset,
		Stage: lifecycleJournalStageDown, ServerID: "pep", Project: "opensamguk-spep", ResetTarget: &plan.Target, ResetExecution: &chain}
	if cfg.writeLifecycleJournalRecord(journal) != nil {
		t.Fatal("synthetic live journal")
	}
	prepare, _ := json.Marshal(struct {
		SchemaVersion     int    `json:"schemaVersion"`
		ApprovalIntentSHA string `json:"approvalIntentSha256"`
		IntentBytes       string `json:"approvalIntentBytesBase64url"`
	}{1, intentSHA, base64.RawURLEncoding.EncodeToString(intentWire)})
	number := func(n int) *int { return &n }
	text := func(s string) *string { return &s }
	running := true
	runtime := resetRuntimeObservation{Version: 1, ServerID: "pep", WorldID: 1, OperationID: plan.OperationID, AppSourceSHA: plan.AppSourceSHA,
		TargetFingerprint: plan.TargetFingerprint, Evidence: refs, StartedAt: accepted.Add(6 * time.Second), CompletedAt: accepted.Add(8 * time.Second), ImageDigests: plan.NewImageDigests,
		Containers: map[string]resetRuntimeContainer{}, Raw: resetAdminCurrentObservation{ObservedAt: accepted.Add(7 * time.Second), Current: resetAdminCurrent{
			WorldID: number(1), Generation: text("0"), ScenarioCode: text("scenario_3190"), TurnTerm: number(60), MaxGeneral: number(50), BlockGeneralCreate: number(1), FirstTurn: text("immediate"), StartTime: text(accepted.Format(time.RFC3339Nano))}}}
	for i, service := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		id := strings.Repeat(string(rune('1'+i)), 64)
		settings := map[string]string{}
		for _, item := range resetRuntimeFixtureSettings(service) {
			if item != nil {
				pair := strings.SplitN(item.(string), "=", 2)
				settings[pair[0]] = pair[1]
			}
		}
		container := resetRuntimeContainer{ID: id, Name: "/spep-" + service, ImageID: "sha256:" + id, Running: &running, Status: "running", Project: "opensamguk-spep", Service: service, SeedSettings: settings}
		if service == "game-api" {
			container.ServerIDs = []string{"SERVER_ID=pep"}
		}
		runtime.Containers[service] = container
	}
	runtimeWire, _ := json.Marshal(runtime)
	for leaf, wire := range map[string][]byte{".deployer-reset-intents": intentWire, ".deployer-reset-prepare-bodies": prepare, ".deployer-reset-approvals": planWire, ".deployer-reset-preflights": preflightWire, ".deployer-reset-runtime": runtimeWire} {
		if writeResetImmutablePrivateBytesWithUID(filepath.Join(root, leaf), plan.OperationID, resetD101OriginalSHA(wire), wire, uid) != nil {
			t.Fatalf("synthetic custody %s", leaf)
		}
	}
	return cfg, uid, plan.OperationID
}

func TestResetD101IssuerPersistsActualBoundSuccessExactlyOnceWithoutPhysicalReplay(t *testing.T) {
	cfg, uid, op := resetD101IssuerFixture(t)
	before, _ := cfg.lifecycleOperationStore.Lookup(op)
	sha, err := cfg.publishResetD101SucceededResultWithCustodyUID(context.Background(), op, uid)
	if err != nil {
		t.Fatal("bound synthetic success refused", err)
	}
	wire, err := readResetPrivateCustody(filepath.Join(cfg.serversDir, ".deployer-reset-results"), op, uid)
	result, decodeErr := decodeResetD101ExecutionResult(wire, sha)
	if err != nil || decodeErr != nil || result.AcceptedAtUTC != before.CreatedAt.UTC().Format(time.RFC3339Nano) || result.CompletedAtUTC != before.UpdatedAt.UTC().Format(time.RFC3339Nano) {
		t.Fatal("issuer renewed durable physical times", err, decodeErr)
	}
	leaf := filepath.Join(cfg.serversDir, ".deployer-reset-results", op+".json")
	info, _ := os.Stat(leaf)
	second, err := cfg.publishResetD101SucceededResultWithCustodyUID(context.Background(), op, uid)
	after, _ := os.Stat(leaf)
	current, _ := cfg.lifecycleOperationStore.Lookup(op)
	if err != nil || sha != second || current != before || !os.SameFile(info, after) || !info.ModTime().Equal(after.ModTime()) {
		t.Fatal("receipt retry changed outcome/custody")
	}
	if !stateFilePresent(cfg.lifecycleJournalFile) {
		t.Fatal("publication helper cleared live journal")
	}
	// Restart beyond ordinary retention must preserve this operation identity.
	reopened := mustOpenOperationStore(t, cfg.lifecycleOperationStore.path)
	got, ok := reopened.Lookup(op)
	if !ok || got != before {
		t.Fatal("D101 terminal identity lost on restart")
	}
	legacy := got
	legacy.D101IntentSHA = ""
	legacy.CreatedAt = time.Time{}
	legacy.UpdatedAt = time.Time{}
	if _, _, err := reopened.Reserve(legacy); err == nil {
		t.Fatal("retained D101 ID reused through legacy admission")
	}
}

func TestResetD101IssuerUnavailablePreservesDurableSuccessAndJournal(t *testing.T) {
	for _, mode := range []string{"authority", "stale-clock", "runtime", "prepare", "changed-prepare", "running", "different-current-intent", "cancelled", "malformed-existing-result"} {
		t.Run(mode, func(t *testing.T) {
			cfg, uid, op := resetD101IssuerFixture(t)
			before, _ := cfg.lifecycleOperationStore.Lookup(op)
			journalBefore, _ := os.ReadFile(cfg.lifecycleJournalFile)
			ctx := context.Background()
			switch mode {
			case "authority":
				cfg.d101PurposeAuthority = nil
			case "stale-clock":
				source := cfg.d101PurposeAuthority
				cfg.d101PurposeAuthority = func(ctx context.Context, op, sha string) (resetD101VerifiedPurposeAuthority, error) {
					authority, err := source(ctx, op, sha)
					authority.ClockObservedAt = time.Now().Add(-resetPreflightMaxAge)
					return authority, err
				}
			case "runtime":
				_ = os.Remove(filepath.Join(cfg.serversDir, ".deployer-reset-runtime", op+".json"))
			case "prepare":
				_ = os.Remove(filepath.Join(cfg.serversDir, ".deployer-reset-prepare-bodies", op+".json"))
			case "changed-prepare":
				leaf := filepath.Join(cfg.serversDir, ".deployer-reset-prepare-bodies", op+".json")
				wire, err := os.ReadFile(leaf)
				if err != nil {
					t.Fatal(err)
				}
				var body map[string]any
				if json.Unmarshal(wire, &body) != nil {
					t.Fatal("fixture prepare")
				}
				body["approvalIntentSha256"] = strings.Repeat("f", 64)
				changed, _ := json.Marshal(body)
				if os.Remove(leaf) != nil || writeResetImmutablePrivateBytesWithUID(filepath.Dir(leaf), op, resetD101OriginalSHA(changed), changed, uid) != nil {
					t.Fatal("changed synthetic prepare")
				}
			case "running":
				changed := before
				changed.Status = lifecycleJobRunning
				cfg.lifecycleOperationStore.operations[op] = changed
				before = changed
			case "different-current-intent":
				changed := before
				changed.D101IntentSHA = strings.Repeat("f", 64)
				cfg.lifecycleOperationStore.operations[op] = changed
				before = changed
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "malformed-existing-result":
				wire := []byte(`{"schemaVersion":1}`)
				if writeResetImmutablePrivateBytesWithUID(filepath.Join(cfg.serversDir, ".deployer-reset-results"), op, resetD101OriginalSHA(wire), wire, uid) != nil {
					t.Fatal("fixture result")
				}
			}
			if _, err := cfg.publishResetD101SucceededResultWithCustodyUID(ctx, op, uid); err == nil {
				t.Fatal("unavailable source accepted")
			}
			after, _ := cfg.lifecycleOperationStore.Lookup(op)
			journalAfter, _ := os.ReadFile(cfg.lifecycleJournalFile)
			if after != before || !bytes.Equal(journalBefore, journalAfter) {
				t.Fatal("refusal rewrote physical outcome or live journal")
			}
			if mode != "malformed-existing-result" && stateFilePresent(filepath.Join(cfg.serversDir, ".deployer-reset-results", op+".json")) {
				t.Fatal("refusal published result")
			}
		})
	}
}

func TestResetD101SucceededCleanupWithoutAuthorityRetainsJournal(t *testing.T) {
	cfg, _, op := resetD101IssuerFixture(t)
	cfg.d101PurposeAuthority = nil
	if cfg.settleSucceededLifecycleJournal(context.Background(), op) == nil || !stateFilePresent(cfg.lifecycleJournalFile) {
		t.Fatal("missing issuer authority cleared journal")
	}
	record, _ := cfg.lifecycleOperationStore.Lookup(op)
	if record.Status != lifecycleJobSucceeded {
		t.Fatal("receipt-only refusal changed physical success")
	}
}
