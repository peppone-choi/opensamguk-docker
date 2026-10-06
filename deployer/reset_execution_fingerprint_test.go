package main

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestResetExecutionFingerprintKeepsLegacyAndBindsBothProofs(t *testing.T) {
	plan, _, _ := resetEvidenceFixture(t)
	legacy := resetRequestFingerprint("pep", plan.Target)
	old, err := resetExecutionRequestFingerprint("pep", plan.Target, resetExecutionEvidenceRefs{})
	if err != nil || old != legacy {
		t.Fatal("legacy nil-evidence fingerprint changed")
	}
	refs := resetExecutionEvidenceRefs{strings.Repeat("c", 64), strings.Repeat("d", 64)}
	approved, err := resetExecutionRequestFingerprint("pep", plan.Target, refs)
	if err != nil || approved == legacy {
		t.Fatal("proof hashes omitted from durable identity")
	}
	for _, changed := range []resetExecutionEvidenceRefs{
		{strings.Repeat("e", 64), refs.ExecutionReceiptSHA},
		{refs.ApprovalPlanSHA, strings.Repeat("e", 64)},
	} {
		actual, err := resetExecutionRequestFingerprint("pep", plan.Target, changed)
		if err != nil || actual == approved {
			t.Fatal("different proof hashes share a durable fingerprint")
		}
	}
	if resetRequestFingerprint("pep", plan.Target) != legacy {
		t.Fatal("typed target hash mutated while binding proof hashes")
	}
	for _, bad := range []resetExecutionEvidenceRefs{{refs.ApprovalPlanSHA, ""}, {"", refs.ExecutionReceiptSHA}, {"INVALID", refs.ExecutionReceiptSHA}} {
		if _, err := resetExecutionRequestFingerprint("pep", plan.Target, bad); err == nil {
			t.Fatal("partial or malformed proof accepted")
		}
	}
}

func TestResetExecutionProofConflictAndCompletedReplayInDurableStore(t *testing.T) {
	cfg := configuredResetOperationTest(t)
	plan, _, _ := resetEvidenceFixture(t)
	refs := resetExecutionEvidenceRefs{strings.Repeat("c", 64), strings.Repeat("d", 64)}
	fingerprint, err := resetExecutionRequestFingerprint("pep", plan.Target, refs)
	if err != nil {
		t.Fatal(err)
	}
	record := durableOperationRecord{OperationID: plan.OperationID, Kind: lifecycleKindReset, SubjectID: "pep", RequestFingerprint: fingerprint, Status: lifecycleJobRunning}
	mustReserveOperation(t, cfg.lifecycleOperationStore, record)
	mustTransitionOperation(t, cfg.lifecycleOperationStore, record.OperationID, lifecycleJobSucceeded, http.StatusOK, durableOperationSuccessMessage(lifecycleKindReset))
	replay, exists, err := cfg.replayDurableLifecycleOperation(record.OperationID, lifecycleKindReset, "pep", fingerprint)
	if err != nil || !exists || replay.Status != lifecycleJobSucceeded {
		t.Fatal("identical completed durable identity did not replay")
	}
	refs.ExecutionReceiptSHA = strings.Repeat("e", 64)
	changed, err := resetExecutionRequestFingerprint("pep", plan.Target, refs)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cfg.replayDurableLifecycleOperation(record.OperationID, lifecycleKindReset, "pep", changed); !errors.Is(err, errLifecycleOperationConflict) {
		t.Fatal("same operation with a different proof was not rejected")
	}
}

func TestSuppliedResetProofCannotReachUnconnectedWorker(t *testing.T) {
	for _, mode := range []string{"valid-shaped", "partial", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			cfg := configuredResetOperationTest(t)
			calls := &dockerCallRecorder{}
			cfg.dockerRunner = func(args ...string) (string, error) { calls.record(args...); return "unexpected", nil }
			first, second := strings.Repeat("c", 64), strings.Repeat("d", 64)
			want := http.StatusServiceUnavailable
			if mode == "partial" {
				second = ""
				want = http.StatusBadRequest
			}
			if mode == "malformed" {
				first = "invalid"
				want = http.StatusBadRequest
			}
			body := `{"id":"pep","confirm":"RESET pep","scenarioCode":"scenario_3190","approvalPlanSha256":"` + first + `","executionReceiptSha256":"` + second + `"}`
			oldEnv, oldShared := readFile(t, cfg.serversDir+"/spep.env"), readFile(t, cfg.sharedEnvFile())
			response := envRequest(t, cfg.withAuth(cfg.handleServerReset), http.MethodPost, "/servers/reset", body)
			if response.Code != want || calls.count() != 0 || stateFilePresent(cfg.lifecycleJournalFile) ||
				readFile(t, cfg.serversDir+"/spep.env") != oldEnv || readFile(t, cfg.sharedEnvFile()) != oldShared {
				t.Fatal("supplied proof silently reached an unconnected worker or mutated state")
			}
		})
	}
}
