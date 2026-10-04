package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLegacyPinnedResetJournalLoadsButCannotRepair(t *testing.T) {
	for _, stage := range []string{lifecycleJournalStagePrepared, lifecycleJournalStageEnv, lifecycleJournalStageRegistry, lifecycleJournalStageDown} {
		for _, matching := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/matching=%v", stage, matching), func(t *testing.T) {
				cfg := configuredResetOperationTest(t)
				legacy := resetDigestFixture(t, nil)
				if !matching {
					legacy.Updates["WEB_GAME_TAG"] = strings.Repeat("c", 40)
				}
				wire, err := json.Marshal(lifecycleJournal{
					Version: lifecycleJournalVersion, Operation: "reset", Stage: stage,
					ServerID: "pep", Project: "opensamguk-spep", ResetTarget: &legacy,
				})
				if err != nil {
					t.Fatal(err)
				}
				writeEnv(t, cfg.lifecycleJournalFile, string(wire))
				if _, exists, err := cfg.readLifecycleJournal(); err != nil || !exists {
					t.Fatalf("legacy journal is not readable: exists=%v err=%v", exists, err)
				}
				configureLoadConfigTest(t, cfg)
				restarted, err := loadConfig()
				if err != nil {
					t.Fatalf("legacy journal prevented startup: %v", err)
				}
				envFile := filepath.Join(cfg.serversDir, "spep.env")
				oldEnv := readFile(t, envFile)
				oldShared := readFile(t, cfg.sharedEnvFile())
				calls := &dockerCallRecorder{}
				restarted.dockerRunner = func(args ...string) (string, error) { calls.record(args...); return "ok", nil }
				if err := restarted.repairLifecycleJournal(); err == nil {
					t.Fatal("legacy unbound images were replayed")
				}
				if calls.count() != 0 {
					t.Fatal("legacy replay reached Docker")
				}
				if readFile(t, envFile) != oldEnv || readFile(t, cfg.sharedEnvFile()) != oldShared || readFile(t, cfg.lifecycleJournalFile) != string(wire) {
					t.Fatal("legacy refusal changed reset state or discarded journal")
				}
			})
		}
	}
}

func TestResetCandidateUsesVerifiedLocalImagesBeforePull(t *testing.T) {
	for _, cached := range []bool{true, false} {
		t.Run(fmt.Sprintf("cached=%v", cached), func(t *testing.T) {
			cfg := testConfig(t)
			envFile := filepath.Join(cfg.serversDir, "spep.env")
			writeEnv(t, envFile, "SERVER_ID=pep\nGHCR_OWNER=owner\nIMAGE_TAG=old\nSERVER_GENERATION=1\nSCENARIO_CODE=scenario_1020\nSCENARIO_SEED_ENABLED=true\n")
			target, err := cfg.serverTargetForID("pep")
			if err != nil {
				t.Fatal(err)
			}
			pulls, inspections := 0, 0
			cfg.dockerRunner = func(args ...string) (string, error) {
				if len(args) > 1 && args[0] == "image" && args[1] == "inspect" {
					inspections++
					if !cached && pulls == 0 {
						return "null", nil
					}
					out, _ := resetDigestInspectFixture(t, args)
					return out, nil
				}
				if strings.Contains(strings.Join(args, " "), "pull game-engine game-api web-game") {
					pulls++
				}
				return "ok", nil
			}
			if _, err := cfg.pullResetCandidate(context.Background(), target, resetDigestFixture(t, resetDigestPins())); err != nil {
				t.Fatal(err)
			}
			if cached && (pulls != 0 || inspections != 3) {
				t.Fatalf("verified local images were pulled again: pulls=%d inspections=%d", pulls, inspections)
			}
			if !cached && (pulls != 1 || inspections != 4) {
				t.Fatalf("missing local images were not checked before and after pull: pulls=%d inspections=%d", pulls, inspections)
			}
		})
	}
}

func withResetDigestPins(t *testing.T, body string) string {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal([]byte(body), &fields); err != nil {
		t.Fatal(err)
	}
	fields["imageDigests"] = resetDigestPins()
	payload, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func resetDigestInspectFixture(t *testing.T, args []string) (string, bool) {
	t.Helper()
	if len(args) < 2 || args[0] != "image" || args[1] != "inspect" {
		return "", false
	}
	ref := args[len(args)-1]
	for _, service := range resetImageServices {
		if strings.Contains(ref, ":"+service+"-") {
			out, _ := json.Marshal(map[string]any{"repoDigests": []string{"ghcr.io/owner/opensamguk@" + resetDigestPins()[service]}, "os": "linux", "architecture": "amd64"})
			return string(out), true
		}
	}
	t.Fatalf("unexpected image reference: %s", ref)
	return "", false
}

func resetDigestFixture(t *testing.T, digests map[string]string) resetLifecycleTarget {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"scenarioCode": "scenario_990002", "generation": 0, "scenarioSeedEnabled": true,
		"updates":      map[string]string{"IMAGE_TAG": strings.Repeat("b", 40), "WEB_GAME_TAG": strings.Repeat("b", 40)},
		"imageDigests": digests,
	})
	if err != nil {
		t.Fatal(err)
	}
	var target resetLifecycleTarget
	if err := json.Unmarshal(payload, &target); err != nil {
		t.Fatal(err)
	}
	return target
}

func TestLeasedResetDigestFailureSettlesWithoutPublishingTarget(t *testing.T) {
	cfg := configuredResetOperationTest(t)
	envFile := filepath.Join(cfg.serversDir, "spep.env")
	oldEnv := readFile(t, envFile)
	oldShared := readFile(t, cfg.sharedEnvFile())
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		if dockerPreflightProbe(args) {
			return "29.0.0\n", nil
		}
		calls.record(args...)
		if len(args) > 1 && args[0] == "image" && args[1] == "inspect" {
			return `{"repoDigests":[],"os":"linux","architecture":"amd64"}`, nil
		}
		return "ok", nil
	}
	maintenance := cfg.withAuth(cfg.withLoopback(cfg.handleMaintenance))
	entered := decodeMaintenanceResponse(t, loopbackRequest(t, maintenance, http.MethodPost, "/maintenance/enter", ""))
	tag := strings.Repeat("b", 40)
	body := withResetDigestPins(t, `{"id":"pep","confirm":"RESET pep","operationId":"0123456789abcdef0123456789abcdef","scenarioCode":"scenario_990002","generation":"0","imageTag":"`+tag+`","webGameTag":"`+tag+`"}`)
	request := httptest.NewRequest(http.MethodPost, "/servers/reset", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set(maintenanceLeaseHeader, entered.Lease)
	request.RemoteAddr = "127.0.0.1:31000"
	response := httptest.NewRecorder()
	cfg.withAuth(cfg.handleServerReset)(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("reset submission: %d %s", response.Code, response.Body.String())
	}
	var accepted createServerResponse
	if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	waitForLifecycleJob(t, cfg.lifecycleJobs, accepted.JobID, lifecycleJobFailed)
	operation, ok := cfg.lifecycleOperationStore.Lookup(accepted.OperationID)
	if !ok || operation.Status != lifecycleJobFailed {
		t.Fatalf("operation did not settle: %#v", operation)
	}
	for _, call := range calls.snapshot() {
		if strings.Contains(call, "down ") || strings.Contains(call, "up ") {
			t.Fatalf("unverified images reached mutation: %s", call)
		}
	}
	if readFile(t, envFile) != oldEnv || readFile(t, cfg.sharedEnvFile()) != oldShared || stateFilePresent(cfg.lifecycleJournalFile) {
		t.Fatal("failed verification published reset state")
	}
	var state maintenanceResponse
	for i := 0; i < 200; i++ {
		state = decodeMaintenanceResponse(t, loopbackRequest(t, maintenance, http.MethodGet, "/maintenance", ""))
		if state.State == maintenanceStateDrained {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if state.State != maintenanceStateDrained {
		t.Fatal("failed verification reopened maintenance")
	}
	leave := loopbackRequest(t, maintenance, http.MethodPost, "/maintenance/leave", "")
	if leave.Code != http.StatusOK || decodeMaintenanceResponse(t, leave).State != maintenanceStateOpen {
		t.Fatalf("settled failure prevented maintenance leave: %d %s", leave.Code, leave.Body.String())
	}
}

func TestLeasedResetRejectsInvalidDigestInputsWithoutConsumingLease(t *testing.T) {
	cfg := configuredResetOperationTest(t)
	envFile := filepath.Join(cfg.serversDir, "spep.env")
	writeEnv(t, envFile, readFile(t, envFile)+"GHCR_OWNER=owner\n")
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		if dockerPreflightProbe(args) {
			return "29.0.0\n", nil
		}
		calls.record(args...)
		if out, ok := resetDigestInspectFixture(t, args); ok {
			return out, nil
		}
		return "ok", nil
	}
	maintenance := cfg.withAuth(cfg.withLoopback(cfg.handleMaintenance))
	entered := decodeMaintenanceResponse(t, loopbackRequest(t, maintenance, http.MethodPost, "/maintenance/enter", ""))
	tag := strings.Repeat("b", 40)
	valid := withResetDigestPins(t, `{"id":"pep","confirm":"RESET pep","operationId":"0123456789abcdef0123456789abcdef","scenarioCode":"scenario_990002","generation":"0","imageTag":"`+tag+`","webGameTag":"`+tag+`"}`)
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/servers/reset", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer test-token")
		r.Header.Set(maintenanceLeaseHeader, entered.Lease)
		r.RemoteAddr = "127.0.0.1:31000"
		w := httptest.NewRecorder()
		cfg.withAuth(cfg.handleServerReset)(w, r)
		return w
	}
	for _, mode := range []string{"missing", "extra-service", "different-sha"} {
		var fields map[string]any
		if err := json.Unmarshal([]byte(valid), &fields); err != nil {
			t.Fatal(err)
		}
		switch mode {
		case "missing":
			delete(fields, "imageDigests")
		case "extra-service":
			fields["imageDigests"].(map[string]any)["unknown"] = "sha256:" + strings.Repeat("d", 64)
		case "different-sha":
			fields["webGameTag"] = strings.Repeat("c", 40)
		}
		body, _ := json.Marshal(fields)
		response := post(string(body))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected400 got%d", mode, response.Code)
		}
	}
	if calls.count() != 0 || stateFilePresent(cfg.lifecycleJournalFile) {
		t.Fatal("rejected inputs reached worker")
	}
	accepted := post(valid)
	if accepted.Code != http.StatusOK {
		t.Fatalf("rejected inputs consumed lease: %d %s", accepted.Code, accepted.Body.String())
	}
	var response createServerResponse
	if err := json.Unmarshal(accepted.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	waitForLifecycleJob(t, cfg.lifecycleJobs, response.JobID, lifecycleJobSucceeded)
}

func TestResetImageOwnerMatchesComposeFallback(t *testing.T) {
	cfg := testConfig(t)
	cfg.ghcrOwner = "unrelated-shared-owner"
	envFile := filepath.Join(cfg.serversDir, "spep.env")
	writeEnv(t, envFile, "SERVER_ID=pep\nIMAGE_TAG=old\nSERVER_GENERATION=1\nSCENARIO_CODE=scenario_1020\nSCENARIO_SEED_ENABLED=true\n")
	target, err := cfg.serverTargetForID("pep")
	if err != nil {
		t.Fatal(err)
	}
	cfg.dockerRunner = func(args ...string) (string, error) {
		out, inspect := resetDigestInspectFixture(t, args)
		if !inspect {
			t.Fatal("verified Compose-default images were pulled")
		}
		if !strings.HasPrefix(args[len(args)-1], "ghcr.io/peppone-choi/opensamguk:") {
			t.Fatal("shared owner overrode Compose fallback")
		}
		return strings.ReplaceAll(out, "ghcr.io/owner/", "ghcr.io/peppone-choi/"), nil
	}
	if _, err := cfg.pullResetCandidate(context.Background(), target, resetDigestFixture(t, resetDigestPins())); err != nil {
		t.Fatal(err)
	}
}

func TestResetRecoveryVerifiesPinnedImagesBeforeEnvMutation(t *testing.T) {
	cfg := configuredResetOperationTest(t)
	envFile := filepath.Join(cfg.serversDir, "spep.env")
	oldEnv := readFile(t, envFile)
	oldShared := readFile(t, cfg.sharedEnvFile())
	target, err := cfg.serverTargetForID("pep")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.writeResetLifecycleJournal(target, resetDigestFixture(t, resetDigestPins())); err != nil {
		t.Fatal(err)
	}
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		if dockerPreflightProbe(args) {
			return "29.0.0\n", nil
		}
		calls.record(args...)
		if len(args) > 1 && args[0] == "image" && args[1] == "inspect" {
			return "null", nil
		}
		return "ok", nil
	}
	if err := cfg.repairLifecycleJournal(); err == nil {
		t.Fatal("unverified recovery succeeded")
	}
	if readFile(t, envFile) != oldEnv || readFile(t, cfg.sharedEnvFile()) != oldShared {
		t.Fatal("recovery verification changed env or registry")
	}
	if !stateFilePresent(cfg.lifecycleJournalFile) {
		t.Fatal("failed recovery discarded evidence")
	}
	for _, call := range calls.snapshot() {
		if strings.Contains(call, "down ") || strings.Contains(call, "up ") {
			t.Fatalf("unverified recovery reached mutation: %s", call)
		}
	}
}

func resetDigestPins() map[string]string {
	return map[string]string{
		"game-api":    "sha256:" + strings.Repeat("a", 64),
		"game-engine": "sha256:" + strings.Repeat("b", 64),
		"web-game":    "sha256:" + strings.Repeat("c", 64),
	}
}

func TestResetImageDigestsAreRequiredAndBoundToFingerprint(t *testing.T) {
	for _, pins := range []map[string]string{nil, {}, {"game-api": "sha256:" + strings.Repeat("a", 64)},
		{"game-api": "latest", "game-engine": "sha256:" + strings.Repeat("b", 64), "web-game": "sha256:" + strings.Repeat("c", 64)}} {
		if _, err := normalizeResetLifecycleTarget(resetDigestFixture(t, pins)); err == nil {
			t.Errorf("incomplete image digest target accepted: %v", pins)
		}
	}
	first := resetDigestFixture(t, resetDigestPins())
	changed := resetDigestPins()
	changed["game-api"] = "sha256:" + strings.Repeat("d", 64)
	if resetRequestFingerprint("pep", first) == resetRequestFingerprint("pep", resetDigestFixture(t, changed)) {
		t.Fatal("different approved image digests share an operation fingerprint")
	}
}

func TestResetCandidateVerifiesAllImageDigestsBeforePublishing(t *testing.T) {
	for _, mode := range []string{"valid", "mismatch", "architecture", "unknown", "inspect-error"} {
		t.Run(mode, func(t *testing.T) {
			cfg := testConfig(t)
			envFile := filepath.Join(cfg.serversDir, "spep.env")
			original := "SERVER_ID=pep\nGHCR_OWNER=owner\nIMAGE_TAG=old\nWEB_GAME_TAG=old\nSERVER_GENERATION=1\nSCENARIO_CODE=scenario_1020\nSCENARIO_SEED_ENABLED=true\n"
			writeEnv(t, envFile, original)
			target, err := cfg.serverTargetForID("pep")
			if err != nil {
				t.Fatal(err)
			}
			inspected := []string{}
			cfg.dockerRunner = func(args ...string) (string, error) {
				if len(args) > 1 && args[0] == "image" && args[1] == "inspect" {
					ref := args[len(args)-1]
					inspected = append(inspected, ref)
					if mode == "inspect-error" {
						return "private diagnostic", errors.New("private diagnostic")
					}
					if mode == "unknown" {
						return "null", nil
					}
					service := ""
					for _, candidate := range []string{"game-api", "game-engine", "web-game"} {
						if strings.Contains(ref, ":"+candidate+"-") {
							service = candidate
						}
					}
					if service == "" {
						t.Fatalf("unexpected reference: %s", ref)
					}
					digest := resetDigestPins()[service]
					arch := "amd64"
					if mode == "mismatch" {
						digest = "sha256:" + strings.Repeat("d", 64)
					}
					if mode == "architecture" {
						arch = "arm64"
					}
					out, _ := json.Marshal(map[string]any{"repoDigests": []string{"ghcr.io/owner/opensamguk@" + digest}, "os": "linux", "architecture": arch})
					return string(out), nil
				}
				return "ok", nil
			}
			_, err = cfg.pullResetCandidate(context.Background(), target, resetDigestFixture(t, resetDigestPins()))
			if mode == "valid" {
				if err != nil || len(inspected) != 3 {
					t.Fatalf("all images were not verified: inspections=%v err=%v", inspected, err)
				}
			} else if err == nil {
				t.Fatal("unverified candidate was accepted")
			} else if strings.Contains(err.Error(), "private diagnostic") {
				t.Fatal("inspect diagnostic escaped")
			}
			if got := readFile(t, envFile); got != original {
				t.Fatal("candidate inspection changed canonical env")
			}
			if stateFilePresent(cfg.lifecycleJournalFile) {
				t.Fatal("candidate inspection published a journal")
			}
			if files, _ := filepath.Glob(filepath.Join(cfg.serversDir, ".reset-pull-*.env")); len(files) != 0 {
				t.Fatal("temporary env retained")
			}
		})
	}
}

// The exact service tag is part of the approved candidate; a correct digest
// returned for service-latest must not make a mutable tag acceptable.
func TestResetCandidatePinsExactServiceTagsForInspectAndPull(t *testing.T) {
	cfg := testConfig(t)
	envFile := filepath.Join(cfg.serversDir, "spep.env")
	writeEnv(t, envFile, "SERVER_ID=pep\nGHCR_OWNER=owner\nIMAGE_TAG=old\nWEB_GAME_TAG=old\nSERVER_GENERATION=1\nSCENARIO_CODE=scenario_1020\nSCENARIO_SEED_ENABLED=true\n")
	target, err := cfg.serverTargetForID("pep")
	if err != nil {
		t.Fatal(err)
	}
	candidate := resetDigestFixture(t, resetDigestPins())
	pulled := false
	inspected := map[string]bool{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		if len(args) > 1 && args[0] == "image" && args[1] == "inspect" {
			ref := args[len(args)-1]
			service := ""
			for _, name := range resetImageServices {
				if ref == "ghcr.io/owner/opensamguk:"+name+"-"+candidate.Updates["IMAGE_TAG"] {
					service = name
				}
			}
			if service == "" {
				t.Fatalf("inspection did not use exact approved tag: %s", ref)
			}
			if !pulled {
				return "null", nil
			}
			inspected[service] = true
			out, ok := resetDigestInspectFixture(t, args)
			if !ok {
				t.Fatal("missing image fixture")
			}
			return out, nil
		}
		if strings.Contains(strings.Join(args, " "), "pull game-engine game-api web-game") {
			staged := ""
			for i, arg := range args {
				if arg == "--env-file" && i+1 < len(args) {
					staged = args[i+1]
				}
			}
			values, err := readEnvValues(staged)
			if err != nil {
				t.Fatal(err)
			}
			if values["IMAGE_TAG"] != candidate.Updates["IMAGE_TAG"] || values["WEB_GAME_TAG"] != candidate.Updates["WEB_GAME_TAG"] {
				t.Fatal("pull did not use exact approved tags")
			}
			pulled = true
			return "ok", nil
		}
		t.Fatalf("unexpected candidate command: %v", args)
		return "", nil
	}
	if _, err := cfg.pullResetCandidate(context.Background(), target, candidate); err != nil {
		t.Fatal(err)
	}
	if !pulled || len(inspected) != 3 {
		t.Fatalf("exact candidate not verified: pulled=%v inspected=%v", pulled, inspected)
	}
}

func TestLinkedLegacyPinnedJournalCleanupRequiresBoundSuccess(t *testing.T) {
	for _, mode := range []string{"running", "succeeded", "wrong-subject", "wrong-kind", "wrong-fingerprint", "postcondition-failure"} {
		t.Run(mode, func(t *testing.T) {
			cfg := configuredResetOperationTest(t)
			operationID := "8899aabbccddeeff0011223344556677"
			legacy, err := normalizeResetLifecycleJournalTarget(resetDigestFixture(t, nil))
			if err != nil {
				t.Fatal(err)
			}
			record := durableOperationRecord{OperationID: operationID, Kind: lifecycleKindReset, SubjectID: "pep", RequestFingerprint: resetRequestFingerprint("pep", legacy), Status: lifecycleJobRunning}
			if mode == "wrong-subject" {
				record.SubjectID = "uni"
			}
			if mode == "wrong-kind" {
				record.Kind = lifecycleKindCreate
			}
			if mode == "wrong-fingerprint" {
				record.RequestFingerprint = strings.Repeat("f", 64)
			}
			mustReserveOperation(t, cfg.lifecycleOperationStore, record)
			if mode != "running" {
				mustTransitionOperation(t, cfg.lifecycleOperationStore, operationID, lifecycleJobSucceeded, http.StatusOK, durableOperationResetSucceededMessage)
			}
			target, err := cfg.serverTargetForID("pep")
			if err != nil {
				t.Fatal(err)
			}
			// A completed legacy reset has already published its env and registry.
			// Apply the explicit old settings without the new strict execution gate.
			values := map[string]string{"IMAGE_TAG": legacy.Updates["IMAGE_TAG"], "WEB_GAME_TAG": legacy.Updates["WEB_GAME_TAG"], "SERVER_GENERATION": "0", "SCENARIO_CODE": "scenario_990002", "SCENARIO_SEED_ENABLED": "true"}
			if _, err := patchEnvFile(target.EnvFile, serverEnvAllowlist, values); err != nil {
				t.Fatal(err)
			}
			if err := cfg.reconcileServerRegistry(target); err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(lifecycleJournal{Version: lifecycleJournalVersion, Operation: "reset", OperationID: operationID, OperationKind: lifecycleKindReset, Stage: lifecycleJournalStageDown, ServerID: "pep", Project: target.Project, ResetTarget: &legacy})
			if err != nil {
				t.Fatal(err)
			}
			writeEnv(t, cfg.lifecycleJournalFile, string(wire))
			configureLoadConfigTest(t, cfg)
			restarted, err := loadConfig()
			if err != nil {
				t.Fatal(err)
			}
			restarted.httpGet = cfg.httpGet
			if mode == "postcondition-failure" {
				restarted.httpGet = func(context.Context, string) (int, []byte, error) { return 0, nil, errors.New("synthetic unavailable") }
				restarted.resetVerifyTimeout = 20 * time.Millisecond
				restarted.resetVerifyPollInterval = time.Millisecond
			}
			calls := &dockerCallRecorder{}
			restarted.dockerRunner = func(args ...string) (string, error) { calls.record(args...); return "ok", nil }
			oldEnv, oldShared := readFile(t, target.EnvFile), readFile(t, cfg.sharedEnvFile())
			repairErr := restarted.repairLifecycleJournal()
			if mode == "succeeded" {
				if repairErr != nil || stateFilePresent(cfg.lifecycleJournalFile) {
					t.Fatalf("bound completed journal not cleared: %v", repairErr)
				}
			} else {
				if repairErr == nil || readFile(t, cfg.lifecycleJournalFile) != string(wire) {
					t.Fatalf("unsafe legacy repair/clear in %s: %v", mode, repairErr)
				}
			}
			if calls.count() != 0 {
				t.Fatalf("legacy cleanup/refusal reached Docker: %v", calls.snapshot())
			}
			if readFile(t, target.EnvFile) != oldEnv || readFile(t, cfg.sharedEnvFile()) != oldShared {
				t.Fatal("legacy cleanup/refusal changed env or registry")
			}
			after, ok := restarted.lifecycleOperationStore.Lookup(operationID)
			if !ok {
				t.Fatal("linked operation lost")
			}
			if mode != "running" && after.Status != lifecycleJobSucceeded {
				t.Fatal("terminal linked operation changed on cleanup refusal")
			}
		})
	}
}
