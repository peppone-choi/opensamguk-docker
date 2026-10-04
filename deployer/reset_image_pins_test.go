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
)

func TestLegacyPinnedResetJournalLoadsButCannotRepair(t *testing.T) {
	for _, stage := range []string{lifecycleJournalStagePrepared, lifecycleJournalStageEnv, lifecycleJournalStageRegistry, lifecycleJournalStageDown} {
		t.Run(stage, func(t *testing.T) {
			cfg := configuredResetOperationTest(t)
			legacy := resetDigestFixture(t, nil)
			legacy.Updates["WEB_GAME_TAG"] = strings.Repeat("c", 40)
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

func TestResetCandidateUsesVerifiedLocalImagesBeforePull(t *testing.T) {
	for _, cached := range []bool{true, false} {
		t.Run(fmt.Sprintf("cached=%v", cached), func(t *testing.T) {
			cfg := testConfig(t)
			envFile := filepath.Join(cfg.serversDir, "spep.env")
			writeEnv(t, envFile, "SERVER_ID=pep\nIMAGE_TAG=old\nSERVER_GENERATION=1\nSCENARIO_CODE=scenario_1020\nSCENARIO_SEED_ENABLED=true\n")
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
	state := decodeMaintenanceResponse(t, loopbackRequest(t, maintenance, http.MethodGet, "/maintenance", ""))
	if state.State != maintenanceStateDrained {
		t.Fatal("failed verification reopened maintenance")
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
			original := "SERVER_ID=pep\nIMAGE_TAG=old\nWEB_GAME_TAG=old\nSERVER_GENERATION=1\nSCENARIO_CODE=scenario_1020\nSCENARIO_SEED_ENABLED=true\n"
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
