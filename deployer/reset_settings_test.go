package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestExplicitResetSettingsPreserveZeroAndEmptyLookupInTargetAndRegistry(t *testing.T) {
	cfg := configuredResetOperationTest(t)
	envFile := filepath.Join(cfg.serversDir, "spep.env")
	writeEnv(t, envFile, readFile(t, envFile)+"SCENARIO_LOOKUP_DIR=/data/scenarios\n")
	var request resetServerRequest
	if err := json.Unmarshal([]byte(`{"serverName":"빼섭","generation":"0","scenarioCode":"scenario_3190","scenarioSeedEnabled":true,"scenarioLookupDir":"","turnTerm":"60","maxGeneral":50,"firstTurn":"immediate","extend":"1","blockGeneralCreate":"1","npcMode":"0","showImgLevel":"3"}`), &request); err != nil {
		t.Fatal(err)
	}
	updates, err := resetEnvUpdates(request)
	if err != nil {
		t.Fatal(err)
	}
	target, err := resetLifecycleTargetForEnv(envFile, updates)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyResetLifecycleTarget(envFile, target); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.syncRegistryEntryFromEnv("pep", envFile); err != nil {
		t.Fatal(err)
	}
	entry, err := cfg.registryEntryByID("pep")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Name != "빼섭" || entry.Generation != 0 {
		t.Fatalf("reset identity was not preserved: name=%s generation=%d", entry.Name, entry.Generation)
	}
	for key, expected := range map[string]string{
		"SERVER_NAME": "빼섭", "SERVER_GENERATION": "0", "SCENARIO_CODE": "scenario_3190",
		"SCENARIO_LOOKUP_DIR": "", "RESET_TURNTERM": "60", "RESET_MAXGENERAL": "50", "RESET_FIRST_TURN": "immediate",
	} {
		value, present := target.Updates[key]
		if !present || value != expected || !strings.Contains(readFile(t, envFile), key+"="+expected+"\n") {
			t.Fatalf("target/env setting lost: %s", key)
		}
		if actual, present := entry.Env[key]; !present || actual != expected {
			t.Fatalf("registry setting lost: %s", key)
		}
	}
	for key, replacement := range map[string]string{"SERVER_NAME": "다른 이름", "RESET_MAXGENERAL": "51", "RESET_FIRST_TURN": "scheduled", "SCENARIO_LOOKUP_DIR": "/data/scenarios"} {
		changed := target
		changed.Updates = make(map[string]string, len(target.Updates))
		for k, v := range target.Updates {
			changed.Updates[k] = v
		}
		changed.Updates[key] = replacement
		if resetRequestFingerprint("pep", changed) == resetRequestFingerprint("pep", target) {
			t.Fatalf("request fingerprint omitted %s", key)
		}
	}
}

func TestExplicitResetSettingsRejectInvalidTypedValues(t *testing.T) {
	for _, body := range []string{
		`{"maxGeneral":0}`, `{"maxGeneral":10000}`, `{"maxGeneral":50.5}`, `{"maxGeneral":"50"}`,
		`{"firstTurn":""}`, `{"firstTurn":" immediate"}`, `{"firstTurn":"NOW"}`,
		`{"serverName":""}`, `{"serverName":" 빼섭"}`, `{"serverName":"빼섭\n"}`,
		`{"scenarioLookupDir":" "}`, `{"scenarioLookupDir":"/tmp/scenarios"}`, `{"scenarioLookupDir":"/data/scenarios/"}`,
	} {
		var request resetServerRequest
		err := json.Unmarshal([]byte(body), &request)
		if err == nil {
			_, err = resetEnvUpdates(request)
		}
		if err == nil {
			t.Fatalf("invalid explicit setting was accepted: %s", body)
		}
	}
	for _, values := range []map[string]string{
		{"RESET_MAXGENERAL": "0"}, {"RESET_MAXGENERAL": "99999999999999999999"}, {"RESET_MAXGENERAL": "５０"},
		{"RESET_MAXGENERAL": " 50"}, {"RESET_FIRST_TURN": " immediate"}, {"SERVER_NAME": "빼섭\n"}, {"SCENARIO_LOOKUP_DIR": "/data/scenarios/"},
	} {
		if _, err := normalizeResetLifecycleTarget(resetLifecycleTarget{ScenarioCode: "scenario_3190", Generation: 0, ScenarioSeedEnabled: true, Updates: values}); err == nil {
			t.Fatal("invalid journal setting was accepted")
		}
	}
}

func TestLegacyResetDoesNotInventExplicitSettingsOrChangeFingerprintShape(t *testing.T) {
	cfg := configuredResetOperationTest(t)
	envFile := filepath.Join(cfg.serversDir, "spep.env")
	writeEnv(t, envFile, readFile(t, envFile)+"SERVER_NAME=old\nRESET_MAXGENERAL=500\nRESET_FIRST_TURN=scheduled\nSCENARIO_LOOKUP_DIR=/data/scenarios\n")
	target, err := resetLifecycleTargetForEnv(envFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"SERVER_NAME", "RESET_MAXGENERAL", "RESET_FIRST_TURN", "SCENARIO_LOOKUP_DIR"} {
		if _, present := target.Updates[key]; present {
			t.Fatalf("legacy target invented an explicit setting: %s", key)
		}
	}
}

func TestExplicitResetSettingsReachEngineWithoutProcessOverrideOrComposeDefaults(t *testing.T) {
	compose := readFile(t, filepath.Join("..", "docker-compose.server.yml"))
	start := strings.Index(compose, "\n  game-engine:\n")
	if start < 0 {
		t.Fatal("missing engine")
	}
	engine := compose[start:]
	end := strings.Index(engine, "\n  game-api:\n")
	if end < 0 {
		t.Fatal("missing API boundary")
	}
	engine = engine[:end]
	for _, key := range []string{"RESET_MAXGENERAL", "RESET_FIRST_TURN"} {
		if !strings.Contains(engine, key+": ${"+key+":-}") {
			t.Fatalf("engine setting is not wired: %s", key)
		}
		if _, protected := serverComposeInterpolationKeys[key]; !protected {
			t.Fatalf("process override is not removed: %s", key)
		}
	}
}

func Test3190ResetCannotUseUnleasedLegacyPath(t *testing.T) {
	cfg := configuredResetOperationTest(t)
	envFile := filepath.Join(cfg.serversDir, "spep.env")
	oldEnv, oldShared := readFile(t, envFile), readFile(t, cfg.sharedEnvFile())
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) { calls.record(args...); return "unexpected", nil }
	response := envRequest(t, cfg.withAuth(cfg.handleServerReset), http.MethodPost, "/servers/reset", `{"id":"pep","confirm":"RESET pep","scenarioCode":"scenario_3190","generation":"0"}`)
	if response.Code != http.StatusBadRequest || calls.count() != 0 || stateFilePresent(cfg.lifecycleJournalFile) || readFile(t, envFile) != oldEnv || readFile(t, cfg.sharedEnvFile()) != oldShared {
		t.Fatal("3190 request entered a reset without the maintenance prerequisites")
	}
}
