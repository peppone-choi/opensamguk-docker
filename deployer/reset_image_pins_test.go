package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

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
