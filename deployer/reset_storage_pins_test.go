package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestResetStoragePinsPreserveLegacyAndRejectIncompleteTarget(t *testing.T) {
	legacy := resetDigestFixture(t, resetDigestPins())
	normalized, err := normalizeResetLifecycleTarget(legacy)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(normalized)
	if strings.Contains(string(wire), "storageImageDigests") || strings.Contains(string(wire), "GAME_POSTGRES_IMAGE") {
		t.Fatal("legacy target invented storage pins")
	}
	plan, _, _ := resetEvidenceFixture(t)
	expected := plan.Target
	for _, service := range resetStorageServices {
		key := "GAME_POSTGRES_IMAGE"
		if service == "game-redis" {
			key = "GAME_REDIS_IMAGE"
		}
		if expected.Updates[key] != resetStorageReference(service, expected.StorageImageDigests[service]) {
			t.Fatal("storage reference is not immutable")
		}
	}
	for _, mode := range []string{"missing", "mutable", "extra", "wrong-reference", "no-app-pins"} {
		t.Run(mode, func(t *testing.T) {
			bad := resetDigestFixture(t, resetDigestPins())
			bad.StorageImageDigests = map[string]string{"game-postgres": "sha256:" + strings.Repeat("d", 64), "game-redis": "sha256:" + strings.Repeat("e", 64)}
			switch mode {
			case "missing":
				delete(bad.StorageImageDigests, "game-redis")
			case "mutable":
				bad.StorageImageDigests["game-redis"] = "latest"
			case "extra":
				bad.StorageImageDigests["gateway-redis"] = "sha256:" + strings.Repeat("f", 64)
			case "wrong-reference":
				bad.Updates["GAME_POSTGRES_IMAGE"] = "untrusted.invalid/postgres:latest"
			case "no-app-pins":
				delete(bad.Updates, "IMAGE_TAG")
				delete(bad.Updates, "WEB_GAME_TAG")
				bad.ImageDigests = nil
			}
			if _, err := normalizeResetLifecycleTarget(bad); err == nil {
				t.Fatal("invalid storage target accepted")
			}
		})
	}
	cfg := testConfig(t)
	env := filepath.Join(cfg.serversDir, "spep.env")
	writeEnv(t, env, "SERVER_ID=pep\nSERVER_GENERATION=1\nSCENARIO_CODE=scenario_990002\nSCENARIO_SEED_ENABLED=true\n")
	updates := map[string]string{"IMAGE_TAG": legacy.Updates["IMAGE_TAG"], "WEB_GAME_TAG": legacy.Updates["WEB_GAME_TAG"]}
	target, err := resetLifecycleTargetForEnvWithStorageDigests(env, updates, resetDigestPins(), expected.StorageImageDigests)
	if err != nil || len(target.StorageImageDigests) != 2 {
		t.Fatalf("typed storage target failed: %v", err)
	}
	for _, key := range []string{"GAME_POSTGRES_IMAGE", "GAME_REDIS_IMAGE"} {
		for _, entry := range cfg.serverComposeEnvironment([]string{key + "=untrusted:latest"}) {
			if strings.HasPrefix(entry, key+"=") {
				t.Fatal("process override survived")
			}
		}
	}
}

func TestResetStorageInspectionChecksExactDigestRepositoryAndPlatform(t *testing.T) {
	plan, _, _ := resetEvidenceFixture(t)
	for _, mode := range []string{"valid", "wrong-digest", "wrong-repository", "wrong-platform", "missing-inspection"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			cfg := config{dockerRunnerContext: func(ctx context.Context, args ...string) (string, error) {
				calls++
				if args[0] != "image" || args[1] != "inspect" {
					t.Fatal("storage verifier reached mutation")
				}
				if mode == "missing-inspection" {
					return "", errors.New("synthetic unavailable")
				}
				service := resetStorageServices[calls-1]
				reference := resetStorageReference(service, plan.Target.StorageImageDigests[service])
				if args[len(args)-1] != reference {
					t.Fatal("mutable reference inspected")
				}
				name := "postgres"
				if service == "game-redis" {
					name = "redis"
				}
				digest := "docker.io/library/" + name + "@" + plan.Target.StorageImageDigests[service]
				if mode == "wrong-digest" {
					digest = "docker.io/library/" + name + "@sha256:" + strings.Repeat("f", 64)
				}
				if mode == "wrong-repository" {
					digest = "untrusted.invalid/" + name + "@" + plan.Target.StorageImageDigests[service]
				}
				arch := "amd64"
				if mode == "wrong-platform" {
					arch = "arm64"
				}
				wire, _ := json.Marshal(map[string]any{"repoDigests": []string{digest}, "os": "linux", "architecture": arch})
				return string(wire), nil
			}}
			err := cfg.verifyResetCandidateStorageImages(context.Background(), plan.Target)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
			if mode == "valid" && calls != 2 {
				t.Fatal("both storage images were not inspected")
			}
		})
	}
}

func TestResetFiveImagePullUsesImmutableStorageInStagedEnv(t *testing.T) {
	cfg := testConfig(t)
	env := filepath.Join(cfg.serversDir, "spep.env")
	writeEnv(t, env, "SERVER_ID=pep\nIMAGE_TAG=old\nSERVER_GENERATION=1\nSCENARIO_CODE=scenario_990002\nSCENARIO_SEED_ENABLED=true\nGHCR_OWNER=owner\n")
	original := readFile(t, env)
	target, err := cfg.serverTargetForID("pep")
	if err != nil {
		t.Fatal(err)
	}
	candidate := resetDigestFixture(t, resetDigestPins())
	candidate.StorageImageDigests = map[string]string{"game-postgres": "sha256:" + strings.Repeat("d", 64), "game-redis": "sha256:" + strings.Repeat("e", 64)}
	candidate, err = normalizeResetLifecycleTarget(candidate)
	if err != nil {
		t.Fatal(err)
	}
	pulled := false
	inspected := map[string]bool{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		if len(args) > 1 && args[0] == "image" && args[1] == "inspect" {
			if !pulled {
				return "null", nil
			}
			ref := args[len(args)-1]
			for _, service := range resetStorageServices {
				if ref == resetStorageReference(service, candidate.StorageImageDigests[service]) {
					inspected[service] = true
					name := "postgres"
					if service == "game-redis" {
						name = "redis"
					}
					wire, _ := json.Marshal(map[string]any{"repoDigests": []string{name + "@" + candidate.StorageImageDigests[service]}, "os": "linux", "architecture": "amd64"})
					return string(wire), nil
				}
			}
			for _, service := range resetImageServices {
				if ref == "ghcr.io/owner/opensamguk:"+service+"-"+candidate.Updates["IMAGE_TAG"] {
					inspected[service] = true
				}
			}
			out, ok := resetDigestInspectFixture(t, args)
			if !ok {
				t.Fatal("unknown app image inspected")
			}
			return out, nil
		}
		if strings.Contains(strings.Join(args, " "), "pull game-engine game-api web-game game-postgres game-redis") {
			staged := ""
			for index, arg := range args {
				if arg == "--env-file" {
					staged = args[index+1]
				}
			}
			values, err := readEnvValues(staged)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"GAME_POSTGRES_IMAGE", "GAME_REDIS_IMAGE"} {
				if values[key] != candidate.Updates[key] {
					t.Fatal("pull used an unpinned storage env")
				}
			}
			pulled = true
			return "ok", nil
		}
		t.Fatal("unexpected mutation")
		return "", nil
	}
	if _, err := cfg.pullResetCandidate(context.Background(), target, candidate); err != nil {
		t.Fatal(err)
	}
	if !pulled || len(inspected) != 5 || readFile(t, env) != original || stateFilePresent(cfg.lifecycleJournalFile) {
		t.Fatal("five-image staging mutated canonical state")
	}
}

func TestD101GenericRecoveryCannotBypassMissingEvidenceWorkflow(t *testing.T) {
	cfg := configuredResetOperationTest(t)
	plan, _, _ := resetEvidenceFixture(t)
	target, err := cfg.serverTargetForID("pep")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.writeResetLifecycleJournal(target, plan.Target); err != nil {
		t.Fatal(err)
	}
	oldEnv, oldShared, oldJournal := readFile(t, target.EnvFile), readFile(t, cfg.sharedEnvFile()), readFile(t, cfg.lifecycleJournalFile)
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) { calls.record(args...); return "unexpected", nil }
	if err := cfg.repairLifecycleJournal(); err == nil {
		t.Fatal("D101 generic replay ran without evidence binding")
	}
	if calls.count() != 0 || readFile(t, target.EnvFile) != oldEnv || readFile(t, cfg.sharedEnvFile()) != oldShared || readFile(t, cfg.lifecycleJournalFile) != oldJournal {
		t.Fatal("closed D101 recovery reached Docker or changed canonical state")
	}
}
