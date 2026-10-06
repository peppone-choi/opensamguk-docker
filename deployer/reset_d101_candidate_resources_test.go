package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestCandidateComposeContainsOnlyOperationScopedStorageAndLiveAppsJoinSameNetwork(t *testing.T) {
	op := strings.Repeat("a", 32)
	pins := map[string]string{}
	for _, service := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		pins[service] = "sha256:" + strings.Repeat("b", 64)
	}
	candidate, live, err := produceResetD101CandidateCompose(op, pins)
	if err != nil {
		t.Fatal(err)
	}
	var storage, apps map[string]any
	if json.Unmarshal(candidate, &storage) != nil || json.Unmarshal(live, &apps) != nil {
		t.Fatal("compose originals")
	}
	services := storage["services"].(map[string]any)
	if len(services) != 2 || services["game-postgres"] == nil || services["game-redis"] == nil {
		t.Fatal("candidate live services")
	}
	names := resetD101CandidateResourceNames(op)
	if storage["name"] != names.Project || storage["networks"].(map[string]any)["candidate"].(map[string]any)["name"] != names.Network {
		t.Fatal("wrong storage scope")
	}
	liveServices := apps["services"].(map[string]any)
	if len(liveServices) != 3 || liveServices["game-postgres"] != nil || liveServices["game-redis"] != nil {
		t.Fatal("live replaces verified storage")
	}
	if apps["networks"].(map[string]any)["d101-candidate"].(map[string]any)["name"] != names.Network {
		t.Fatal("different live DB network")
	}
	if strings.Contains(string(candidate), "docker.sock") || strings.Contains(string(candidate), "privileged") {
		t.Fatal("storage capability drift")
	}
}

func TestCandidateGuardedConfigChecksAuthorityForEachHelperCommand(t *testing.T) {
	for _, mode := range []string{"context-runner", "legacy-runner"} {
		t.Run(mode, func(t *testing.T) {
			a := workerAdmissionFixture(t)
			var calls []string
			physical := func(args ...string) (string, error) {
				calls = append(calls, args[0])
				return "original-output", nil
			}
			original := config{dockerRunner: physical}
			if mode == "context-runner" {
				original.dockerRunnerContext = func(ctx context.Context, args ...string) (string, error) {
					if ctx.Err() != nil {
						t.Fatal("cancelled physical command")
					}
					return physical(args...)
				}
				original.dockerRunner = func(...string) (string, error) { t.Fatal("runner precedence changed"); return "", nil }
			}
			revoked := false
			guard := func(context.Context) error {
				calls = append(calls, "guard")
				if revoked {
					return errors.New("revoked")
				}
				return nil
			}
			guarded := original.withResetD101CandidateCommandGuard(a, guard)
			ctx := context.Background()
			for _, command := range []string{"inspect", "image"} {
				if out, err := guarded.runServerDockerContext(ctx, command, "unchanged-argument"); err != nil || out != "original-output" {
					t.Fatalf("guarded runner output: %q %v", out, err)
				}
			}
			revoked = true
			if out, err := guarded.runServerDockerContext(ctx, "start"); err == nil || out != "" {
				t.Fatal("revoked authority reached physical runner")
			}
			if !reflect.DeepEqual(calls, []string{"guard", "inspect", "guard", "image", "guard"}) {
				t.Fatalf("physical order: %v", calls)
			}
			if out, err := original.runServerDockerContext(ctx, "original"); err != nil || out != "original-output" {
				t.Fatal("guard copy mutated original runner")
			}
		})
	}
}
