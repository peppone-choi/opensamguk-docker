package main

import (
	"encoding/json"
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
