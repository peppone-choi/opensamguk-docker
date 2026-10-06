package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func candidateCapsFixture(t *testing.T) ([]byte, time.Time, time.Time) {
	t.Helper()
	started := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	value := resetD101CandidateCapsObservation{SchemaVersion: 1, Kind: "D101_CANDIDATE_DB_CAPS_V1", DatabaseName: "game", DatabaseUser: "game", ServerAddress: "172.18.0.3", ServerPort: 5432, TransactionReadOnly: "on", TransactionIsolation: "repeatable read", WorldRowCount: 1, WorldID: 1, ScenarioCode: "scenario_3190", TickSeconds: 3600, GenerationType: "number", GenerationRaw: "0", GenerationApprovalIntentSHA: strings.Repeat("b", 64), ConfigMaxGeneralType: "number", ConfigMaxGeneralRaw: "50", GameEnvRowCount: 1, GameEnvMaxGeneralType: "number", GameEnvMaxGeneralRaw: "50", ObservedAtUTC: started.Add(time.Second).Format(time.RFC3339Nano)}
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return wire, started, started.Add(2 * time.Second)
}
func TestCandidateCapsRequiresActualNumericBothCapsAndCandidateDatabaseIdentity(t *testing.T) {
	wire, started, completed := candidateCapsFixture(t)
	if _, err := decodeResetD101CandidateCaps(wire, "game", "game", "172.18.0.3", strings.Repeat("b", 64), started, completed); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		key   string
		value any
	}{
		{"generationType", "string"}, {"generationRaw", nil}, {"generationApprovalIntentSha256", strings.Repeat("c", 64)}, {"generationRaw", "1"}, {"configMaxGeneralType", "string"}, {"configMaxGeneralRaw", "500"}, {"gameEnvMaxGeneralType", "string"}, {"gameEnvMaxGeneralRaw", "50.0"},
		{"gameEnvRowCount", 2}, {"worldRowCount", 2}, {"serverAddress", "172.18.0.4"}, {"serverPort", 5433}, {"databaseUser", "other"},
		{"transactionReadOnly", "off"}, {"transactionIsolation", "read committed"}, {"tickSeconds", 60}, {"worldId", 2}, {"scenarioCode", "scenario_990002"},
		{"observedAtUtc", started.Add(-time.Second).Format(time.RFC3339Nano)}, {"configMaxGeneralRaw", nil}, {"unexpected", true},
	} {
		var tree map[string]any
		if json.Unmarshal(wire, &tree) != nil {
			t.Fatal("fixture")
		}
		tree[change.key] = change.value
		changed, _ := json.Marshal(tree)
		if _, err := decodeResetD101CandidateCaps(changed, "game", "game", "172.18.0.3", strings.Repeat("b", 64), started, completed); err == nil {
			t.Fatal("accepted " + change.key)
		}
	}
	duplicate := append(append([]byte(nil), wire[:len(wire)-1]...), []byte(`,"worldId":1}`)...)
	if _, err := decodeResetD101CandidateCaps(duplicate, "game", "game", "172.18.0.3", strings.Repeat("b", 64), started, completed); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := decodeResetD101CandidateCaps(wire, "game", "game", "172.18.0.3", strings.Repeat("b", 64), started, started.Add(30*time.Second)); err == nil {
		t.Fatal("stale accepted")
	}
}
func TestCandidateCapsMountRequiresOnlyPrivateReadonlyCredentialAndBoundedTemporaryData(t *testing.T) {
	job := resetD101CapsJob{Mounts: []resetD101CapsMount{{"bind", "/private/pgpass", "/run/d101/pgpass", false}, {"tmpfs", "", "/var/lib/postgresql/data", true}}}
	if !validResetD101CapsMount(job, "/private/pgpass") {
		t.Fatal("fixed mount rejected")
	}
	for _, mode := range []string{"writable-secret", "other-secret", "volume", "extra"} {
		changed := job
		changed.Mounts = append([]resetD101CapsMount(nil), job.Mounts...)
		switch mode {
		case "writable-secret":
			changed.Mounts[0].RW = true
		case "other-secret":
			changed.Mounts[0].Source = "/other/pgpass"
		case "volume":
			changed.Mounts[1].Type = "volume"
		case "extra":
			changed.Mounts = append(changed.Mounts, resetD101CapsMount{"bind", "/var/run/docker.sock", "/socket", false})
		}
		if validResetD101CapsMount(changed, "/private/pgpass") {
			t.Fatal("accepted " + mode)
		}
	}
}
