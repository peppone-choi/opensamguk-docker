package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func restoredDatabaseFixture() (resetD101RestoredDatabaseOriginal, time.Time, time.Time) {
	start := time.Unix(1791162000, 0).UTC()
	end := start.Add(2 * time.Second)
	return resetD101RestoredDatabaseOriginal{1, "D101_RESTORED_DATABASE_OBSERVATION_V1", "game", "game", "172.22.0.3", 5432,
		"on", "repeatable read", 1, 1, "scenario_990002", 300, "number", "9", start.Add(time.Second).Format(time.RFC3339Nano)}, start, end
}

func TestRestoredDatabaseUsesActualOldIdentityAndRefusesNewWorldSubstitution(t *testing.T) {
	value, start, end := restoredDatabaseFixture()
	wire, _ := json.Marshal(value)
	observed, err := decodeResetD101RestoredDatabase(wire, "game", "game", "172.22.0.3", start, end)
	registry := resetD101OldCanonicalRegistry{ID: "pep", Generation: 9, ScenarioCode: "scenario_990002"}
	if err != nil || requireResetD101RestoredDatabaseMatchesOld(observed, registry, 300) != nil {
		t.Fatal("actual old identity refused", err)
	}
	for _, mode := range []string{"new-world", "unknown-generation", "unknown-scenario", "unknown-tick", "wrong-world"} {
		t.Run(mode, func(t *testing.T) {
			changed, old, tick := observed, registry, 300
			switch mode {
			case "new-world":
				changed.GenerationRaw, changed.ScenarioCode, changed.TickSeconds = "0", "scenario_3190", 3600
			case "unknown-generation":
				old.Generation = -1
			case "unknown-scenario":
				old.ScenarioCode = ""
			case "unknown-tick":
				tick = 0
			case "wrong-world":
				changed.WorldID = 2
			}
			if requireResetD101RestoredDatabaseMatchesOld(changed, old, tick) == nil {
				t.Fatal("new/unknown old-world identity accepted")
			}
		})
	}
}

func TestRestoredDatabaseRejectsWriteTransactionEndpointTypesAndMalformedOriginals(t *testing.T) {
	fixture, start, end := restoredDatabaseFixture()
	for _, mode := range []string{"writeable", "isolation", "address", "database", "user", "port", "world-count", "generation-type", "generation-decimal", "generation-leading-zero", "generation-negative", "observed-future", "stale", "duplicate", "unknown", "null", "trailing", "utf8"} {
		t.Run(mode, func(t *testing.T) {
			value, completed := fixture, end
			switch mode {
			case "writeable":
				value.TransactionReadOnly = "off"
			case "isolation":
				value.TransactionIsolation = "read committed"
			case "address":
				value.ServerAddress = "172.22.0.4"
			case "database":
				value.DatabaseName = "other"
			case "user":
				value.DatabaseUser = "other"
			case "port":
				value.ServerPort = 5433
			case "world-count":
				value.WorldRowCount = 2
			case "generation-type":
				value.GenerationType = "string"
			case "generation-decimal":
				value.GenerationRaw = "9.0"
			case "generation-leading-zero":
				value.GenerationRaw = "09"
			case "generation-negative":
				value.GenerationRaw = "-1"
			case "observed-future":
				value.ObservedAtUTC = end.Add(time.Second).Format(time.RFC3339Nano)
			case "stale":
				completed = start.Add(resetPreflightMaxAge)
			}
			wire, _ := json.Marshal(value)
			switch mode {
			case "duplicate":
				wire = []byte(strings.Replace(string(wire), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1))
			case "unknown":
				wire = []byte(strings.TrimSuffix(string(wire), "}") + `,"restoreSucceeded":true}`)
			case "null":
				wire = []byte(strings.Replace(string(wire), `"generationRaw":"9"`, `"generationRaw":null`, 1))
			case "trailing":
				wire = append(wire, []byte(`{}`)...)
			case "utf8":
				wire = []byte{0xff}
			}
			if _, err := decodeResetD101RestoredDatabase(wire, "game", "game", "172.22.0.3", start, completed); err == nil {
				t.Fatal("unbound SQL observation accepted", mode)
			}
		})
	}
}

func TestRestoredDatabaseMissingSameOpClaimCannotInvokeDockerOrProduceProof(t *testing.T) {
	calls := 0
	c := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	inputs := resetD101RestoredDatabaseInputs{strings.Repeat("a", 64), "opensamguk-spep", "opensamguk-spep_default", "game", "game", "/srv/local/servers/private/pgpass", "/srv/host/servers/private/pgpass", strings.Repeat("b", 64)}
	observed, err := c.collectResetD101RestoredDatabase(context.Background(), resetD101SucceededRestore{}, inputs)
	if err == nil || calls != 0 || observed.sha != "" || observed.jobID != "" || len(observed.original) != 0 {
		t.Fatal("missing same-op immutable claim produced DB recovery observation")
	}
}

func TestRestoredDatabaseActualPSQLCommandRejectsChangedEndpointSQLAndUser(t *testing.T) {
	id := strings.Repeat("a", 64)
	args := []string{"-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-h", "172.22.0.3", "-p", "5432", "-U", "game", "-d", "game", "-c", resetD101RestoredDatabaseSQL}
	for _, mode := range []string{"valid", "endpoint", "sql", "user", "path", "id", "unknown"} {
		fields := map[string]any{"id": id, "path": "psql", "args": append([]string(nil), args...), "user": "0:0"}
		switch mode {
		case "endpoint":
			fields["args"].([]string)[7] = "172.22.0.4"
		case "sql":
			fields["args"].([]string)[len(args)-1] = "UPDATE world_state SET generation=0"
		case "user":
			fields["user"] = "postgres"
		case "path":
			fields["path"] = "sh"
		case "id":
			fields["id"] = strings.Repeat("b", 64)
		case "unknown":
			fields["authorized"] = true
		}
		wire, _ := json.Marshal(fields)
		c := config{dockerRunnerContext: func(_ context.Context, actual ...string) (string, error) {
			if len(actual) != 4 || actual[0] != "inspect" || actual[3] != id {
				t.Fatal("unexpected physical command")
			}
			return string(wire), nil
		}}
		if err := c.requireResetD101RestoredPSQLCommand(context.Background(), id, args); (err == nil) != (mode == "valid") {
			t.Fatal("actual fixed PSQL command validation mismatch", mode, err)
		}
	}
}
