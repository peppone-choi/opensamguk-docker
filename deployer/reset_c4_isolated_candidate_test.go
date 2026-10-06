package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Every observed value below is an isolated synthetic codec fixture. It is not
// C4 producer output, an actual daemon/container observation, or issued proof.
func resetC4CandidateFixture(t *testing.T) ([]byte, resetC4IsolatedProofBinding, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	app := strings.Repeat("a", 40)
	reference := strings.Repeat("b", 64)
	source := resetC4SelectedSource{"CLASSPATH", "scenario_3190", reference, 1234, strings.Repeat("c", 64), strings.Repeat("d", 64)}
	activeRetainers, zero := uint64(17), uint64(0)
	missing := []string{}
	operation, targetFingerprint := strings.Repeat("1", 32), strings.Repeat("f", 64)
	proof := resetC4IsolatedProofCandidate{OperationID: operation, TargetFingerprint: targetFingerprint, SchemaVersion: 1, EvidenceKind: "C4_ISOLATED_3190_SEED_TICK",
		EvidenceStatus: "OBSERVED_ISOLATED", AppSourceSHA: &app, ReferenceClasspathScenarioSHA: reference,
		SelectedSource: &source, MissingReasons: &missing}
	boundary := now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
	next := now.Add(-time.Hour).Format(time.RFC3339Nano)
	uuid := func(digit string) string {
		return strings.Repeat(digit, 8) + "-" + strings.Repeat(digit, 4) + "-4" + strings.Repeat(digit, 3) + "-8" + strings.Repeat(digit, 3) + "-" + strings.Repeat(digit, 12)
	}
	for index := 0; index < 2; index++ {
		value := string(rune('1' + index))
		before := string(rune('3' + index*2))
		after := string(rune('4' + index*2))
		proof.Runs = append(proof.Runs, resetC4IsolatedRun{
			RunID: uuid(value), ObservedAtUTC: now.Add(-time.Minute).Format(time.RFC3339Nano),
			PostgresContainerID: strings.Repeat(string(rune('1'+index*2)), 64),
			RedisContainerID:    strings.Repeat(string(rune('2'+index*2)), 64),
			WorldID:             1, Generation: "0", ScenarioCode: "scenario_3190", SelectedSourceRawBytesSHA: reference,
			Settings:       resetC4IsolatedSettings{190, 1, 1, 3600, 50, 50, 1, 1, "immediate"},
			SeedRows:       resetC4IsolatedRows{384, 21, 1428, 384, &activeRetainers, &zero},
			FirstTick:      resetC4IsolatedFirstTick{boundary, 384, boundary, next},
			ColdRestart:    resetC4IsolatedRestart{uuid(before), uuid(after), boundary, &zero},
			StableStateSHA: strings.Repeat("e", 64),
		})
	}
	wire, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	return wire, resetC4IsolatedProofBinding{operation, targetFingerprint, app, reference, source, &activeRetainers}, now
}
func resetC4WireSHA(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func TestResetC4CandidateHashesOriginalBytesAndKeepsActiveRetainerDenominator(t *testing.T) {
	wire, binding, now := resetC4CandidateFixture(t)
	before := append([]byte{}, wire...)
	proof, err := decodeResetC4IsolatedProofCandidate(wire, resetC4WireSHA(wire), binding, now)
	if err != nil || len(proof.Runs) != 2 || *proof.Runs[0].SeedRows.Retainer != 17 {
		t.Fatal("synthetic candidate refused")
	}
	if !bytes.Equal(before, wire) {
		t.Fatal("input mutated")
	}
	changed := append(append([]byte{}, wire...), '\n')
	if _, err = decodeResetC4IsolatedProofCandidate(changed, resetC4WireSHA(wire), binding, now); err == nil {
		t.Fatal("bytes were reserialized to pass old SHA")
	}
	if _, err = decodeResetC4IsolatedProofCandidate(changed, resetC4WireSHA(changed), binding, now); err != nil {
		t.Fatal("original different wire SHA refused")
	}
	var value map[string]any
	if json.Unmarshal(wire, &value) != nil {
		t.Fatal("fixture invalid")
	}
	zero := uint64(0)
	binding.ExpectedActiveRetainerRows = &zero
	for _, run := range value["runs"].([]any) {
		run.(map[string]any)["seedRows"].(map[string]any)["retainer"] = 0
	}
	wire, _ = json.Marshal(value)
	if _, err = decodeResetC4IsolatedProofCandidate(wire, resetC4WireSHA(wire), binding, now); err != nil {
		t.Fatal("explicit active-retainer zero defaulted or refused")
	}
	binding.ExpectedActiveRetainerRows = nil
	if _, err = decodeResetC4IsolatedProofCandidate(wire, resetC4WireSHA(wire), binding, now); err == nil {
		t.Fatal("unknown expected active rows accepted")
	}
}

func TestResetC4StaticOrNotProducedAndWrongBindingsCannotBecomeCandidate(t *testing.T) {
	wire, binding, now := resetC4CandidateFixture(t)
	samples := []string{
		`{"schemaVersion":1,"readOnly":true,"runtimeEffectiveSource":"UNKNOWN"}`,
		`{"schemaVersion":1,"evidenceKind":"C4_ISOLATED_3190_SEED_TICK","evidenceStatus":"NOT_PRODUCED","appSourceSha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","referenceClasspathScenarioSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","selectedSource":null,"runs":null,"missingReasons":["not produced"]}`,
	}
	for _, sample := range samples {
		raw := []byte(sample)
		if proof, err := decodeResetC4IsolatedProofCandidate(raw, resetC4WireSHA(raw), binding, now); err == nil || proof.SchemaVersion != 0 {
			t.Fatal("static or unproduced sample accepted")
		}
	}
	changed := binding
	changed.AppSourceSHA = strings.Repeat("f", 40)
	if _, err := decodeResetC4IsolatedProofCandidate(wire, resetC4WireSHA(wire), changed, now); err == nil {
		t.Fatal("other app accepted")
	}
	changed = binding
	changed.SelectedSource.RawByteLength++
	if _, err := decodeResetC4IsolatedProofCandidate(wire, resetC4WireSHA(wire), changed, now); err == nil {
		t.Fatal("other bytes accepted")
	}
	if _, err := decodeResetC4IsolatedProofCandidate(wire, strings.Repeat("f", 64), binding, now); err == nil {
		t.Fatal("other raw digest accepted")
	}
}
func TestResetC4CandidateRejectsMissingWrongOrNonIndependentMeasurements(t *testing.T) {
	wire, binding, now := resetC4CandidateFixture(t)
	type mutation struct {
		name   string
		change func(map[string]any)
	}
	run := func(root map[string]any, index int) map[string]any {
		return root["runs"].([]any)[index].(map[string]any)
	}
	cases := []mutation{
		{"other-operation", func(v map[string]any) { v["operationId"] = strings.Repeat("2", 32) }},
		{"other-target", func(v map[string]any) { v["targetFingerprint"] = strings.Repeat("a", 64) }},
		{"key-alias", func(v map[string]any) { v["OperationId"] = v["operationId"]; delete(v, "operationId") }},
		{"nested-key-alias", func(v map[string]any) {
			rows := run(v, 0)["seedRows"].(map[string]any)
			rows["HumanOwner"] = rows["humanOwner"]
			delete(rows, "humanOwner")
		}},
		{"unproduced", func(v map[string]any) { v["evidenceStatus"] = "NOT_PRODUCED" }},
		{"null-app", func(v map[string]any) { v["appSourceSha"] = nil }},
		{"null-source", func(v map[string]any) { v["selectedSource"] = nil }},
		{"null-runs", func(v map[string]any) { v["runs"] = nil }},
		{"one-run", func(v map[string]any) { v["runs"] = v["runs"].([]any)[:1] }},
		{"null-reasons", func(v map[string]any) { v["missingReasons"] = nil }},
		{"still-missing", func(v map[string]any) { v["missingReasons"] = []string{"restart missing"} }},
		{"unknown-top", func(v map[string]any) { v["approved"] = true }},
		{"unknown-nested", func(v map[string]any) { run(v, 0)["settings"].(map[string]any)["approved"] = true }},
		{"source-kind", func(v map[string]any) { v["selectedSource"].(map[string]any)["kind"] = "UNKNOWN" }},
		{"same-run-id", func(v map[string]any) { run(v, 1)["runId"] = run(v, 0)["runId"] }},
		{"same-postgres", func(v map[string]any) { run(v, 1)["postgresContainerId"] = run(v, 0)["postgresContainerId"] }},
		{"same-storage", func(v map[string]any) { run(v, 1)["redisContainerId"] = run(v, 0)["postgresContainerId"] }},
		{"world", func(v map[string]any) { run(v, 0)["worldId"] = 2 }},
		{"number-generation", func(v map[string]any) { run(v, 0)["generation"] = 0 }},
		{"null-generation", func(v map[string]any) { run(v, 0)["generation"] = nil }},
		{"selected-sha", func(v map[string]any) { run(v, 0)["selectedSourceRawBytesSha256"] = strings.Repeat("f", 64) }},
		{"config-cap", func(v map[string]any) { run(v, 0)["settings"].(map[string]any)["maxGeneralConfig"] = 51 }},
		{"env-cap", func(v map[string]any) { run(v, 0)["settings"].(map[string]any)["maxGeneralGameEnv"] = nil }},
		{"block-open", func(v map[string]any) { run(v, 0)["settings"].(map[string]any)["blockGeneralCreateConfig"] = 0 }},
		{"roster-is-not-stored", func(v map[string]any) { run(v, 0)["seedRows"].(map[string]any)["general"] = 1000 }},
		{"position-missing", func(v map[string]any) { run(v, 0)["seedRows"].(map[string]any)["generalPosition"] = 0 }},
		{"declared-is-not-active", func(v map[string]any) { run(v, 0)["seedRows"].(map[string]any)["retainer"] = 228 }},
		{"null-human-zero", func(v map[string]any) { run(v, 0)["seedRows"].(map[string]any)["humanOwner"] = nil }},
		{"missing-human-zero", func(v map[string]any) { delete(run(v, 0)["seedRows"].(map[string]any), "humanOwner") }},
		{"owned-human", func(v map[string]any) { run(v, 0)["seedRows"].(map[string]any)["humanOwner"] = 1 }},
		{"handled-zero", func(v map[string]any) { run(v, 0)["firstTick"].(map[string]any)["handledCount"] = 0 }},
		{"handled-boolean", func(v map[string]any) { run(v, 0)["firstTick"].(map[string]any)["handledCount"] = true }},
		{"no-flush", func(v map[string]any) {
			run(v, 0)["firstTick"].(map[string]any)["flushedLastTurnTimeUtc"] = now.Format(time.RFC3339Nano)
		}},
		{"next-boundary", func(v map[string]any) {
			run(v, 0)["firstTick"].(map[string]any)["nextBoundaryAtUtc"] = now.Format(time.RFC3339Nano)
		}},
		{"same-process", func(v map[string]any) {
			r := run(v, 0)["coldRestart"].(map[string]any)
			r["afterDaemonNonce"] = r["beforeDaemonNonce"]
		}},
		{"no-reload", func(v map[string]any) {
			run(v, 0)["coldRestart"].(map[string]any)["reloadedLastTurnTimeUtc"] = now.Format(time.RFC3339Nano)
		}},
		{"reapplied", func(v map[string]any) { run(v, 0)["coldRestart"].(map[string]any)["sameBoundaryReappliedCount"] = 1 }},
		{"null-reapplied-zero", func(v map[string]any) { run(v, 0)["coldRestart"].(map[string]any)["sameBoundaryReappliedCount"] = nil }},
		{"future-observation", func(v map[string]any) { run(v, 0)["observedAtUtc"] = now.Add(time.Second).Format(time.RFC3339Nano) }},
		{"timezone-alias", func(v map[string]any) {
			run(v, 0)["observedAtUtc"] = strings.TrimSuffix(run(v, 0)["observedAtUtc"].(string), "Z") + "+00:00"
		}},
		{"different-stable-state", func(v map[string]any) { run(v, 1)["stableStateSha256"] = strings.Repeat("f", 64) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var value map[string]any
			if json.Unmarshal(wire, &value) != nil {
				t.Fatal("fixture invalid")
			}
			test.change(value)
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := decodeResetC4IsolatedProofCandidate(raw, resetC4WireSHA(raw), binding, now); err == nil || result.SchemaVersion != 0 {
				t.Fatal("ambiguous or mismatched observation accepted")
			}
		})
	}
}
func TestResetC4CandidateStrictJSONAndBodyLimit(t *testing.T) {
	wire, binding, now := resetC4CandidateFixture(t)
	samples := [][]byte{
		bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1),
		append(append([]byte{}, wire...), []byte("{}")...),
		bytes.Replace(wire, []byte(`"humanOwner":0`), []byte(`"humanOwner":0.0`), 1),
		bytes.Repeat([]byte(" "), resetEvidenceMaxBytes+1),
		nil,
	}
	for _, raw := range samples {
		if _, err := decodeResetC4IsolatedProofCandidate(raw, resetC4WireSHA(raw), binding, now); err == nil {
			t.Fatal("malformed or oversized bytes accepted")
		}
	}
}

func TestResetC4CandidateRequiresEveryExactFieldAndExplicitValue(t *testing.T) {
	wire, binding, now := resetC4CandidateFixture(t)
	var original map[string]any
	if json.Unmarshal(wire, &original) != nil {
		t.Fatal("fixture invalid")
	}
	// Visit every object key, including both independent runs. Each mutation
	// changes one key only, so omission/null refusal cannot depend on another error.
	var paths [][]any
	var visit func(any, []any)
	visit = func(value any, path []any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				next := append(append([]any{}, path...), key)
				paths = append(paths, next)
				visit(child, next)
			}
		case []any:
			for index, child := range typed {
				visit(child, append(append([]any{}, path...), index))
			}
		}
	}
	visit(original, nil)
	for _, path := range paths {
		for _, makeNull := range []bool{false, true} {
			var root map[string]any
			if json.Unmarshal(wire, &root) != nil {
				t.Fatal("fixture invalid")
			}
			var parent any = root
			for _, step := range path[:len(path)-1] {
				switch typed := step.(type) {
				case string:
					parent = parent.(map[string]any)[typed]
				case int:
					parent = parent.([]any)[typed]
				}
			}
			key := path[len(path)-1].(string)
			if makeNull {
				parent.(map[string]any)[key] = nil
			} else {
				delete(parent.(map[string]any), key)
			}
			raw, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = decodeResetC4IsolatedProofCandidate(raw, resetC4WireSHA(raw), binding, now); err == nil {
				t.Fatalf("missing/null field accepted: %v null=%v", path, makeNull)
			}
		}
	}
}
