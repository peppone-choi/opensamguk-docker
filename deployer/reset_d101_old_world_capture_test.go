package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func oldWorldCaptureFixture() (resetD101OldWorldOriginal, time.Time, time.Time) {
	start := time.Unix(1791162000, 0).UTC()
	end := start.Add(2 * time.Second)
	return resetD101OldWorldOriginal{1, "D101_OLD_WORLD_DATABASE_OBSERVATION_V1", "game", "game", "172.22.0.3", 5432,
		"on", "repeatable read", 1, 1, "scenario_990002", 300, "number", "9", start.Add(time.Second).Format(time.RFC3339Nano)}, start, end
}

func oldWorldCaptureIntent(t *testing.T) resetDecodedApprovalIntent {
	t.Helper()
	wire, _, _ := resetIntentFixture(t)
	var raw resetApprovalIntent
	if err := json.Unmarshal(wire, &raw); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw.WindowOpensAtUnix = now.Add(-time.Minute).Unix()
	raw.DestructiveCutoffUnix = now.Add(5 * time.Minute).Unix()
	raw.RecoveryDeadlineUnix = now.Add(10 * time.Minute).Unix()
	wire, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := decodeResetApprovalIntent(wire, resetD101OriginalSHA(wire))
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func TestOldWorldCaptureSQLUsesFrozenReadOnlyExact15Original(t *testing.T) {
	sum := sha256.Sum256([]byte(resetD101OldWorldSQL))
	if hex.EncodeToString(sum[:]) != "bfcae4d9714f779a09d0da9de0176dfeed5bc90c56185a397f88a0e6b21b796b" {
		t.Fatal("C8/C9 SQL original changed, including final LF")
	}
	value, start, end := oldWorldCaptureFixture()
	wire, _ := json.Marshal(value)
	got, err := decodeResetD101OldWorld(wire, "game", "game", "172.22.0.3", start, end)
	if err != nil || got != value {
		t.Fatal("actual old source fields rejected", err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(wire, &fields) != nil || len(fields) != 15 {
		t.Fatal("exact15 changed")
	}
	// This is a pure transport-data clone, not an authority/retention constructor.
	observation := resetD101OldWorldObservation{original: bytes.Clone(wire), sha: resetD101OriginalSHA(wire), value: got}
	copy := observation.originalBytes()
	copy[0] = 'x'
	if !bytes.Equal(observation.originalBytes(), wire) || observation.sha != resetD101OriginalSHA(wire) {
		t.Fatal("caller could mutate original observation")
	}
}

func TestOldWorldCaptureRejectsRoleTypesEndpointsAndTemporalSubstitution(t *testing.T) {
	fixture, start, end := oldWorldCaptureFixture()
	modes := []string{"restored-kind", "schema", "database", "user", "address", "port", "read-write", "isolation", "world-count", "world-id",
		"scenario", "tick-zero", "tick-overflow", "generation-type", "generation-plus", "generation-minus-zero", "generation-leading-zero",
		"generation-negative", "generation-float", "generation-overflow", "future", "before-start", "clock-offset", "no-Z", "backwards", "age-boundary",
		"zero-start", "duplicate", "unknown", "case-alias", "null", "trailing", "utf8", "oversize"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			v, started, completed := fixture, start, end
			switch mode {
			case "restored-kind":
				v.Kind = "D101_RESTORED_DATABASE_OBSERVATION_V1"
			case "schema":
				v.SchemaVersion = 2
			case "database":
				v.DatabaseName = "other"
			case "user":
				v.DatabaseUser = "other"
			case "address":
				v.ServerAddress = "172.22.0.4"
			case "port":
				v.ServerPort = 5433
			case "read-write":
				v.TransactionReadOnly = "off"
			case "isolation":
				v.TransactionIsolation = "read committed"
			case "world-count":
				v.WorldRowCount = 2
			case "world-id":
				v.WorldID = 2
			case "scenario":
				v.ScenarioCode = "UNKNOWN"
			case "tick-zero":
				v.TickSeconds = 0
			case "tick-overflow":
				v.TickSeconds = 2147483648
			case "generation-type":
				v.GenerationType = "null"
			case "generation-plus":
				v.GenerationRaw = "+9"
			case "generation-minus-zero":
				v.GenerationRaw = "-0"
			case "generation-leading-zero":
				v.GenerationRaw = "09"
			case "generation-negative":
				v.GenerationRaw = "-1"
			case "generation-float":
				v.GenerationRaw = "9.0"
			case "generation-overflow":
				v.GenerationRaw = "2147483648"
			case "future":
				v.ObservedAtUTC = end.Add(time.Second).Format(time.RFC3339Nano)
			case "before-start":
				v.ObservedAtUTC = start.Add(-time.Nanosecond).Format(time.RFC3339Nano)
			case "clock-offset":
				v.ObservedAtUTC = "2026-10-05T10:20:01+00:00"
			case "no-Z":
				v.ObservedAtUTC = "2026-10-05T10:20:01"
			case "backwards":
				completed = start.Add(-time.Second)
			case "age-boundary":
				completed = start.Add(resetPreflightMaxAge)
			case "zero-start":
				started = time.Time{}
			}
			wire, _ := json.Marshal(v)
			switch mode {
			case "duplicate":
				wire = []byte(strings.Replace(string(wire), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1))
			case "unknown":
				wire = []byte(strings.TrimSuffix(string(wire), "}") + `,"authorized":true}`)
			case "case-alias":
				wire = []byte(strings.Replace(string(wire), `"worldId"`, `"WorldId"`, 1))
			case "null":
				wire = []byte(strings.Replace(string(wire), `"generationRaw":"9"`, `"generationRaw":null`, 1))
			case "trailing":
				wire = append(wire, []byte(`{}`)...)
			case "utf8":
				wire = []byte{0xff}
			case "oversize":
				wire = append(wire, bytes.Repeat([]byte(" "), 16*1024)...)
			}
			if _, err := decodeResetD101OldWorld(wire, "game", "game", "172.22.0.3", started, completed); err == nil {
				t.Fatal("unknown/substituted old source accepted")
			}
		})
	}
	// Numeric JSON types and every top-level null remain strict, including null
	// that Go would otherwise coerce to a zero value.
	wire, _ := json.Marshal(fixture)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(wire, &fields)
	for key := range fields {
		t.Run("null-"+key, func(t *testing.T) {
			changed := make(map[string]json.RawMessage, len(fields))
			for k, v := range fields {
				changed[k] = v
			}
			changed[key] = json.RawMessage("null")
			raw, _ := json.Marshal(changed)
			if _, err := decodeResetD101OldWorld(raw, "game", "game", "172.22.0.3", start, end); err == nil {
				t.Fatal("null field accepted")
			}
		})
	}
	for _, old := range []string{`"schemaVersion":1`, `"serverPort":5432`, `"worldRowCount":1`, `"worldId":1`, `"tickSeconds":300`} {
		raw := []byte(strings.Replace(string(wire), old, old+".0", 1))
		if _, err := decodeResetD101OldWorld(raw, "game", "game", "172.22.0.3", start, end); err == nil {
			t.Fatal("decimal integer accepted")
		}
	}
}

func TestOldWorldCaptureRestoredIdentityAlwaysComparesActualPreSQL(t *testing.T) {
	old, _, _ := oldWorldCaptureFixture()
	restored := resetD101RestoredDatabaseOriginal{1, "D101_RESTORED_DATABASE_OBSERVATION_V1", "game", "game", "172.22.0.3", 5432,
		"on", "repeatable read", 1, 1, old.ScenarioCode, old.TickSeconds, "number", old.GenerationRaw, old.ObservedAtUTC}
	if requireResetD101RestoredMatchesObservedOld(restored, old) != nil {
		t.Fatal("actual original identity mismatched")
	}
	// No nullable canonical is an input: its null cannot suppress these comparisons.
	for _, mode := range []string{"generation", "scenario", "tick", "unknown-preSQL", "restored-as-old"} {
		t.Run(mode, func(t *testing.T) {
			v, before := restored, old
			switch mode {
			case "generation":
				v.GenerationRaw = "0"
			case "scenario":
				v.ScenarioCode = "scenario_3190"
			case "tick":
				v.TickSeconds = 3600
			case "unknown-preSQL":
				before.GenerationRaw = "null"
				v.GenerationRaw = "null"
			case "restored-as-old":
				before.Kind = restored.Kind
			}
			if requireResetD101RestoredMatchesObservedOld(v, before) == nil {
				t.Fatal("restored data substituted for actual old source")
			}
		})
	}
}

func TestOldWorldCaptureMissingGuardOrImmutableIntentCannotInvokeCommands(t *testing.T) {
	intent := oldWorldCaptureIntent(t)
	for _, mode := range []string{"nil-guard", "nil-context", "cancelled", "expired-deadline", "missing-original", "changed-original", "changed-typed-intent", "before-window", "expired-cutoff", "guard-deny", "guard-cancel", "command-cancel", "command-error"} {
		t.Run(mode, func(t *testing.T) {
			current := intent
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var runContext context.Context = ctx
			guarded, commands := 0, 0
			// Fake source checks context/lease/freeze; this is not a production authority.
			leaseFrozen := true
			guard := func(c context.Context) error {
				guarded++
				if c.Err() != nil || !leaseFrozen {
					return errors.New("fake lease/freeze denied")
				}
				return nil
			}
			command := func(c context.Context) (string, error) {
				commands++
				if mode == "command-cancel" {
					cancel()
				}
				if mode == "command-error" {
					return "not evidence", errors.New("fake failure")
				}
				return "fake observation only", nil
			}
			switch mode {
			case "nil-guard":
				guard = nil
			case "nil-context":
				runContext = nil
			case "cancelled":
				cancel()
			case "expired-deadline":
				expired, stop := context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer stop()
				runContext = expired
			case "missing-original":
				current.original = nil
			case "changed-original":
				current.original = bytes.Clone(current.original)
				current.original[0] = 'x'
			case "changed-typed-intent":
				current.Intent.OperationID = "different"
			case "before-window", "expired-cutoff":
				var raw resetApprovalIntent
				_ = json.Unmarshal(current.originalBytes(), &raw)
				if mode == "before-window" {
					raw.WindowOpensAtUnix = time.Now().Add(time.Minute).Unix()
				} else {
					raw.DestructiveCutoffUnix = time.Now().Add(-time.Second).Unix()
				}
				wire, _ := json.Marshal(raw)
				var err error
				current, err = decodeResetApprovalIntent(wire, resetD101OriginalSHA(wire))
				if err != nil {
					t.Fatal("synthetic transport setup", err)
				}
			case "guard-deny":
				leaseFrozen = false
			case "guard-cancel":
				guard = func(c context.Context) error { guarded++; cancel(); return c.Err() }
			}
			out, err := runResetD101OldWorldCommand(runContext, current, guard, command)
			expected := 0
			if mode == "command-cancel" || mode == "command-error" {
				expected = 1
			}
			if err == nil || out != "" || commands != expected {
				t.Fatal("unbound data/authority invoked or returned observation", mode, guarded, commands)
			}
		})
	}
	calls := 0
	c := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	inputs := resetD101OldWorldCaptureInputs{strings.Repeat("a", 64), "opensamguk-spep", "opensamguk-spep_default", "game", "game", "/fixed/servers/private/pgpass", "/host/servers/private/pgpass", strings.Repeat("b", 64)}
	observed, err := c.collectResetD101OldWorld(context.Background(), intent, inputs, nil)
	if err == nil || calls != 0 || observed.sha != "" || observed.jobID != "" || len(observed.original) != 0 {
		t.Fatal("absent guard produced a physical old-world observation")
	}
}

func TestOldWorldCaptureEveryFakeCommandKeepsSameDeadlineAndFreeze(t *testing.T) {
	intent := oldWorldCaptureIntent(t)
	deadline := time.Now().Add(10 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	guards, commands := 0, 0
	leasedFrozen := true
	guard := func(c context.Context) error {
		guards++
		d, ok := c.Deadline()
		if !ok || !d.Equal(deadline) || c.Err() != nil || !leasedFrozen {
			return errors.New("fake fixed source denied")
		}
		return nil
	}
	command := func(c context.Context) (string, error) {
		commands++
		d, _ := c.Deadline()
		if !d.Equal(deadline) || guards != commands {
			t.Fatal("deadline refreshed or command bundled without guard")
		}
		return "fake raw only", nil
	}
	for n := 0; n < 2; n++ {
		if _, err := runResetD101OldWorldCommand(ctx, intent, guard, command); err != nil {
			t.Fatal(err)
		}
	}
	leasedFrozen = false
	if _, err := runResetD101OldWorldCommand(ctx, intent, guard, command); err == nil || commands != 2 || guards != 3 {
		t.Fatal("writer resumed yet another command ran")
	}
}

func TestOldWorldCaptureNativePgpassEndpointDoesNotPermitFallback(t *testing.T) {
	prefix := "172.22.0.3:5432:game:game:"
	for _, v := range []string{prefix + "synthetic-only\n", prefix + `synthetic\:only\\value`} {
		if !resetD101OldWorldPassMatches([]byte(v), "172.22.0.3", "game", "game") {
			t.Fatal("valid synthetic endpoint-bound file rejected")
		}
	}
	for _, v := range []string{"*:5432:game:game:synthetic", "172.22.0.4:5432:game:game:synthetic", "172.22.0.3:5433:game:game:synthetic", "172.22.0.3:5432:other:game:synthetic", prefix, "", prefix + "one\n" + prefix + "two", prefix + "unescaped:colon", prefix + `trailing\`, prefix + `invalid\x`, prefix + "nul\x00value"} {
		if resetD101OldWorldPassMatches([]byte(v), "172.22.0.3", "game", "game") {
			t.Fatal("wildcard/changed/extra native record accepted")
		}
	}
}
