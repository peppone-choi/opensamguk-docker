package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"text/template"
	"time"
)

func resetRuntimeFixture(t *testing.T, mode string) (config, resetExecutionPhaseBinding, resetExecutionEvidence, resetRuntimeRawSource, func() time.Time, *int) {
	t.Helper()
	plan, preflight, _ := resetEvidenceFixture(t)
	start := time.Now().UTC().Add(-time.Second)
	plan.WindowOpensAtUnix = start.Unix() - 60
	plan.DestructiveCutoffUnix = start.Unix() + 300
	plan.RecoveryDeadlineUnix = start.Unix() + 3600
	preflight.ObservedAtUnix = start.Unix() - 1
	preflight.ExpiresAtUnix = start.Unix() + 20
	preflight.BackupRetainUntilUnix = start.Unix() + 7*24*60*60
	binding := resetExecutionPhaseBinding{OperationID: plan.OperationID, Target: plan.Target, AcceptedAtUnix: start.Unix(), Evidence: resetExecutionEvidenceRefs{preflight.ApprovalPlanSHA, strings.Repeat("d", 64)}}
	services := []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"}
	imageServices := map[string]string{}
	observations := map[string]int{}
	commands := 0
	cfg := config{serversDir: t.TempDir(), dockerRunnerContext: func(ctx context.Context, args ...string) (string, error) {
		commands++
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if args[0] == "image" {
			if args[1] != "inspect" {
				t.Fatal("mutation command reached")
			}
			service := imageServices[args[len(args)-1]]
			repository := "ghcr.io/peppone-choi/opensamguk"
			if service == "game-postgres" {
				repository = "docker.io/library/postgres"
			}
			if service == "game-redis" {
				repository = "redis"
			}
			pin := plan.NewImageDigests[service]
			if mode == "pin" {
				pin = "sha256:" + strings.Repeat("f", 64)
			}
			if mode == "repository" {
				repository = "registry.invalid/fake"
			}
			values := map[string]any{"repoDigests": []string{repository + "@" + pin}, "os": "linux", "architecture": "amd64"}
			if mode == "architecture" {
				values["architecture"] = "arm64"
			}
			wire, _ := json.Marshal(values)
			return string(wire), nil
		}
		if args[0] != "inspect" {
			t.Fatal("mutation command reached")
		}
		if mode == "inspect-error" {
			return "private diagnostic must stay opaque", errors.New("synthetic unavailable")
		}
		service := strings.TrimPrefix(args[len(args)-1], "spep-")
		index := 0
		for i, s := range services {
			if s == service {
				index = i
			}
		}
		id := strings.Repeat(string(rune('1'+index)), 64)
		image := "sha256:" + id
		imageServices[image] = service
		observations[service]++
		values := map[string]any{"id": id, "name": "/spep-" + service, "image": image, "running": true, "status": "running", "project": "opensamguk-spep", "service": service, "serverIds": []any{nil}, "seedSettings": resetRuntimeFixtureSettings(service)}
		if service == "game-api" {
			values["serverIds"] = []any{"SERVER_ID=pep", nil}
		}
		if service == "game-postgres" || service == "game-redis" {
			values["project"] = resetD101CandidateResourceNames(plan.OperationID).Project
		}
		switch mode {
		case "old-id":
			values["id"] = preflight.StoppedContainerIDs[service]
		case "duplicate-id":
			values["id"] = strings.Repeat("1", 64)
		case "stopped":
			values["running"] = false
		case "missing-state":
			delete(values, "running")
		case "world-project":
			values["project"] = "opensamguk-suni"
		case "wrong-service":
			values["service"] = "gateway-api"
		case "missing-server-id":
			values["serverIds"] = []any{nil}
		case "wrong-server-id":
			values["serverIds"] = []any{"SERVER_ID=uni", nil}
		case "duplicate-server-id":
			values["serverIds"] = []any{"SERVER_ID=pep", "SERVER_ID=pep", nil}
		case "runtime-drift":
			if observations[service] > 1 {
				values["image"] = "sha256:" + strings.Repeat("f", 64)
			}
		}
		parts := strings.Split(mode, ":")
		if len(parts) == 4 && parts[0] == "setting" && service == parts[1] {
			selected := values["seedSettings"].([]any)
			changed := []any{}
			for _, item := range selected[:len(selected)-1] {
				text := item.(string)
				if strings.HasPrefix(text, parts[2]+"=") {
					switch parts[3] {
					case "missing":
						continue
					case "wrong":
						text = parts[2] + "=wrong"
					case "duplicate":
						changed = append(changed, text)
					case "null":
						changed = append(changed, nil)
					}
				}
				changed = append(changed, text)
			}
			values["seedSettings"] = append(changed, nil)
		}
		if mode == "engine-settings-drift" && service == "game-engine" && observations[service] > 1 {
			values["seedSettings"] = []any{"OPENSAMGUK_WORLD_ID=1", "SCENARIO_DIR=/data/scenarios", nil}
		}
		wire, _ := json.Marshal(values)
		return string(wire), nil
	}}
	number := func(n int) *int { return &n }
	text := func(s string) *string { return &s }
	raw := func(ctx context.Context, b resetExecutionPhaseBinding) (resetAdminCurrentObservation, error) {
		if mode == "raw-error" {
			return resetAdminCurrentObservation{}, errResetExecutionEvidence
		}
		result := resetAdminCurrentObservation{ObservedAt: start.Add(time.Second), Current: resetAdminCurrent{
			WorldID: number(1), Generation: text("0"), ScenarioCode: text("scenario_3190"), TurnTerm: number(60),
			MaxGeneral: number(50), BlockGeneralCreate: number(1), FirstTurn: text("immediate"), StartTime: text(start.Add(-time.Hour).Format(time.RFC3339Nano)),
			Year: number(190), Month: number(1), Phase: number(0), Status: text("READY")}}
		if mode == "raw-block-open" {
			result.Current.BlockGeneralCreate = number(0)
		}
		if mode == "old-raw" {
			result.ObservedAt = start.Add(-time.Second)
		}
		if mode == "future-raw" {
			result.ObservedAt = start.Add(3 * time.Second)
		}
		return result, nil
	}
	clockCalls := 0
	clock := func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return start
		}
		if mode == "late" {
			return start.Add(30 * time.Second)
		}
		return start.Add(2 * time.Second)
	}
	installSyntheticCandidatePromotion(t, cfg, plan, start)
	return cfg, binding, resetExecutionEvidence{plan, preflight}, raw, clock, &commands
}

func TestResetRuntimeObservesFivePhysicalPinsAndRawWithoutMutation(t *testing.T) {
	cfg, binding, evidence, raw, clock, commands := resetRuntimeFixture(t, "valid")
	before, _ := json.Marshal(evidence)
	observed, err := cfg.collectResetD101RuntimeWithSourceAndCustodyUID(context.Background(), binding, evidence, "ghcr.io/peppone-choi/opensamguk", raw, clock, uint32(os.Geteuid()))
	if err != nil || len(observed.Containers) != 5 || len(observed.ImageDigests) != 5 || *commands != 15 ||
		observed.TargetFingerprint != evidence.Plan.TargetFingerprint || observed.WorldID != 1 || observed.Raw.Current.Phase == nil || *observed.Raw.Current.Phase != 0 {
		t.Fatalf("complete isolated runtime observation refused: %v commands=%d", err, *commands)
	}
	after, _ := json.Marshal(evidence)
	if !bytes.Equal(before, after) || !reflect.DeepEqual(observed.ImageDigests, evidence.Plan.NewImageDigests) {
		t.Fatal("source changed")
	}
}

func TestResetRuntimeUnknownMismatchOrDriftCannotIssueObservation(t *testing.T) {
	for _, mode := range []string{"pin", "repository", "architecture", "inspect-error", "old-id", "duplicate-id", "stopped", "missing-state", "world-project", "wrong-service", "missing-server-id", "wrong-server-id", "duplicate-server-id", "runtime-drift", "raw-error", "raw-block-open", "old-raw", "future-raw", "late", "engine-settings-drift"} {
		t.Run(mode, func(t *testing.T) {
			cfg, binding, evidence, raw, clock, _ := resetRuntimeFixture(t, mode)
			observed, err := cfg.collectResetD101RuntimeWithSourceAndCustodyUID(context.Background(), binding, evidence, "ghcr.io/peppone-choi/opensamguk", raw, clock, uint32(os.Geteuid()))
			if err == nil || observed.Version != 0 {
				t.Fatal("invalid physical/runtime source accepted")
			}
		})
	}
	cfg, binding, evidence, raw, clock, commands := resetRuntimeFixture(t, "valid")
	if _, err := cfg.collectResetD101RuntimeWithSourceAndCustodyUID(context.Background(), binding, evidence, "https://caller.invalid", raw, clock, uint32(os.Geteuid())); err == nil || *commands != 0 {
		t.Fatal("caller origin reached Docker")
	}
	if _, err := cfg.collectResetD101RuntimeWithSourceAndCustodyUID(context.Background(), binding, evidence, "ghcr.io/peppone-choi/opensamguk", nil, clock, uint32(os.Geteuid())); err == nil || *commands != 0 {
		t.Fatal("missing source reached Docker")
	}
	if _, err := cfg.collectResetD101Runtime(context.Background(), binding, "ghcr.io/peppone-choi/opensamguk"); err == nil || *commands != 0 {
		t.Fatal("missing durable operation source reached Docker")
	}
}

func TestResetRuntimeTemplateSelectsOnlyAllowedIdentityAndSeedSettings(t *testing.T) {
	formatter := template.Must(template.New("nonsecret").Funcs(template.FuncMap{
		"json":  func(v any) string { wire, _ := json.Marshal(v); return string(wire) },
		"split": strings.Split,
	}).Parse(resetRuntimeContainerFormat))
	values := map[string]any{"Id": strings.Repeat("1", 64), "Name": "/spep-game-api", "Image": "sha256:" + strings.Repeat("2", 64),
		"State": map[string]any{"Running": true, "Status": "running"},
		"Config": map[string]any{"Labels": map[string]string{"com.docker.compose.project": "opensamguk-spep", "com.docker.compose.service": "game-api"},
			"Env": []string{"JWT_PRIVATE_KEY=private-must-not-return", "INTERNAL_SERVICE_TOKEN=secret-must-not-return", "SERVER_ID=pep", "OPENSAMGUK_WORLD_ID=1", "SCENARIO_DIR=", "SERVER_GENERATION=0", "SERVER_NAME=빼섭", "GAME_DB_PASSWORD=db-secret-must-not-return"}}}
	var out bytes.Buffer
	if err := formatter.Execute(&out, values); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "private-must-not-return") || strings.Contains(out.String(), "secret-must-not-return") || strings.Contains(out.String(), "db-secret-must-not-return") {
		t.Fatal("private environment projected")
	}
	var wire map[string]any
	if json.Unmarshal(out.Bytes(), &wire) != nil {
		t.Fatal("selected projection invalid")
	}
	selected := wire["serverIds"].([]any)
	if len(selected) != 2 || selected[0] != "SERVER_ID=pep" || selected[1] != nil {
		t.Fatal("explicit selected identity lost")
	}
	settings := wire["seedSettings"].([]any)
	if len(settings) != 5 || settings[len(settings)-1] != nil {
		t.Fatal("non-secret explicit seed settings lost")
	}
	if !bytes.Contains(out.Bytes(), []byte("SCENARIO_DIR=")) || !bytes.Contains(out.Bytes(), []byte("SERVER_GENERATION=0")) {
		t.Fatal("empty lookup or generation zero lost")
	}
}

func resetRuntimeFixtureSettings(service string) []any {
	switch service {
	case "game-api":
		return []any{"SERVER_NAME=빼섭", "SERVER_GENERATION=0", "OPENSAMGUK_WORLD_ID=1", "SCENARIO_DIR=", nil}
	case "game-engine":
		return []any{"OPENSAMGUK_WORLD_ID=1", "SCENARIO_CODE=scenario_3190", "SCENARIO_DIR=", "SCENARIO_SEED_ENABLED=true",
			"RESET_TURNTERM=60", "RESET_MAXGENERAL=50", "RESET_FIRST_TURN=immediate", "RESET_BLOCK_GENERAL_CREATE=1", nil}
	}
	return []any{nil}
}

func TestResetRuntimeRequiresExplicitAPIAndEngineSettings(t *testing.T) {
	for _, service := range []string{"game-api", "game-engine"} {
		selected := resetRuntimeFixtureSettings(service)
		for _, item := range selected[:len(selected)-1] {
			key, _, _ := strings.Cut(item.(string), "=")
			for _, mutation := range []string{"missing", "wrong", "duplicate", "null"} {
				mode := "setting:" + service + ":" + key + ":" + mutation
				t.Run(mode, func(t *testing.T) {
					cfg, binding, evidence, raw, clock, _ := resetRuntimeFixture(t, mode)
					observed, err := cfg.collectResetD101RuntimeWithSourceAndCustodyUID(context.Background(), binding, evidence, "ghcr.io/peppone-choi/opensamguk", raw, clock, uint32(os.Geteuid()))
					if err == nil || observed.Version != 0 {
						t.Fatal("missing, defaulted or ambiguous seed setting accepted")
					}
				})
			}
		}
	}
	for _, selected := range [][]*string{nil, {}, {nil, nil}} {
		if _, err := resetRuntimeSeedSettings("game-api", selected); err == nil {
			t.Fatal("missing or null settings accepted")
		}
	}
}

func installSyntheticCandidatePromotion(t *testing.T, c config, plan resetApprovalPlan, start time.Time) {
	t.Helper()
	resources := resetD101CandidateResourceNames(plan.OperationID)
	resources.CandidateComposeFile = "/synthetic/candidate.json"
	resources.LiveComposeFile = "/synthetic/live.json"
	resources.CandidateComposeSHA = strings.Repeat("a", 64)
	resources.LiveComposeSHA = strings.Repeat("b", 64)
	generation := 0
	seedValue := resetD101CandidateSeedReceipt{SchemaVersion: 1, Kind: "D101_SEED_ONLY_RESULT_V1", OriginalOp: plan.OperationID, TargetFingerprint: plan.TargetFingerprint, AppSourceSHA: plan.AppSourceSHA, ImagePins: plan.NewImageDigests, SelectedSourceReceiptSHA: plan.SelectedSourceReceiptSHA, EffectiveOptions: map[string]string{}, OptionProvenance: map[string]string{}, ObservedGeneration: &generation, ConfigMaxGeneral: 50, GameEnvMaxGeneral: 50, ObservedAtUTC: start.Add(-2 * time.Second).Format(time.RFC3339Nano)}
	seed, _ := json.Marshal(seedValue)
	capsValue := resetD101CandidateCapsObservation{SchemaVersion: 1, Kind: "D101_CANDIDATE_DB_CAPS_V1", DatabaseName: "synthetic", DatabaseUser: "synthetic", ServerAddress: "172.18.0.3", ServerPort: 5432, TransactionReadOnly: "on", TransactionIsolation: "repeatable read", WorldRowCount: 1, WorldID: 1, ScenarioCode: "scenario_3190", TickSeconds: 3600, GenerationType: "number", GenerationRaw: "0", ConfigMaxGeneralType: "number", ConfigMaxGeneralRaw: "50", GameEnvRowCount: 1, GameEnvMaxGeneralType: "number", GameEnvMaxGeneralRaw: "50", ObservedAtUTC: start.Add(-2 * time.Second).Format(time.RFC3339Nano)}
	caps, _ := json.Marshal(capsValue)
	proof := resetD101CandidatePromotionProof{SchemaVersion: 1, Kind: "D101_CANDIDATE_PROMOTION_V1", OperationID: plan.OperationID, ApprovalIntentSHA: plan.ApprovalIntentSHA, TargetFingerprint: plan.TargetFingerprint, CommandPlanSHA: strings.Repeat("a", 64), SelectedSourceReceiptSHA: plan.SelectedSourceReceiptSHA, SeedReceiptSHA: resetD101OriginalSHA(seed), WorkerContainerID: strings.Repeat("6", 64), PostgresContainerID: strings.Repeat("4", 64), RedisContainerID: strings.Repeat("5", 64), ActualCapsSHA: resetD101OriginalSHA(caps), CapsReaderSHA: strings.Repeat("b", 64), ObservedAtUTC: start.Add(-time.Second).Format(time.RFC3339Nano), Resources: resources, AppSourceSHA: plan.AppSourceSHA}
	wire, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		directory string
		wire      []byte
	}{{".deployer-reset-candidate-seed", seed}, {".deployer-reset-candidate-caps", caps}, {".deployer-reset-candidate-promotion", wire}} {
		dir := filepath.Join(c.serversDir, item.directory)
		if os.Mkdir(dir, 0700) != nil {
			t.Fatal("fixture directory")
		}
		if writeResetImmutablePrivateBytesWithUID(dir, plan.OperationID, resetD101OriginalSHA(item.wire), item.wire, uint32(os.Geteuid())) != nil {
			t.Fatal("fixture custody")
		}
	}
}
