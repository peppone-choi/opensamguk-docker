package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	cfg := config{dockerRunnerContext: func(ctx context.Context, args ...string) (string, error) {
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
		values := map[string]any{"id": id, "name": "/spep-" + service, "image": image, "running": true, "status": "running", "project": "opensamguk-spep", "service": service, "serverIds": []any{nil}}
		if service == "game-api" {
			values["serverIds"] = []any{"SERVER_ID=pep", nil}
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
	return cfg, binding, resetExecutionEvidence{plan, preflight}, raw, clock, &commands
}

func TestResetRuntimeObservesFivePhysicalPinsAndRawWithoutMutation(t *testing.T) {
	cfg, binding, evidence, raw, clock, commands := resetRuntimeFixture(t, "valid")
	before, _ := json.Marshal(evidence)
	observed, err := cfg.collectResetD101RuntimeWithSource(context.Background(), binding, evidence, "ghcr.io/peppone-choi/opensamguk", raw, clock)
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
	for _, mode := range []string{"pin", "repository", "architecture", "inspect-error", "old-id", "duplicate-id", "stopped", "missing-state", "world-project", "wrong-service", "missing-server-id", "wrong-server-id", "duplicate-server-id", "runtime-drift", "raw-error", "raw-block-open", "old-raw", "future-raw", "late"} {
		t.Run(mode, func(t *testing.T) {
			cfg, binding, evidence, raw, clock, _ := resetRuntimeFixture(t, mode)
			observed, err := cfg.collectResetD101RuntimeWithSource(context.Background(), binding, evidence, "ghcr.io/peppone-choi/opensamguk", raw, clock)
			if err == nil || observed.Version != 0 {
				t.Fatal("invalid physical/runtime source accepted")
			}
		})
	}
	cfg, binding, evidence, raw, clock, commands := resetRuntimeFixture(t, "valid")
	if _, err := cfg.collectResetD101RuntimeWithSource(context.Background(), binding, evidence, "https://caller.invalid", raw, clock); err == nil || *commands != 0 {
		t.Fatal("caller origin reached Docker")
	}
	if _, err := cfg.collectResetD101RuntimeWithSource(context.Background(), binding, evidence, "ghcr.io/peppone-choi/opensamguk", nil, clock); err == nil || *commands != 0 {
		t.Fatal("missing source reached Docker")
	}
	if _, err := cfg.collectResetD101Runtime(context.Background(), binding, "ghcr.io/peppone-choi/opensamguk"); err == nil || *commands != 0 {
		t.Fatal("missing durable operation source reached Docker")
	}
}

func TestResetRuntimeTemplateSelectsOnlyServerIdentity(t *testing.T) {
	formatter := template.Must(template.New("nonsecret").Funcs(template.FuncMap{
		"json":  func(v any) string { wire, _ := json.Marshal(v); return string(wire) },
		"split": strings.Split,
	}).Parse(resetRuntimeContainerFormat))
	values := map[string]any{"Id": strings.Repeat("1", 64), "Name": "/spep-game-api", "Image": "sha256:" + strings.Repeat("2", 64),
		"State": map[string]any{"Running": true, "Status": "running"},
		"Config": map[string]any{"Labels": map[string]string{"com.docker.compose.project": "opensamguk-spep", "com.docker.compose.service": "game-api"},
			"Env": []string{"JWT_PRIVATE_KEY=private-must-not-return", "INTERNAL_SERVICE_TOKEN=secret-must-not-return", "SERVER_ID=pep"}}}
	var out bytes.Buffer
	if err := formatter.Execute(&out, values); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "private-must-not-return") || strings.Contains(out.String(), "secret-must-not-return") {
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
}
