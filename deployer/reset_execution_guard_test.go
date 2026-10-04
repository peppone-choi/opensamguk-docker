package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestResetPhaseRefreshAfterThirtySecondsWithoutChangingInitialEvidence(t *testing.T) {
	plan, receipt, accepted := resetEvidenceFixture(t)
	binding := resetExecutionPhaseBinding{OperationID: plan.OperationID, Target: plan.Target, AcceptedAtUnix: accepted.Unix(), Phase: "before-down", PreviousAttestationSHA: strings.Repeat("e", 64)}
	evidence := resetExecutionEvidence{Plan: plan, Preflight: receipt}
	phaseStart := accepted.Add(90 * time.Second)
	fresh := resetExecutionPhaseSnapshot{ObservedAt: phaseStart, ServerID: "pep", OperationID: binding.OperationID,
		TargetFingerprint: plan.TargetFingerprint, PublicationState: "VERIFYING", PublicationRevision: receipt.PublicationRevision,
		WriterFreezeReceiptSHA: plan.WriterFreezeReceiptSHA, WriterFreezeHeld: true}
	if validateResetPreflight(receipt, plan, receipt.ApprovalPlanSHA, accepted) != nil {
		t.Fatal("initial admission refused")
	}
	if validateResetPreflight(receipt, plan, receipt.ApprovalPlanSHA, phaseStart) == nil {
		t.Fatal("queued old receipt became fresh")
	}
	if validateResetPhaseSnapshot(fresh, evidence, binding, phaseStart, phaseStart.Add(time.Second)) != nil {
		t.Fatal("fresh later phase refused")
	}
	cases := map[string]func(*resetExecutionPhaseSnapshot){
		"old-phase":                       func(s *resetExecutionPhaseSnapshot) { s.ObservedAt = accepted },
		"future-clock":                    func(s *resetExecutionPhaseSnapshot) { s.ObservedAt = phaseStart.Add(2 * time.Second) },
		"freeze-released-after-backup":    func(s *resetExecutionPhaseSnapshot) { s.WriterFreezeHeld = false },
		"wrong-freeze-owner":              func(s *resetExecutionPhaseSnapshot) { s.WriterFreezeReceiptSHA = strings.Repeat("f", 64) },
		"publication-opened-after-backup": func(s *resetExecutionPhaseSnapshot) { s.PublicationState = "PUBLIC" },
		"revision-changed":                func(s *resetExecutionPhaseSnapshot) { s.PublicationRevision = "3" },
		"different-operation":             func(s *resetExecutionPhaseSnapshot) { s.OperationID = strings.Repeat("f", 32) },
		"different-target":                func(s *resetExecutionPhaseSnapshot) { s.TargetFingerprint = strings.Repeat("f", 64) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := fresh
			change(&bad)
			if validateResetPhaseSnapshot(bad, evidence, binding, phaseStart, phaseStart.Add(time.Second)) == nil {
				t.Fatal("stale/changed phase accepted")
			}
		})
	}
	if validateResetPhaseSnapshot(fresh, evidence, binding, phaseStart, phaseStart.Add(resetPreflightMaxAge)) == nil {
		t.Fatal("late phase accepted")
	}
	cutoff := time.Unix(plan.DestructiveCutoffUnix, 0)
	fresh.ObservedAt = cutoff
	if validateResetPhaseSnapshot(fresh, evidence, binding, cutoff, cutoff) == nil {
		t.Fatal("cutoff renewed")
	}
	if (config{}).verifyResetExecutionPhase(context.Background(), binding, nil) == nil {
		t.Fatal("missing mandatory live source defaulted open")
	}
}

func TestResetStoppedGuardBindsEveryContainerWithoutMutation(t *testing.T) {
	plan, receipt, _ := resetEvidenceFixture(t)
	evidence := resetExecutionEvidence{Plan: plan, Preflight: receipt}
	cases := []string{"valid", "running", "missing-state", "wrong-project", "wrong-service", "recreated-container", "wrong-image", "inspection-error"}
	for _, mode := range cases {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			cfg := config{dockerRunnerContext: func(ctx context.Context, args ...string) (string, error) {
				calls++
				if args[0] == "image" {
					if args[1] != "inspect" {
						t.Fatal("mutation command reached")
					}
					pin := "sha256:" + strings.Repeat("a", 64)
					if mode == "wrong-image" {
						pin = "sha256:" + strings.Repeat("f", 64)
					}
					wire, _ := json.Marshal([]string{"registry.invalid/old@" + pin})
					return string(wire), nil
				}
				if args[0] != "inspect" {
					t.Fatalf("mutation command reached: %s", args[0])
				}
				if mode == "inspection-error" {
					return "", errors.New("synthetic unavailable")
				}
				service := strings.TrimPrefix(args[len(args)-1], "spep-")
				values := map[string]any{"id": receipt.StoppedContainerIDs[service], "image": "sha256:" + strings.Repeat("c", 64), "running": false, "status": "exited", "project": "opensamguk-spep", "service": service}
				switch mode {
				case "running":
					values["running"] = true
				case "missing-state":
					delete(values, "running")
				case "wrong-project":
					values["project"] = "opensamguk-suni"
				case "wrong-service":
					values["service"] = "gateway-api"
				case "recreated-container":
					values["id"] = strings.Repeat("f", 64)
				}
				wire, _ := json.Marshal(values)
				return string(wire), nil
			}}
			err := cfg.verifyResetStoppedContainers(context.Background(), evidence)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
			if mode == "valid" && calls != 10 {
				t.Fatalf("all five container/image bindings not checked: %d", calls)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if (config{}).verifyResetStoppedContainers(ctx, evidence) == nil {
		t.Fatal("cancelled phase accepted")
	}
}

func TestResetSpaceProductOverflowAndRealFilesystemObservation(t *testing.T) {
	if _, err := checkedResetSpaceProduct(^uint64(0), 2); err == nil {
		t.Fatal("overflow accepted")
	}
	if value, err := checkedResetSpaceProduct(10, 20); err != nil || value != 200 {
		t.Fatal("valid byte calculation refused")
	}
	if _, _, err := observeResetFilesystem(t.TempDir()); err != nil {
		t.Fatal("owned local filesystem observation failed")
	}
	if _, _, err := observeResetFilesystem("/no-such-c8-reset-fixture-path"); err == nil {
		t.Fatal("unknown filesystem accepted")
	}
}
