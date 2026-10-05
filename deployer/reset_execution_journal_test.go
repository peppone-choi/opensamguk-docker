package main

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func resetExecutionChainFixture(t *testing.T, count int) (resetApprovalPlan, resetExecutionPhaseBinding, resetExecutionJournal) {
	t.Helper()
	plan, receipt, accepted := resetEvidenceFixture(t)
	binding := resetExecutionPhaseBinding{OperationID: plan.OperationID, Target: plan.Target,
		Evidence: resetExecutionEvidenceRefs{receipt.ApprovalPlanSHA, strings.Repeat("d", 64)}, AcceptedAtUnix: accepted.Unix(), Phase: "prepared"}
	record := resetExecutionJournal{}
	phases := []string{"prepared", "before-journal", "before-down"}
	for i := 0; i < count; i++ {
		start := accepted.UTC().Add(time.Duration(i*45) * time.Second)
		snapshot := resetExecutionPhaseSnapshot{ObservedAt: start.Add(time.Second), ServerID: "pep", OperationID: plan.OperationID,
			TargetFingerprint: plan.TargetFingerprint, PublicationState: "VERIFYING", PublicationRevision: receipt.PublicationRevision,
			WriterFreezeReceiptSHA: plan.WriterFreezeReceiptSHA, WriterFreezeHeld: true}
		binding.Phase = phases[i]
		if i > 0 {
			binding.PreviousAttestationSHA = record.Attestations[i-1].SHA
		}
		a := resetExecutionAttestation{Phase: binding.Phase, PreviousSHA: binding.PreviousAttestationSHA,
			StartedAt: start, CompletedAt: start.Add(2 * time.Second), Snapshot: snapshot,
			Space: resetExecutionSpaceSnapshot{Device: 100, AvailableBytes: resetDiskReserveBytes + 1000, AvailableInodes: 100}}
		var err error
		if i == 0 {
			record, err = newResetExecutionJournal(binding, a)
		} else {
			record, err = appendResetExecutionAttestation(record, binding, a)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return plan, binding, record
}

func cloneResetExecutionChain(t *testing.T, record resetExecutionJournal) resetExecutionJournal {
	t.Helper()
	wire, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var copied resetExecutionJournal
	if json.Unmarshal(wire, &copied) != nil {
		t.Fatal("clone failed")
	}
	return copied
}

func TestResetExecutionChainRetainsInitialProofAfterNinetySeconds(t *testing.T) {
	plan, _, record := resetExecutionChainFixture(t, 3)
	if validateResetExecutionJournal(record, plan.OperationID, plan.Target) != nil {
		t.Fatal("90-second legitimate chain refused")
	}
	reopened := cloneResetExecutionChain(t, record)
	if !reflect.DeepEqual(record, reopened) || validateResetExecutionJournal(reopened, plan.OperationID, plan.Target) != nil {
		t.Fatal("restart changed immutable evidence or attestation chain")
	}
	if record.Attestations[2].StartedAt.Sub(time.Unix(record.AcceptedAtUnix, 0)) != 90*time.Second {
		t.Fatal("fixture renewed initial admission")
	}
}

func TestResetExecutionChainRefusesTamperingAndReorderedPhases(t *testing.T) {
	plan, _, record := resetExecutionChainFixture(t, 3)
	cases := map[string]func(*resetExecutionJournal){
		"accepted-time":   func(r *resetExecutionJournal) { r.AcceptedAtUnix++ },
		"initial-receipt": func(r *resetExecutionJournal) { r.Evidence.ExecutionReceiptSHA = strings.Repeat("e", 64) },
		"approval-plan":   func(r *resetExecutionJournal) { r.Evidence.ApprovalPlanSHA = strings.Repeat("e", 64) },
		"target":          func(r *resetExecutionJournal) { r.TargetFingerprint = strings.Repeat("e", 64) },
		"request":         func(r *resetExecutionJournal) { r.RequestFingerprint = strings.Repeat("e", 64) },
		"chain-link":      func(r *resetExecutionJournal) { r.Attestations[2].PreviousSHA = strings.Repeat("e", 64) },
		"space":           func(r *resetExecutionJournal) { r.Attestations[2].Space.AvailableBytes++ },
		"skip-phase":      func(r *resetExecutionJournal) { r.Attestations = append(r.Attestations[:1], r.Attestations[2]) },
		"renew-window": func(r *resetExecutionJournal) {
			r.Attestations[2].CompletedAt = r.Attestations[2].StartedAt.Add(30 * time.Second)
		},
		"changed-revision-resealed": func(r *resetExecutionJournal) {
			a := &r.Attestations[2]
			a.Snapshot.PublicationRevision = "3"
			a.SHA = resetExecutionAttestationSHA(*r, *a)
		},
		"noncanonical-revision-resealed": func(r *resetExecutionJournal) {
			a := &r.Attestations[2]
			a.Snapshot.PublicationRevision = "02"
			a.SHA = resetExecutionAttestationSHA(*r, *a)
		},
		"freeze-owner-resealed": func(r *resetExecutionJournal) {
			a := &r.Attestations[2]
			a.Snapshot.WriterFreezeReceiptSHA = strings.Repeat("e", 64)
			a.SHA = resetExecutionAttestationSHA(*r, *a)
		},
		"publication-open-resealed": func(r *resetExecutionJournal) {
			a := &r.Attestations[2]
			a.Snapshot.PublicationState = "PUBLIC"
			a.SHA = resetExecutionAttestationSHA(*r, *a)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := cloneResetExecutionChain(t, record)
			change(&bad)
			if validateResetExecutionJournal(bad, plan.OperationID, plan.Target) == nil {
				t.Fatal("invalid chain accepted")
			}
		})
	}
	if validateResetExecutionJournal(record, strings.Repeat("e", 32), plan.Target) == nil {
		t.Fatal("different operation accepted")
	}
}

func TestResetExecutionJournalDurablyBindsOperationAdmission(t *testing.T) {
	cfg := configuredResetOperationTest(t)
	plan, binding, record := resetExecutionChainFixture(t, 2)
	mustReserveOperation(t, cfg.lifecycleOperationStore, durableOperationRecord{OperationID: plan.OperationID, Kind: lifecycleKindReset,
		SubjectID: "pep", RequestFingerprint: record.RequestFingerprint, Status: lifecycleJobRunning,
		CreatedAt: time.Unix(record.AcceptedAtUnix, 0), UpdatedAt: time.Unix(record.AcceptedAtUnix, 0)})
	target, err := cfg.serverTargetForID("pep")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.writeResetExecutionLifecycleJournal(target, plan.Target, plan.OperationID, record); err != nil {
		t.Fatal(err)
	}
	reopened, exists, err := cfg.readLifecycleJournal()
	if err != nil || !exists || reopened.ResetExecution == nil || !reflect.DeepEqual(record, *reopened.ResetExecution) {
		t.Fatal("durable restart lost execution evidence")
	}
	before := readFile(t, cfg.lifecycleJournalFile)
	if cfg.advanceLifecycleJournal(lifecycleJournalStageDown) == nil || readFile(t, cfg.lifecycleJournalFile) != before {
		t.Fatal("destructive stage advanced without third phase")
	}
	binding.Phase = "before-down"
	binding.PreviousAttestationSHA = record.Attestations[1].SHA
	if cfg.appendResetExecutionPhaseToJournal(context.Background(), binding, nil) == nil || readFile(t, cfg.lifecycleJournalFile) != before {
		t.Fatal("missing live source changed journal")
	}
	bad := cloneResetExecutionChain(t, record)
	bad.AcceptedAtUnix++
	if cfg.validateResetExecutionOperation(bad, plan.OperationID) == nil {
		t.Fatal("retry renewed durable admission")
	}
	bad = cloneResetExecutionChain(t, record)
	bad.RequestFingerprint = strings.Repeat("e", 64)
	if cfg.validateResetExecutionOperation(bad, plan.OperationID) == nil {
		t.Fatal("different proof identity accepted")
	}
}

func TestResetExecutionJournalMalformedProofCannotReachRecoveryMutation(t *testing.T) {
	cfg := configuredResetOperationTest(t)
	plan, _, record := resetExecutionChainFixture(t, 2)
	mustReserveOperation(t, cfg.lifecycleOperationStore, durableOperationRecord{OperationID: plan.OperationID, Kind: lifecycleKindReset,
		SubjectID: "pep", RequestFingerprint: record.RequestFingerprint, Status: lifecycleJobRunning,
		CreatedAt: time.Unix(record.AcceptedAtUnix, 0), UpdatedAt: time.Unix(record.AcceptedAtUnix, 0)})
	target, err := cfg.serverTargetForID("pep")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.writeResetExecutionLifecycleJournal(target, plan.Target, plan.OperationID, record) != nil {
		t.Fatal("write failed")
	}
	before := readFile(t, cfg.lifecycleJournalFile)
	var journal lifecycleJournal
	if json.Unmarshal([]byte(before), &journal) != nil {
		t.Fatal("decode failed")
	}
	journal.ResetExecution.Evidence.ExecutionReceiptSHA = strings.Repeat("e", 64)
	wire, _ := json.Marshal(journal)
	if os.WriteFile(cfg.lifecycleJournalFile, wire, 0600) != nil {
		t.Fatal("fixture failed")
	}
	calls := 0
	cfg.dockerRunner = func(...string) (string, error) { calls++; return "unexpected", nil }
	oldEnv := readFile(t, target.EnvFile)
	if cfg.repairLifecycleJournal() == nil || calls != 0 || readFile(t, target.EnvFile) != oldEnv ||
		readFile(t, cfg.lifecycleJournalFile) != string(wire) {
		t.Fatal("malformed proof reached recovery mutation")
	}
}
