package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func resetD101WorkerLeaseFixture(t *testing.T) (config, *operationLease, resetExecutionPhaseBinding, serverTarget) {
	t.Helper()
	cfg, _, op := resetD101IssuerFixture(t)
	record, _ := cfg.lifecycleOperationStore.Lookup(op)
	record.Status = lifecycleJobRunning
	cfg.lifecycleOperationStore.operations[op] = record
	journal, exists, err := cfg.readLifecycleJournal()
	if err != nil || !exists {
		t.Fatal("synthetic worker journal", err)
	}
	if os.Remove(cfg.lifecycleJournalFile) != nil {
		t.Fatal("synthetic pre-worker fixture")
	}
	binding := resetExecutionPhaseBinding{OperationID: op, Target: *journal.ResetTarget, Evidence: journal.ResetExecution.Evidence, AcceptedAtUnix: record.CreatedAt.Unix(), Phase: "prepared"}
	coordinator := newOperationCoordinator("", "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	lease := &operationLease{coordinator: coordinator, jobID: strings.Repeat("b", 32), ctx: ctx, cancel: cancel}
	coordinator.closed = true
	coordinator.active = lease
	coordinator.maintenanceLease = &maintenanceAdmissionLease{token: "synthetic", operationID: op, jobID: lease.jobID, consumed: true}
	cfg.operations = coordinator
	cfg.ghcrOwner = "peppone-choi"
	target, err := cfg.serverTargetForID("pep")
	if err != nil {
		t.Fatal(err)
	}
	return cfg, lease, binding, target
}

func TestResetD101WorkerLeaseRequiresConsumedBoundCurrentAdmission(t *testing.T) {
	cfg, lease, binding, _ := resetD101WorkerLeaseFixture(t)
	if cfg.requireResetD101WorkerLease(lease, binding) != nil {
		t.Fatal("consumed current synthetic lease refused")
	}
	for _, mode := range []string{"nil-lease", "nil-context", "open-barrier", "different-active", "unconsumed", "different-op", "different-job", "different-fingerprint", "different-created-at", "no-intent", "terminal", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			cfg, lease, binding, _ := resetD101WorkerLeaseFixture(t)
			before, _ := cfg.lifecycleOperationStore.Lookup(binding.OperationID)
			switch mode {
			case "nil-lease":
				lease = nil
			case "nil-context":
				lease.ctx = nil
			case "open-barrier":
				cfg.operations.closed = false
			case "different-active":
				cfg.operations.active = &operationLease{}
			case "unconsumed":
				cfg.operations.maintenanceLease.consumed = false
			case "different-op":
				cfg.operations.maintenanceLease.operationID = strings.Repeat("f", 32)
			case "different-job":
				cfg.operations.maintenanceLease.jobID = strings.Repeat("f", 32)
			case "different-fingerprint":
				binding.Evidence.ExecutionReceiptSHA = strings.Repeat("f", 64)
			case "different-created-at":
				binding.AcceptedAtUnix++
			case "no-intent":
				before.D101IntentSHA = ""
				cfg.lifecycleOperationStore.operations[binding.OperationID] = before
			case "terminal":
				before.Status = lifecycleJobSucceeded
				cfg.lifecycleOperationStore.operations[binding.OperationID] = before
			case "cancelled":
				lease.cancel()
			}
			if cfg.requireResetD101WorkerLease(lease, binding) == nil {
				t.Fatal("unowned or changed admission accepted")
			}
			after, _ := cfg.lifecycleOperationStore.Lookup(binding.OperationID)
			if after != before {
				t.Fatal("lease check modified durable state")
			}
		})
	}
}

func TestResetD101PhysicalWorkerMissingSourcesAndWrongTargetPerformNoWork(t *testing.T) {
	for _, mode := range []string{"phase-source", "authority", "wrong-env", "wrong-project", "wrong-repository", "wrong-initial-phase"} {
		t.Run(mode, func(t *testing.T) {
			cfg, lease, binding, target := resetD101WorkerLeaseFixture(t)
			source := resetExecutionPhaseSource(func(context.Context, resetExecutionPhaseBinding) (resetExecutionPhaseSnapshot, error) {
				t.Fatal("unqualified worker observed phase")
				return resetExecutionPhaseSnapshot{}, errResetExecutionEvidence
			})
			switch mode {
			case "phase-source":
				source = nil
			case "authority":
				cfg.d101PurposeAuthority = nil
			case "wrong-env":
				target.EnvFile += ".other"
			case "wrong-project":
				target.Project = "opensamguk-sother"
			case "wrong-repository":
				cfg.ghcrOwner = "invalid/owner"
			case "wrong-initial-phase":
				binding.Phase = "before-down"
			}
			before, _ := cfg.lifecycleOperationStore.Lookup(binding.OperationID)
			beforeWire, _ := json.Marshal(binding)
			if _, err := cfg.runResetD101PhysicalWorker(lease, target, binding, source); err == nil {
				t.Fatal("unqualified physical worker started")
			}
			after, _ := cfg.lifecycleOperationStore.Lookup(binding.OperationID)
			afterWire, _ := json.Marshal(binding)
			if before != after || string(beforeWire) != string(afterWire) || stateFilePresent(cfg.lifecycleJournalFile) {
				t.Fatal("refusal mutated admission/target/journal")
			}
		})
	}
}
