package main

import (
	"context"
	"strings"
	"testing"
)

func preStopLeaseFixture(t *testing.T) (config, *resetD101PreStopPreparation) {
	t.Helper()
	c, _, binding, _ := resetD101WorkerLeaseFixture(t)
	delete(c.lifecycleOperationStore.operations, binding.OperationID)
	co := newOperationCoordinator("", "", nil)
	co.closed = true
	co.maintenanceLease = &maintenanceAdmissionLease{token: "synthetic-prestop-token", operationID: binding.OperationID}
	c.operations = co
	intent := resetDecodedApprovalIntent{SHA: strings.Repeat("b", 64), Intent: resetApprovalIntent{OperationID: binding.OperationID}}
	planSHA := strings.Repeat("c", 64)
	p, err := co.prepare(lifecycleKindReset, binding.OperationID, "pep", resetD101PreStopPreparationFingerprint(intent.SHA, planSHA), co.maintenanceLease.token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.complete(true) })
	return c, &resetD101PreStopPreparation{preparation: p, lease: co.maintenanceLease, caller: context.Background(), intent: intent, planSHA: planSHA}
}
func TestPreStopPreparationLeaseRequiresActualUnconsumedSamePreparation(t *testing.T) {
	c, s := preStopLeaseFixture(t)
	if c.requireResetD101PreStopLease(s) != nil {
		t.Fatal("actual unconsumed fixture lease rejected")
	}
	for _, mode := range []string{"nil", "open", "active", "different-preparation", "different-lease", "consumed", "job", "operation", "token", "fingerprint", "context", "cancelled", "journal-pending", "settlement-pending", "durable-first-admission", "different-plan"} {
		t.Run(mode, func(t *testing.T) {
			c, s := preStopLeaseFixture(t)
			switch mode {
			case "nil":
				s = nil
			case "open":
				c.operations.closed = false
			case "active":
				c.operations.active = &operationLease{}
			case "different-preparation":
				c.operations.preparing = &operationPreparation{}
			case "different-lease":
				copy := *s.lease
				c.operations.maintenanceLease = &copy
			case "consumed":
				s.lease.consumed = true
			case "job":
				s.lease.jobID = "synthetic"
			case "operation":
				s.lease.operationID = strings.Repeat("f", 32)
			case "token":
				s.preparation.leaseAttempt = "different"
			case "fingerprint":
				s.preparation.fingerprint = strings.Repeat("d", 64)
			case "context":
				s.preparation.ctx = nil
			case "cancelled":
				s.preparation.cancel()
			case "journal-pending":
				c.operations.journalPending = true
			case "settlement-pending":
				c.operations.preparationSettlementPending = true
			case "durable-first-admission":
				c.lifecycleOperationStore.operations[s.intent.Intent.OperationID] = durableOperationRecord{OperationID: s.intent.Intent.OperationID}
			case "different-plan":
				s.planSHA = strings.Repeat("d", 64)
			}
			if c.requireResetD101PreStopLease(s) == nil {
				t.Fatal("changed prestop lease accepted")
			}
		})
	}
	if c.lifecycleOperationStore.operations[s.intent.Intent.OperationID].OperationID != "" || s.lease.consumed || c.operations.active != nil {
		t.Fatal("lease check admitted/promoted durable worker")
	}
	s.preparation.complete(true)
	if c.requireResetD101PreStopLease(s) == nil || s.lease.consumed {
		t.Fatal("completed preparation remained valid or consumed lease")
	}
}
func TestPreStopPreparationMissingPurposeSourceCannotBeginOrReadOriginals(t *testing.T) {
	for _, mode := range []string{"nil-context", "cancelled", "missing-fixed-source"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			if mode == "nil-context" {
				ctx = nil
			}
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			var c config
			s, err := c.beginResetD101PreStopPreparation(ctx, strings.Repeat("a", 32), strings.Repeat("b", 64), strings.Repeat("c", 64), "synthetic")
			if err == nil || s != nil {
				t.Fatal("uninstalled prestop source started preparation")
			}
		})
	}
}
