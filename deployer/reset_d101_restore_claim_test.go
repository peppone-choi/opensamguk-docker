package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func restoreCoordinatorFixture(t *testing.T) (*operationCoordinator, string, uint32) {
	t.Helper()
	// macOS temp roots may contain /var -> /private/var. Positive custody
	// fixtures use their canonical parent; the symlink rejection stays strict.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return newOperationCoordinator(filepath.Join(dir, "maintenance.json"), filepath.Join(dir, "lifecycle.json"), nil), strings.Repeat("a", 32), uint32(os.Getuid())
}

func TestSucceededRestoreLeaseSurvivesDoneAndRestartWithoutLifecycleRewrite(t *testing.T) {
	c, op, uid := restoreCoordinatorFixture(t)
	lease, err := c.beginResetD101SucceededRestoreWithCustodyUID(op, uid)
	if err != nil || lease == nil || c.active != lease || !c.closed || c.journalPending || stateFilePresent(c.journalPath) || stateFilePresent(c.markerPath) {
		t.Fatal("separate restore owner not acquired", err)
	}
	gate := resetD101RestoreGatePath(c.markerPath)
	before, err := os.ReadFile(gate)
	if err != nil || requireResetD101RestoreGate(gate, op, uid) != nil {
		t.Fatal("durable same-op gate missing", err)
	}
	lease.Done()
	if c.active != nil || !c.closed || !stateFilePresent(gate) {
		t.Fatal("Done cleared durable recovery ownership")
	}
	for _, coordinator := range []*operationCoordinator{c, newOperationCoordinator(c.markerPath, c.journalPath, nil)} {
		if _, err := coordinator.leaveMaintenance(); err == nil || !coordinator.closed {
			t.Fatal("UNKNOWN restore reopened maintenance")
		}
		if _, err := coordinator.beginResetD101SucceededRestoreWithCustodyUID(op, uid); err == nil {
			t.Fatal("restore1 replayed after restart")
		}
		if _, err := coordinator.begin(""); err == nil {
			t.Fatal("ordinary mutation admitted during UNKNOWN restore")
		}
	}
	after, _ := os.ReadFile(gate)
	if string(after) != string(before) || stateFilePresent(c.journalPath) {
		t.Fatal("original gate or completed lifecycle journal rewritten")
	}
}

func TestSucceededRestoreLeaseExclusiveConcurrentAttempt(t *testing.T) {
	c, op, uid := restoreCoordinatorFixture(t)
	var wg sync.WaitGroup
	results := make(chan *operationLease, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lease, _ := c.beginResetD101SucceededRestoreWithCustodyUID(op, uid)
			results <- lease
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for lease := range results {
		if lease != nil {
			winners++
			defer lease.Done()
		}
	}
	if winners != 1 {
		t.Fatal("restore gate did not serialize attempts", winners)
	}
}

func TestSucceededRestoreCanOwnRetainedSameOpDrainedMaintenance(t *testing.T) {
	c, op, uid := restoreCoordinatorFixture(t)
	c.closed = true
	c.maintenanceLease = &maintenanceAdmissionLease{operationID: op, jobID: strings.Repeat("b", 32), consumed: true}
	if err := os.WriteFile(c.markerPath, []byte("original maintenance"), 0600); err != nil {
		t.Fatal(err)
	}
	lease, err := c.beginResetD101SucceededRestoreWithCustodyUID(op, uid)
	if err != nil || lease == nil || c.active != lease || c.maintenanceLease.operationID != op || c.maintenanceLease.jobID != "" || !c.maintenanceLease.consumed {
		t.Fatal("completed same-op maintenance could not own separate restore", err)
	}
	defer lease.Done()
	before, err := os.ReadFile(c.markerPath)
	if err != nil || string(before) != "original maintenance" || stateFilePresent(c.journalPath) {
		t.Fatal("original maintenance or completed lifecycle journal changed")
	}
}

func TestSucceededRestoreLeaseRefusesBusyForeignAndUnsafeCustody(t *testing.T) {
	for _, mode := range []string{"active", "preparing", "settlement", "maintenance", "journal", "foreign-gate", "group-writable", "symlink-parent", "invalid-op"} {
		t.Run(mode, func(t *testing.T) {
			c, op, uid := restoreCoordinatorFixture(t)
			activeCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "active":
				c.active = &operationLease{ctx: activeCtx, cancel: cancel}
			case "preparing":
				c.preparing = &operationPreparation{}
			case "settlement":
				c.preparationSettlementPending = true
			case "maintenance":
				c.maintenanceLease = &maintenanceAdmissionLease{operationID: strings.Repeat("b", 32)}
			case "journal":
				if err := os.WriteFile(c.journalPath, []byte("retained journal"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-gate":
				if err := os.WriteFile(resetD101RestoreGatePath(c.markerPath), []byte("foreign or partial gate"), 0400); err != nil {
					t.Fatal(err)
				}
			case "group-writable":
				if err := os.Chmod(filepath.Dir(c.markerPath), 0770); err != nil {
					t.Fatal(err)
				}
			case "symlink-parent":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(filepath.Dir(c.markerPath), link); err != nil {
					t.Fatal(err)
				}
				c.markerPath = filepath.Join(link, "maintenance.json")
			case "invalid-op":
				op = "not-an-operation"
			}
			if _, err := c.beginResetD101SucceededRestoreWithCustodyUID(op, uid); err == nil || activeCtx.Err() != nil {
				t.Fatal("busy/foreign authority acquired or existing owner cancelled", err)
			}
			if mode != "foreign-gate" && stateFilePresent(resetD101RestoreGatePath(c.markerPath)) {
				t.Fatal("rejection created a restore attempt")
			}
		})
	}
}

func TestSucceededRestoreMissingInstalledSourcesCannotInvokePhysicalWork(t *testing.T) {
	c, op, _ := restoreCoordinatorFixture(t)
	calls := 0
	cfg := config{operations: c, dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	attempt, err := cfg.claimResetD101SucceededRestore(context.Background(), op, strings.Repeat("a", 64))
	if err == nil || calls != 0 || attempt.lease != nil || attempt.claimSHA != "" || stateFilePresent(resetD101RestoreGatePath(c.markerPath)) {
		t.Fatal("missing fixed sources acquired physical recovery")
	}
}
