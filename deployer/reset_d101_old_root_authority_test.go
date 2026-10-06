package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func native9RootDataFixture(t *testing.T) config {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	jobs := newLifecycleJobManager()
	store := mustOpenOperationStore(t, filepath.Join(dir, "operations.json"))
	c := config{serversDir: dir, lifecycleJobs: jobs, lifecycleOperationStore: store, maintenanceFile: filepath.Join(dir, "marker"), lifecycleJournalFile: filepath.Join(dir, "journal")}
	c.operations = newOperationCoordinator(c.maintenanceFile, c.lifecycleJournalFile, jobs)
	return c
}
func TestNative9ExistingRootCapturesActualNonemptyState(t *testing.T) {
	c := native9RootDataFixture(t)
	op := strings.Repeat("a", 32)
	job := strings.Repeat("b", 32)
	pending := pendingDurableOperation(op)
	c.lifecycleOperationStore.operations[op] = pending
	deferred := pending
	deferred.Status = lifecycleJobFailed
	c.lifecycleOperationStore.deferredTransitions[op] = deferred
	c.lifecycleJobs.jobs[job] = lifecycleJob{id: job, operationID: op, status: lifecycleJobRunning, result: json.RawMessage(`{"physicalStage":"running"}`)}
	c.lifecycleJobs.operationJobs[op] = job
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.operations.active = &operationLease{coordinator: c.operations, jobID: job, ctx: ctx, cancel: cancel}
	c.operations.preparing = &operationPreparation{coordinator: c.operations, ctx: ctx, cancel: cancel, operationID: strings.Repeat("c", 32), fingerprint: strings.Repeat("d", 64), leaseAttempt: "private transport"}
	c.operations.preparationSettlementPending = true
	c.operations.journalPending = true
	producer := registerResetD101OldRoot(&c, nil)
	if producer == nil || !producer.objectsMatch() {
		t.Fatal("actual pointers not registered")
	}
	v, err := captureResetD101ExistingRootHeapUnverified(context.Background(), &c)
	if err != nil || len(v.Jobs) != 1 || len(v.Store) != 1 || len(v.Deferred) != 1 || len(v.ActiveJobIDs) != 1 || len(v.Preparations) != 1 || !v.JournalPending || !v.SettlementPending || v.Jobs[job].Status != lifecycleJobRunning {
		t.Fatalf("lost actual state: %v %#v", err, v)
	}
	if bytes.Contains([]byte(v.Preparations[0].LeaseAttemptSHA), []byte("private transport")) {
		t.Fatal("transport secret exposed")
	}
	v.Jobs[job] = resetD101RootJobData{}
	v.Store[op] = durableOperationRecord{}
	if c.lifecycleJobs.jobs[job].status != lifecycleJobRunning || c.lifecycleOperationStore.operations[op] != pending {
		t.Fatal("heap result aliases live maps")
	}
	if producer.freezeMaps() == nil {
		t.Fatal("inflight actual root frozen")
	}
	if _, err := producer.authenticate(context.Background(), []byte("request")); err == nil {
		t.Fatal("data fixture became production authority")
	}
	c.lifecycleJobs = newLifecycleJobManager()
	if producer.objectsMatch() {
		t.Fatal("replacement empty manager accepted as actual root")
	}
}
func TestNative9RootCaptureUsesCoordinatorJobsStoreLockOrder(t *testing.T) {
	c := native9RootDataFixture(t)
	c.operations.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := captureResetD101ExistingRootHeapUnverified(context.Background(), &c); done <- err }()
	if !c.lifecycleJobs.mu.TryLock() {
		c.operations.mu.Unlock()
		t.Fatal("jobs lock acquired before coordinator")
	}
	c.lifecycleJobs.mu.Unlock()
	if !c.lifecycleOperationStore.mu.TryLock() {
		c.operations.mu.Unlock()
		t.Fatal("store lock acquired before coordinator")
	}
	c.lifecycleOperationStore.mu.Unlock()
	c.operations.mu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("capture lock deadlock")
	}
}
func TestNative9RootNativeOwnerBlocksAdmissionAndReadMutation(t *testing.T) {
	c := native9RootDataFixture(t)
	job := strings.Repeat("a", 32)
	op := strings.Repeat("b", 32)
	c.lifecycleJobs.jobs[job] = lifecycleJob{id: job, operationID: op, status: lifecycleJobSucceeded, finishedAt: time.Now().Add(-48 * time.Hour)}
	c.lifecycleJobs.operationJobs[op] = job
	g := &resetD101RootOwnerGate{}
	g.state.Store(int32(resetD101RootOwnerPresent))
	c.operations.d101NativeOwner = g
	c.lifecycleJobs.d101NativeOwner = g
	c.lifecycleOperationStore.d101NativeOwner = g
	before := c.lifecycleJobs.jobs[job]
	if _, err := c.lifecycleJobs.reserve(); err == nil {
		t.Fatal("owner allows new job")
	}
	if _, ok := c.lifecycleJobs.lookup(job); !ok {
		t.Fatal("read pruned actual terminal job")
	}
	if _, ok := c.lifecycleJobs.lookupOperation(op); !ok {
		t.Fatal("operation lookup pruned actual terminal")
	}
	if !reflect.DeepEqual(before, c.lifecycleJobs.jobs[job]) {
		t.Fatal("read changed frozen job")
	}
	p := registerResetD101OldRoot(&c, nil)
	if p.freezeMaps() != nil || !g.frozen.Load() {
		t.Fatal("drained same root did not freeze")
	}
	if !g.blocksMutation() {
		t.Fatal("frozen owner allows writes")
	}
	if err := c.writeLifecycleJournalRecord(lifecycleJournal{}); err == nil {
		t.Fatal("frozen root writes journal")
	}
	if _, err := os.Stat(c.lifecycleJournalFile); !os.IsNotExist(err) {
		t.Fatal("denied journal mutated target")
	}
}
func TestNative9RemovedKnownOwnerDoesNotBecomeAbsent(t *testing.T) {
	c := native9RootDataFixture(t)
	path := resetD101RootOwnerPath(c.serversDir)
	if probeResetD101RootOwner(path, false) != resetD101RootOwnerAbsent {
		t.Fatal("genuine absence denied")
	}
	if probeResetD101RootOwner(path, true) != resetD101RootOwnerUnknown {
		t.Fatal("removed unresolved owner became absent")
	}
	if err := os.Symlink(filepath.Join(c.serversDir, "missing"), path); err != nil {
		t.Fatal(err)
	}
	if probeResetD101RootOwner(path, false) != resetD101RootOwnerUnknown {
		t.Fatal("symlink owner considered absent")
	}
}
