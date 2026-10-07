package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
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
	g.frozen.Store(true)
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

func TestRemovedNativeCLIRejectsBeforeConfiguration(t *testing.T) {
	for _, command := range []string{"--d101-host-operation", "--d101-issue-current-receipt", "--d101-prepared-relay", "--d101-initialize-key3", "--d101-native-keeper"} {
		t.Run(command, func(t *testing.T) {
			var output, errorOutput bytes.Buffer
			handled, status := earlyCommand([]string{"deployer", command, "--operation-id", strings.Repeat("a", 32)}, func(string) string { t.Fatal("removed command reads environment"); return "" }, nil, &output, &errorOutput)
			if !handled || status != 2 || output.Len() != 0 {
				t.Fatal("removed native command can enter service startup")
			}
		})
	}
}

func TestRemovedNativeOperationRoutesCannotMutate(t *testing.T) {
	c := native9RootDataFixture(t)
	c.dockerRunner = func(...string) (string, error) { t.Fatal("removed route ran Docker"); return "", nil }
	for _, suffix := range []string{"seed-approval", "recovery-result", "prepared-proof/" + strings.Repeat("b", 64), "execution-result/" + strings.Repeat("b", 64)} {
		t.Run(suffix, func(t *testing.T) {
			path := "/operations/" + strings.Repeat("a", 32) + "/" + suffix
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			c.handleOperation(w, r)
			if w.Code != http.StatusBadRequest || isAuthenticatedHTTPRouteAllowed(http.MethodGet, path) {
				t.Fatal("removed operation accepted")
			}
			if stateFilePresent(c.lifecycleJournalFile) || len(c.lifecycleOperationStore.operations) != 0 {
				t.Fatal("removed route wrote lifecycle state")
			}
		})
	}
}

func TestRetainedNativeSucceededJournalCannotBeCleared(t *testing.T) {
	c := configuredResetOperationTest(t)
	plan, _, chain := resetExecutionChainFixture(t, 3)
	record := durableOperationRecord{OperationID: plan.OperationID, Kind: lifecycleKindReset, SubjectID: "pep", RequestFingerprint: chain.RequestFingerprint, Status: lifecycleJobSucceeded, CreatedAt: time.Unix(chain.AcceptedAtUnix, 0), UpdatedAt: time.Unix(chain.AcceptedAtUnix, 0)}
	mustReserveOperation(t, c.lifecycleOperationStore, record)
	target, err := c.serverTargetForID("pep")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeResetExecutionJournalFixture(c, target, plan.Target, plan.OperationID, chain); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, c.lifecycleJournalFile)
	if c.settleSucceededLifecycleJournal(context.Background(), plan.OperationID) == nil || readFile(t, c.lifecycleJournalFile) != before {
		t.Fatal("retained native barrier cleared")
	}
	after, found := c.lifecycleOperationStore.Lookup(plan.OperationID)
	if !found || after.Status != lifecycleJobSucceeded {
		t.Fatal("barrier refusal changed durable success")
	}
}
