package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDurableOperationStoreSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".deployer-operations.json")
	first := mustOpenOperationStore(t, path)
	id := "0123456789abcdef0123456789abcdef"
	mustReserveOperation(t, first, durableOperationRecord{
		OperationID: id, Kind: lifecycleKindReset, SubjectID: "pep",
		RequestFingerprint: strings.Repeat("a", 64), Status: lifecycleJobPending,
	})
	mustTransitionOperation(t, first, id, lifecycleJobSucceeded, http.StatusOK, "서버 리셋이 완료되었습니다.")

	restarted := mustOpenOperationStore(t, path)
	got, ok := restarted.Lookup(id)
	if !ok || got.Status != lifecycleJobSucceeded || got.SubjectID != "pep" {
		t.Fatalf("restarted lookup = %#v, %v", got, ok)
	}
}

func TestDurableOperationStoreRejectsMalformedFile(t *testing.T) {
	for name, contents := range map[string]string{
		"malformed record": `{"version":1,"operations":[{"operationId":"bad"}]}`,
		"missing records":  `{"version":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".deployer-operations.json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := openDurableOperationStore(path, 512, 24*time.Hour); err == nil {
				t.Fatal("malformed durable operation store opened")
			}
		})
	}
}

func TestDurableOperationStoreRejects513thNonTerminalRecord(t *testing.T) {
	store := mustOpenOperationStore(t, filepath.Join(t.TempDir(), ".deployer-operations.json"))
	for i := 0; i < durableOperationMaxEntries; i++ {
		mustReserveOperation(t, store, durableOperationRecord{
			OperationID:        fmt.Sprintf("%032x", i+1),
			Kind:               lifecycleKindCreate,
			SubjectID:          "pep",
			RequestFingerprint: fmt.Sprintf("%064x", i+1),
			Status:             lifecycleJobPending,
		})
	}
	_, _, err := store.Reserve(durableOperationRecord{
		OperationID:        strings.Repeat("f", 32),
		Kind:               lifecycleKindCreate,
		SubjectID:          "pep",
		RequestFingerprint: strings.Repeat("f", 64),
		Status:             lifecycleJobPending,
	})
	if err == nil {
		t.Fatal("513th non-terminal durable operation was accepted")
	}
}

func TestDurableOperationStorePrunesExpiredTerminalRecord(t *testing.T) {
	store := mustOpenOperationStore(t, filepath.Join(t.TempDir(), ".deployer-operations.json"))
	now := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	id := strings.Repeat("a", 32)
	mustReserveOperation(t, store, durableOperationRecord{
		OperationID: id, Kind: lifecycleKindClose, SubjectID: "pep",
		RequestFingerprint: strings.Repeat("b", 64), Status: lifecycleJobPending,
	})
	mustTransitionOperation(t, store, id, lifecycleJobSucceeded, http.StatusOK, "서버 종료가 완료되었습니다.")

	now = now.Add(durableOperationTerminalRetention)
	mustReserveOperation(t, store, durableOperationRecord{
		OperationID: strings.Repeat("c", 32), Kind: lifecycleKindCreate, SubjectID: "pep",
		RequestFingerprint: strings.Repeat("d", 64), Status: lifecycleJobPending,
	})
	if got, ok := store.Lookup(id); ok {
		t.Fatalf("expired terminal record retained: %#v", got)
	}
	restarted := mustOpenOperationStore(t, store.path)
	if _, ok := restarted.Lookup(id); ok {
		t.Fatal("expired terminal record remained on disk")
	}
}

func TestDurableOperationStoreRetainsNonTerminalRecordPastRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".deployer-operations.json")
	store, err := openDurableOperationStore(path, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	id := strings.Repeat("a", 32)
	mustReserveOperation(t, store, durableOperationRecord{
		OperationID: id, Kind: lifecycleKindReset, SubjectID: "pep",
		RequestFingerprint: strings.Repeat("b", 64), Status: lifecycleJobRunning,
	})

	now = now.Add(2 * time.Hour)
	_, _, err = store.Reserve(durableOperationRecord{
		OperationID: strings.Repeat("c", 32), Kind: lifecycleKindReset, SubjectID: "pep",
		RequestFingerprint: strings.Repeat("d", 64), Status: lifecycleJobPending,
	})
	if err == nil {
		t.Fatal("non-terminal record was pruned to admit another operation")
	}
	if got, ok := store.Lookup(id); !ok || got.Status != lifecycleJobRunning {
		t.Fatalf("non-terminal lookup = %#v, %v", got, ok)
	}
}

func TestDurableOperationStoreRejectsUnsafePublicMessages(t *testing.T) {
	for name, message := range map[string]string{
		"control character":   "reset failed\ndocker output",
		"over 300 characters": strings.Repeat("가", durableOperationMessageLimit+1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".deployer-operations.json")
			store := mustOpenOperationStore(t, path)
			id := strings.Repeat("a", 32)
			mustReserveOperation(t, store, durableOperationRecord{
				OperationID: id, Kind: lifecycleKindReset, SubjectID: "pep",
				RequestFingerprint: strings.Repeat("b", 64), Status: lifecycleJobPending,
			})
			if _, err := store.Transition(id, lifecycleJobFailed, http.StatusInternalServerError, message); err == nil {
				t.Fatal("unsafe public message was accepted")
			}
			restarted := mustOpenOperationStore(t, path)
			got, ok := restarted.Lookup(id)
			if !ok || got.Status != lifecycleJobPending || got.PublicMessage != "" {
				t.Fatalf("restarted lookup after rejected message = %#v, %v", got, ok)
			}
		})
	}
}

func TestDurableOperationStoreRecoversJournaledAndCancelsUnjournaledWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".deployer-operations.json")
	store := mustOpenOperationStore(t, path)
	journaledID := strings.Repeat("a", 32)
	unjournaledID := strings.Repeat("b", 32)
	for _, record := range []durableOperationRecord{
		{OperationID: journaledID, Kind: lifecycleKindReset, SubjectID: "pep", RequestFingerprint: strings.Repeat("c", 64), Status: lifecycleJobRunning},
		{OperationID: unjournaledID, Kind: lifecycleKindCreate, SubjectID: "shu", RequestFingerprint: strings.Repeat("d", 64), Status: lifecycleJobPending},
	} {
		mustReserveOperation(t, store, record)
	}
	if err := store.Recover(journaledID); err != nil {
		t.Fatalf("recover durable operations: %v", err)
	}
	restarted := mustOpenOperationStore(t, path)
	journaled, _ := restarted.Lookup(journaledID)
	unjournaled, _ := restarted.Lookup(unjournaledID)
	if journaled.Status != lifecycleJobRecoveryRequired || journaled.PublicMessage != durableOperationRecoveryMessage {
		t.Fatalf("journaled operation = %#v", journaled)
	}
	if unjournaled.Status != lifecycleJobCancelled || unjournaled.PublicMessage != durableOperationRestartMessage {
		t.Fatalf("unjournaled operation = %#v", unjournaled)
	}
}

func TestDurableOperationStoreLoadConfigUsesOverrideAndFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom-operations.json")
	t.Setenv("SERVERS_DIR", t.TempDir())
	t.Setenv("DEPLOYER_OPERATION_STORE_FILE", path)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.lifecycleOperationStore == nil || cfg.lifecycleOperationStore.path != path {
		t.Fatalf("operation store path = %#v", cfg.lifecycleOperationStore)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"operations":[{"operationId":"bad"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig accepted a malformed existing operation store")
	}
}

func mustOpenOperationStore(t *testing.T, path string) *durableOperationStore {
	t.Helper()
	store, err := openDurableOperationStore(path, 512, 24*time.Hour)
	if err != nil {
		t.Fatalf("open durable operation store: %v", err)
	}
	return store
}

func mustReserveOperation(t *testing.T, store *durableOperationStore, record durableOperationRecord) {
	t.Helper()
	if _, _, err := store.Reserve(record); err != nil {
		t.Fatalf("reserve durable operation: %v", err)
	}
}

func mustTransitionOperation(t *testing.T, store *durableOperationStore, operationID string, status lifecycleJobStatus, httpStatus int, publicMessage string) {
	t.Helper()
	if _, err := store.Transition(operationID, status, httpStatus, publicMessage); err != nil {
		t.Fatalf("transition durable operation: %v", err)
	}
}
