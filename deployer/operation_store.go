package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	durableOperationStoreVersion      = 1
	durableOperationMaxEntries        = 512
	durableOperationTerminalRetention = 24 * time.Hour
	durableOperationMessageLimit      = 300
	durableOperationStoreFileName     = ".deployer-operations.json"

	durableOperationRecoveryMessage = "서버 복구 확인이 필요합니다. 운영 복구가 끝날 때까지 기다려 주세요."
	durableOperationRestartMessage  = "deployer 재시작 전에 작업이 중단되었습니다. 다시 요청해 주세요."
)

var durableOperationFingerprintRe = regexp.MustCompile(`^[a-f0-9]{64}$`)

type durableOperationRecord struct {
	OperationID        string             `json:"operationId"`
	Kind               lifecycleKind      `json:"kind"`
	SubjectID          string             `json:"subjectId"`
	RequestFingerprint string             `json:"requestFingerprint"`
	Status             lifecycleJobStatus `json:"status"`
	HTTPStatus         int                `json:"httpStatus"`
	PublicMessage      string             `json:"publicMessage"`
	CreatedAt          time.Time          `json:"createdAt"`
	UpdatedAt          time.Time          `json:"updatedAt"`
}

type durableOperationDocument struct {
	Version    int                      `json:"version"`
	Operations []durableOperationRecord `json:"operations"`
}

type durableOperationStore struct {
	mu         sync.Mutex
	path       string
	maxEntries int
	retention  time.Duration
	operations map[string]durableOperationRecord
	now        func() time.Time
}

func openDurableOperationStore(path string, maxEntries int, retention time.Duration) (*durableOperationStore, error) {
	if path == "" {
		return nil, errors.New("durable operation store path is empty")
	}
	if maxEntries <= 0 {
		return nil, errors.New("durable operation store capacity must be positive")
	}
	if retention <= 0 {
		return nil, errors.New("durable operation terminal retention must be positive")
	}
	store := &durableOperationStore{
		path:       path,
		maxEntries: maxEntries,
		retention:  retention,
		operations: make(map[string]durableOperationRecord),
		now:        time.Now,
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open durable operation store: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var document durableOperationDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode durable operation store: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode durable operation store: %w", err)
	}
	if document.Version != durableOperationStoreVersion {
		return nil, fmt.Errorf("unsupported durable operation store version %d", document.Version)
	}
	if document.Operations == nil {
		return nil, errors.New("durable operation store operations are missing")
	}
	if len(document.Operations) > maxEntries {
		return nil, fmt.Errorf("durable operation store contains %d records, maximum is %d", len(document.Operations), maxEntries)
	}
	for _, record := range document.Operations {
		if err := validateDurableOperationRecord(record); err != nil {
			return nil, fmt.Errorf("invalid durable operation record: %w", err)
		}
		if _, exists := store.operations[record.OperationID]; exists {
			return nil, fmt.Errorf("duplicate durable operation id %q", record.OperationID)
		}
		store.operations[record.OperationID] = record
	}

	now := store.currentTimeLocked()
	pruned := cloneDurableOperations(store.operations)
	if pruneExpiredDurableOperations(pruned, now, retention) {
		if err := store.persistLocked(pruned); err != nil {
			return nil, fmt.Errorf("prune durable operation store: %w", err)
		}
		store.operations = pruned
	}
	return store, nil
}

// Reserve durably creates an operation. An identical reservation replays the
// existing record; reusing an id for a different request is rejected.
func (s *durableOperationStore) Reserve(record durableOperationRecord) (durableOperationRecord, bool, error) {
	if s == nil {
		return durableOperationRecord{}, false, errors.New("durable operation store unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.operations[record.OperationID]; ok {
		if existing.Kind != record.Kind || existing.SubjectID != record.SubjectID || existing.RequestFingerprint != record.RequestFingerprint {
			return durableOperationRecord{}, false, errLifecycleOperationConflict
		}
		return existing, true, nil
	}

	now := s.currentTimeLocked().UTC()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = record.CreatedAt
	}
	if err := validateDurableOperationRecord(record); err != nil {
		return durableOperationRecord{}, false, err
	}

	next := cloneDurableOperations(s.operations)
	pruneExpiredDurableOperations(next, now, s.retention)
	if len(next) >= s.maxEntries {
		return durableOperationRecord{}, false, errLifecycleJobCapacity
	}
	next[record.OperationID] = record
	if err := s.persistLocked(next); err != nil {
		return durableOperationRecord{}, false, err
	}
	s.operations = next
	return record, false, nil
}

// Transition durably changes a non-terminal operation state.
func (s *durableOperationStore) Transition(operationID string, status lifecycleJobStatus, httpStatus int, publicMessage string) (durableOperationRecord, error) {
	if s == nil {
		return durableOperationRecord{}, errors.New("durable operation store unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.operations[operationID]
	if !ok {
		return durableOperationRecord{}, os.ErrNotExist
	}
	if isTerminalLifecycleJob(record.Status) {
		if record.Status == status && record.HTTPStatus == httpStatus && record.PublicMessage == publicMessage {
			return record, nil
		}
		return durableOperationRecord{}, errors.New("durable operation is already terminal")
	}
	record.Status = status
	record.HTTPStatus = httpStatus
	record.PublicMessage = publicMessage
	record.UpdatedAt = s.currentTimeLocked().UTC()
	if err := validateDurableOperationRecord(record); err != nil {
		return durableOperationRecord{}, err
	}
	next := cloneDurableOperations(s.operations)
	pruneExpiredDurableOperations(next, record.UpdatedAt, s.retention)
	next[operationID] = record
	if err := s.persistLocked(next); err != nil {
		return durableOperationRecord{}, err
	}
	s.operations = next
	return record, nil
}

func (s *durableOperationStore) Lookup(operationID string) (durableOperationRecord, bool) {
	if s == nil {
		return durableOperationRecord{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.operations[operationID]
	return record, ok
}

// Recover reconciles unfinished records after restart. The operation linked to
// the surviving lifecycle journal remains recoverable; all other unfinished
// work is safe to cancel because no durable mutation boundary was crossed.
func (s *durableOperationStore) Recover(journalOperationID string) error {
	if s == nil {
		return errors.New("durable operation store unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.currentTimeLocked().UTC()
	next := cloneDurableOperations(s.operations)
	changed := pruneExpiredDurableOperations(next, now, s.retention)
	for id, record := range next {
		if isTerminalLifecycleJob(record.Status) {
			continue
		}
		if journalOperationID != "" && id == journalOperationID {
			record.Status = lifecycleJobRecoveryRequired
			record.HTTPStatus = http.StatusAccepted
			record.PublicMessage = durableOperationRecoveryMessage
		} else {
			record.Status = lifecycleJobCancelled
			record.HTTPStatus = http.StatusConflict
			record.PublicMessage = durableOperationRestartMessage
		}
		record.UpdatedAt = now
		if err := validateDurableOperationRecord(record); err != nil {
			return err
		}
		next[id] = record
		changed = true
	}
	if !changed {
		return nil
	}
	if err := s.persistLocked(next); err != nil {
		return err
	}
	s.operations = next
	return nil
}

func (s *durableOperationStore) currentTimeLocked() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

func (s *durableOperationStore) persistLocked(operations map[string]durableOperationRecord) error {
	document := durableOperationDocument{Version: durableOperationStoreVersion, Operations: make([]durableOperationRecord, 0, len(operations))}
	for _, record := range operations {
		document.Operations = append(document.Operations, record)
	}
	data, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode durable operation store: %w", err)
	}
	data = append(data, '\n')
	if err := writeDurableOperationFile(s.path, data); err != nil {
		return fmt.Errorf("persist durable operation store: %w", err)
	}
	return nil
}

func writeDurableOperationFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".deployer-operations-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func validateDurableOperationRecord(record durableOperationRecord) error {
	if !lifecycleJobIDRe.MatchString(record.OperationID) {
		return errors.New("operation id must be 32 lowercase hexadecimal characters")
	}
	if record.Kind != lifecycleKindCreate && record.Kind != lifecycleKindClose && record.Kind != lifecycleKindReset {
		return errors.New("operation kind is invalid")
	}
	if record.SubjectID == "" || len(record.SubjectID) > maxPublicServerIDLength || !serverIDRe.MatchString(record.SubjectID) {
		return errors.New("operation subject id is invalid")
	}
	if !durableOperationFingerprintRe.MatchString(record.RequestFingerprint) {
		return errors.New("request fingerprint must be 64 lowercase hexadecimal characters")
	}
	if !isDurableOperationStatus(record.Status) {
		return errors.New("operation status is invalid")
	}
	if record.HTTPStatus != 0 && (record.HTTPStatus < 100 || record.HTTPStatus > 599) {
		return errors.New("operation HTTP status is invalid")
	}
	if err := validateDurableOperationMessage(record.PublicMessage); err != nil {
		return err
	}
	if record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() || record.UpdatedAt.Before(record.CreatedAt) {
		return errors.New("operation timestamps are invalid")
	}
	return nil
}

func validateDurableOperationMessage(message string) error {
	if !utf8.ValidString(message) {
		return errors.New("public message is not valid UTF-8")
	}
	if utf8.RuneCountInString(message) > durableOperationMessageLimit {
		return fmt.Errorf("public message exceeds %d characters", durableOperationMessageLimit)
	}
	for _, r := range message {
		if unicode.IsControl(r) {
			return errors.New("public message contains control characters")
		}
	}
	return nil
}

func isDurableOperationStatus(status lifecycleJobStatus) bool {
	switch status {
	case lifecycleJobPending, lifecycleJobRunning, lifecycleJobRecoveryRequired, lifecycleJobSucceeded, lifecycleJobFailed, lifecycleJobCancelled:
		return true
	default:
		return false
	}
}

func pruneExpiredDurableOperations(operations map[string]durableOperationRecord, now time.Time, retention time.Duration) bool {
	changed := false
	for id, record := range operations {
		if !isTerminalLifecycleJob(record.Status) || now.Before(record.UpdatedAt.Add(retention)) {
			continue
		}
		delete(operations, id)
		changed = true
	}
	return changed
}

func cloneDurableOperations(source map[string]durableOperationRecord) map[string]durableOperationRecord {
	cloned := make(map[string]durableOperationRecord, len(source))
	for id, record := range source {
		cloned[id] = record
	}
	return cloned
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
