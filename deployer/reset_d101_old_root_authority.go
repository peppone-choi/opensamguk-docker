package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101native"
)

// Native presence is independent of D101 supplier availability. Missing D101
// inputs deny only D101 paths; genuinely absent owner preserves normal startup.
type resetD101RootOwnerState int32

const (
	resetD101RootOwnerAbsent resetD101RootOwnerState = iota
	resetD101RootOwnerPresent
	resetD101RootOwnerUnknown
)

type resetD101RootOwnerGate struct {
	state  atomic.Int32
	frozen atomic.Bool
	// Immutable after publication under coordinator -> jobs -> store locks.
	preparation *operationPreparation
}

func (g *resetD101RootOwnerGate) blocksAdmission() bool {
	return g != nil && resetD101RootOwnerState(g.state.Load()) != resetD101RootOwnerAbsent
}
func (g *resetD101RootOwnerGate) blocksMutation() bool {
	return g != nil && (g.frozen.Load() || resetD101RootOwnerState(g.state.Load()) == resetD101RootOwnerUnknown)
}
func (g *resetD101RootOwnerGate) blocksPromotion(p *operationPreparation) bool {
	return g.blocksAdmission() && (g.blocksMutation() || g.preparation != p)
}
func resetD101RootOwnerPath(servers string) string {
	return filepath.Join(servers, ".deployer-d101-native-owner")
}

// An observed unresolved owner cannot become absent merely because its path
// disappears. No create/open/chmod/prune/authentication occurs during this probe.
func probeResetD101RootOwner(path string, unresolved bool) resetD101RootOwnerState {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return resetD101RootOwnerUnknown
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := "/"
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if unresolved {
				return resetD101RootOwnerUnknown
			}
			return resetD101RootOwnerAbsent
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return resetD101RootOwnerUnknown
		}
		if i < len(parts)-1 {
			if !info.IsDir() {
				return resetD101RootOwnerUnknown
			}
			continue
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 || info.Mode().Perm() != 0400 {
			return resetD101RootOwnerUnknown
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || st.Nlink != 1 {
			return resetD101RootOwnerUnknown
		}
		return resetD101RootOwnerPresent
	}
	return resetD101RootOwnerUnknown
}
func resetD101RootStartupOwner(servers string, unresolved bool) error {
	if probeResetD101RootOwner(resetD101RootOwnerPath(servers), unresolved) != resetD101RootOwnerAbsent {
		return errResetExecutionEvidence
	}
	return nil
}

type resetD101RootExpected struct {
	binding                             d101native.PreBinding
	process                             d101native.Process
	imageDigest                         string
	storePin                            d101custody.NativeFilePin
	marker, journal                     resetD101RootPathExpected
	ownerParentDevice, ownerParentInode uint64
}

// These fields are local private authenticated input, not request JSON or a
// decoded owner document. Real human/purpose/source/Root delivery is mandatory.
type resetD101RootAuthentication struct {
	expected resetD101RootExpected
	original []byte
}
type resetD101RootSource interface {
	AuthenticateRoot(context.Context, *config, []byte) (*resetD101RootAuthentication, error)
	RecheckRoot(context.Context, *config, *resetD101RootAuthentication) error
}
type resetD101OldRootProducer struct {
	configuration *config
	coordinator   *operationCoordinator
	jobs          *lifecycleJobManager
	store         *durableOperationStore
	source        resetD101RootSource
	busy          atomic.Bool
}

func registerResetD101OldRoot(c *config, source resetD101RootSource) *resetD101OldRootProducer {
	if c == nil || c.operations == nil || c.lifecycleJobs == nil || c.lifecycleOperationStore == nil {
		return nil
	}
	return &resetD101OldRootProducer{configuration: c, coordinator: c.operations, jobs: c.lifecycleJobs, store: c.lifecycleOperationStore, source: source}
}
func (p *resetD101OldRootProducer) objectsMatch() bool {
	return p != nil && p.configuration != nil && p.coordinator != nil && p.jobs != nil && p.store != nil && p.configuration.operations == p.coordinator && p.configuration.lifecycleJobs == p.jobs && p.configuration.lifecycleOperationStore == p.store && p.coordinator.jobs == p.jobs
}
func resetD101CurrentRootProcess(expected d101native.Process) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || uint32(os.Getpid()) != expected.PID || rootBuiltSourceSHA != expected.SourceSHA || !d101native.ValidProcess(expected) {
		return errResetExecutionEvidence
	}
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return errResetExecutionEvidence
	}
	start, err := resetD101RootStartTicks(raw)
	if err != nil || start != expected.StartTicks {
		return errResetExecutionEvidence
	}
	parent, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(expected.ParentPID), 10) + "/stat")
	if err != nil {
		return errResetExecutionEvidence
	}
	parentStart, err := resetD101RootStartTicks(parent)
	if err != nil || uint32(os.Getppid()) != expected.ParentPID || parentStart != expected.ParentStartTicks {
		return errResetExecutionEvidence
	}
	actualPath, err := os.Readlink("/proc/self/exe")
	if err != nil || actualPath != expected.ExePath {
		return errResetExecutionEvidence
	}
	exe, err := os.Open("/proc/self/exe")
	if err != nil {
		return errResetExecutionEvidence
	}
	defer exe.Close()
	info, err := exe.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > 64<<20 {
		return errResetExecutionEvidence
	}
	body, err := io.ReadAll(io.LimitReader(exe, info.Size()+1))
	defer clear(body)
	if err != nil || int64(len(body)) != info.Size() || resetD101OriginalSHA(body) != expected.ExeSHA256 {
		return errResetExecutionEvidence
	}
	after, err := exe.Stat()
	if err != nil || !os.SameFile(info, after) || after.ModTime() != info.ModTime() {
		return errResetExecutionEvidence
	}
	return nil
}
func resetD101RootStartTicks(raw []byte) (uint64, error) {
	end := strings.LastIndex(string(raw), ") ")
	if end < 0 {
		return 0, errResetExecutionEvidence
	}
	fields := strings.Fields(string(raw[end+2:]))
	if len(fields) < 20 {
		return 0, errResetExecutionEvidence
	}
	v, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || v == 0 {
		return 0, errResetExecutionEvidence
	}
	return v, nil
}

// Holding the store uses its existing root:0600 representation, never chmods or
// invokes openDurableOperationStore/Recover. All I/O occurs outside map mutexes.
type resetD101RootHeldStore struct {
	file *os.File
	wire []byte
	pin  d101custody.NativeFilePin
	path string
}

func holdResetD101RootStore(path string, want d101custody.NativeFilePin) (*resetD101RootHeldStore, error) {
	if !filepath.IsAbs(path) || want.OwnerUID != 0 || want.FileMode != 0600 || want.LinkCount != 1 || want.Snapshot.ByteLength == 0 || want.Snapshot.ByteLength > 16<<20 {
		return nil, errResetExecutionEvidence
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	h := &resetD101RootHeldStore{file: file, path: path, pin: want}
	fail := func() (*resetD101RootHeldStore, error) { file.Close(); return nil, errResetExecutionEvidence }
	h.wire = make([]byte, want.Snapshot.ByteLength)
	if _, err = file.ReadAt(h.wire, 0); err != nil {
		return fail()
	}
	if h.recheck() != nil {
		return fail()
	}
	return h, nil
}
func (h *resetD101RootHeldStore) recheck() error {
	if h == nil || h.file == nil {
		return errResetExecutionEvidence
	}
	fd, e1 := h.file.Stat()
	named, e2 := os.Lstat(h.path)
	parent, e3 := os.Lstat(filepath.Dir(h.path))
	if e1 != nil || e2 != nil || e3 != nil || !os.SameFile(fd, named) || named.Mode()&os.ModeSymlink != 0 || !fd.Mode().IsRegular() || fd.Size() != int64(len(h.wire)) || fd.Mode().Perm() != 0600 {
		return errResetExecutionEvidence
	}
	st, ok := fd.Sys().(*syscall.Stat_t)
	ps, ok2 := parent.Sys().(*syscall.Stat_t)
	if !ok || !ok2 || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || st.Nlink != 1 {
		return errResetExecutionEvidence
	}
	pin := d101custody.NativeFilePin{SHA256: resetD101OriginalSHA(h.wire), Snapshot: d101custody.PrivateSnapshot{Device: uint64(st.Dev), Inode: uint64(st.Ino), ByteLength: uint64(fd.Size()), ModifiedAtUnixNano: fd.ModTime().UnixNano()}, OwnerUID: st.Uid, FileMode: uint32(fd.Mode().Perm()), LinkCount: uint64(st.Nlink), ParentSnapshot: d101custody.PrivateSnapshot{Device: uint64(ps.Dev), Inode: uint64(ps.Ino), ByteLength: uint64(parent.Size()), ModifiedAtUnixNano: parent.ModTime().UnixNano()}, ParentOwnerUID: ps.Uid, ParentMode: uint32(parent.Mode().Perm())}
	if pin != h.pin {
		return errResetExecutionEvidence
	}
	now := make([]byte, len(h.wire))
	defer clear(now)
	if _, err := h.file.ReadAt(now, 0); err != nil || !bytes.Equal(now, h.wire) {
		return errResetExecutionEvidence
	}
	return nil
}
func (p *resetD101OldRootProducer) authenticate(ctx context.Context, request []byte) (*resetD101RootAuthentication, error) {
	if ctx == nil || ctx.Err() != nil || !p.objectsMatch() || d101native.Missing(p.source) {
		return nil, errResetD101InstallationNotSupplied
	}
	a, err := p.source.AuthenticateRoot(ctx, p.configuration, bytes.Clone(request))
	if err != nil || a == nil || len(a.original) == 0 || !d101native.ValidBinding(a.expected.binding) || !strings.HasPrefix(a.expected.imageDigest, "sha256:") || !d101native.ValidSHA(strings.TrimPrefix(a.expected.imageDigest, "sha256:")) || resetD101CurrentRootProcess(a.expected.process) != nil || p.source.RecheckRoot(ctx, p.configuration, a) != nil || ctx.Err() != nil || !p.objectsMatch() {
		return nil, errResetExecutionEvidence
	}
	a.original = bytes.Clone(a.original)
	return a, nil
}

// Admission close is a real owner transition; it does not cancel existing work.
// Publish only immutable gate pointers while locks are held. Durable I/O and
// actual authentication occur before/after these locks, never inside them.
func (p *resetD101OldRootProducer) closeAdmission(ctx context.Context, a *resetD101RootAuthentication) error {
	if !p.objectsMatch() || a == nil || d101native.Missing(p.source) || p.source.RecheckRoot(ctx, p.configuration, a) != nil {
		return errResetExecutionEvidence
	}
	gate := &resetD101RootOwnerGate{}
	gate.state.Store(int32(resetD101RootOwnerPresent))
	c, j, s := p.coordinator, p.jobs, p.store
	c.mu.Lock()
	j.mu.Lock()
	s.mu.Lock()
	if !p.objectsMatch() || c.d101NativeOwner.blocksAdmission() || j.d101NativeOwner.blocksAdmission() || s.d101NativeOwner.blocksAdmission() {
		s.mu.Unlock()
		j.mu.Unlock()
		c.mu.Unlock()
		return errResetExecutionEvidence
	}
	gate.preparation = c.preparing
	c.d101NativeOwner = gate
	j.d101NativeOwner = gate
	s.d101NativeOwner = gate
	c.cond.Broadcast()
	s.mu.Unlock()
	j.mu.Unlock()
	c.mu.Unlock()
	fail := func() error { gate.state.Store(int32(resetD101RootOwnerUnknown)); return errResetExecutionEvidence }
	path := resetD101RootOwnerPath(p.configuration.serversDir)
	dir, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fail()
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return fail()
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || uint64(st.Dev) != a.expected.ownerParentDevice || uint64(st.Ino) != a.expected.ownerParentInode || info.Mode().Perm()&0022 != 0 {
		return fail()
	}
	// Owner data is factual and contains only the authenticated original ref/hash.
	wire, err := json.Marshal(struct {
		SchemaVersion     uint32             `json:"schemaVersion"`
		Kind              string             `json:"kind"`
		OperationID       string             `json:"operationId"`
		TargetSHA         string             `json:"targetFingerprint"`
		Revision          string             `json:"publicationRevision"`
		Root              d101native.Process `json:"root"`
		Image             string             `json:"imageDigest"`
		AuthenticationSHA string             `json:"authenticationSha256"`
	}{1, "D101_ROOT_ADMISSION_OWNER", a.expected.binding.OperationID, a.expected.binding.TargetFingerprint, a.expected.binding.PublicationRevision, a.expected.process, a.expected.imageDigest, resetD101OriginalSHA(a.original)})
	if err != nil {
		return fail()
	}
	file, err := openResetD101RootOwnerAt(dir, filepath.Base(path))
	if err != nil {
		return fail()
	}
	defer file.Close()
	if n, err := file.Write(wire); err != nil || n != len(wire) || file.Sync() != nil || dir.Sync() != nil {
		return fail()
	}
	held, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fail()
	}
	defer held.Close()
	readback, err := io.ReadAll(io.LimitReader(held, int64(len(wire))+1))
	issued, ierr := file.Stat()
	named, nerr := os.Lstat(path)
	parentNow, perr := os.Lstat(filepath.Dir(path))
	if ierr != nil || nerr != nil || perr != nil || !os.SameFile(issued, named) || !os.SameFile(info, parentNow) || probeResetD101RootOwner(path, false) != resetD101RootOwnerPresent {
		return fail()
	}
	if err != nil || !bytes.Equal(readback, wire) || p.source.RecheckRoot(ctx, p.configuration, a) != nil || ctx.Err() != nil || resetD101CurrentRootProcess(a.expected.process) != nil {
		return fail()
	}
	return nil
}
func (p *resetD101OldRootProducer) freezeMaps() error {
	if !p.objectsMatch() {
		return errResetExecutionEvidence
	}
	c, j, s := p.coordinator, p.jobs, p.store
	c.mu.Lock()
	j.mu.Lock()
	s.mu.Lock()
	defer c.mu.Unlock()
	defer j.mu.Unlock()
	defer s.mu.Unlock()
	g := c.d101NativeOwner
	if !p.objectsMatch() || g == nil || g != j.d101NativeOwner || g != s.d101NativeOwner || resetD101RootOwnerState(g.state.Load()) != resetD101RootOwnerPresent || c.active != nil || c.preparing != nil || c.preparationSettlementPending || c.journalPending || len(s.deferredTransitions) != 0 {
		return errResetExecutionEvidence
	}
	for _, job := range j.jobs {
		if !isTerminalLifecycleJob(job.status) {
			return errResetExecutionEvidence
		}
	}
	for _, op := range s.operations {
		if !isTerminalLifecycleJob(op.Status) {
			return errResetExecutionEvidence
		}
	}
	g.frozen.Store(true)
	return nil
}

type resetD101RootJobData struct {
	ID              string             `json:"id"`
	Status          lifecycleJobStatus `json:"status"`
	FinishedAt      time.Time          `json:"finishedAt"`
	OperationID     string             `json:"operationId"`
	Fingerprint     string             `json:"fingerprint"`
	Kind            lifecycleKind      `json:"kind"`
	SubjectID       string             `json:"subjectId"`
	HTTPStatus      int                `json:"httpStatus"`
	PublicMessage   string             `json:"publicMessage"`
	Result          json.RawMessage    `json:"result"`
	HasCancel       bool               `json:"hasCancel"`
	CancelRequested bool               `json:"cancelRequested"`
}
type resetD101RootPreparationData struct {
	Kind                  lifecycleKind `json:"kind"`
	OperationID           string        `json:"operationId"`
	SubjectID             string        `json:"subjectId"`
	Fingerprint           string        `json:"fingerprint"`
	LeaseAttemptSHA       string        `json:"leaseAttemptSha"`
	AdmissionErrorPresent bool          `json:"admissionErrorPresent"`
	ContextStopped        bool          `json:"contextStopped"`
}
type resetD101RootMaintenanceData struct {
	TokenSHA    string `json:"tokenSha"`
	OperationID string `json:"operationId"`
	JobID       string `json:"jobId"`
	Consumed    bool   `json:"consumed"`
}
type resetD101RootUnverifiedHeap struct {
	Binding               d101native.PreBinding             `json:"binding"`
	RootProcess           d101native.Process                `json:"rootProcess"`
	ImageDigest           string                            `json:"imageDigest"`
	AuthenticationSHA     string                            `json:"authenticationSha256"`
	StartedAt             time.Time                         `json:"startedAt"`
	EndedAt               time.Time                         `json:"endedAt"`
	CoordinatorClosed     bool                              `json:"coordinatorClosed"`
	NativeOwnerState      int32                             `json:"nativeOwnerState"`
	NativeOwnerFrozen     bool                              `json:"nativeOwnerFrozen"`
	MarkerOriginal        resetD101RootPathData             `json:"markerOriginal"`
	JournalOriginal       resetD101RootPathData             `json:"journalOriginal"`
	JournalPending        bool                              `json:"journalPending"`
	SettlementPending     bool                              `json:"settlementPending"`
	ActiveJobIDs          []string                          `json:"activeJobIds"`
	ActiveContextsStopped []bool                            `json:"activeContextsStopped"`
	Preparations          []resetD101RootPreparationData    `json:"preparations"`
	Maintenance           []resetD101RootMaintenanceData    `json:"maintenance"`
	Jobs                  map[string]resetD101RootJobData   `json:"jobs"`
	OperationJobs         map[string]string                 `json:"operationJobs"`
	Store                 map[string]durableOperationRecord `json:"store"`
	Deferred              map[string]durableOperationRecord `json:"deferred"`
	JobsMaxEntries        int                               `json:"jobsMaxEntries"`
	JobsRetentionNanos    int64                             `json:"jobsRetentionNanos"`
	StoreMaxEntries       int                               `json:"storeMaxEntries"`
	StoreRetentionNanos   int64                             `json:"storeRetentionNanos"`
	StorePath             string                            `json:"storePath"`
	MarkerPath            string                            `json:"markerPath"`
	JournalPath           string                            `json:"journalPath"`
}

func hashResetD101RootTransport(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Called only on the live *config owned by actual main's registered handler.
// Uses actual maps; never constructs a fresh manager/store/coordinator.
// No lookup/prune/Reserve/Recover/cancel/maintenance entry, file writes or I/O.
// Native identity, durable owner, held marker/journal/store FD originals, and
// independently authenticated delivery must surround this data-only capture.
// Atomic map order: coordinator -> jobs -> store. No external calls while held.
func captureResetD101ExistingRootHeapUnverified(ctx context.Context, c *config) (resetD101RootUnverifiedHeap, error) {
	deny := func() (resetD101RootUnverifiedHeap, error) {
		return resetD101RootUnverifiedHeap{}, errResetExecutionEvidence
	}
	if ctx == nil || ctx.Err() != nil || c == nil || c.operations == nil || c.lifecycleJobs == nil || c.lifecycleOperationStore == nil {
		return deny()
	}
	coord, jobs, store := c.operations, c.lifecycleJobs, c.lifecycleOperationStore
	started := time.Now().UTC()
	coord.mu.Lock()
	defer coord.mu.Unlock()
	jobs.mu.Lock()
	defer jobs.mu.Unlock()
	store.mu.Lock()
	defer store.mu.Unlock()
	if ctx.Err() != nil || coord.jobs != jobs || coord.markerPath != c.maintenanceFile || coord.journalPath != c.lifecycleJournalFile || store.path == "" {
		return deny()
	}
	v := resetD101RootUnverifiedHeap{StartedAt: started, CoordinatorClosed: coord.closed, JournalPending: coord.journalPending, SettlementPending: coord.preparationSettlementPending,
		ActiveJobIDs: []string{}, ActiveContextsStopped: []bool{}, Preparations: []resetD101RootPreparationData{}, Maintenance: []resetD101RootMaintenanceData{},
		Jobs: make(map[string]resetD101RootJobData, len(jobs.jobs)), OperationJobs: make(map[string]string, len(jobs.operationJobs)), Store: make(map[string]durableOperationRecord, len(store.operations)), Deferred: make(map[string]durableOperationRecord, len(store.deferredTransitions)),
		JobsMaxEntries: jobs.maxEntries, JobsRetentionNanos: int64(jobs.terminalRetention), StoreMaxEntries: store.maxEntries, StoreRetentionNanos: int64(store.retention), StorePath: store.path, MarkerPath: coord.markerPath, JournalPath: coord.journalPath}
	if g := coord.d101NativeOwner; g != nil {
		if g != jobs.d101NativeOwner || g != store.d101NativeOwner {
			return deny()
		}
		v.NativeOwnerState = g.state.Load()
		v.NativeOwnerFrozen = g.frozen.Load()
	} else if jobs.d101NativeOwner != nil || store.d101NativeOwner != nil {
		return deny()
	}
	if a := coord.active; a != nil {
		if a.coordinator != coord || a.ctx == nil {
			return deny()
		}
		v.ActiveJobIDs = append(v.ActiveJobIDs, a.jobID)
		v.ActiveContextsStopped = append(v.ActiveContextsStopped, a.ctx.Err() != nil)
	}
	if p := coord.preparing; p != nil {
		if p.coordinator != coord || p.ctx == nil {
			return deny()
		}
		v.Preparations = append(v.Preparations, resetD101RootPreparationData{p.kind, p.operationID, p.subjectID, p.fingerprint, hashResetD101RootTransport(p.leaseAttempt), p.admissionErr != nil, p.ctx.Err() != nil})
	}
	if m := coord.maintenanceLease; m != nil {
		v.Maintenance = append(v.Maintenance, resetD101RootMaintenanceData{hashResetD101RootTransport(m.token), m.operationID, m.jobID, m.consumed})
	}
	for id, j := range jobs.jobs {
		// Existing raw result is retained privately; no config/JWT/token export.
		// A zero-length result is represented by an empty byte string in the
		// final private exact payload; null/optional fields are not authority.
		body := append(json.RawMessage(nil), j.result...)
		if len(body) > 0 && !json.Valid(body) {
			return deny()
		}
		v.Jobs[id] = resetD101RootJobData{j.id, j.status, j.finishedAt, j.operationID, j.operationFingerprint, j.kind, j.subjectID, j.httpStatus, j.publicMessage, body, j.cancel != nil, j.cancelRequested}
	}
	for id, job := range jobs.operationJobs {
		v.OperationJobs[id] = job
	}
	for id, record := range store.operations {
		v.Store[id] = record
	}
	for id, record := range store.deferredTransitions {
		v.Deferred[id] = record
	}
	v.EndedAt = time.Now().UTC()
	if ctx.Err() != nil {
		return deny()
	}
	return v, nil
}

// Entire live maps are returned as private data only, never as public authority.
func (p *resetD101OldRootProducer) capture(ctx context.Context, a *resetD101RootAuthentication) (resetD101RootUnverifiedHeap, error) {
	deny := func() (resetD101RootUnverifiedHeap, error) {
		return resetD101RootUnverifiedHeap{}, errResetExecutionEvidence
	}
	if a == nil || !p.objectsMatch() || d101native.Missing(p.source) || ctx == nil || ctx.Err() != nil || resetD101CurrentRootProcess(a.expected.process) != nil || p.source.RecheckRoot(ctx, p.configuration, a) != nil {
		return deny()
	}
	held, err := holdResetD101RootStore(p.store.path, a.expected.storePin)
	if err != nil {
		return deny()
	}
	defer held.file.Close()
	defer clear(held.wire)
	marker, err := holdResetD101RootPath(p.configuration.maintenanceFile, a.expected.marker)
	if err != nil {
		return deny()
	}
	defer marker.close()
	journal, err := holdResetD101RootPath(p.configuration.lifecycleJournalFile, a.expected.journal)
	if err != nil {
		return deny()
	}
	defer journal.close()
	first, err := captureResetD101ExistingRootHeapUnverified(ctx, p.configuration)
	if err != nil || !p.objectsMatch() || held.recheck() != nil || marker.recheck() != nil || journal.recheck() != nil || resetD101CurrentRootProcess(a.expected.process) != nil || p.source.RecheckRoot(ctx, p.configuration, a) != nil {
		return deny()
	}
	second, err := captureResetD101ExistingRootHeapUnverified(ctx, p.configuration)
	if err != nil || !p.objectsMatch() || held.recheck() != nil || marker.recheck() != nil || journal.recheck() != nil || resetD101CurrentRootProcess(a.expected.process) != nil || p.source.RecheckRoot(ctx, p.configuration, a) != nil || ctx.Err() != nil {
		return deny()
	}
	// Capture timestamps differ; every actual map/lease/store/config datum must not.
	second.StartedAt = first.StartedAt
	second.EndedAt = first.EndedAt
	if !reflect.DeepEqual(first, second) {
		return deny()
	}
	var document durableOperationDocument
	if decodeResetPrivateJSON(held.wire, &document) != nil || document.Version != durableOperationStoreVersion || len(document.Operations) != len(first.Store) {
		return deny()
	}
	for _, op := range document.Operations {
		actual, ok := first.Store[op.OperationID]
		if !ok || actual != op {
			return deny()
		}
	}
	first.Binding = a.expected.binding
	first.RootProcess = a.expected.process
	first.ImageDigest = a.expected.imageDigest
	first.AuthenticationSHA = resetD101OriginalSHA(a.original)
	first.MarkerOriginal = marker.data()
	first.JournalOriginal = journal.data()
	return first, nil
}
func (p *resetD101OldRootProducer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost || p == nil || d101native.Missing(p.source) || !p.busy.CompareAndSwap(false, true) {
			writeJSON(w, 503, errorResponse{Error: "native Root producer unavailable"})
			return
		}
		defer p.busy.Store(false)
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
		defer clear(body)
		if err != nil || len(body) == 0 || len(body) > 64<<10 {
			writeJSON(w, 503, errorResponse{Error: "native Root request unavailable"})
			return
		}
		a, err := p.authenticate(r.Context(), body)
		if err != nil {
			writeJSON(w, 503, errorResponse{Error: "native Root authority unavailable"})
			return
		}
		defer clear(a.original)
		// Request action is carried by actual authenticated private source. The
		// owner transition is once; later captures preserve the same current owner.
		if !p.coordinator.nativeAdmissionBlocked() {
			if p.closeAdmission(r.Context(), a) != nil {
				writeJSON(w, 503, errorResponse{Error: "native Root admission HOLD"})
				return
			}
		}
		fresh, err := p.authenticate(r.Context(), body)
		if err != nil || fresh.expected.binding != a.expected.binding || fresh.expected.process != a.expected.process || fresh.expected.imageDigest != a.expected.imageDigest {
			writeJSON(w, 503, errorResponse{Error: "native Root source changed"})
			return
		}
		clear(a.original)
		a = fresh
		defer clear(fresh.original)
		if p.freezeMaps() != nil {
			writeJSON(w, 503, errorResponse{Error: "native Root not drained"})
			return
		}
		heap, err := p.capture(r.Context(), a)
		if err != nil {
			writeJSON(w, 503, errorResponse{Error: "native Root capture HOLD"})
			return
		}
		wire, err := json.Marshal(heap)
		if err != nil || len(wire) > 64<<10 || !p.objectsMatch() || resetD101CurrentRootProcess(a.expected.process) != nil || p.source.RecheckRoot(r.Context(), p.configuration, a) != nil || r.Context().Err() != nil {
			writeJSON(w, 503, errorResponse{Error: "native Root complete capture exceeds bound"})
			return
		}
		defer clear(wire)
		// Actual source authentication and object/native recheck above are required;
		// transport credentials are additional gates, never the producer authority.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(wire)
	}
}

// Presence/absence and the parent native identity are independently supplied.
// Absent journal/marker is an observed fact, never an empty synthetic original.
type resetD101RootPathExpected struct {
	present                   bool
	pin                       d101custody.NativeFilePin
	parentDevice, parentInode uint64
	parentUID, parentMode     uint32
}
type resetD101RootPathData struct {
	Present  bool                      `json:"present"`
	Original []byte                    `json:"original"`
	Pin      d101custody.NativeFilePin `json:"pin"`
}
type resetD101RootHeldPath struct {
	path     string
	expected resetD101RootPathExpected
	held     *resetD101RootHeldStore
}

func holdResetD101RootPath(path string, e resetD101RootPathExpected) (*resetD101RootHeldPath, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || e.parentDevice == 0 || e.parentInode == 0 || e.parentUID != 0 || e.parentMode&0022 != 0 {
		return nil, errResetExecutionEvidence
	}
	h := &resetD101RootHeldPath{path: path, expected: e}
	if e.present {
		held, err := holdResetD101RootStore(path, e.pin)
		if err != nil {
			return nil, err
		}
		h.held = held
	}
	if h.recheck() != nil {
		h.close()
		return nil, errResetExecutionEvidence
	}
	return h, nil
}
func (h *resetD101RootHeldPath) recheck() error {
	if h == nil {
		return errResetExecutionEvidence
	}
	parent, err := os.Lstat(filepath.Dir(h.path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return errResetExecutionEvidence
	}
	st, ok := parent.Sys().(*syscall.Stat_t)
	e := h.expected
	if !ok || uint64(st.Dev) != e.parentDevice || uint64(st.Ino) != e.parentInode || st.Uid != e.parentUID || uint32(parent.Mode().Perm()) != e.parentMode {
		return errResetExecutionEvidence
	}
	if e.present {
		if h.held == nil {
			return errResetExecutionEvidence
		}
		return h.held.recheck()
	}
	_, err = os.Lstat(h.path)
	if !os.IsNotExist(err) {
		return errResetExecutionEvidence
	}
	return nil
}
func (h *resetD101RootHeldPath) close() {
	if h != nil && h.held != nil {
		h.held.file.Close()
		clear(h.held.wire)
	}
}
func (h *resetD101RootHeldPath) data() resetD101RootPathData {
	if h == nil || h.held == nil {
		return resetD101RootPathData{Original: []byte{}}
	}
	return resetD101RootPathData{true, bytes.Clone(h.held.wire), h.held.pin}
}

func (g *resetD101RootOwnerGate) allowsPreparationDrain(operationID, fingerprint string, kind lifecycleKind) bool {
	if g == nil {
		return false
	}
	p := g.preparation
	return g != nil && !g.blocksMutation() && p != nil && p.operationID != "" && p.operationID == operationID && p.fingerprint == fingerprint && p.kind == kind
}
func (c *operationCoordinator) nativeMutationBlocked() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.d101NativeOwner.blocksMutation()
}
func (c *operationCoordinator) nativeAdmissionBlocked() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.d101NativeOwner.blocksAdmission()
}
