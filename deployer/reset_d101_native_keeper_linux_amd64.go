//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"opensamguk-deployer/internal/d101native"
	"opensamguk-deployer/internal/d101custody"
)

// Actual preAcquisition and handoff sources are absent until independently
// installed. They cannot use phase12 receipt/final reader as initial authority.
type resetD101NativePreAcquisition struct {
	binding                         d101native.PreBinding
	lockPath, directory             string
	directoryDevice, directoryInode uint64
	approvalOriginal                []byte
	existing                        *resetD101NativeExistingKeeper
	// Routing data must be covered by the actual preAcquisition source's
	// independent original approval/recheck; this string never grants authority.
	physicalMode                    string
}
type resetD101NativeExistingKeeper struct {
	binding         d101native.PreBinding
	peer            d101native.Process
	requestOriginal []byte
}
type resetD101NativePreAcquisitionSource interface {
	AuthenticatePreAcquisition(context.Context, string, bool) (*resetD101NativePreAcquisition, error)
	RecheckPreAcquisition(context.Context, *resetD101NativePreAcquisition) error
	RequestExistingKeeper(context.Context, *resetD101NativeExistingKeeper, bool) error
}
type resetD101NativeStageSource interface {
	CaptureAuthenticatedStage(context.Context, *resetD101NativeKeeper, uint64) (any, error)
	RecheckAuthenticatedStage(context.Context, *resetD101NativeKeeper, uint64, any) error
	AwaitAuthenticatedPhysicalHandoff(context.Context, *resetD101NativeKeeper) error
	AuthenticateLastOwnedHandles(context.Context, *resetD101NativeKeeper, d101native.HeldTerminalDisposition) error
	ObserveActualRelease(context.Context, *resetD101NativeKeeper, d101native.HeldTerminalDisposition) (*resetD101NativeReleaseInputs, error)
}
type resetD101NativeKeeper struct {
	installer                   *resetD101NativeAuthorityInstaller
	pre                         *resetD101NativePreAcquisition
	descriptor, directory       *os.File
	refs                        []d101native.RawRef
	child                       *exec.Cmd
	childStart                  uint64
	childExited                 bool
	attempted, acquired, closed bool
	physicalMode                string
	clientInput                 *d101native.ManagementClientInput
	clientContext               context.Context
	clientCancel                context.CancelFunc
	clientSession               *d101native.ManagementSession
	clientBinding               *d101native.ManagementConnectionBinding
	clientExpected              []byte
	clientCloseOnce             sync.Once
	clientCloseErr              error
}

func resetD101NativeSequenceLeaf(sequence uint64) string {
	leaves := []string{"acquisition.bin", "installed-writer-inventory.bin", "console-admission.bin", "root-admission.bin", "turn-flush.bin", "publisher.bin", "postgres-admission.bin", "old-services.bin", "keeper-session.bin", "writer-freeze-receipt.bin", "final-plan-bound.bin", "issuer-running.bin", "issuer-done.bin", "physical-running.bin", "terminal.bin"}
	if sequence >= uint64(len(leaves)) {
		return ""
	}
	return leaves[sequence]
}
func (k *resetD101NativeKeeper) check(ctx context.Context) error {
	if k == nil || ctx == nil || ctx.Err() != nil || k.pre == nil || k.installer == nil || d101native.Missing(k.installer.preAcquisition) || k.closed || time.Now().Unix() >= k.pre.binding.OriginalCutoffUnix || k.installer.preAcquisition.RecheckPreAcquisition(ctx, k.pre) != nil || resetD101CurrentRootProcess(k.pre.binding.Keeper.Process) != nil {
		return errResetExecutionEvidence
	}
	if k.acquired {
		if k.descriptor == nil || k.descriptor.Fd() != 9 {
			return errResetExecutionEvidence
		}
		fd, e1 := k.descriptor.Stat()
		named, e2 := os.Lstat(k.pre.lockPath)
		if e1 != nil || e2 != nil || !os.SameFile(fd, named) || !fd.Mode().IsRegular() || named.Mode()&os.ModeSymlink != 0 {
			return errResetExecutionEvidence
		}
		st, ok := fd.Sys().(*syscall.Stat_t)
		pin := k.pre.binding.Keeper.Lock
		if !ok || uint64(st.Dev) != pin.Device || uint64(st.Ino) != pin.Inode || st.Uid != pin.OwnerUID || uint32(fd.Mode().Perm()) != pin.Mode || uint64(st.Nlink) != pin.Links {
			return errResetExecutionEvidence
		}
	}
	if k.directory != nil {
		fd, e1 := k.directory.Stat()
		named, e2 := os.Lstat(k.pre.directory)
		if e1 != nil || e2 != nil || !os.SameFile(fd, named) || !fd.IsDir() || fd.Mode().Perm() != 0700 {
			return errResetExecutionEvidence
		}
		st, ok := fd.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || uint64(st.Dev) != k.pre.directoryDevice || uint64(st.Ino) != k.pre.directoryInode {
			return errResetExecutionEvidence
		}
	}
	return nil
}

// Acquire exactly once; never create, truncate, overwrite or reopen the lock.
func (k *resetD101NativeKeeper) acquire(ctx context.Context) error {
	if k.check(ctx) != nil || k.pre.lockPath != "/tmp/opensamguk-production.lock" {
		return errResetExecutionEvidence
	}
	var occupied syscall.Stat_t
	if err := syscall.Fstat(9, &occupied); err == nil || err != syscall.EBADF {
		return errResetExecutionEvidence
	}
	fd, err := syscall.Open(k.pre.lockPath, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	file := os.NewFile(uintptr(fd), "native-keeper-existing-lock")
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return errResetExecutionEvidence
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	p := k.pre.binding.Keeper.Lock
	if !ok || !info.Mode().IsRegular() || uint64(st.Dev) != p.Device || uint64(st.Ino) != p.Inode || st.Uid != p.OwnerUID || uint64(st.Nlink) != p.Links || uint32(info.Mode().Perm()) != p.Mode {
		file.Close()
		return errResetExecutionEvidence
	}
	if fd != 9 {
		if syscall.Fstat(9, &occupied) != syscall.EBADF || syscall.Dup3(fd, 9, 0) != nil {
			file.Close()
			return errResetExecutionEvidence
		}
		file.Close()
		file = os.NewFile(9, "native-keeper-owned-fd9")
	}
	// Busy is definite denial; repeated acquisition or fresh inode is forbidden.
	if syscall.Flock(9, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		file.Close()
		return errResetExecutionEvidence
	}
	k.descriptor = file
	k.acquired = true
	if k.check(ctx) != nil {
		return errResetExecutionEvidence
	}
	return nil
}
func (k *resetD101NativeKeeper) openNamespace(ctx context.Context) error {
	if k.check(ctx) != nil || k.pre.directory != filepath.Join("/etc/opensamguk/d101/current-authority", k.pre.binding.OperationID) {
		return errResetExecutionEvidence
	}
	dir, err := os.OpenFile(k.pre.directory, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	k.directory = dir
	if k.check(ctx) != nil {
		return errResetExecutionEvidence
	}
	return nil
}
func nativeResetD101Ref(file, parent *os.File, path string, wire []byte) (d101native.RawRef, error) {
	info, e1 := file.Stat()
	dir, e2 := parent.Stat()
	named, e3 := os.Lstat(path)
	if e1 != nil || e2 != nil || e3 != nil || !os.SameFile(info, named) || !info.Mode().IsRegular() || info.Size() != int64(len(wire)) || info.Mode().Perm() != 0400 || !dir.IsDir() || dir.Mode().Perm() != 0700 {
		return d101native.RawRef{}, errResetExecutionEvidence
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	ds, ok2 := dir.Sys().(*syscall.Stat_t)
	if !ok || !ok2 || st.Uid != 0 || ds.Uid != 0 || st.Nlink != 1 {
		return d101native.RawRef{}, errResetExecutionEvidence
	}
	return d101native.RawRef{Path: path, Bytes: uint64(len(wire)), SHA256: resetD101OriginalSHA(wire), Native: d101native.NativePin{Device: uint64(st.Dev), Inode: uint64(st.Ino), OwnerUID: st.Uid, Mode: uint32(info.Mode().Perm()), Links: uint64(st.Nlink), ParentDevice: uint64(ds.Dev), ParentInode: uint64(ds.Ino)}}, nil
}
func (k *resetD101NativeKeeper) writeExclusive(ctx context.Context, leaf string, wire []byte) (d101native.RawRef, error) {
	if k.check(ctx) != nil || k.directory == nil || leaf == "" || filepath.Base(leaf) != leaf || len(wire) == 0 || len(wire) > 64<<10 {
		return d101native.RawRef{}, errResetExecutionEvidence
	}
	path := filepath.Join(k.pre.directory, leaf)
	fd, err := syscall.Openat(int(k.directory.Fd()), leaf, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0400)
	if err != nil {
		return d101native.RawRef{}, errResetExecutionEvidence
	}
	k.attempted = true
	file := os.NewFile(uintptr(fd), "native-owned-original")
	defer file.Close()
	if n, err := file.Write(wire); err != nil || n != len(wire) || file.Sync() != nil || k.directory.Sync() != nil {
		return d101native.RawRef{}, errResetExecutionEvidence
	}
	back := make([]byte, len(wire))
	defer clear(back)
	if _, err := file.ReadAt(back, 0); err != nil || !bytes.Equal(back, wire) || k.check(ctx) != nil {
		return d101native.RawRef{}, errResetExecutionEvidence
	}
	return nativeResetD101Ref(file, k.directory, path, wire)
}
func (k *resetD101NativeKeeper) bindHeader(sequence uint64, record any) error {
	if k == nil || k.pre == nil || sequence != uint64(len(k.refs)) || sequence > 14 {
		return errResetExecutionEvidence
	}
	if sequence == 0 {
		x, ok := record.(*d101native.Acquired)
		if !ok {
			return errResetExecutionEvidence
		}
		x.Binding = k.pre.binding
		x.LeafKind = "ACQUISITION"
		x.Phase = "ACQUIRED"
		x.Sequence = 0
		return nil
	}
	phase := "CLOSING"
	if sequence == 9 {
		phase = "FROZEN"
	}
	kinds := []string{"ACQUISITION", "installed-writer-inventory", "console-admission", "root-admission", "turn-flush", "publisher", "postgres-admission", "old-services", "keeper-session", "writer-freeze-receipt", "FINAL_PLAN_BOUND", "ISSUER_RUNNING", "ISSUER_DONE", "PHYSICAL_RUNNING", ""}
	if sequence >= 10 && sequence <= 13 {
		phase = kinds[sequence]
	}
	h := d101native.PreHeader{Binding: k.pre.binding, LeafKind: kinds[sequence], Phase: phase, Sequence: sequence, PreviousOriginalRef: k.refs[sequence-1], AcquisitionRef: k.refs[0]}
	switch x := record.(type) {
	case *d101native.Inventory:
		if sequence != 1 {
			return errResetExecutionEvidence
		}
		x.Header = h
	case *d101native.ConsoleAdmission:
		if sequence != 2 {
			return errResetExecutionEvidence
		}
		x.Header = h
	case *d101native.RootAdmission:
		if sequence != 3 {
			return errResetExecutionEvidence
		}
		x.Header = h
	case *d101native.TurnFlush:
		if sequence != 4 {
			return errResetExecutionEvidence
		}
		x.Header = h
	case *d101native.Publisher:
		if sequence != 5 {
			return errResetExecutionEvidence
		}
		x.Header = h
	case *d101native.PostgresAdmission:
		if sequence != 6 {
			return errResetExecutionEvidence
		}
		x.Header = h
	case *d101native.OldServices:
		if sequence != 7 {
			return errResetExecutionEvidence
		}
		x.Header = h
	case *d101native.KeeperSession:
		if sequence != 8 {
			return errResetExecutionEvidence
		}
		x.Header = h
	case *d101native.Freeze:
		if sequence != 9 {
			return errResetExecutionEvidence
		}
		x.Header = h
		x.InventoryRef = k.refs[1]
		x.ConsoleAdmissionRef = k.refs[2]
		x.RootAdmissionRef = k.refs[3]
		x.TurnFlushRef = k.refs[4]
		x.PublisherRef = k.refs[5]
		x.PostgresAdmissionRef = k.refs[6]
		x.OldServicesRef = k.refs[7]
		x.KeeperSessionRef = k.refs[8]
	case *d101native.FinalBound:
		if sequence != 10 {
			return errResetExecutionEvidence
		}
		x.Header.Pre = h
		x.Header.FreezeOriginalRef = k.refs[9]
	case *d101native.IssuerRunning:
		if sequence != 11 {
			return errResetExecutionEvidence
		}
		x.Header.Pre = h
		x.Header.FreezeOriginalRef = k.refs[9]
	case *d101native.IssuerDone:
		if sequence != 12 {
			return errResetExecutionEvidence
		}
		x.Header.Pre = h
		x.Header.FreezeOriginalRef = k.refs[9]
	case *d101native.PhysicalRunning:
		if sequence != 13 {
			return errResetExecutionEvidence
		}
		x.Header.Plan.Pre = h
		x.Header.Plan.FreezeOriginalRef = k.refs[9]
		x.Header.IssuerDoneRef = k.refs[12]
	case *d101native.Released:
		if sequence != 14 {
			return errResetExecutionEvidence
		}
		h.Phase = "RELEASED"
		x.Header.Plan.Pre = h
		x.Header.Plan.FreezeOriginalRef = k.refs[9]
		x.Header.IssuerDoneRef = k.refs[12]
	case *d101native.RecoveredRelease:
		if sequence != 14 {
			return errResetExecutionEvidence
		}
		h.Phase = "RECOVERED_RELEASED"
		x.Header.Plan.Pre = h
		x.Header.Plan.FreezeOriginalRef = k.refs[9]
		x.Header.IssuerDoneRef = k.refs[12]
	default:
		return errResetExecutionEvidence
	}
	return nil
}
func (k *resetD101NativeKeeper) stage(ctx context.Context, sequence uint64) (any, []byte, error) {
	if k.check(ctx) != nil || d101native.Missing(k.installer.stages) {
		return nil, nil, errResetD101InstallationNotSupplied
	}
	record, err := k.installer.stages.CaptureAuthenticatedStage(ctx, k, sequence)
	if err != nil || record == nil || k.bindHeader(sequence, record) != nil || k.installer.stages.RecheckAuthenticatedStage(ctx, k, sequence, record) != nil {
		return nil, nil, errResetExecutionEvidence
	}
	if sequence == 11 || sequence == 13 {
		var child d101native.Process
		switch x := record.(type) {
		case *d101native.IssuerRunning:
			child = x.Child
		case *d101native.PhysicalRunning:
			child = x.Child
		default:
			return nil, nil, errResetExecutionEvidence
		}
		if k.child == nil || k.childExited || !d101native.ValidProcess(child) || child.PID != uint32(k.child.Process.Pid) || child.StartTicks != k.childStart || child.ParentPID != k.pre.binding.Keeper.Process.PID || child.ParentStartTicks != k.pre.binding.Keeper.Process.StartTicks || child.ExePath != k.pre.binding.Keeper.Process.ExePath || child.ExeSHA256 != k.pre.binding.Keeper.Process.ExeSHA256 || child.SourceSHA != rootBuiltSourceSHA {
			return nil, nil, errResetExecutionEvidence
		}
		actualPath, e := os.Readlink("/proc/" + strconv.Itoa(k.child.Process.Pid) + "/exe")
		if e != nil || actualPath != child.ExePath {
			return nil, nil, errResetExecutionEvidence
		}
	}
	wire, err := k.installer.signStage(ctx, k.descriptor, record)
	if err != nil {
		return nil, nil, err
	}
	// A child is born paused. Its real PID/start is included before releasing the
	// birth pipe; READY/JWT/issuer ledger side effects follow durable phase11.
	ref, err := k.writeExclusive(ctx, resetD101NativeSequenceLeaf(sequence), wire)
	if err != nil || k.installer.stages.RecheckAuthenticatedStage(ctx, k, sequence, record) != nil {
		return nil, nil, errResetExecutionEvidence
	}
	k.refs = append(k.refs, ref)
	return record, wire, nil
}
func (k *resetD101NativeKeeper) prepareManagedPhysicalClient(ctx context.Context) error {
	if k.check(ctx) != nil || k.physicalMode != "" || k.clientInput != nil { return errResetExecutionEvidence }
	switch k.pre.physicalMode {
	case "--d101-host-operation":
		k.physicalMode = k.pre.physicalMode // Explicit actual-source approval only.
		return nil
	case "--d101-managed-host-operation":
	default:
		return errResetExecutionEvidence
	}
	clientCtx, cancel := context.WithDeadline(ctx, time.Unix(k.pre.binding.OriginalCutoffUnix, 0))
	held, session, expected, err := d101native.OpenInstalledManagementClient(clientCtx, k.pre.binding, nil, d101custody.Original{})
	if err != nil || held == nil || session != nil || len(expected) != 0 || k.check(ctx) != nil {
		if held != nil { held.Close() }
		cancel()
		return errResetExecutionEvidence
	}
	k.physicalMode = k.pre.physicalMode
	k.clientInput, k.clientContext, k.clientCancel = held, clientCtx, cancel
	return nil
}

func (k *resetD101NativeKeeper) approvedChildMode(ctx context.Context, issuer bool) (string, error) {
	if k.check(ctx) != nil || k.physicalMode == "" || k.physicalMode != k.pre.physicalMode { return "", errResetExecutionEvidence }
	if k.physicalMode != "--d101-host-operation" && k.physicalMode != "--d101-managed-host-operation" { return "", errResetExecutionEvidence }
	if k.physicalMode == "--d101-managed-host-operation" && (k.clientInput == nil || k.clientContext == nil || k.clientContext.Err() != nil) { return "", errResetExecutionEvidence }
	if issuer { return "--d101-issue-current-receipt", nil }
	return k.physicalMode, nil
}

func (k *resetD101NativeKeeper) openManagedPhysicalClient(ctx context.Context, wire []byte) error {
	if k.check(ctx) != nil || k.physicalMode != "--d101-managed-host-operation" || k.clientInput == nil ||
		k.clientContext == nil || k.clientContext.Err() != nil || k.clientSession != nil || len(k.refs) != 14 ||
		!bytes.Equal(wire, k.refsWire(13)) { return errResetExecutionEvidence }
	paused := d101custody.Original{Bytes: bytes.Clone(wire), SHA256: resetD101OriginalSHA(wire)}
	defer clear(paused.Bytes)
	held, session, expected, err := d101native.OpenInstalledManagementClient(k.clientContext, k.pre.binding, k.clientInput, paused)
	if err != nil || held != k.clientInput || session == nil || len(expected) == 0 { return errResetExecutionEvidence }
	k.clientSession, k.clientExpected = session, bytes.Clone(expected)
	binding, err := session.Consume(k.clientContext)
	if err != nil || binding == nil { return errResetExecutionEvidence }
	k.clientBinding = binding
	return k.recheckManagedPhysicalClient(ctx)
}

func (k *resetD101NativeKeeper) recheckManagedPhysicalClient(ctx context.Context) error {
	if k.check(ctx) != nil || k.physicalMode != "--d101-managed-host-operation" || k.physicalMode != k.pre.physicalMode ||
		k.clientContext == nil || k.clientContext.Err() != nil || k.clientInput == nil || k.clientSession == nil ||
		k.clientBinding == nil || len(k.clientExpected) == 0 || k.clientBinding.RecheckExpected(k.clientContext, k.clientExpected) != nil || k.check(ctx) != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func (k *resetD101NativeKeeper) closeManagedPhysicalClient() error {
	if k == nil { return nil }
	k.clientCloseOnce.Do(func() {
		if k.clientInput != nil { k.clientCloseErr = k.clientInput.Close() }
		if k.clientCancel != nil { k.clientCancel() }
		// Keep the selected route and closed binding; absence cannot become a
		// legacy fallback. Native stages never consult this closed binding.
	})
	return k.clientCloseErr
}

func (k *resetD101NativeKeeper) startChild(ctx context.Context, issuer bool, input io.Reader, output io.Writer) (*os.File, error) {
	if k.check(ctx) != nil || k.child != nil && !k.childExited {
		return nil, errResetExecutionEvidence
	}
	const binary = "/etc/opensamguk/d101/native-helper/deployer"
	if k.pre.binding.Keeper.Process.ExePath != binary {
		return nil, errResetExecutionEvidence
	}
	mode, err := k.approvedChildMode(ctx, issuer)
	if err != nil { return nil, err }
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	null, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		gateRead.Close()
		gateWrite.Close()
		return nil, err
	}
	cmd := exec.Command(binary, mode, "--operation-id", k.pre.binding.OperationID)
	cmd.ExtraFiles = []*os.File{null, null, null, null, null, gateRead, k.descriptor}
	cmd.Stdin = input
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		null.Close()
		gateRead.Close()
		gateWrite.Close()
		return nil, err
	}
	null.Close()
	gateRead.Close()
	k.child = cmd
	k.childExited = false
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/stat")
	if err != nil {
		gateWrite.Close()
		return nil, errResetExecutionEvidence
	}
	k.childStart, err = resetD101RootStartTicks(raw)
	if err != nil {
		gateWrite.Close()
		return nil, err
	}
	return gateWrite, nil
}
func (k *resetD101NativeKeeper) waitChild(ctx context.Context) error {
	if k.child == nil || k.childStart == 0 {
		return errResetExecutionEvidence
	}
	done := make(chan error, 1)
	go func() { done <- k.child.Wait() }()
	select {
	case <-ctx.Done():
		return errResetExecutionEvidence
	case err := <-done:
		k.childExited = true
		if err != nil || k.child.ProcessState == nil || !k.child.ProcessState.Success() {
			return errResetExecutionEvidence
		}
	}
	return k.check(ctx)
}
func (k *resetD101NativeKeeper) releaseActual(ctx context.Context, wire []byte) error {
	if k.check(ctx) != nil || len(k.refs) != 15 || !k.childExited || k.installer.release == nil || d101native.Missing(k.installer.stages) {
		return errResetExecutionEvidence
	}
	pins := k.installer.release
	if d101native.Missing(pins.source) || !d101native.ValidRef(pins.expected.ObserverOrigin) || !d101native.ValidRef(pins.expected.ReleaseActorOrigin) || !d101native.ValidRef(pins.expected.ReleaseAuthorization) || pins.expected.Binding != k.pre.binding {
		return errResetExecutionEvidence
	} // Independent signature inputs are supplied by actual source.
	d := pins.disposition
	if d.TerminalRef() != k.refs[14] || !bytes.Equal(wire, k.refsWire(14)) || d.Binding() != k.pre.binding || k.installer.stages.AuthenticateLastOwnedHandles(ctx, k, d) != nil {
		return errResetExecutionEvidence
	}
	if k.check(ctx) != nil {
		return errResetExecutionEvidence
	}
	// No flock(UN), reopen or close retry. Unknown close cannot claim completion.
	k.closed = true
	if k.descriptor.Close() != nil {
		return errResetExecutionEvidence
	}
	r, err := k.installer.stages.ObserveActualRelease(ctx, k, d)
	if err != nil || r == nil {
		return errResetExecutionEvidence
	}
	k.installer.release = r
	completion, err := k.installer.overallCompletion(ctx)
	if err != nil || completion == nil || !completion.Complete() || completion.NewOperationAllowed() {
		return errResetExecutionEvidence
	}
	return nil
}
func (k *resetD101NativeKeeper) refsWire(sequence uint64) []byte {
	if sequence >= uint64(len(k.refs)) {
		return nil
	}
	r := k.refs[sequence]
	fd, err := syscall.Openat(int(k.directory.Fd()), filepath.Base(r.Path), syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil
	}
	file := os.NewFile(uintptr(fd), "held-sequence-readback")
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, int64(r.Bytes)+1))
	if err != nil || uint64(len(b)) != r.Bytes || resetD101OriginalSHA(b) != r.SHA256 {
		return nil
	}
	return b
}

// Parent owns this keeper for its full lifetime. Before actual release, HOLD
// retains FD9 and originals. A failed/unknown final close preserves same-op HOLD
// without claiming the FD is still held; no unlink/reacquire/sign retry occurs.
var resetD101HeldNativeKeeper *resetD101NativeKeeper

func runResetD101NativeKeeper(ctx context.Context, op string, issuerOnly bool, input io.Reader, output io.Writer) int {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || !lifecycleJobIDRe.MatchString(op) {
		return 2
	}
	v, err := actualResetD101NativeEntry(ctx, "keeper", op)
	if err != nil || v == nil || d101native.Missing(v.preAcquisition) || d101native.Missing(v.stages) || d101native.Missing(v.signing) {
		return 2
	}
	p, err := v.preAcquisition.AuthenticatePreAcquisition(ctx, op, issuerOnly)
	if err != nil || p == nil || !d101native.ValidBinding(p.binding) || p.binding.OperationID != op || len(p.approvalOriginal) == 0 || uint64(len(p.approvalOriginal)) != p.binding.PreAcquisitionApprovalRef.Bytes || resetD101OriginalSHA(p.approvalOriginal) != p.binding.PreAcquisitionApprovalRef.SHA256 || v.preAcquisition.RecheckPreAcquisition(ctx, p) != nil {
		return 2
	}
	if p.existing != nil {
		if p.existing.binding != p.binding || !d101native.ValidProcess(p.existing.peer) || len(p.existing.requestOriginal) == 0 || v.preAcquisition.RequestExistingKeeper(ctx, p.existing, issuerOnly) != nil {
			return 3
		}
		// Request delivery is a fact, not overall completion or FD ownership.
		return 3
	}
	if p.binding.Keeper.Process.PID != uint32(os.Getpid()) || p.binding.Keeper.Process.SourceSHA != rootBuiltSourceSHA || p.directoryDevice == 0 || p.directoryInode == 0 {
		return 2
	}
	k := &resetD101NativeKeeper{installer: v, pre: p}
	if k.prepareManagedPhysicalClient(ctx) != nil { return 2 }
	defer k.closeManagedPhysicalClient()
	resetD101HeldNativeKeeper = k
	if k.acquire(ctx) != nil {
		if k.acquired {
			return 3
		}
		return 2
	}
	if k.openNamespace(ctx) != nil {
		return 3
	}
	intent, err := json.Marshal(struct {
		Kind        string            `json:"kind"`
		OperationID string            `json:"operationId"`
		Keeper      d101native.Keeper `json:"keeper"`
	}{"NATIVE_KEEPER_ATTEMPT", op, p.binding.Keeper})
	if err != nil {
		return 3
	}
	if _, err = k.writeExclusive(ctx, "keeper-attempt.json", intent); err != nil {
		return 3
	}
	for seq := uint64(0); seq <= 10; seq++ {
		if _, _, err = k.stage(ctx, seq); err != nil {
			return 3
		}
	}
	birth, err := k.startChild(ctx, true, input, output)
	if err != nil {
		return 3
	}
	if _, _, err = k.stage(ctx, 11); err != nil {
		birth.Close()
		return 3
	}
	if _, err = birth.Write([]byte{'B'}); err != nil {
		birth.Close()
		return 3
	}
	birth.Close()
	if k.waitChild(ctx) != nil {
		return 3
	}
	if _, _, err = k.stage(ctx, 12); err != nil {
		return 3
	}
	if issuerOnly && v.stages.AwaitAuthenticatedPhysicalHandoff(ctx, k) != nil {
		return 3
	}
	// Physical permission is reauthenticated for this exact operation/target,
	// original cutoff and same keeper. It is never inferred from issuer exit0.
	birth, err = k.startChild(ctx, false, nil, io.Discard)
	if err != nil { return 3 }
	record, physicalWire, err := k.stage(ctx, 13)
	if err != nil { birth.Close(); return 3 }
	if k.physicalMode == "--d101-managed-host-operation" {
		if k.openManagedPhysicalClient(ctx, physicalWire) != nil ||
			v.stages.RecheckAuthenticatedStage(ctx, k, 13, record) != nil || k.recheckManagedPhysicalClient(ctx) != nil {
			birth.Close(); return 3
		}
	}
	if _, err = birth.Write([]byte{'B'}); err != nil { birth.Close(); return 3 }
	birth.Close()
	// EOF/client cancellation never substitutes for actual native child Wait.
	if k.waitChild(ctx) != nil { return 3 }
	if k.closeManagedPhysicalClient() != nil { return 3 }
	_, terminal, err := k.stage(ctx, 14)
	if err != nil {
		return 3
	}
	if k.releaseActual(ctx, terminal) != nil {
		return 3
	}
	if k.directory != nil {
		k.directory.Close()
	}
	return 0
}
func awaitResetD101NativeBirth(ctx context.Context, v *resetD101NativeAuthorityInstaller, op string) error {
	if v == nil || d101native.Missing(v.preAcquisition) || d101native.Missing(v.installation) || ctx == nil || ctx.Err() != nil || v.installation.AuthenticateInstallation(ctx, op, "child-birth") != nil {
		return errResetExecutionEvidence
	}
	gate := os.NewFile(8, "inherited-native-birth-gate")
	if gate == nil {
		return errResetExecutionEvidence
	}
	defer gate.Close()
	var b [1]byte
	if _, err := io.ReadFull(gate, b[:]); err != nil || b[0] != 'B' || ctx.Err() != nil || v.installation.RecheckInstallation(ctx, op, "child-birth") != nil {
		return errResetExecutionEvidence
	}
	return nil
}

// The only diagnostics here are stage facts, never key/JWT/original bodies.
func resetD101NativeHoldMessage(w io.Writer) {
	if w != nil {
		_, _ = fmt.Fprintln(w, "D101 native same operation HOLD")
	}
}

// Linux production owner creation is relative to the already authenticated,
// held parent directory. Failed openat never wraps an invalid native FD.
func openResetD101RootOwnerAt(parent *os.File, leaf string) (*os.File, error) {
	if parent == nil || leaf != ".deployer-d101-native-owner" {
		return nil, errResetExecutionEvidence
	}
	fd, err := syscall.Openat(int(parent.Fd()), leaf, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0400)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "native-root-owner"), nil
}
