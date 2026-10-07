package d101native

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"opensamguk-deployer/internal/d101custody"
)

// These are private IPC integrity primitives, not enrollment or authentication.
// A matching process, credential or sealed carrier cannot construct a trusted
// BootstrapLease or register ReviewedReaderFactory. Independent management
// delegation/session/audit authentication remains a separate required source.
// Linux constants below are used only after the Linux/amd64 runtime guard.
const managementSOLSocket = 1
const managementSockType = 3
const managementPassCred = 16
const managementSCMCredentials = 2
const managementSCMRights = 1
const managementSeqPacket = 5
const managementMessageTruncated = 0x20
const managementControlTruncated = 0x8
const managementCloseReceivedDescriptorsOnExec = 0x40000000
const managementFGetSeals = 1034
const managementRequiredSeals = 0x1 | 0x2 | 0x4 | 0x8
const managementSysFcntlAMD64 = 72

type ManagementPeerObservation struct {
	PID        uint32
	StartTicks uint64
	UID, GID   uint32
}

// Holds only the private source socket, never an OFD lock or FD9 duplicate.
// Every accepted packet remains unverified management data.
type ManagementTransport struct {
	mu     sync.Mutex
	conn   *net.UnixConn
	peer   ManagementPeerObservation
	closed atomic.Bool
}

func managementLinuxAMD64() bool { return runtime.GOOS == "linux" && runtime.GOARCH == "amd64" }

func managementProcessStart(pid uint32) (uint64, error) {
	if !managementLinuxAMD64() || pid == 0 {
		return 0, ErrUnavailable
	}
	f, err := os.Open("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat")
	if err != nil {
		return 0, ErrUnavailable
	}
	defer f.Close()
	wire, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil || len(wire) > 64<<10 {
		return 0, ErrUnavailable
	}
	// The comm field may contain spaces and parentheses. Field22 is index19
	// after the last ')' ending comm, not index21 of strings.Fields(stat).
	end := strings.LastIndexByte(string(wire), ')')
	if end < 0 {
		return 0, ErrUnavailable
	}
	fields := strings.Fields(string(wire[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return 0, ErrUnavailable
	}
	n, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || n == 0 {
		return 0, ErrUnavailable
	}
	return n, nil
}

// The caller supplies observations frozen independently of incoming packets.
// This checks transport identity only and does NOT certify the installer role,
// its artifact, its sshd/audit source, or any human delegation.
func OpenManagementTransport(ctx context.Context, socket *os.File, peer ManagementPeerObservation) (*ManagementTransport, error) {
	if !managementLinuxAMD64() || ctx == nil || ctx.Err() != nil || socket == nil || peer.PID == 0 || peer.StartTicks == 0 {
		return nil, ErrUnavailable
	}
	start, err := managementProcessStart(peer.PID)
	kind, kindErr := syscall.GetsockoptInt(int(socket.Fd()), managementSOLSocket, managementSockType)
	if err != nil || start != peer.StartTicks || kindErr != nil || kind != managementSeqPacket ||
		syscall.SetsockoptInt(int(socket.Fd()), managementSOLSocket, managementPassCred, 1) != nil {
		return nil, ErrUnavailable
	}
	// FileConn duplicates only this socket. The borrowed input remains owned by
	// its caller and is not closed here; the transport closes its own duplicate.
	conn, err := net.FileConn(socket)
	if err != nil {
		return nil, ErrUnavailable
	}
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, ErrUnavailable
	}
	if ctx.Err() != nil {
		unix.Close()
		return nil, ErrUnavailable
	}
	return &ManagementTransport{conn: unix, peer: peer}, nil
}

// Receive exactly one bounded seqpacket with a fresh per-message credential.
// Unknown ancillary data, exported descriptors, truncation, missing credentials,
// PID reuse/exit or cancellation rejects the entire packet. No packet supplies
// its own expected peer. Socketpair creation credentials alone are not used.
func (t *ManagementTransport) ReadUnverified(ctx context.Context, limit int) ([]byte, error) {
	if t == nil || ctx == nil || ctx.Err() != nil || limit <= 0 || limit > 64<<10 {
		return nil, ErrUnavailable
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	deadline, bounded := ctx.Deadline()
	if t.closed.Load() || t.conn == nil || !bounded || !deadline.After(time.Now()) {
		return nil, ErrUnavailable
	}
	start, err := managementProcessStart(t.peer.PID)
	if err != nil || start != t.peer.StartTicks || t.conn.SetReadDeadline(deadline) != nil {
		return nil, ErrUnavailable
	}
	// Periodic bounded reads also observe cancellation before the deadline.
	wire := make([]byte, limit+1)
	oob := make([]byte, 64<<10)
	var n, control, flags int
	raw, rawErr := t.conn.SyscallConn()
	if rawErr != nil {
		return nil, ErrUnavailable
	}
	for {
		poll := time.Now().Add(50 * time.Millisecond)
		if poll.After(deadline) {
			poll = deadline
		}
		if ctx.Err() != nil || t.conn.SetReadDeadline(poll) != nil {
			clear(wire)
			return nil, ErrUnavailable
		}
		var receiveErr error
		pollErr := raw.Read(func(fd uintptr) bool {
			n, control, flags, _, receiveErr = syscall.Recvmsg(int(fd), wire, oob, managementCloseReceivedDescriptorsOnExec)
			return receiveErr != syscall.EAGAIN && receiveErr != syscall.EWOULDBLOCK
		})
		err = receiveErr
		if pollErr != nil {
			err = pollErr
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() && ctx.Err() == nil && time.Now().Before(deadline) {
			continue
		}
		break
	}
	if control < 0 || control > len(oob) {
		clear(wire)
		return nil, ErrUnavailable
	}
	messages, parseErr := syscall.ParseSocketControlMessage(oob[:control])
	credentials := 0
	valid := parseErr == nil && err == nil && n > 0 && n <= limit && flags&(managementMessageTruncated|managementControlTruncated) == 0
	for _, msg := range messages {
		if msg.Header.Level == managementSOLSocket && msg.Header.Type == managementSCMRights {
			// Receiving SCM_RIGHTS creates descriptors even when the message is
			// rejected. Close every received descriptor rather than leaking it.
			fds, rightsErr := syscall.ParseUnixRights(&msg)
			if rightsErr == nil {
				for _, fd := range fds {
					syscall.Close(fd)
				}
			}
			valid = false
			continue
		}
		if msg.Header.Level != managementSOLSocket || msg.Header.Type != managementSCMCredentials || len(msg.Data) != 12 {
			valid = false
			continue
		}
		credentials++
		if binary.LittleEndian.Uint32(msg.Data[0:4]) != t.peer.PID ||
			binary.LittleEndian.Uint32(msg.Data[4:8]) != t.peer.UID || binary.LittleEndian.Uint32(msg.Data[8:12]) != t.peer.GID {
			valid = false
		}
	}
	start, startErr := managementProcessStart(t.peer.PID)
	if !valid || credentials != 1 || startErr != nil || start != t.peer.StartTicks || ctx.Err() != nil || t.closed.Load() {
		clear(wire)
		return nil, ErrUnavailable
	}
	return wire[:n:n], nil
}

func (t *ManagementTransport) Close() error {
	if t == nil {
		return nil
	}
	// Close must interrupt a blocked receive; it cannot wait for the receive
	// mutex or for the original operation deadline to expire.
	if t.closed.Swap(true) {
		return nil
	}
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// Seals and hashes are immutable carrier observations, not approved original
// custody or authentication. In particular this memfd is not a nlink1 native
// original and is never returned as a RawRef/NativePin/HeldOriginal.
func ReadSealedManagementCarrier(ctx context.Context, file *os.File, expectedSHA string, expectedBytes uint64) ([]byte, error) {
	if !managementLinuxAMD64() || ctx == nil || ctx.Err() != nil || file == nil || !ValidSHA(expectedSHA) || expectedBytes == 0 || expectedBytes > 64<<20 {
		return nil, ErrUnavailable
	}
	seals, _, errno := syscall.RawSyscall(managementSysFcntlAMD64, file.Fd(), managementFGetSeals, 0)
	before, err := file.Stat()
	if errno != 0 || seals&managementRequiredSeals != managementRequiredSeals || err != nil || !before.Mode().IsRegular() || before.Size() != int64(expectedBytes) {
		return nil, ErrUnavailable
	}
	wire := make([]byte, int(expectedBytes)+1)
	n, readErr := file.ReadAt(wire, 0)
	after, afterErr := file.Stat()
	nextSeals, _, nextErr := syscall.RawSyscall(managementSysFcntlAMD64, file.Fd(), managementFGetSeals, 0)
	if readErr != io.EOF || n != int(expectedBytes) || Hash(wire[:n]) != expectedSHA ||
		afterErr != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) || nextErr != 0 || nextSeals != seals || ctx.Err() != nil {
		clear(wire)
		return nil, ErrUnavailable
	}
	copy := bytes.Clone(wire[:n])
	clear(wire)
	return copy, nil
}

// Management inputs are opaque and source-owned. The installed authentication
// handoff is still absent; transport integrity and signer possession cannot
// substitute for it. These types expose no constructor or serialization API.
type ManagementServerInput struct {
	source *heldInstalledManagementServerSource
	frozen *managementFrozenInput
}
type ManagementClientInput struct {
	source *heldInstalledManagementClientSource
	frozen *managementFrozenInput
	mu sync.Mutex
	state managementInstalledClientState
	expectedNative PreBinding
	ownerContext context.Context
	ownedCancel context.CancelFunc
	bindingDone chan struct{}
	session *ManagementSession
	ownedStream net.Conn
	coreOwned bool
	closeOnce sync.Once
	closeErr error
}

// These states govern ownership, never source authentication.
type managementInstalledClientState uint8
const (
	managementClientUnprepared managementInstalledClientState = iota
	managementClientHeld
	managementClientBinding
	managementClientTransferred
	managementClientClosed
)

// Close owns only preparation originals/client cancellation, or the exact
// transferred session. Native custody and its context are never resources here.
func (input *ManagementClientInput) Close() error {
	if input == nil { return nil }
	input.closeOnce.Do(func() {
		input.mu.Lock()
		input.state = managementClientClosed
		cancel, done := input.ownedCancel, input.bindingDone
		input.ownedCancel = nil
		input.mu.Unlock()
		if cancel != nil { cancel() }
		// Cancellation interrupts binding; join it before touching its resources.
		if done != nil { <-done }
		input.mu.Lock()
		session, stream, coreOwned := input.session, input.ownedStream, input.coreOwned
		source, frozen := input.source, input.frozen
		input.mu.Unlock()
		var err error
		if session != nil {
			err = session.Close()
		} else if !coreOwned {
			if stream != nil { err = errors.Join(err, stream.Close()) }
			releaseManagementInputCancel(frozen)
			if source != nil && source.originals != nil { err = errors.Join(err, source.originals.integrity.Close()) }
		}
		input.mu.Lock(); input.closeErr = err; input.mu.Unlock()
	})
	input.mu.Lock(); defer input.mu.Unlock()
	return input.closeErr
}

type managementBindingWire struct {
	OperationID string
	TargetFingerprint string
	PublicationRevision string
	ApprovedCardSHA256 string
	InstallerEnrollmentSHA256 string
	InstallerArtifactSHA256 string
	InstallerPID uint32
	InstallerStartTicks uint64
	InstallerParentPID uint32
	InstallerParentStartTicks uint64
	InstallerExePath string
	InstallerExeSHA256 string
	InstallerSourceSHA string
	ScopeWire []byte
	OriginalCutoffUnix uint64
	OriginalRecoveryDeadlineUnix uint64
}

type managementFrame struct {
	Kind string
	SessionID []byte
	Nonce string
	BindingWire []byte
}

// All members below belong to the installed source owner, not to the peer or
// CLI. retained selects an already authenticated existing scope; it is not a
// new wire purpose. No authenticated constructor for these originals exists
// until the independent installation/enrollment/human/key-use handoff arrives.
// Retained originals are integrity data only. Expected identities are cloned
// before acquisition; their origin and the authenticated source remain separate.
// Production calls this machinery only after the independent source gate.
type managementHeldOriginal struct {
	ref RawRef
	file, parent *os.File
	fileInfo, parentInfo os.FileInfo
	wire []byte
}
type managementOriginalSet struct {
	mu sync.Mutex
	ctx context.Context
	uid uint32
	entries []managementHeldOriginal
	closed bool
	closeErr error
}

func managementOriginalContext(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil { return false }
	deadline, ok := ctx.Deadline()
	return ok && deadline.After(time.Now())
}
func managementOriginalRef(ref RawRef, uid uint32) bool {
	// Keep the public root-only RawRef contract unchanged. The private UID
	// parameter exists for disposable integrity fixtures, never authentication.
	root := ref
	root.Native.OwnerUID = 0
	return ValidRef(root) && ref.Native.OwnerUID == uid && ref.Bytes <= PayloadMaxBytes
}
func managementOriginalFile(info os.FileInfo, ref RawRef) bool {
	if info == nil { return false }
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		uint64(stat.Dev) == ref.Native.Device && uint64(stat.Ino) == ref.Native.Inode && stat.Uid == ref.Native.OwnerUID &&
		uint32(info.Mode().Perm()) == ref.Native.Mode && uint64(stat.Nlink) == ref.Native.Links &&
		info.Size() > 0 && uint64(info.Size()) == ref.Bytes
}
func managementOriginalParent(info os.FileInfo, ref RawRef) bool {
	if info == nil { return false }
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.IsDir() && info.Mode().Perm() == 0700 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		uint64(stat.Dev) == ref.Native.ParentDevice && uint64(stat.Ino) == ref.Native.ParentInode && stat.Uid == ref.Native.OwnerUID
}
func managementOriginalSnapshot(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) && before.Size() == after.Size() &&
		before.Mode() == after.Mode() && before.ModTime().Equal(after.ModTime())
}
func (entry *managementHeldOriginal) check() error {
	if entry == nil || entry.file == nil || entry.parent == nil { return ErrUnavailable }
	parentPath := filepath.Dir(entry.ref.Path)
	canonical, err := filepath.EvalSymlinks(parentPath)
	if err != nil || canonical != parentPath { return ErrUnavailable }
	fileFD, fileErr := entry.file.Stat()
	parentFD, parentErr := entry.parent.Stat()
	filePath, pathErr := os.Lstat(entry.ref.Path)
	parentPathInfo, dirErr := os.Lstat(parentPath)
	if fileErr != nil || parentErr != nil || pathErr != nil || dirErr != nil ||
		!managementOriginalFile(fileFD, entry.ref) || !managementOriginalFile(filePath, entry.ref) ||
		!managementOriginalParent(parentFD, entry.ref) || !managementOriginalParent(parentPathInfo, entry.ref) ||
		!managementOriginalSnapshot(entry.fileInfo, fileFD) || !managementOriginalSnapshot(entry.fileInfo, filePath) ||
		!managementOriginalSnapshot(entry.parentInfo, parentFD) || !managementOriginalSnapshot(entry.parentInfo, parentPathInfo) {
		return ErrUnavailable
	}
	return nil
}
func (entry *managementHeldOriginal) read(ctx context.Context) ([]byte, error) {
	if !managementOriginalContext(ctx) || entry.check() != nil { return nil, ErrUnavailable }
	wire := make([]byte, int(entry.ref.Bytes))
	n, err := entry.file.ReadAt(wire, 0)
	if err != nil || n != len(wire) || Hash(wire) != entry.ref.SHA256 || entry.check() != nil || !managementOriginalContext(ctx) {
		clear(wire); return nil, ErrUnavailable
	}
	return wire, nil
}
func holdManagementOriginals(ctx context.Context, refs []RawRef) (*managementOriginalSet, error) {
	return holdManagementOriginalsUID(ctx, refs, 0)
}
func holdManagementOriginalsUID(ctx context.Context, refs []RawRef, uid uint32) (*managementOriginalSet, error) {
	if !managementOriginalContext(ctx) || len(refs) == 0 || len(refs) > 256 { return nil, ErrUnavailable }
	frozen := append([]RawRef(nil), refs...)
	paths := make(map[string]bool, len(frozen))
	native := make(map[[2]uint64]bool, len(frozen))
	for _, ref := range frozen {
		identity := [2]uint64{ref.Native.Device, ref.Native.Inode}
		if !managementOriginalRef(ref, uid) || paths[ref.Path] || native[identity] { return nil, ErrUnavailable }
		paths[ref.Path], native[identity] = true, true
	}
	set := &managementOriginalSet{ctx: ctx, uid: uid}
	success := false
	defer func() { if !success { set.Close() } }()
	for _, ref := range frozen {
		if !managementOriginalContext(ctx) { return nil, ErrUnavailable }
		parentPath := filepath.Dir(ref.Path)
		canonical, err := filepath.EvalSymlinks(parentPath)
		if err != nil || canonical != parentPath { return nil, ErrUnavailable }
		parentInfo, err := os.Lstat(parentPath)
		if err != nil || !managementOriginalParent(parentInfo, ref) { return nil, ErrUnavailable }
		fileInfo, err := os.Lstat(ref.Path)
		if err != nil || !managementOriginalFile(fileInfo, ref) { return nil, ErrUnavailable }
		parentFD, err := syscall.Open(parentPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err != nil { return nil, ErrUnavailable }
		entry := managementHeldOriginal{ref: ref, parent: os.NewFile(uintptr(parentFD), parentPath), fileInfo: fileInfo, parentInfo: parentInfo}
		set.entries = append(set.entries, entry) // Own the parent before any later acquisition can fail.
		held := &set.entries[len(set.entries)-1]
		fileFD, err := syscall.Open(ref.Path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil { return nil, ErrUnavailable }
		held.file = os.NewFile(uintptr(fileFD), ref.Path)
		wire, err := held.read(ctx)
		if err != nil { return nil, ErrUnavailable }
		held.wire = wire
	}
	// Recheck all siblings together after the last acquisition, including hashes.
	if set.recheck(ctx) != nil { return nil, ErrUnavailable }
	success = true
	return set, nil
}
func (set *managementOriginalSet) recheck(ctx context.Context) error {
	if set == nil { return ErrUnavailable }
	set.mu.Lock(); defer set.mu.Unlock()
	return set.recheckLocked(ctx)
}
func (set *managementOriginalSet) recheckLocked(ctx context.Context) error {
	if set.closed || len(set.entries) == 0 || !managementOriginalContext(ctx) || !managementOriginalContext(set.ctx) { return ErrUnavailable }
	for i := range set.entries {
		wire, err := set.entries[i].read(ctx)
		if err != nil { return ErrUnavailable }
		equal := bytes.Equal(wire, set.entries[i].wire)
		clear(wire)
		if !equal || !managementOriginalContext(set.ctx) { return ErrUnavailable }
	}
	// One final whole-set metadata pass rejects a sibling changed during reads.
	for i := range set.entries { if set.entries[i].check() != nil { return ErrUnavailable } }
	if !managementOriginalContext(ctx) || !managementOriginalContext(set.ctx) { return ErrUnavailable }
	return nil
}
func (set *managementOriginalSet) copyOriginals(ctx context.Context) ([][]byte, error) {
	if set == nil { return nil, ErrUnavailable }
	set.mu.Lock(); defer set.mu.Unlock()
	if set.recheckLocked(ctx) != nil { return nil, ErrUnavailable }
	copies := make([][]byte, len(set.entries))
	for i := range set.entries { copies[i] = bytes.Clone(set.entries[i].wire) }
	if !managementOriginalContext(ctx) || !managementOriginalContext(set.ctx) {
		for _, wire := range copies { clear(wire) }; return nil, ErrUnavailable
	}
	return copies, nil
}
func (set *managementOriginalSet) Close() error {
	if set == nil { return nil }
	set.mu.Lock(); defer set.mu.Unlock()
	if set.closed { return set.closeErr }
	set.closed = true
	for i := range set.entries {
		entry := &set.entries[i]
		clear(entry.wire); entry.wire = nil
		if entry.file != nil { set.closeErr = errors.Join(set.closeErr, entry.file.Close()); entry.file = nil }
		if entry.parent != nil { set.closeErr = errors.Join(set.closeErr, entry.parent.Close()); entry.parent = nil }
	}
	return set.closeErr
}

type heldManagementInstalledOriginals struct {
	binding managementBindingWire
	retained bool
	user string
	targetAddress string
	clientKey []byte
	hostKey []byte
	authTries int
	handshakeBytes int64
	readFile, writeFile *os.File
	// A concrete source must authenticate endpoint/native peer and owned stream
	// provenance before this slot can be used. A pointer is not authority.
	approvedUnix *net.UnixConn
	nativeBinding PreBinding
	originals []*os.File
	integrity *managementOriginalSet
	ownerContext context.Context
	executable *os.File
}

func (o *heldManagementInstalledOriginals) recheck(ctx context.Context) error {
	// Missing: independently authenticated installation, target/user, human,
	// custodian/retention, key-use and enrollment originals, plus their native
	// held lifetime. No raw DTO/stat/hash/file or boolean can satisfy this gate.
	// The source owner must supply that concrete handoff in a later owned hunk.
	return ErrUnavailable
}

type heldInstalledManagementServerSource struct {
	originals *heldManagementInstalledOriginals
	hostSigner ssh.Signer
}
type heldInstalledManagementClientSource struct {
	originals *heldManagementInstalledOriginals
	clientSigner ssh.Signer
}

func holdInstalledManagementServerSource(ctx context.Context) (*heldInstalledManagementServerSource, error) {
	return nil, ErrUnavailable
}
func holdInstalledManagementClientSource(ctx context.Context, expectedNative PreBinding) (*heldInstalledManagementClientSource, error) {
	return nil, ErrUnavailable
}

type managementFrozenInput struct {
	ctx context.Context
	deadline time.Time
	bindingWire []byte
	originals *heldManagementInstalledOriginals
	retained bool
	user, targetAddress string
	clientKey, hostKey []byte
	authTries int
	handshakeBytes int64
	cancelMu sync.Mutex
	ownedCancel context.CancelFunc
}

func managementActiveDeadline(ctx context.Context, b managementBindingWire, retained bool) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil || b.OriginalCutoffUnix == 0 || b.OriginalCutoffUnix > math.MaxInt64 || b.OriginalRecoveryDeadlineUnix > math.MaxInt64 {
		return time.Time{}, ErrUnavailable
	}
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) {
		return time.Time{}, ErrUnavailable
	}
	active := b.OriginalCutoffUnix
	if retained {
		active = b.OriginalRecoveryDeadlineUnix
		if active == 0 { return time.Time{}, ErrUnavailable }
	}
	original := time.Unix(int64(active), 0)
	if !original.After(time.Now()) { return time.Time{}, ErrUnavailable }
	if original.Before(deadline) { deadline = original }
	return deadline, nil
}

func managementValidBinding(b managementBindingWire) bool {
	revision, err := strconv.ParseInt(b.PublicationRevision, 10, 64)
	process := Process{PID: b.InstallerPID, StartTicks: b.InstallerStartTicks, ParentPID: b.InstallerParentPID,
		ParentStartTicks: b.InstallerParentStartTicks, ExePath: b.InstallerExePath, ExeSHA256: b.InstallerExeSHA256, SourceSHA: b.InstallerSourceSHA}
	return ValidNonce(b.OperationID) && ValidSHA(b.TargetFingerprint) && err == nil && revision > 0 &&
		strconv.FormatInt(revision, 10) == b.PublicationRevision && ValidSHA(b.ApprovedCardSHA256) &&
		ValidSHA(b.InstallerEnrollmentSHA256) && ValidSHA(b.InstallerArtifactSHA256) && ValidProcess(process) &&
		len(b.ScopeWire) > 0 && len(b.ScopeWire) <= PayloadMaxBytes && b.OriginalCutoffUnix > 0 &&
		b.OriginalCutoffUnix <= math.MaxInt64 && b.OriginalRecoveryDeadlineUnix <= math.MaxInt64
}

// Ordinary bounded context mechanics never authenticate an installed source.
// The owner must already have a live bound; a caller cannot invent that bound.
func managementInstalledDeadline(caller, owner context.Context, binding managementBindingWire, retained bool) (time.Time, error) {
	if caller == nil || caller.Err() != nil || !managementOriginalContext(owner) { return time.Time{}, ErrUnavailable }
	deadline, err := managementActiveDeadline(owner, binding, retained)
	if err != nil { return time.Time{}, ErrUnavailable }
	if callerDeadline, bounded := caller.Deadline(); bounded {
		if !callerDeadline.After(time.Now()) { return time.Time{}, ErrUnavailable }
		if callerDeadline.Before(deadline) { deadline = callerDeadline }
	}
	if caller.Err() != nil || owner.Err() != nil || !deadline.After(time.Now()) { return time.Time{}, ErrUnavailable }
	return deadline, nil
}
func newManagementInstalledContext(caller, owner context.Context, binding managementBindingWire, retained bool) (context.Context, context.CancelFunc, error) {
	deadline, err := managementInstalledDeadline(caller, owner, binding, retained)
	if err != nil { return nil, nil, ErrUnavailable }
	child, childCancel := context.WithDeadline(owner, deadline)
	stopCaller := context.AfterFunc(caller, childCancel)
	var once sync.Once
	cancel := func() { once.Do(func() { stopCaller(); childCancel() }) }
	if caller.Err() != nil || owner.Err() != nil || !managementOriginalContext(child) {
		cancel(); return nil, nil, ErrUnavailable
	}
	return child, cancel, nil
}
func managementInstalledSourceContext(caller context.Context, originals *heldManagementInstalledOriginals) (context.Context, context.CancelFunc, error) {
	if originals == nil || !managementOriginalContext(originals.ownerContext) || originals.recheck(originals.ownerContext) != nil {
		return nil, nil, ErrUnavailable
	}
	return newManagementInstalledContext(caller, originals.ownerContext, originals.binding, originals.retained)
}
func takeManagementInputCancel(f *managementFrozenInput) context.CancelFunc {
	if f == nil { return nil }
	f.cancelMu.Lock(); defer f.cancelMu.Unlock()
	cancel := f.ownedCancel
	f.ownedCancel = nil
	return cancel
}
func releaseManagementInputCancel(f *managementFrozenInput) {
	if cancel := takeManagementInputCancel(f); cancel != nil { cancel() }
}

// SSH string prefixes and integers are counted before marshal/allocation.
// Each add is checked against the existing payload ceiling before summation.
func managementStringsFit(fixed uint64, lengths ...int) bool {
	if fixed > PayloadMaxBytes { return false }
	for _, length := range lengths {
		if length < 0 || uint64(length) > PayloadMaxBytes-fixed { return false }
		fixed += uint64(length)
	}
	return fixed > 0
}
func managementBindingSize(b managementBindingWire) bool {
	// Ten strings, two uint32s and four uint64s in the unchanged tuple16.
	return managementStringsFit(10*4+2*4+4*8, len(b.OperationID), len(b.TargetFingerprint), len(b.PublicationRevision),
		len(b.ApprovedCardSHA256), len(b.InstallerEnrollmentSHA256), len(b.InstallerArtifactSHA256), len(b.InstallerExePath),
		len(b.InstallerExeSHA256), len(b.InstallerSourceSHA), len(b.ScopeWire))
}

func freezeManagementInput(ctx context.Context, o *heldManagementInstalledOriginals) (*managementFrozenInput, error) {
	if ctx == nil || ctx.Err() != nil || o == nil { return nil, ErrUnavailable }
	contextDeadline, bounded := ctx.Deadline()
	if !bounded || !contextDeadline.After(time.Now()) || o.recheck(ctx) != nil { return nil, ErrUnavailable }
	if o.integrity == nil || o.integrity.recheck(ctx) != nil { return nil, ErrUnavailable }
	deadline, err := managementActiveDeadline(ctx, o.binding, o.retained)
	if err != nil || !managementValidBinding(o.binding) || o.user == "" || o.targetAddress == "" ||
		o.authTries <= 0 || o.handshakeBytes <= 0 || !managementPlainKey(o.clientKey) || !managementPlainKey(o.hostKey) {
		return nil, ErrUnavailable
	}
	if !managementBindingSize(o.binding) { return nil, ErrUnavailable }
	wire := ssh.Marshal(&o.binding)
	if len(wire) == 0 || len(wire) > PayloadMaxBytes { return nil, ErrUnavailable }
	return &managementFrozenInput{ctx: ctx, deadline: deadline, bindingWire: bytes.Clone(wire), originals: o, retained: o.retained,
		user: o.user, targetAddress: o.targetAddress, clientKey: bytes.Clone(o.clientKey), hostKey: bytes.Clone(o.hostKey),
		authTries: o.authTries, handshakeBytes: o.handshakeBytes}, nil
}

func newManagementServerInput(ctx context.Context, source *heldInstalledManagementServerSource) (*ManagementServerInput, error) {
	if source == nil || source.hostSigner == nil { return nil, ErrUnavailable }
	f, err := freezeManagementInput(ctx, source.originals)
	if err != nil || source.hostSigner.PublicKey() == nil || !bytes.Equal(source.hostSigner.PublicKey().Marshal(), f.hostKey) {
		return nil, ErrUnavailable
	}
	return &ManagementServerInput{source: source, frozen: f}, nil
}
func newManagementClientInput(ctx context.Context, source *heldInstalledManagementClientSource) (*ManagementClientInput, error) {
	if source == nil || source.clientSigner == nil { return nil, ErrUnavailable }
	f, err := freezeManagementInput(ctx, source.originals)
	if err != nil || source.clientSigner.PublicKey() == nil || !bytes.Equal(source.clientSigner.PublicKey().Marshal(), f.clientKey) {
		return nil, ErrUnavailable
	}
	return &ManagementClientInput{source: source, frozen: f}, nil
}

func managementPlainKey(wire []byte) bool {
	key, err := ssh.ParsePublicKey(wire)
	return err == nil && key.Type() == ssh.KeyAlgoED25519 && bytes.Equal(key.Marshal(), wire)
}

func (f *managementFrozenInput) recheck(ctx context.Context) error {
	if f == nil || ctx == nil || ctx.Err() != nil || f.ctx == nil || f.ctx.Err() != nil ||
		!f.deadline.After(time.Now()) || f.originals == nil {
		return ErrUnavailable
	}
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) || f.originals.recheck(ctx) != nil || !managementBindingSize(f.originals.binding) || !bytes.Equal(f.bindingWire, ssh.Marshal(&f.originals.binding)) ||
		f.retained != f.originals.retained || f.user != f.originals.user || f.targetAddress != f.originals.targetAddress ||
		!bytes.Equal(f.clientKey, f.originals.clientKey) || !bytes.Equal(f.hostKey, f.originals.hostKey) ||
		f.authTries != f.originals.authTries || f.handshakeBytes != f.originals.handshakeBytes {
		return ErrUnavailable
	}
	if f.originals.integrity == nil || f.originals.integrity.recheck(ctx) != nil { return ErrUnavailable }
	return nil
}

// Only concrete supported streams can be transferred. This check performs no
// read/write/deadline mutation; refused streams remain owned by their caller.
func managementSupportedStream(stream net.Conn) bool {
	if !managementLinuxAMD64() { return false }
	switch c := stream.(type) {
	case *net.TCPConn:
		if c == nil { return false }
		raw, err := c.SyscallConn()
		if err != nil { return false }
		kind, socketErr := 0, error(nil)
		err = raw.Control(func(fd uintptr) { kind, socketErr = syscall.GetsockoptInt(int(fd), managementSOLSocket, managementSockType) })
		return err == nil && socketErr == nil && kind == 1
	case *net.UnixConn:
		if c == nil { return false }
		raw, err := c.SyscallConn()
		if err != nil { return false }
		kind, socketErr := 0, error(nil)
		err = raw.Control(func(fd uintptr) { kind, socketErr = syscall.GetsockoptInt(int(fd), managementSOLSocket, managementSockType) })
		return err == nil && socketErr == nil && kind == 1
	case *managementStdioConn:
		return c != nil && c.source != nil && c.reader != nil && c.writer != nil && !c.closed.Load()
	default:
		return false
	}
}

type managementStdioAddress string
func (a managementStdioAddress) Network() string { return "stdio" }
func (a managementStdioAddress) String() string { return string(a) }

type managementStdioConn struct {
	source *heldManagementInstalledOriginals
	reader, writer *os.File
	address managementStdioAddress
	closed atomic.Bool
}
func (c *managementStdioConn) Read(p []byte) (int, error) {
	if c == nil || c.closed.Load() || c.reader == nil { return 0, ErrUnavailable }
	return c.reader.Read(p)
}
func (c *managementStdioConn) Write(p []byte) (int, error) {
	if c == nil || c.closed.Load() || c.writer == nil { return 0, ErrUnavailable }
	return c.writer.Write(p)
}
func (c *managementStdioConn) LocalAddr() net.Addr { if c == nil { return nil }; return c.address }
func (c *managementStdioConn) RemoteAddr() net.Addr { if c == nil { return nil }; return c.address }
func (c *managementStdioConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.closed.Load() || c.reader == nil { return ErrUnavailable }
	return c.reader.SetReadDeadline(t)
}
func (c *managementStdioConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.closed.Load() || c.writer == nil { return ErrUnavailable }
	return c.writer.SetWriteDeadline(t)
}
func (c *managementStdioConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
func (c *managementStdioConn) Close() error {
	if c == nil || c.closed.Swap(true) { return nil }
	var err error
	if c.reader != nil { err = errors.Join(err, c.reader.Close()) }
	if c.writer != nil && c.writer != c.reader { err = errors.Join(err, c.writer.Close()) }
	return err
}
func newManagementStdio(ctx context.Context, f *managementFrozenInput) (*managementStdioConn, error) {
	if f.recheck(ctx) != nil { return nil, ErrUnavailable }
	o := f.originals
	if o.readFile == nil || o.writeFile == nil || o.readFile == o.writeFile || o.readFile.Fd() != 0 || o.writeFile.Fd() != 1 {
		return nil, ErrUnavailable
	}
	c := &managementStdioConn{source: o, reader: o.readFile, writer: o.writeFile, address: managementStdioAddress(f.targetAddress)}
	if c.SetDeadline(f.deadline) != nil { c.Close(); return nil, ErrUnavailable }
	return c, nil
}

// Selection follows independent source authentication; kernel shape alone is
// not enrollment, endpoint authorization or native peer provenance.
func newManagementInstalledStream(ctx context.Context, f *managementFrozenInput) (net.Conn, error) {
	if f.recheck(ctx) != nil { return nil, ErrUnavailable }
	o := f.originals
	if o.approvedUnix == nil { return newManagementStdio(ctx, f) }
	stream := o.approvedUnix
	raw, err := stream.SyscallConn()
	if err != nil { return nil, ErrUnavailable }
	allowed := false
	if raw.Control(func(fd uintptr) { allowed = fd > 2 && (fd < 6 || fd > 9) }) != nil || !allowed { return nil, ErrUnavailable }
	// Only the authenticated owned carrier, independently excluded from native
	// descriptors above, can be closed on a later selection/deadline failure.
	transferred := false
	defer func() { if !transferred { stream.Close(); o.approvedUnix = nil } }()
	if o.readFile != nil || o.writeFile != nil || !managementSupportedStream(stream) { return nil, ErrUnavailable }
	if stream.SetDeadline(f.deadline) != nil { return nil, ErrUnavailable }
	transferred = true
	return stream, nil
}

// The existing actual-original authentication gate must independently compare
// the native constraint and shared source owner. Equality does not authenticate.
func recheckHeldInstalledNativeOwner(ctx context.Context, source *heldInstalledManagementClientSource, expectedNative PreBinding) error {
	if ctx == nil || ctx.Err() != nil || !ValidBinding(expectedNative) || source == nil || source.originals == nil ||
		source.originals.recheck(ctx) != nil || source.originals.nativeBinding != expectedNative ||
		source.originals.binding.OperationID != expectedNative.OperationID || source.originals.binding.TargetFingerprint != expectedNative.TargetFingerprint ||
		source.originals.binding.PublicationRevision != expectedNative.PublicationRevision || int64(source.originals.binding.OriginalCutoffUnix) != expectedNative.OriginalCutoffUnix ||
		!managementOriginalContext(source.originals.ownerContext) {
		return ErrUnavailable
	}
	if _, err := managementInstalledDeadline(ctx, source.originals.ownerContext, source.originals.binding, source.originals.retained); err != nil { return ErrUnavailable }
	return nil
}

func bindInstalledManagementPausedChild(ctx context.Context, source *heldInstalledManagementClientSource, expectedNative PreBinding, paused d101custody.Original) (*managementFrozenInput, error) {
	// Actual durable13 provenance, same prebirth owner, live paused child/role,
	// barrier/gate ownership and independent canonical16 producer are absent.
	// Neither raw Original/hash nor a parsed future tuple can replace them.
	return nil, ErrUnavailable
}

func OpenInstalledManagementServer(ctx context.Context) (*ManagementSession, error) {
	source, err := holdInstalledManagementServerSource(ctx)
	if err != nil { return nil, ErrUnavailable }
	if source == nil || source.originals == nil { return nil, ErrUnavailable }
	transferred := false
	defer func() { if !transferred && source.originals.integrity != nil { source.originals.integrity.Close() } }()
	derived, cancel, err := managementInstalledSourceContext(ctx, source.originals)
	if err != nil { return nil, ErrUnavailable }
	defer func() { if cancel != nil { cancel() } }()
	input, err := newManagementServerInput(derived, source)
	if err != nil { return nil, ErrUnavailable }
	input.frozen.cancelMu.Lock(); input.frozen.ownedCancel = cancel; input.frozen.cancelMu.Unlock()
	cancel = nil // The frozen input now owns only this cancellation resource.
	defer releaseManagementInputCancel(input.frozen)
	stream, err := newManagementInstalledStream(derived, input.frozen)
	if err != nil { return nil, ErrUnavailable }
	session, err := OpenManagementServer(derived, stream, input)
	if err != nil { stream.Close(); return nil, ErrUnavailable }
	transferred = true
	return session, nil
}
// Phase one retains the actual source owner without a stream or frozen child
// input. Phase two uses only that owner after independent durable13/pause auth.
func OpenInstalledManagementClient(ctx context.Context, expectedNative PreBinding, held *ManagementClientInput, pausedOriginal d101custody.Original) (*ManagementClientInput, *ManagementSession, []byte, error) {
	if held == nil {
		if ctx == nil || ctx.Err() != nil || !ValidBinding(expectedNative) || len(pausedOriginal.Bytes) != 0 || pausedOriginal.SHA256 != "" { return nil, nil, nil, ErrUnavailable }
		source, err := holdInstalledManagementClientSource(ctx, expectedNative)
		if err != nil || source == nil || source.originals == nil { return nil, nil, nil, ErrUnavailable }
		input := &ManagementClientInput{source: source, expectedNative: expectedNative}
		success := false
		defer func() { if !success { input.Close() } }()
		if recheckHeldInstalledNativeOwner(ctx, source, expectedNative) != nil || source.originals.approvedUnix != nil ||
			source.originals.readFile != nil || source.originals.writeFile != nil { return nil, nil, nil, ErrUnavailable }
		derived, cancel, err := managementInstalledSourceContext(ctx, source.originals)
		if err != nil { return nil, nil, nil, ErrUnavailable }
		input.ownerContext, input.ownedCancel = derived, cancel
		if recheckHeldInstalledNativeOwner(derived, source, expectedNative) != nil { return nil, nil, nil, ErrUnavailable }
		input.state = managementClientHeld
		success = true
		return input, nil, nil, nil
	}
	// Only the first phase-two caller owns the transition and its cleanup.
	// A competing/repeated caller refuses without closing that caller's owner.
	held.mu.Lock()
	if held.state != managementClientHeld { held.mu.Unlock(); return nil, nil, nil, ErrUnavailable }
	held.state = managementClientBinding
	held.bindingDone = make(chan struct{})
	done := held.bindingDone
	source, owner, originalExpected := held.source, held.ownerContext, held.expectedNative
	held.mu.Unlock()
	success := false
	defer func() {
		close(done)
		if !success { held.Close() }
	}()
	if ctx == nil || ctx.Err() != nil || expectedNative != originalExpected || !managementOriginalContext(owner) ||
		len(pausedOriginal.Bytes) == 0 || len(pausedOriginal.Bytes) > EnvelopeMaxBytes || Hash(pausedOriginal.Bytes) != pausedOriginal.SHA256 ||
		recheckHeldInstalledNativeOwner(owner, source, expectedNative) != nil { return nil, nil, nil, ErrUnavailable }
	derived, cancel, err := newManagementInstalledContext(ctx, owner, source.originals.binding, source.originals.retained)
	if err != nil { return nil, nil, nil, ErrUnavailable }
	defer func() { if !success { cancel() } }()
	paused := d101custody.Original{Bytes: bytes.Clone(pausedOriginal.Bytes), SHA256: pausedOriginal.SHA256}
	defer clear(paused.Bytes)
	if Hash(paused.Bytes) != paused.SHA256 || ctx.Err() != nil { return nil, nil, nil, ErrUnavailable }
	frozen, err := bindInstalledManagementPausedChild(derived, source, expectedNative, paused)
	if err != nil || frozen == nil || frozen.originals != source.originals || frozen.recheck(derived) != nil ||
		recheckHeldInstalledNativeOwner(derived, source, expectedNative) != nil { return nil, nil, nil, ErrUnavailable }
	// Both caller links stay owned after successful return. Core construction
	// consumes this exact cancellation resource, never the native parent's.
	held.mu.Lock()
	if held.state != managementClientBinding { held.mu.Unlock(); return nil, nil, nil, ErrUnavailable }
	prepCancel := held.ownedCancel
	var cancelOnce sync.Once
	ownedCancel := func() { cancelOnce.Do(func() { cancel(); if prepCancel != nil { prepCancel() } }) }
	held.ownedCancel = ownedCancel
	held.frozen = frozen
	frozen.cancelMu.Lock(); frozen.ownedCancel = ownedCancel; frozen.cancelMu.Unlock()
	held.mu.Unlock()
	expected := bytes.Clone(frozen.bindingWire) // Independent source bytes, before handshake.
	defer func() { if !success { clear(expected) } }()
	stream, err := newManagementInstalledStream(derived, frozen)
	if stream != nil { held.mu.Lock(); held.ownedStream = stream; held.mu.Unlock() }
	if err != nil { return nil, nil, nil, ErrUnavailable }
	// If construction consumes cancellation, the core owns stream/originals
	// even on error and performs its own joined cleanup. Do not double-close.
	session, err := OpenManagementClient(derived, stream, held)
	frozen.cancelMu.Lock(); coreOwned := frozen.ownedCancel == nil; frozen.cancelMu.Unlock()
	held.mu.Lock()
	held.coreOwned = coreOwned
	if session != nil { held.session = session }
	if err != nil || session == nil || !coreOwned || held.state != managementClientBinding {
		held.mu.Unlock(); return nil, nil, nil, ErrUnavailable
	}
	if !bytes.Equal(expected, frozen.bindingWire) || recheckHeldInstalledNativeOwner(derived, source, expectedNative) != nil || session.Recheck(derived) != nil {
		held.mu.Unlock(); return nil, nil, nil, ErrUnavailable
	}
	held.state = managementClientTransferred
	held.ownedCancel = nil // The same session owns cancellation and originals.
	held.mu.Unlock()
	success = true
	return held, session, expected, nil
}

// Session state never supplies native or human authority. All invalid events
// take the same mutex before any proof can be returned. Underlying close comes
// before joining readers; invalidation itself never joins its own watcher.
type ManagementSession struct {
	mu sync.Mutex
	stream net.Conn
	conn ssh.Conn
	channel ssh.Channel
	input *managementFrozenInput
	deadline time.Time
	sessionID []byte
	nonce string
	bound, consumed, invalid bool
	epoch uint64
	stop chan struct{}
	closeDone chan struct{}
	wake chan struct{}
	workers sync.WaitGroup
	closeErr error
	ownedOriginals *managementOriginalSet
	ownedCancel context.CancelFunc
	constructionDone chan struct{}
	finalizeDone chan struct{}
	constructionOnce sync.Once
	releaseOnce sync.Once
	releaseErr error
}
type ManagementConnectionBinding struct {
	session *ManagementSession
	epoch uint64
}

func (s *ManagementSession) markInvalidLocked() (net.Conn, chan struct{}, bool) {
	if s.invalid { return nil, nil, false }
	s.invalid = true
	s.bound = false
	s.epoch++
	if s.stop != nil { close(s.stop) }
	return s.stream, s.closeDone, true
}
func (s *ManagementSession) finishInvalidation(stream net.Conn, done chan struct{}) {
	s.mu.Lock(); cancel := s.ownedCancel; s.ownedCancel = nil; s.mu.Unlock()
	if cancel != nil { cancel() }
	if stream != nil {
		err := stream.Close()
		s.mu.Lock(); s.closeErr = err; s.mu.Unlock()
	}
	if done != nil { close(done) }
}
func (s *ManagementSession) invalidate() {
	if s == nil { return }
	s.mu.Lock()
	stream, done, first := s.markInvalidLocked()
	s.mu.Unlock()
	if first { s.finishInvalidation(stream, done) }
}
func (s *ManagementSession) finishConstruction() {
	if s == nil { return }
	s.constructionOnce.Do(func() { if s.constructionDone != nil { close(s.constructionDone) } })
}
func (s *ManagementSession) releaseOwned() {
	// Called only outside the worker group, after its members have exited.
	s.releaseOnce.Do(func() {
		err := s.ownedOriginals.Close()
		s.mu.Lock(); s.releaseErr = err; s.mu.Unlock()
	})
}
func (s *ManagementSession) finalizeInvalidation() {
	if s.finalizeDone != nil { defer close(s.finalizeDone) }
	// Construction may still add SSH watchers. Wait for that phase to end
	// before joining; this finalizer is deliberately not a member of workers.
	<-s.constructionDone
	<-s.closeDone
	s.workers.Wait()
	s.releaseOwned()
}
func (s *ManagementSession) Close() error {
	if s == nil { return nil }
	s.invalidate()
	s.mu.Lock(); closeDone := s.closeDone; s.mu.Unlock()
	if closeDone != nil { <-closeDone }
	if s.constructionDone != nil { <-s.constructionDone }
	s.workers.Wait()
	s.releaseOwned()
	if s.finalizeDone != nil { <-s.finalizeDone }
	s.mu.Lock(); defer s.mu.Unlock()
	return errors.Join(s.closeErr, s.releaseErr)
}
func (s *ManagementSession) shorten(ctx context.Context) error {
	if s == nil { return ErrUnavailable }
	if ctx == nil || ctx.Err() != nil { s.invalidate(); return ErrUnavailable }
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) { s.invalidate(); return ErrUnavailable }
	s.mu.Lock()
	if s.invalid || s.input == nil || s.input.ctx == nil || s.input.ctx.Err() != nil || !s.deadline.After(time.Now()) {
		s.mu.Unlock(); s.invalidate(); return ErrUnavailable
	}
	if deadline.Before(s.deadline) {
		s.deadline = deadline
		if s.stream == nil || s.stream.SetDeadline(deadline) != nil {
			s.mu.Unlock(); s.invalidate(); return ErrUnavailable
		}
		select { case s.wake <- struct{}{}: default: }
	}
	s.mu.Unlock()
	return nil
}
func (s *ManagementSession) Recheck(ctx context.Context) error {
	if s.shorten(ctx) != nil { return ErrUnavailable }
	if s.input.recheck(ctx) != nil { s.invalidate(); return ErrUnavailable }
	s.mu.Lock()
	if s.invalid || !s.bound || s.conn == nil || s.channel == nil || !s.deadline.After(time.Now()) ||
		s.input.ctx.Err() != nil || ctx.Err() != nil || !bytes.Equal(s.sessionID, s.conn.SessionID()) || !managementAlgorithms(s.conn) {
		stream, done, first := s.markInvalidLocked()
		s.mu.Unlock()
		if first { s.finishInvalidation(stream, done) }
		return ErrUnavailable
	}
	s.mu.Unlock()
	return nil
}
func (s *ManagementSession) Consume(ctx context.Context) (*ManagementConnectionBinding, error) {
	if s.Recheck(ctx) != nil { return nil, ErrUnavailable }
	s.mu.Lock(); defer s.mu.Unlock()
	if s.invalid || !s.bound || s.consumed || ctx.Err() != nil || s.input.ctx.Err() != nil || !s.deadline.After(time.Now()) {
		return nil, ErrUnavailable
	}
	s.consumed = true
	return &ManagementConnectionBinding{session: s, epoch: s.epoch}, nil
}
func (b *ManagementConnectionBinding) Recheck(ctx context.Context) error {
	if b == nil || b.session == nil || b.session.Recheck(ctx) != nil { return ErrUnavailable }
	s := b.session
	s.mu.Lock(); defer s.mu.Unlock()
	if s.invalid || !s.bound || !s.consumed || s.epoch != b.epoch || ctx.Err() != nil || s.input.ctx.Err() != nil || !s.deadline.After(time.Now()) {
		return ErrUnavailable
	}
	return nil
}

// RecheckExpected adds a same-tuple transport guard. The native owner must
// independently authenticate the expected existing wire; this method is no issuer.
func (b *ManagementConnectionBinding) RecheckExpected(ctx context.Context, expectedBindingWire []byte) error {
	if Missing(ctx) || ctx.Err() != nil || b.Recheck(ctx) != nil { return ErrUnavailable }
	expected, err := cloneManagementExpectedBindingWire(expectedBindingWire)
	if err != nil { return ErrUnavailable }
	defer clear(expected)
	s := b.session
	// Only local immutable/state comparisons run under the epoch mutex.
	// Actual source/lifetime rechecks remain outside it.
	same := func() bool {
		return !s.invalid && s.bound && s.consumed && s.epoch == b.epoch && s.input != nil && s.input.originals != nil &&
			s.input.ctx != nil && s.input.ctx.Err() == nil && ctx.Err() == nil && s.deadline.After(time.Now()) &&
			bytes.Equal(expected, s.input.bindingWire) && managementExpectedBindingMatches(expected, s.input.originals.binding)
	}
	s.mu.Lock()
	matched := same()
	s.mu.Unlock()
	if !matched || b.Recheck(ctx) != nil { return ErrUnavailable }
	s.mu.Lock()
	matched = same()
	s.mu.Unlock()
	if !matched { return ErrUnavailable }
	return nil
}

func cloneManagementExpectedBindingWire(wire []byte) ([]byte, error) {
	if len(wire) == 0 || len(wire) > PayloadMaxBytes { return nil, ErrUnavailable }
	copy := bytes.Clone(wire)
	var binding managementBindingWire
	if ssh.Unmarshal(copy, &binding) != nil || !managementValidBinding(binding) || !managementBindingSize(binding) || !bytes.Equal(copy, ssh.Marshal(&binding)) {
		clear(copy)
		return nil, ErrUnavailable
	}
	return copy, nil
}

// Equality of data alone supplies no authenticated session or native authority.
func managementExpectedBindingMatches(expected []byte, actual managementBindingWire) bool {
	return len(expected) > 0 && len(expected) <= PayloadMaxBytes && managementValidBinding(actual) && managementBindingSize(actual) && bytes.Equal(expected, ssh.Marshal(&actual))
}

func managementAlgorithms(conn ssh.Conn) bool {
	if conn == nil { return false }
	metadata, ok := conn.(ssh.AlgorithmsConnMetadata)
	if !ok || metadata == nil { return false }
	a := metadata.Algorithms()
	return a.KeyExchange == "curve25519-sha256" && a.HostKey == ssh.KeyAlgoED25519 &&
		a.Read.Cipher == "aes256-gcm@openssh.com" && a.Write.Cipher == "aes256-gcm@openssh.com" &&
		a.Read.MAC == "" && a.Write.MAC == ""
}
func managementSSHConfig() ssh.Config {
	return ssh.Config{KeyExchanges: []string{"curve25519-sha256"}, Ciphers: []string{"aes256-gcm@openssh.com"}}
}

// Counts actual handshake reads and writes against an enrolled bound. Only the
// package constructs this wrapper, after accepting ownership of a real stream.
type managementHandshakeConn struct {
	net.Conn
	mu sync.Mutex
	readMu, writeMu sync.Mutex
	remainingRead, remainingWrite int64
	complete bool
}
func (c *managementHandshakeConn) Read(p []byte) (int, error) {
	if c == nil || c.Conn == nil { return 0, ErrUnavailable }
	c.readMu.Lock(); defer c.readMu.Unlock()
	if len(p) == 0 { return 0, nil }
	c.mu.Lock()
	bounded := !c.complete
	if bounded {
		if c.remainingRead <= 0 { c.mu.Unlock(); return 0, ErrUnavailable }
		if int64(len(p)) > c.remainingRead { p = p[:int(c.remainingRead)] }
	}
	c.mu.Unlock()
	n, err := c.Conn.Read(p)
	if n < 0 || n > len(p) || n == 0 && err == nil { return 0, ErrUnavailable }
	c.mu.Lock(); if bounded { c.remainingRead -= int64(n) }; c.mu.Unlock()
	return n, err
}
func (c *managementHandshakeConn) Write(p []byte) (int, error) {
	if c == nil || c.Conn == nil { return 0, ErrUnavailable }
	c.writeMu.Lock(); defer c.writeMu.Unlock()
	if len(p) == 0 { return 0, nil }
	c.mu.Lock()
	bounded := !c.complete
	if bounded && int64(len(p)) > c.remainingWrite { c.mu.Unlock(); return 0, ErrUnavailable }
	c.mu.Unlock()
	n, err := c.Conn.Write(p)
	if n < 0 || n > len(p) { return 0, ErrUnavailable }
	c.mu.Lock(); if bounded { c.remainingWrite -= int64(n) }; c.mu.Unlock()
	if n != len(p) && err == nil { err = io.ErrShortWrite }
	return n, err
}
func (c *managementHandshakeConn) finish() { c.mu.Lock(); c.complete = true; c.mu.Unlock() }

func newManagementSession(ctx context.Context, stream net.Conn, f *managementFrozenInput) (*ManagementSession, error) {
	if f.recheck(ctx) != nil || !managementSupportedStream(stream) { return nil, ErrUnavailable }
	s := &ManagementSession{stream: stream, input: f, deadline: f.deadline, epoch: 1, stop: make(chan struct{}), closeDone: make(chan struct{}), wake: make(chan struct{}, 1),
		ownedOriginals: f.originals.integrity, ownedCancel: takeManagementInputCancel(f), constructionDone: make(chan struct{}), finalizeDone: make(chan struct{})}
	go s.finalizeInvalidation()
	if s.shorten(ctx) != nil || stream.SetDeadline(s.deadline) != nil { s.finishConstruction(); s.Close(); return nil, ErrUnavailable }
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			s.mu.Lock(); deadline := s.deadline; s.mu.Unlock()
			timer := time.NewTimer(time.Until(deadline))
			select {
			case <-s.stop: timer.Stop(); return
			case <-f.ctx.Done(): timer.Stop(); s.invalidate(); return
			case <-ctx.Done(): timer.Stop(); s.invalidate(); return
			case <-timer.C: s.invalidate(); return
			case <-s.wake: timer.Stop()
			case <-ticker.C:
				timer.Stop()
				if f.recheck(f.ctx) != nil { s.invalidate(); return }
			}
		}
	}()
	return s, nil
}

func (s *ManagementSession) observeConnection(conn ssh.Conn, requests <-chan *ssh.Request) {
	s.mu.Lock(); s.conn = conn; s.sessionID = bytes.Clone(conn.SessionID()); s.mu.Unlock()
	s.workers.Add(2)
	go func() { defer s.workers.Done(); conn.Wait(); s.invalidate() }()
	go func() {
		defer s.workers.Done()
		select {
		case <-s.stop: return
		case req, ok := <-requests:
			s.invalidate()
			if ok && req != nil && req.WantReply { req.Reply(false, nil) }
		}
	}()
}
func (s *ManagementSession) refuseChannels(channels <-chan ssh.NewChannel) {
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		select {
		case <-s.stop: return
		case channel, ok := <-channels:
			s.invalidate()
			if ok && channel != nil { channel.Reject(ssh.Prohibited, "unavailable") }
		}
	}()
}
func (s *ManagementSession) observeChannel(channel ssh.Channel, requests <-chan *ssh.Request) {
	s.mu.Lock(); s.channel = channel; s.mu.Unlock()
	s.workers.Add(2)
	go func() {
		defer s.workers.Done()
		select {
		case <-s.stop: return
		case req, ok := <-requests:
			s.invalidate()
			if ok && req != nil && req.WantReply { req.Reply(false, nil) }
		}
	}()
	go func() {
		defer s.workers.Done()
		var extra [1]byte
		channel.Stderr().Read(extra[:])
		s.invalidate()
	}()
}
func (s *ManagementSession) observePostBound(channel ssh.Channel) {
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		var extra [1]byte
		channel.Read(extra[:])
		s.invalidate()
	}()
}
func (s *ManagementSession) finishBound(channel ssh.Channel, nonce string) error {
	if !ValidNonce(nonce) || s.input.recheck(s.input.ctx) != nil { return ErrUnavailable }
	s.observePostBound(channel)
	s.mu.Lock(); defer s.mu.Unlock()
	if s.invalid || s.input.ctx.Err() != nil || !s.deadline.After(time.Now()) { return ErrUnavailable }
	s.nonce = nonce
	s.bound = true
	return nil
}

func managementReadFull(reader io.Reader, wire []byte) error {
	if reader == nil { return ErrUnavailable }
	for len(wire) != 0 {
		n, err := reader.Read(wire)
		if n <= 0 || n > len(wire) { return ErrUnavailable }
		wire = wire[n:]
		if err != nil && (err != io.EOF || len(wire) != 0) { return ErrUnavailable }
	}
	return nil
}
func managementFrameSize(frame managementFrame) bool {
	return managementStringsFit(4*4, len(frame.Kind), len(frame.SessionID), len(frame.Nonce), len(frame.BindingWire))
}
func managementReadFrame(reader io.Reader) (*managementFrame, error) {
	var header [4]byte
	if managementReadFull(reader, header[:]) != nil { return nil, ErrUnavailable }
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > PayloadMaxBytes { return nil, ErrUnavailable }
	body := make([]byte, int(length))
	defer clear(body)
	if managementReadFull(reader, body) != nil { return nil, ErrUnavailable }
	var frame managementFrame
	if ssh.Unmarshal(body, &frame) != nil || !managementFrameSize(frame) || !bytes.Equal(body, ssh.Marshal(&frame)) || !ValidNonce(frame.Nonce) ||
		len(frame.SessionID) == 0 || len(frame.BindingWire) == 0 { return nil, ErrUnavailable }
	frame.SessionID = bytes.Clone(frame.SessionID)
	frame.BindingWire = bytes.Clone(frame.BindingWire)
	return &frame, nil
}
func managementWriteFrame(writer io.Writer, frame managementFrame) error {
	if writer == nil || !managementFrameSize(frame) || !ValidNonce(frame.Nonce) || len(frame.SessionID) == 0 || len(frame.BindingWire) == 0 {
		return ErrUnavailable
	}
	body := ssh.Marshal(&frame)
	defer clear(body)
	if len(body) == 0 || len(body) > PayloadMaxBytes { return ErrUnavailable }
	wire := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(wire, uint32(len(body)))
	copy(wire[4:], body)
	defer clear(wire)
	for remaining := wire; len(remaining) != 0; {
		n, err := writer.Write(remaining)
		if err != nil || n <= 0 || n > len(remaining) { return ErrUnavailable }
		remaining = remaining[n:]
	}
	return nil
}
func (s *ManagementSession) expectFrame(reader io.Reader, kind, nonce string) (*managementFrame, error) {
	frame, err := managementReadFrame(reader)
	if err != nil || frame.Kind != kind || !bytes.Equal(frame.SessionID, s.sessionID) ||
		!bytes.Equal(frame.BindingWire, s.input.bindingWire) || (nonce != "" && frame.Nonce != nonce) {
		return nil, ErrUnavailable
	}
	return frame, nil
}
func (s *ManagementSession) sendFrame(writer io.Writer, kind, nonce string) error {
	return managementWriteFrame(writer, managementFrame{kind, s.sessionID, nonce, s.input.bindingWire})
}

func OpenManagementServer(ctx context.Context, stream net.Conn, input *ManagementServerInput) (*ManagementSession, error) {
	if input == nil || input.source == nil || input.source.originals == nil || input.source.hostSigner == nil ||
		input.frozen == nil || input.frozen.originals != input.source.originals || input.frozen.recheck(ctx) != nil {
		return nil, ErrUnavailable
	}
	f := input.frozen
	if input.source.hostSigner.PublicKey() == nil || !bytes.Equal(input.source.hostSigner.PublicKey().Marshal(), f.hostKey) {
		return nil, ErrUnavailable
	}
	s, err := newManagementSession(ctx, stream, f)
	if err != nil { return nil, ErrUnavailable }
	success := false
	defer func() { s.finishConstruction(); if !success { s.Close() } }()
	config := &ssh.ServerConfig{Config: managementSSHConfig(), MaxAuthTries: f.authTries, PublicKeyAuthAlgorithms: []string{ssh.KeyAlgoED25519}}
	var verified *ssh.Permissions
	var verifiedSession []byte
	config.PublicKeyCallback = func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if f.recheck(ctx) != nil || metadata.User() != f.user || key.Type() != ssh.KeyAlgoED25519 || !bytes.Equal(key.Marshal(), f.clientKey) {
			return nil, ErrUnavailable
		}
		return &ssh.Permissions{}, nil
	}
	config.VerifiedPublicKeyCallback = func(metadata ssh.ConnMetadata, key ssh.PublicKey, permissions *ssh.Permissions, algorithm string) (*ssh.Permissions, error) {
		if f.recheck(ctx) != nil || permissions == nil || metadata.User() != f.user || key.Type() != ssh.KeyAlgoED25519 ||
			algorithm != ssh.KeyAlgoED25519 || !bytes.Equal(key.Marshal(), f.clientKey) || len(metadata.SessionID()) == 0 {
			return nil, ErrUnavailable
		}
		verified = &ssh.Permissions{}
		verifiedSession = bytes.Clone(metadata.SessionID())
		return verified, nil
	}
	config.AddHostKey(input.source.hostSigner)
	bounded := &managementHandshakeConn{Conn: stream, remainingRead: f.handshakeBytes, remainingWrite: f.handshakeBytes}
	server, channels, requests, err := ssh.NewServerConn(bounded, config)
	if err != nil { return nil, ErrUnavailable }
	bounded.finish()
	s.observeConnection(server.Conn, requests)
	if verified == nil || server.Permissions != verified || server.User() != f.user ||
		!bytes.Equal(server.SessionID(), verifiedSession) || !managementAlgorithms(server.Conn) || f.recheck(ctx) != nil {
		return nil, ErrUnavailable
	}
	var offered ssh.NewChannel
	select { case <-s.stop: return nil, ErrUnavailable; case offered = <-channels: }
	if offered == nil || offered.ChannelType() != "session" || len(offered.ExtraData()) != 0 {
		s.invalidate(); if offered != nil { offered.Reject(ssh.Prohibited, "unavailable") }; return nil, ErrUnavailable
	}
	channel, channelRequests, err := offered.Accept()
	if err != nil { return nil, ErrUnavailable }
	s.refuseChannels(channels)
	var request *ssh.Request
	select { case <-s.stop: return nil, ErrUnavailable; case request = <-channelRequests: }
	payload := ssh.Marshal(&struct { Name string }{"d101-native-management"})
	if request == nil || request.Type != "subsystem" || !request.WantReply || !bytes.Equal(request.Payload, payload) || f.recheck(ctx) != nil {
		s.invalidate(); if request != nil && request.WantReply { request.Reply(false, nil) }; return nil, ErrUnavailable
	}
	if request.Reply(true, nil) != nil { return nil, ErrUnavailable }
	s.observeChannel(channel, channelRequests)
	var entropy [16]byte
	if f.recheck(ctx) != nil { return nil, ErrUnavailable }
	if _, err := io.ReadFull(rand.Reader, entropy[:]); err != nil { return nil, ErrUnavailable }
	nonce := hex.EncodeToString(entropy[:]); clear(entropy[:])
	if s.sendFrame(channel, "CHALLENGE", nonce) != nil { return nil, ErrUnavailable }
	if _, err := s.expectFrame(channel, "RESPONSE", nonce); err != nil { return nil, ErrUnavailable }
	if f.recheck(ctx) != nil || s.sendFrame(channel, "BOUND", nonce) != nil || s.finishBound(channel, nonce) != nil || s.Recheck(ctx) != nil {
		return nil, ErrUnavailable
	}
	success = true
	return s, nil
}

func OpenManagementClient(ctx context.Context, stream net.Conn, input *ManagementClientInput) (*ManagementSession, error) {
	if input == nil || input.source == nil || input.source.originals == nil || input.source.clientSigner == nil ||
		input.frozen == nil || input.frozen.originals != input.source.originals || input.frozen.recheck(ctx) != nil {
		return nil, ErrUnavailable
	}
	f := input.frozen
	if input.source.clientSigner.PublicKey() == nil || !bytes.Equal(input.source.clientSigner.PublicKey().Marshal(), f.clientKey) { return nil, ErrUnavailable }
	s, err := newManagementSession(ctx, stream, f)
	if err != nil { return nil, ErrUnavailable }
	success := false
	defer func() { s.finishConstruction(); if !success { s.Close() } }()
	hostVerified := false
	config := &ssh.ClientConfig{Config: managementSSHConfig(), User: f.user, HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Auth: []ssh.AuthMethod{ssh.PublicKeys(input.source.clientSigner)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if f.recheck(ctx) != nil || hostname != f.targetAddress || remote == nil || key.Type() != ssh.KeyAlgoED25519 || !bytes.Equal(key.Marshal(), f.hostKey) {
				return ErrUnavailable
			}
			hostVerified = true
			return nil
		}}
	bounded := &managementHandshakeConn{Conn: stream, remainingRead: f.handshakeBytes, remainingWrite: f.handshakeBytes}
	conn, channels, requests, err := ssh.NewClientConn(bounded, f.targetAddress, config)
	if err != nil { return nil, ErrUnavailable }
	bounded.finish()
	s.observeConnection(conn, requests)
	s.refuseChannels(channels)
	if !hostVerified || conn.User() != f.user || len(conn.SessionID()) == 0 || !managementAlgorithms(conn) || f.recheck(ctx) != nil { return nil, ErrUnavailable }
	channel, channelRequests, err := conn.OpenChannel("session", nil)
	if err != nil { return nil, ErrUnavailable }
	s.observeChannel(channel, channelRequests)
	payload := ssh.Marshal(&struct { Name string }{"d101-native-management"})
	ok, err := channel.SendRequest("subsystem", true, payload)
	if err != nil || !ok { return nil, ErrUnavailable }
	challenge, err := s.expectFrame(channel, "CHALLENGE", "")
	if err != nil || f.recheck(ctx) != nil || s.sendFrame(channel, "RESPONSE", challenge.Nonce) != nil { return nil, ErrUnavailable }
	if _, err := s.expectFrame(channel, "BOUND", challenge.Nonce); err != nil { return nil, ErrUnavailable }
	if s.finishBound(channel, challenge.Nonce) != nil || s.Recheck(ctx) != nil { return nil, ErrUnavailable }
	success = true
	return s, nil
}
