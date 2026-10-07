package d101native

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"errors"
	"path/filepath"
	"sync"
	"math"
	"net"
	"strings"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"opensamguk-deployer/internal/d101custody"
)

func managementTransportFixture(t *testing.T) (*ManagementTransport, *os.File) {
	t.Helper()
	if !managementLinuxAMD64() {
		t.Skip("actual Linux seqpacket/kernel credential fixture")
	}
	pair, err := syscall.Socketpair(syscall.AF_UNIX, managementSeqPacket, 0)
	if err != nil {
		t.Fatal(err)
	}
	in, out := os.NewFile(uintptr(pair[0]), "fixture-receiver"), os.NewFile(uintptr(pair[1]), "fixture-sender")
	t.Cleanup(func() { in.Close(); out.Close() })
	start, err := managementProcessStart(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	v, err := OpenManagementTransport(context.Background(), in, ManagementPeerObservation{uint32(os.Getpid()), start, uint32(os.Geteuid()), uint32(os.Getegid())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v, out
}

func TestManagementTransportActualKernelCredentialAndPacket(t *testing.T) {
	v, sender := managementTransportFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	want := []byte("unverified-original-data")
	if err := syscall.Sendmsg(int(sender.Fd()), want, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	got, err := v.ReadUnverified(ctx, 128)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("packet read failed: %v", err)
	}
	// This test exercises data integrity only; it creates no management
	// authentication, BootstrapLease, issuer or ReaderFactory authority.
}

func TestManagementTransportRejectsTruncationAndExportWithoutLeak(t *testing.T) {
	for _, mode := range []string{"truncated", "exported-descriptor", "wrong-credential"} {
		t.Run(mode, func(t *testing.T) {
			v, sender := managementTransportFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			payload := []byte("unverified")
			var oob []byte
			if mode == "truncated" {
				payload = bytes.Repeat([]byte("x"), 129)
			}
			if mode == "wrong-credential" {
				v.peer.UID++ // Frozen expectation deliberately disagrees with kernel.
			}
			if mode == "exported-descriptor" {
				f, err := os.CreateTemp(t.TempDir(), "ordinary-data")
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				oob = syscall.UnixRights(int(f.Fd()))
			}
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil || syscall.Sendmsg(int(sender.Fd()), payload, oob, nil, 0) != nil {
				t.Fatal("fixture send")
			}
			if wire, err := v.ReadUnverified(ctx, 128); err == nil || wire != nil {
				t.Fatal("invalid packet accepted")
			}
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(before) != len(after) {
				t.Fatal("rejected packet leaked descriptors")
			}
		})
	}
}

func TestManagementTransportCloseInterruptsBlockedReceive(t *testing.T) {
	v, _ := managementTransportFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := v.ReadUnverified(ctx, 128); done <- err }()
	readyBy := time.Now().Add(100 * time.Millisecond)
	for v.mu.TryLock() {
		v.mu.Unlock()
		if time.Now().After(readyBy) {
			t.Fatal("receive did not start")
		}
		time.Sleep(time.Millisecond)
	}
	started := time.Now()
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) >= 300*time.Millisecond {
		t.Fatal("close waited for the receive mutex")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed transport accepted a packet")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("close waited for the operation deadline")
	}
}

func managementSealedFixture(t *testing.T, seals uintptr) *os.File {
	t.Helper()
	if !managementLinuxAMD64() {
		t.Skip("actual Linux memfd seal fixture")
	}
	name := append([]byte("d101-fixture-carrier"), 0)
	// Linux amd64 SYS_MEMFD_CREATE=319; CLOEXEC|ALLOW_SEALING=3.
	fd, _, errno := syscall.RawSyscall(319, uintptr(unsafe.Pointer(&name[0])), 3, 0)
	runtime.KeepAlive(name)
	if errno != 0 {
		t.Fatal(errno)
	}
	f := os.NewFile(fd, "fixture-sealed-carrier")
	t.Cleanup(func() { f.Close() })
	if _, err := f.Write([]byte("unverified-carrier")); err != nil {
		t.Fatal(err)
	}
	_, _, errno = syscall.RawSyscall(managementSysFcntlAMD64, f.Fd(), 1033, seals)
	if errno != 0 {
		t.Fatal(errno)
	}
	return f
}

func TestManagementCarrierActualSealsAndIndependentExpectation(t *testing.T) {
	f := managementSealedFixture(t, managementRequiredSeals)
	want := []byte("unverified-carrier")
	got, err := ReadSealedManagementCarrier(context.Background(), f, Hash(want), uint64(len(want)))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("sealed carrier read")
	}
	if _, err := f.WriteAt([]byte("changed"), 0); err == nil {
		t.Fatal("kernel allowed mutation of fully sealed carrier")
	}
	if data, err := ReadSealedManagementCarrier(context.Background(), f, Hash([]byte("wrong")), uint64(len(want))); err == nil || data != nil {
		t.Fatal("adopted carrier hash")
	}
	missingWriteSeal := managementSealedFixture(t, managementRequiredSeals&^0x8)
	if data, err := ReadSealedManagementCarrier(context.Background(), missingWriteSeal, Hash(want), uint64(len(want))); err == nil || data != nil {
		t.Fatal("missing write seal accepted")
	}
}

// These fixtures exercise refusal and transport mechanics only. They never
// install an authenticated source, credential, signer, human grant or factory.
type managementRefusedStream struct { touches int }
func (c *managementRefusedStream) Read([]byte) (int, error) { c.touches++; return 0, io.EOF }
func (c *managementRefusedStream) Write([]byte) (int, error) { c.touches++; return 0, io.ErrClosedPipe }
func (c *managementRefusedStream) Close() error { c.touches++; return nil }
func (c *managementRefusedStream) LocalAddr() net.Addr { c.touches++; return nil }
func (c *managementRefusedStream) RemoteAddr() net.Addr { c.touches++; return nil }
func (c *managementRefusedStream) SetDeadline(time.Time) error { c.touches++; return nil }
func (c *managementRefusedStream) SetReadDeadline(time.Time) error { c.touches++; return nil }
func (c *managementRefusedStream) SetWriteDeadline(time.Time) error { c.touches++; return nil }

type managementNoAlgorithmsConn struct { ssh.Conn }
type managementWrongAlgorithmsConn struct { ssh.Conn }
func (managementWrongAlgorithmsConn) Algorithms() ssh.NegotiatedAlgorithms { return ssh.NegotiatedAlgorithms{} }

func TestInstalledManagementSourceRefusesBeforeStreamOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cancelled, stop := context.WithCancel(ctx); stop()
	for _, item := range []struct { name string; ctx context.Context }{
		{"nil", nil}, {"unbounded", context.Background()}, {"bounded", ctx}, {"cancelled", cancelled},
	} {
		t.Run(item.name, func(t *testing.T) {
			if session, err := OpenInstalledManagementServer(item.ctx); session != nil || err != ErrUnavailable { t.Fatal("installed server acquired missing source") }
			if _, session, _, err := OpenInstalledManagementClient(item.ctx, PreBinding{}, nil, d101custody.Original{}); session != nil || err != ErrUnavailable { t.Fatal("installed client acquired missing source") }
			stream := &managementRefusedStream{}
			if session, err := OpenManagementServer(item.ctx, stream, nil); session != nil || err != ErrUnavailable { t.Fatal("nil server input accepted") }
			if session, err := OpenManagementClient(item.ctx, stream, nil); session != nil || err != ErrUnavailable { t.Fatal("nil client input accepted") }
			if session, err := OpenManagementServer(item.ctx, stream, &ManagementServerInput{}); session != nil || err != ErrUnavailable { t.Fatal("zero server input accepted") }
			if session, err := OpenManagementClient(item.ctx, stream, &ManagementClientInput{}); session != nil || err != ErrUnavailable { t.Fatal("zero client input accepted") }
			if stream.touches != 0 { t.Fatal("refused input touched or closed caller stream") }
		})
	}
}

func TestManagementIntegrityCannotConstructAuthenticatedInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, item := range []struct { name string; source *heldManagementInstalledOriginals }{
		{"nil", nil}, {"zero", &heldManagementInstalledOriginals{}},
		{"wire-only", &heldManagementInstalledOriginals{binding: managementBindingWire{ScopeWire: []byte("unverified-data")}, user: "unverified-user", targetAddress: "unverified-target", authTries: 1, handshakeBytes: 1}},
	} {
		t.Run(item.name, func(t *testing.T) {
			if frozen, err := freezeManagementInput(ctx, item.source); frozen != nil || err != ErrUnavailable { t.Fatal("integrity promoted to authentication") }
			if input, err := newManagementServerInput(ctx, &heldInstalledManagementServerSource{originals: item.source}); input != nil || err != ErrUnavailable { t.Fatal("server source without enrollment accepted") }
			if input, err := newManagementClientInput(ctx, &heldInstalledManagementClientSource{originals: item.source}); input != nil || err != ErrUnavailable { t.Fatal("client source without enrollment accepted") }
			if stream, err := newManagementStdio(ctx, &managementFrozenInput{ctx: ctx, originals: item.source}); stream != nil || err != ErrUnavailable { t.Fatal("stdio opened without authenticated source") }
		})
	}
}

func TestManagementActiveDeadlineRejectsFallbackOrExtension(t *testing.T) {
	now := time.Now().Unix()
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(now+120, 0)); defer cancel()
	for _, item := range []struct { name string; cutoff, recovery uint64; retained bool; want int64 }{
		{"current-no-retained-grant", uint64(now+30), 0, false, now+30},
		{"current-cannot-use-later-recovery", uint64(now+30), uint64(now+90), false, now+30},
		{"retained-zero-cannot-fallback", uint64(now+90), 0, true, 0},
		{"retained-uses-own-original", uint64(now-1), uint64(now+30), true, now+30},
		{"retained-expired-cannot-use-cutoff", uint64(now+90), uint64(now-1), true, 0},
		{"current-expired-cannot-switch-purpose", uint64(now-1), uint64(now+90), false, 0},
		{"cutoff-int64-overflow", uint64(math.MaxInt64)+1, 0, false, 0},
		{"recovery-int64-overflow", uint64(now+30), uint64(math.MaxInt64)+1, false, 0},
		{"context-is-upper-bound", uint64(now+240), 0, false, now+120},
	} {
		t.Run(item.name, func(t *testing.T) {
			deadline, err := managementActiveDeadline(ctx, managementBindingWire{OriginalCutoffUnix: item.cutoff, OriginalRecoveryDeadlineUnix: item.recovery}, item.retained)
			if item.want == 0 {
				if err != ErrUnavailable || !deadline.IsZero() { t.Fatal("missing/expired original gained fallback") }
			} else if err != nil || deadline.Unix() != item.want { t.Fatal("active deadline extended or wrong original selected") }
		})
	}
	// A later method context cannot change the source constructor's frozen cap.
	t.Run("later-context-cannot-extend-session", func(t *testing.T) {
		frozen := time.Unix(now+30, 0)
		s := &ManagementSession{input: &managementFrozenInput{ctx: ctx}, deadline: frozen, stop: make(chan struct{}), wake: make(chan struct{}, 1)}
		defer s.Close()
		if s.shorten(ctx) != nil || !s.deadline.Equal(frozen) { t.Fatal("later context extended session") }
	})
	t.Run("unbounded-context-refused", func(t *testing.T) {
		if _, err := managementActiveDeadline(context.Background(), managementBindingWire{OriginalCutoffUnix: uint64(now+30)}, false); err != ErrUnavailable { t.Fatal("unbounded lifetime accepted") }
	})
}

func managementFrameFixture(frame managementFrame, extra []byte) []byte {
	body := append(ssh.Marshal(&frame), extra...)
	wire := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(wire, uint32(len(body)))
	copy(wire[4:], body)
	return wire
}

func TestManagementFramesRejectMalformedOrForeignBinding(t *testing.T) {
	frame := managementFrame{Kind: "RESPONSE", SessionID: []byte("actual-session-fixture"), Nonce: strings.Repeat("a", 32), BindingWire: []byte("independent-binding-fixture")}
	valid := managementFrameFixture(frame, nil)
	oversize := make([]byte, 4); binary.BigEndian.PutUint32(oversize, PayloadMaxBytes+1)
	zero := make([]byte, 4)
	badNonce := frame; badNonce.Nonce = strings.Repeat("A", 32)
	missingSession := frame; missingSession.SessionID = nil
	missingBinding := frame; missingBinding.BindingWire = nil
	for _, item := range []struct { name string; wire []byte }{
		{"header-short", valid[:3]}, {"body-short", valid[:len(valid)-1]}, {"zero", zero}, {"oversize", oversize},
		{"trailing-body", managementFrameFixture(frame, []byte{1})}, {"nonce-uppercase", managementFrameFixture(badNonce, nil)},
		{"missing-session", managementFrameFixture(missingSession, nil)}, {"missing-binding", managementFrameFixture(missingBinding, nil)},
	} {
		t.Run(item.name, func(t *testing.T) {
			if got, err := managementReadFrame(bytes.NewReader(item.wire)); got != nil || err != ErrUnavailable { t.Fatal("malformed frame accepted") }
		})
	}
	for _, item := range []struct { name string; mutate func(*managementFrame) }{
		{"wrong-kind", func(v *managementFrame) { v.Kind = "BOUND" }},
		{"wrong-session", func(v *managementFrame) { v.SessionID = []byte("other-session") }},
		{"wrong-nonce", func(v *managementFrame) { v.Nonce = strings.Repeat("b", 32) }},
		{"wrong-binding", func(v *managementFrame) { v.BindingWire = []byte("peer-supplied-binding") }},
	} {
		t.Run(item.name, func(t *testing.T) {
			changed := frame; item.mutate(&changed)
			s := &ManagementSession{sessionID: frame.SessionID, input: &managementFrozenInput{bindingWire: frame.BindingWire}}
			if got, err := s.expectFrame(bytes.NewReader(managementFrameFixture(changed, nil)), "RESPONSE", frame.Nonce); got != nil || err != ErrUnavailable { t.Fatal("foreign frame became independent expectation") }
		})
	}
}

func TestManagementUnsupportedStreamCannotBecomeSSHTransport(t *testing.T) {
	for _, item := range []struct { name string; stream net.Conn }{
		{"nil", nil}, {"caller-no-op-deadline", &managementRefusedStream{}}, {"unowned-stdio", &managementStdioConn{}},
	} {
		t.Run(item.name, func(t *testing.T) { if managementSupportedStream(item.stream) { t.Fatal("unsupported stream accepted") } })
	}
	t.Run("net-pipe-wrapper", func(t *testing.T) {
		in, out := net.Pipe(); defer in.Close(); defer out.Close()
		if managementSupportedStream(in) { t.Fatal("arbitrary in-memory wrapper accepted") }
	})
	t.Run("fd6-seqpacket", func(t *testing.T) {
		if !managementLinuxAMD64() { t.Skip("actual Linux seqpacket") }
		pair, err := syscall.Socketpair(syscall.AF_UNIX, managementSeqPacket, 0)
		if err != nil { t.Fatal(err) }
		in, out := os.NewFile(uintptr(pair[0]), "seqpacket-in"), os.NewFile(uintptr(pair[1]), "seqpacket-out")
		defer in.Close(); defer out.Close()
		conn, err := net.FileConn(in); if err != nil { t.Fatal(err) }; defer conn.Close()
		if managementSupportedStream(conn) { t.Fatal("FD6 seqpacket reinterpreted as SSH stream") }
	})
}

func TestManagementAlgorithmMetadataHasNoFallback(t *testing.T) {
	for _, item := range []struct { name string; conn ssh.Conn }{
		{"nil", nil}, {"missing-actual-algorithms", managementNoAlgorithmsConn{}}, {"wrong-negotiated-policy", managementWrongAlgorithmsConn{}},
	} {
		t.Run(item.name, func(t *testing.T) { if managementAlgorithms(item.conn) { t.Fatal("missing/wrong negotiated algorithms accepted") } })
	}
}

func TestManagementInvalidationInterruptsReaderAndDeniesProof(t *testing.T) {
	in, out := net.Pipe(); defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second); defer cancel()
	s := &ManagementSession{stream: in, input: &managementFrozenInput{ctx: ctx}, deadline: time.Now().Add(time.Second), epoch: 1,
		bound: true, consumed: true, stop: make(chan struct{}), closeDone: make(chan struct{}), wake: make(chan struct{}, 1)}
	s.workers.Add(1)
	started := make(chan struct{})
	go func() { defer s.workers.Done(); close(started); var b [1]byte; in.Read(b[:]); s.invalidate() }()
	<-started
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case err := <-closed: if err != nil { t.Fatal(err) }
	case <-ctx.Done(): t.Fatal("close did not interrupt/join owned reader")
	}
	if !s.invalid || s.bound || s.epoch != 2 { t.Fatal("invalidation was not monotone") }
	if s.Recheck(ctx) != ErrUnavailable { t.Fatal("invalid session rechecked") }
	if binding, err := s.Consume(ctx); binding != nil || err != ErrUnavailable { t.Fatal("invalid session consumed") }
	if (&ManagementConnectionBinding{session: s, epoch: 1}).Recheck(ctx) != ErrUnavailable { t.Fatal("old binding survived session close") }
	if s.Close() != nil || s.epoch != 2 { t.Fatal("repeat close changed epoch") }
}

func TestManagementZeroSessionAndBindingNeverMintProof(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second); defer cancel()
	for _, item := range []struct { name string; session *ManagementSession }{{"nil", nil}, {"zero", &ManagementSession{}}} {
		t.Run(item.name, func(t *testing.T) {
			if item.session.Recheck(ctx) != ErrUnavailable { t.Fatal("zero session rechecked") }
			if binding, err := item.session.Consume(ctx); binding != nil || err != ErrUnavailable { t.Fatal("zero session consumed") }
			if item.session.Close() != nil { t.Fatal("zero close failed") }
		})
	}
	for _, binding := range []*ManagementConnectionBinding{nil, {}, {session: &ManagementSession{}}} {
		if binding.Recheck(ctx) != ErrUnavailable { t.Fatal("zero binding acquired authority") }
	}
}

// Deliberately unauthenticated observer fixtures: no keys, algorithm metadata,
// approved source or successful management binding is supplied.
type managementNegativeChannel struct { net.Conn }
func (c managementNegativeChannel) CloseWrite() error { return ErrUnavailable }
func (c managementNegativeChannel) SendRequest(string, bool, []byte) (bool, error) { return false, ErrUnavailable }
func (c managementNegativeChannel) Stderr() io.ReadWriter { return c.Conn }
type managementNegativeWaitConn struct { ssh.Conn; stream net.Conn }
func (c managementNegativeWaitConn) SessionID() []byte { return nil }
func (c managementNegativeWaitConn) Wait() error { var b [1]byte; _, err := c.stream.Read(b[:]); return err }

func TestManagementObserversInvalidateUnexpectedQueuesDataOrEOF(t *testing.T) {
	for _, mode := range []string{"global-request", "global-queue-closed", "reverse-channel-queue-closed", "channel-request", "channel-queue-closed", "extended-data", "channel-eof", "connection-wait-eof", "post-bound-extra-data", "post-bound-eof"} {
		t.Run(mode, func(t *testing.T) {
			in, out := net.Pipe(); defer out.Close()
			if out.SetWriteDeadline(time.Now().Add(time.Second)) != nil { t.Fatal("fixture write deadline") }
			s := &ManagementSession{stream: in, epoch: 1, stop: make(chan struct{}), closeDone: make(chan struct{}), wake: make(chan struct{}, 1)}
			defer s.Close()
			requests := make(chan *ssh.Request, 1)
			channels := make(chan ssh.NewChannel)
			channel := managementNegativeChannel{in}
			switch mode {
			case "global-request", "global-queue-closed", "connection-wait-eof":
				s.observeConnection(managementNegativeWaitConn{stream: in}, requests)
				if mode == "global-request" { requests <- &ssh.Request{Type: "unavailable"} }
				if mode == "global-queue-closed" { close(requests) }
				if mode == "connection-wait-eof" { out.Close() }
			case "reverse-channel-queue-closed":
				s.refuseChannels(channels); close(channels)
			case "channel-request", "channel-queue-closed", "extended-data", "channel-eof":
				s.observeChannel(channel, requests)
				if mode == "channel-request" { requests <- &ssh.Request{Type: "exec"} }
				if mode == "channel-queue-closed" { close(requests) }
				if mode == "extended-data" { if _, err := out.Write([]byte{1}); err != nil && err != io.ErrClosedPipe { t.Fatal(err) } }
				if mode == "channel-eof" { out.Close() }
			case "post-bound-extra-data", "post-bound-eof":
				s.observePostBound(channel)
				if mode == "post-bound-extra-data" { if _, err := out.Write([]byte{1}); err != nil && err != io.ErrClosedPipe { t.Fatal(err) } } else { out.Close() }
			}
			select { case <-s.stop: case <-time.After(time.Second): t.Fatal("observer did not invalidate") }
			if s.Close() != nil { t.Fatal("observer workers did not terminate cleanly") }
			s.mu.Lock(); invalid, epoch := s.invalid, s.epoch; s.mu.Unlock()
			if !invalid || epoch != 2 { t.Fatal("observed invalid event did not advance epoch once") }
		})
	}
}

// P1 fixtures hold local integrity bytes only, without an authenticated issuer,
// source constructor, key, signer, enrollment or positive management session.
func managementOriginalFixtureP1(t *testing.T) (context.Context, []RawRef, [][]byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil { t.Fatal(err) }
	if err := os.Chmod(parent, 0700); err != nil { t.Fatal(err) }
	wires := [][]byte{[]byte("first-private-original"), []byte("second-private-original")}
	paths := []string{filepath.Join(parent, "first"), filepath.Join(parent, "second")}
	for i, path := range paths { if err := os.WriteFile(path, wires[i], 0400); err != nil { t.Fatal(err) } }
	parentInfo, err := os.Lstat(parent)
	if err != nil { t.Fatal(err) }
	parentStat := parentInfo.Sys().(*syscall.Stat_t)
	refs := make([]RawRef, len(paths))
	for i, path := range paths {
		info, err := os.Lstat(path)
		if err != nil { t.Fatal(err) }
		stat := info.Sys().(*syscall.Stat_t)
		refs[i] = RawRef{Path: path, Bytes: uint64(len(wires[i])), SHA256: Hash(wires[i]), Native: NativePin{
			Device: uint64(stat.Dev), Inode: uint64(stat.Ino), OwnerUID: stat.Uid, Mode: 0400, Links: uint64(stat.Nlink),
			ParentDevice: uint64(parentStat.Dev), ParentInode: uint64(parentStat.Ino)}}
	}
	return ctx, refs, wires
}
func managementHoldFixtureP1(t *testing.T, ctx context.Context, refs []RawRef) *managementOriginalSet {
	t.Helper()
	set, err := holdManagementOriginalsUID(ctx, refs, uint32(os.Geteuid()))
	if err != nil || set == nil { t.Fatal("local integrity acquisition failed", err) }
	t.Cleanup(func() { set.Close() })
	return set
}
func managementDescriptorCountP1(t *testing.T) int {
	t.Helper()
	path := "/dev/fd"
	if runtime.GOOS == "linux" { path = "/proc/self/fd" }
	// Names only: statting /dev/fd entries may encounter an already closed
	// descriptor. The directory's own FD is present in both inventories.
	directory, err := os.Open(path)
	if err != nil { t.Fatal("actual descriptor directory unavailable", err) }
	names, readErr := directory.Readdirnames(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil { t.Fatal("actual descriptor enumeration unavailable", errors.Join(readErr, closeErr)) }
	count := 0
	for _, name := range names {
		numeric := name != ""
		for i := 0; i < len(name); i++ {
			if name[i] < '0' || name[i] > '9' { numeric = false; break }
		}
		if numeric { count++ }
	}
	if count == 0 { t.Fatal("actual descriptor enumeration contained no numeric FD names") }
	return count
}

func TestManagementOriginalCopiesDoNotAuthenticateP1(t *testing.T) {
	ctx, refs, wires := managementOriginalFixtureP1(t)
	set := managementHoldFixtureP1(t, ctx, refs)
	refs[0].Path, refs[0].SHA256, refs[0].Native.Inode = "/untrusted/replacement", strings.Repeat("0", 64), 0
	copies, err := set.copyOriginals(ctx)
	if err != nil || len(copies) != 2 || !bytes.Equal(copies[0], wires[0]) || !bytes.Equal(copies[1], wires[1]) { t.Fatal("originals not independently cloned") }
	copies[0][0] ^= 1
	again, err := set.copyOriginals(ctx)
	if err != nil || !bytes.Equal(again[0], wires[0]) { t.Fatal("borrowed output changed retained bytes") }
	originals := &heldManagementInstalledOriginals{integrity: set}
	if originals.recheck(ctx) != ErrUnavailable { t.Fatal("integrity became authentication") }
	if f, err := freezeManagementInput(ctx, originals); f != nil || err != ErrUnavailable { t.Fatal("integrity issued input") }
	stream := &managementRefusedStream{}
	if s, err := OpenManagementServer(ctx, stream, &ManagementServerInput{}); s != nil || err != ErrUnavailable || stream.touches != 0 { t.Fatal("missing auth touched stream") }
	file, parent, retained := set.entries[0].file, set.entries[0].parent, set.entries[0].wire
	if set.Close() != nil || set.Close() != nil { t.Fatal("owned close was not idempotent") }
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) { t.Fatal("owned file retained after close") }
	if _, err := parent.Stat(); !errors.Is(err, os.ErrClosed) { t.Fatal("owned parent retained after close") }
	if !bytes.Equal(retained, make([]byte, len(retained))) { t.Fatal("retained bytes not cleared") }
	if got, err := set.copyOriginals(ctx); got != nil || err != ErrUnavailable { t.Fatal("closed originals copied") }
}

func TestManagementOriginalSetRejectsMutationP1(t *testing.T) {
	for _, mode := range []string{"same-length-content-restored-time", "file-replaced", "parent-replaced", "symlink", "permissions", "hard-link", "truncated", "parent-permissions", "held-file-closed", "held-parent-closed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, refs, wires := managementOriginalFixtureP1(t)
			set := managementHoldFixtureP1(t, ctx, refs)
			path, parent := refs[1].Path, filepath.Dir(refs[1].Path)
			must := func(err error) { t.Helper(); if err != nil { t.Fatal(err) } }
			switch mode {
			case "same-length-content-restored-time":
				info, err := os.Stat(path); must(err)
				must(os.Chmod(path, 0600)); changed := bytes.Clone(wires[1]); changed[0] ^= 1
				must(os.WriteFile(path, changed, 0600)); must(os.Chmod(path, 0400)); must(os.Chtimes(path, info.ModTime(), info.ModTime()))
			case "file-replaced": must(os.Rename(path, path+".old")); must(os.WriteFile(path, wires[1], 0400))
			case "parent-replaced":
				old := parent+".moved"; must(os.Rename(parent, old)); t.Cleanup(func() { os.RemoveAll(old) })
				must(os.Mkdir(parent, 0700)); must(os.WriteFile(path, wires[1], 0400))
			case "symlink": must(os.Rename(path, path+".old")); must(os.Symlink(path+".old", path))
			case "permissions": must(os.Chmod(path, 0600))
			case "hard-link": must(os.Link(path, path+".alias"))
			case "truncated": must(os.Chmod(path, 0600)); must(os.Truncate(path, int64(refs[1].Bytes-1))); must(os.Chmod(path, 0400))
			case "parent-permissions": must(os.Chmod(parent, 0755))
			case "held-file-closed": must(set.entries[1].file.Close())
			case "held-parent-closed": must(set.entries[1].parent.Close())
			}
			if set.recheck(ctx) != ErrUnavailable { t.Fatal("changed sibling accepted") }
			if got, err := set.copyOriginals(ctx); got != nil || err != ErrUnavailable { t.Fatal("partial original set exposed") }
		})
	}
}

func TestManagementOriginalAcquisitionCleansPartialFailureP1(t *testing.T) {
	for _, mode := range []string{"nil-context", "unbounded-context", "cancelled-context", "expired-context", "empty", "too-many", "invalid-path", "oversize", "duplicate-path", "duplicate-inode", "wrong-sha-second", "missing-second", "symlink-second", "wrong-parent-second", "wrong-owner"} {
		t.Run(mode, func(t *testing.T) {
			ctx, refs, _ := managementOriginalFixtureP1(t)
			uid := uint32(os.Geteuid())
			switch mode {
			case "nil-context": ctx = nil
			case "unbounded-context": ctx = context.Background()
			case "cancelled-context": c, cancel := context.WithCancel(ctx); cancel(); ctx = c
			case "expired-context": c, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second)); defer cancel(); ctx = c
			case "empty": refs = nil
			case "too-many": refs = make([]RawRef, 257)
			case "invalid-path": refs[0].Path = "relative"
			case "oversize": refs[0].Bytes = PayloadMaxBytes+1
			case "duplicate-path": refs[1].Path = refs[0].Path
			case "duplicate-inode": refs[1].Native.Device, refs[1].Native.Inode = refs[0].Native.Device, refs[0].Native.Inode
			case "wrong-sha-second": refs[1].SHA256 = strings.Repeat("0", 64)
			case "missing-second": if err := os.Remove(refs[1].Path); err != nil { t.Fatal(err) }
			case "symlink-second":
				if err := os.Rename(refs[1].Path, refs[1].Path+".old"); err != nil { t.Fatal(err) }
				if err := os.Symlink(refs[1].Path+".old", refs[1].Path); err != nil { t.Fatal(err) }
			case "wrong-parent-second": refs[1].Native.ParentInode++
			case "wrong-owner": uid++
			}
			before := managementDescriptorCountP1(t)
			if got, err := holdManagementOriginalsUID(ctx, refs, uid); got != nil || err != ErrUnavailable { if got != nil { got.Close() }; t.Fatal("invalid original acquired") }
			if after := managementDescriptorCountP1(t); after != before { t.Fatal("partial acquisition leaked descriptors", before, after) }
		})
	}
}

func TestManagementOriginalLifetimeRejectsCancellationP1(t *testing.T) {
	for _, mode := range []string{"owner-cancel", "caller-cancel", "caller-expired", "caller-unbounded"} {
		t.Run(mode, func(t *testing.T) {
			ctx, refs, _ := managementOriginalFixtureP1(t)
			owner, cancelOwner := context.WithCancel(ctx); defer cancelOwner()
			set := managementHoldFixtureP1(t, owner, refs)
			caller := ctx
			switch mode {
			case "owner-cancel": cancelOwner()
			case "caller-cancel": c, cancel := context.WithCancel(ctx); cancel(); caller = c
			case "caller-expired": c, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second)); defer cancel(); caller = c
			case "caller-unbounded": caller = context.Background()
			}
			if set.recheck(caller) != ErrUnavailable { t.Fatal("dead original lifetime accepted") }
			if got, err := set.copyOriginals(caller); got != nil || err != ErrUnavailable { t.Fatal("dead original bytes copied") }
		})
	}
}

type managementFaultReaderP1 struct { n int; err error }
func (r managementFaultReaderP1) Read([]byte) (int, error) { return r.n, r.err }
type managementFaultWriterP1 struct { n int; err error; touches int; wire []byte; short bool }
func (w *managementFaultWriterP1) Write(p []byte) (int, error) {
	w.touches++
	if w.short { n := len(p); if n > 3 { n = 3 }; w.wire = append(w.wire, p[:n]...); return n, nil }
	return w.n, w.err
}
func managementFrameFixtureP1() managementFrame {
	return managementFrame{Kind: "bound", SessionID: []byte("local-integrity-session-id"), Nonce: strings.Repeat("a", 32), BindingWire: []byte("unverified-binding")}
}

func TestManagementFrameReadRejectsProgressErrorsP1(t *testing.T) {
	frame := managementFrameFixtureP1()
	body := ssh.Marshal(&frame); wire := make([]byte, len(body)+4); binary.BigEndian.PutUint32(wire, uint32(len(body))); copy(wire[4:], body)
	for _, item := range []struct { name string; reader io.Reader }{
		{"nil", nil}, {"zero-progress", managementFaultReaderP1{}}, {"negative-count", managementFaultReaderP1{n:-1}},
		{"over-count", managementFaultReaderP1{n:5}}, {"read-error", managementFaultReaderP1{n:1, err:io.ErrClosedPipe}},
		{"header-short", bytes.NewReader(wire[:3])}, {"body-short", bytes.NewReader(wire[:len(wire)-1])},
		{"oversize-header", bytes.NewReader([]byte{0,1,0,1})},
	} {
		t.Run(item.name, func(t *testing.T) { if got, err := managementReadFrame(item.reader); got != nil || err != ErrUnavailable { t.Fatal("invalid progress accepted") } })
	}
	got, err := managementReadFrame(bytes.NewReader(wire))
	if err != nil || got == nil || !bytes.Equal(got.SessionID, frame.SessionID) || !bytes.Equal(got.BindingWire, frame.BindingWire) { t.Fatal("frame body cleanup destroyed returned data") }
}

func TestManagementFrameWriteRejectsErrorsAndAggregateOverflowP1(t *testing.T) {
	frame := managementFrameFixtureP1()
	for _, mode := range []string{"nil", "zero-progress", "negative-count", "over-count", "write-error", "aggregate-overflow", "uint32-sized-field"} {
		t.Run(mode, func(t *testing.T) {
			candidate := frame
			writer := &managementFaultWriterP1{}
			var output io.Writer = writer
			switch mode {
			case "nil": output = nil
			case "negative-count": writer.n = -1
			case "over-count": writer.n = PayloadMaxBytes+5
			case "write-error": writer.n, writer.err = 1, io.ErrClosedPipe
			case "aggregate-overflow": candidate.BindingWire = make([]byte, PayloadMaxBytes)
			case "uint32-sized-field": candidate.Kind = strings.Repeat("x", PayloadMaxBytes+1)
			}
			if managementWriteFrame(output, candidate) != ErrUnavailable { t.Fatal("invalid write accepted") }
			if (mode == "aggregate-overflow" || mode == "uint32-sized-field") && writer.touches != 0 { t.Fatal("oversize frame touched writer") }
		})
	}
	writer := &managementFaultWriterP1{short:true}
	if managementWriteFrame(writer, frame) != nil || writer.touches < 2 { t.Fatal("short writes not completed") }
	got, err := managementReadFrame(bytes.NewReader(writer.wire))
	if err != nil || !bytes.Equal(got.BindingWire, frame.BindingWire) { t.Fatal("short writes changed wire") }
	atLimit := frame
	atLimit.BindingWire = make([]byte, PayloadMaxBytes-16-len(frame.Kind)-len(frame.SessionID)-len(frame.Nonce))
	if !managementFrameSize(atLimit) || len(ssh.Marshal(&atLimit)) != PayloadMaxBytes { t.Fatal("existing payload ceiling changed") }
	atLimit.BindingWire = append(atLimit.BindingWire, 0)
	if managementFrameSize(atLimit) { t.Fatal("aggregate payload overflow accepted") }
}

func TestManagementBindingAggregateBoundsP1(t *testing.T) {
	b := managementBindingWire{OperationID:"data", ScopeWire:[]byte("scope")}
	if !managementBindingSize(b) || len(ssh.Marshal(&b)) != 10*4+2*4+4*8+len(b.OperationID)+len(b.ScopeWire) { t.Fatal("tuple16 size calculation changed wire") }
	b.ScopeWire = make([]byte, PayloadMaxBytes-80-len(b.OperationID))
	if !managementBindingSize(b) || len(ssh.Marshal(&b)) != PayloadMaxBytes { t.Fatal("binding ceiling mismatch") }
	b.ScopeWire = append(b.ScopeWire, 0)
	if managementBindingSize(b) { t.Fatal("aggregate binding overflow accepted") }
	if managementStringsFit(0, math.MaxInt, math.MaxInt) { t.Fatal("integer overflow accepted") }
}

type managementFaultConnP1 struct { net.Conn; reader io.Reader; writer io.Writer }
func (c *managementFaultConnP1) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *managementFaultConnP1) Write(p []byte) (int, error) { return c.writer.Write(p) }
func TestManagementHandshakeRejectsShortAndInvalidIOP1(t *testing.T) {
	for _, mode := range []string{"read-exhausted", "read-zero-progress", "read-negative", "read-over-count", "read-error", "write-exhausted", "write-short", "write-negative", "write-over-count", "write-error", "nil-connection"} {
		t.Run(mode, func(t *testing.T) {
			writer := &managementFaultWriterP1{}
			conn := &managementHandshakeConn{Conn:&managementFaultConnP1{reader:bytes.NewReader([]byte("ab")), writer:writer}, remainingRead:1, remainingWrite:1}
			switch mode {
			case "nil-connection": conn.Conn = nil
			case "read-exhausted": conn.remainingRead = 0
			case "read-zero-progress": conn.Conn = &managementFaultConnP1{reader:managementFaultReaderP1{}}
			case "read-negative": conn.Conn = &managementFaultConnP1{reader:managementFaultReaderP1{n:-1}}
			case "read-over-count": conn.Conn = &managementFaultConnP1{reader:managementFaultReaderP1{n:2}}
			case "read-error": conn.Conn = &managementFaultConnP1{reader:managementFaultReaderP1{err:io.ErrClosedPipe}}
			case "write-exhausted": conn.remainingWrite = 0
			case "write-short": writer.n = 0
			case "write-negative": writer.n = -1
			case "write-over-count": writer.n = 2
			case "write-error": writer.err = io.ErrClosedPipe
			}
			var n int; var err error
			if strings.HasPrefix(mode, "write") { n, err = conn.Write([]byte{1}) } else { n, err = conn.Read(make([]byte, 2)) }
			if err == nil || n != 0 { t.Fatal("invalid handshake I/O accepted") }
		})
	}
	writer := &managementFaultWriterP1{short:true}
	conn := &managementHandshakeConn{Conn:&managementFaultConnP1{reader:bytes.NewReader([]byte("abc")), writer:writer}, remainingRead:2, remainingWrite:5}
	if n, err := conn.Read(make([]byte, 4)); n != 2 || err != nil || conn.remainingRead != 0 { t.Fatal("actual read budget not enforced") }
	if n, err := conn.Write([]byte("abcde")); n != 3 || err != io.ErrShortWrite || conn.remainingWrite != 2 { t.Fatal("actual partial write not counted") }
	if n, err := conn.Write([]byte("xy")); n != 2 || err != nil || conn.remainingWrite != 0 { t.Fatal("actual remaining write budget lost") }
}

func TestManagementStdioRejectsMissingClosedAndDeadlineErrorsP1(t *testing.T) {
	for _, mode := range []string{"nil", "zero", "closed", "regular-file-deadline"} {
		t.Run(mode, func(t *testing.T) {
			var conn *managementStdioConn
			if mode != "nil" { conn = &managementStdioConn{} }
			if mode == "closed" { conn.closed.Store(true) }
			if mode == "regular-file-deadline" {
				reader, err := os.CreateTemp(t.TempDir(), "reader"); if err != nil { t.Fatal(err) }; defer reader.Close()
				writer, err := os.CreateTemp(t.TempDir(), "writer"); if err != nil { t.Fatal(err) }; defer writer.Close()
				conn.reader, conn.writer = reader, writer
				if err := conn.SetDeadline(time.Now().Add(time.Second)); !errors.Is(err, os.ErrNoDeadline) { t.Fatal("actual unsupported deadline hidden", err) }
			} else {
				if _, err := conn.Read([]byte{1}); err != ErrUnavailable { t.Fatal("missing stdio read accepted") }
				if _, err := conn.Write([]byte{1}); err != ErrUnavailable { t.Fatal("missing stdio write accepted") }
				if conn.SetDeadline(time.Now().Add(time.Second)) == nil { t.Fatal("missing stdio deadline accepted") }
			}
			if conn.Close() != nil || conn.Close() != nil { t.Fatal("stdio close not safe/idempotent") }
		})
	}
}

func TestManagementOwnedReleaseFollowsWorkerJoinP1(t *testing.T) {
	ctx, refs, _ := managementOriginalFixtureP1(t)
	set := managementHoldFixtureP1(t, ctx, refs)
	file, parent := set.entries[0].file, set.entries[0].parent
	in, out := net.Pipe(); defer out.Close()
	s := &ManagementSession{stream:in, ownedOriginals:set, epoch:1, stop:make(chan struct{}), closeDone:make(chan struct{}), constructionDone:make(chan struct{}), wake:make(chan struct{},1)}
	go s.finalizeInvalidation()
	workerEntered, allowExit, workerExited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s.workers.Add(1)
	go func() {
		defer s.workers.Done(); close(workerEntered)
		var b [1]byte; in.Read(b[:]); s.invalidate()
		<-allowExit
		if _, err := file.Stat(); err != nil { t.Error("owned originals released before worker join", err) }
		close(workerExited)
	}()
	<-workerEntered
	s.finishConstruction()
	s.invalidate()
	if s.epoch != 2 || !s.invalid || s.bound { t.Fatal("invalid event not monotone") }
	if _, err := file.Stat(); err != nil { t.Fatal("release preceded join", err) }
	var closes sync.WaitGroup
	closed := make(chan error, 2)
	closes.Add(2)
	for i:=0; i<2; i++ { go func() { defer closes.Done(); closed <- s.Close() }() }
	close(allowExit)
	select { case <-workerExited: case <-ctx.Done(): t.Fatal("owned worker did not exit") }
	for i:=0; i<2; i++ { select { case err:=<-closed: if err != nil { t.Fatal(err) }; case <-ctx.Done(): t.Fatal("close self-joined or leaked worker") } }
	closes.Wait()
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) { t.Fatal("joined file not released") }
	if _, err := parent.Stat(); !errors.Is(err, os.ErrClosed) { t.Fatal("joined parent not released") }
	if proof, err := s.Consume(ctx); proof != nil || err != ErrUnavailable { t.Fatal("released integrity minted proof") }
}

// P2 exercises ordinary context/cancel ownership only. No fixture supplies an
// authenticated source, signer, enrollment or successful management session.
func TestManagementInstalledLifecycleRejectsMissingOwnerBoundsP2(t *testing.T) {
	for _, mode := range []string{"nil-caller", "nil-owner", "cancelled-caller", "cancelled-owner", "unbounded-owner-even-with-bounded-caller", "expired-owner"} {
		t.Run(mode, func(t *testing.T) {
			caller, cancelCaller := context.WithTimeout(context.Background(), time.Minute); defer cancelCaller()
			owner, cancelOwner := context.WithTimeout(context.Background(), time.Minute); defer cancelOwner()
			var callerContext, ownerContext context.Context = caller, owner
			switch mode {
			case "nil-caller": callerContext = nil
			case "nil-owner": ownerContext = nil
			case "cancelled-caller": cancelCaller()
			case "cancelled-owner": cancelOwner()
			case "unbounded-owner-even-with-bounded-caller": ownerContext = context.Background()
			case "expired-owner": expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second)); defer cancel(); ownerContext = expired
			}
			binding := managementBindingWire{OriginalCutoffUnix:uint64(time.Now().Add(30*time.Second).Unix())}
			if deadline, err := managementInstalledDeadline(callerContext, ownerContext, binding, false); !deadline.IsZero() || err != ErrUnavailable { t.Fatal("missing owner bound accepted") }
			if child, cancel, err := newManagementInstalledContext(callerContext, ownerContext, binding, false); child != nil || cancel != nil || err != ErrUnavailable { if cancel != nil { cancel() }; t.Fatal("missing bound created lifecycle resource") }
		})
	}
}

func TestManagementInstalledLifecycleRejectsAbsentActiveOriginalP2(t *testing.T) {
	for _, mode := range []string{"current-cutoff-zero", "current-expired-no-recovery-fallback", "cutoff-int64-overflow", "recovery-int64-overflow", "retained-zero-no-cutoff-fallback", "retained-expired-no-cutoff-fallback"} {
		t.Run(mode, func(t *testing.T) {
			owner, cancelOwner := context.WithTimeout(context.Background(), time.Minute); defer cancelOwner()
			binding := managementBindingWire{OriginalCutoffUnix:uint64(time.Now().Add(30*time.Second).Unix()), OriginalRecoveryDeadlineUnix:uint64(time.Now().Add(40*time.Second).Unix())}
			retained := false
			switch mode {
			case "current-cutoff-zero": binding.OriginalCutoffUnix = 0
			case "current-expired-no-recovery-fallback": binding.OriginalCutoffUnix = uint64(time.Now().Add(-time.Second).Unix())
			case "cutoff-int64-overflow": binding.OriginalCutoffUnix = uint64(math.MaxInt64)+1
			case "recovery-int64-overflow": binding.OriginalRecoveryDeadlineUnix = uint64(math.MaxInt64)+1
			case "retained-zero-no-cutoff-fallback": retained = true; binding.OriginalRecoveryDeadlineUnix = 0
			case "retained-expired-no-cutoff-fallback": retained = true; binding.OriginalRecoveryDeadlineUnix = uint64(time.Now().Add(-time.Second).Unix())
			}
			if child, cancel, err := newManagementInstalledContext(context.Background(), owner, binding, retained); child != nil || cancel != nil || err != ErrUnavailable { if cancel != nil { cancel() }; t.Fatal("absent original replaced by other bound") }
		})
	}
}

func TestManagementInstalledLifecycleMinimumIsNotAuthenticationP2(t *testing.T) {
	for _, mode := range []string{"owner-earliest", "active-original-earliest", "caller-earliest", "background-caller-bounded-ordinary-owner-still-untrusted"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			ownerDeadline, callerDeadline := now.Add(40*time.Second), now.Add(30*time.Second)
			binding := managementBindingWire{OriginalCutoffUnix:uint64(now.Add(20*time.Second).Unix()), OriginalRecoveryDeadlineUnix:uint64(now.Add(25*time.Second).Unix())}
			want := time.Unix(int64(binding.OriginalCutoffUnix), 0)
			if mode == "owner-earliest" { ownerDeadline = now.Add(10*time.Second); want = ownerDeadline }
			if mode == "caller-earliest" { callerDeadline = now.Add(10*time.Second); want = callerDeadline }
			owner, cancelOwner := context.WithDeadline(context.Background(), ownerDeadline); defer cancelOwner()
			boundedCaller, cancelCaller := context.WithDeadline(context.Background(), callerDeadline); defer cancelCaller()
			var caller context.Context = boundedCaller
			if mode == "background-caller-bounded-ordinary-owner-still-untrusted" { caller = context.Background() }
			child, cancel, err := newManagementInstalledContext(caller, owner, binding, false)
			if err != nil || child == nil || cancel == nil { t.Fatal("ordinary bounded minimum failed", err) }; defer cancel()
			deadline, ok := child.Deadline(); if !ok || !deadline.Equal(want) { t.Fatal("ordinary minimum was extended", deadline, want) }
			originals := &heldManagementInstalledOriginals{ownerContext:owner, binding:binding}
			if derived, cancel, err := managementInstalledSourceContext(caller, originals); derived != nil || cancel != nil || err != ErrUnavailable { if cancel != nil { cancel() }; t.Fatal("ordinary owner context authenticated source") }
			if f, err := freezeManagementInput(child, originals); f != nil || err != ErrUnavailable { t.Fatal("ordinary context issued input") }
			stream := &managementRefusedStream{}
			frozen := &managementFrozenInput{ctx:child, originals:originals, deadline:deadline}
			if session, err := newManagementSession(child, stream, frozen); session != nil || err != ErrUnavailable || stream.touches != 0 { t.Fatal("ordinary context acquired transport/session") }
			if stdio, err := newManagementStdio(child, frozen); stdio != nil || err != ErrUnavailable { t.Fatal("ordinary context acquired stdio") }
		})
	}
}

func TestManagementInstalledLifecycleCancellationReleasesLinkP2(t *testing.T) {
	for _, mode := range []string{"caller-cancel", "owner-cancel", "setup-cancel-race", "release-before-input-transfer", "release-after-input-transfer-before-session", "repeat-owned-release"} {
		t.Run(mode, func(t *testing.T) {
			owner, cancelOwner := context.WithTimeout(context.Background(), time.Minute); defer cancelOwner()
			caller, cancelCaller := context.WithCancel(context.Background()); defer cancelCaller()
			binding := managementBindingWire{OriginalCutoffUnix:uint64(time.Now().Add(30*time.Second).Unix())}
			var raced chan struct{}
			if mode == "setup-cancel-race" { raced = make(chan struct{}); go func() { cancelCaller(); close(raced) }() }
			child, cancel, err := newManagementInstalledContext(caller, owner, binding, false)
			if mode == "setup-cancel-race" {
				<-raced
				if err != nil { if err != ErrUnavailable || child != nil || cancel != nil { t.Fatal("raced failure retained resources") }; return }
			}
			if err != nil || child == nil || cancel == nil { t.Fatal("ordinary lifecycle setup failed", err) }; defer cancel()
			switch mode {
			case "caller-cancel": cancelCaller()
			case "owner-cancel": cancelOwner()
			case "release-before-input-transfer": cancel()
			case "release-after-input-transfer-before-session": f := &managementFrozenInput{ownedCancel:cancel}; cancel = nil; releaseManagementInputCancel(f); if takeManagementInputCancel(f) != nil { t.Fatal("input retained released cancel") }
			case "repeat-owned-release":
				f := &managementFrozenInput{ownedCancel:cancel}; cancel = nil
				var workers sync.WaitGroup; workers.Add(2)
				for i:=0; i<2; i++ { go func() { defer workers.Done(); releaseManagementInputCancel(f) }() }; workers.Wait()
				if takeManagementInputCancel(f) != nil { t.Fatal("repeated release retained cancel") }
			}
			select { case <-child.Done(): case <-time.After(time.Second): t.Fatal("linked child survived cancellation/release") }
			if mode != "owner-cancel" && owner.Err() != nil { t.Fatal("child cleanup cancelled borrowed owner") }
			if mode == "release-before-input-transfer" || mode == "release-after-input-transfer-before-session" || mode == "repeat-owned-release" {
				if caller.Err() != nil { t.Fatal("child cleanup cancelled borrowed caller") }
			}
		})
	}
}

func TestManagementInstalledLifecycleTransferCannotMintSessionP2(t *testing.T) {
	for _, mode := range []string{"refused-input-keeps-local-cancel", "transfer-before-watchers", "entry-cleanup-after-transfer-does-not-cancel-mechanics", "invalidated-close-cleans-once-and-denies-proof"} {
		t.Run(mode, func(t *testing.T) {
			owner, cancelOwner := context.WithTimeout(context.Background(), time.Minute); defer cancelOwner()
			binding := managementBindingWire{OriginalCutoffUnix:uint64(time.Now().Add(30*time.Second).Unix())}
			caller, cancelCaller := context.WithCancel(context.Background()); defer cancelCaller()
			child, cancel, err := newManagementInstalledContext(caller, owner, binding, false)
			if err != nil { t.Fatal(err) }
			defer cancel()
			// Count only calls to an actual ordinary child CancelFunc. This is
			// resource bookkeeping, never an authentication callback or issuer.
			var releaseMu sync.Mutex
			releaseCalls := 0
			ownedCancel := func() { releaseMu.Lock(); releaseCalls++; releaseMu.Unlock(); cancel() }
			released := func() int { releaseMu.Lock(); defer releaseMu.Unlock(); return releaseCalls }
			f := &managementFrozenInput{ctx:child, deadline:time.Now().Add(time.Second), originals:&heldManagementInstalledOriginals{ownerContext:owner}, ownedCancel:ownedCancel}
			if mode == "refused-input-keeps-local-cancel" {
				stream := &managementRefusedStream{}
				if session, err := newManagementSession(child, stream, f); session != nil || err != ErrUnavailable || stream.touches != 0 { t.Fatal("refused input minted session") }
				if child.Err() != nil { t.Fatal("refused core stole input cancel") }
				releaseManagementInputCancel(f)
				if child.Err() == nil || released() != 1 { t.Fatal("remaining input cancel not released exactly once") }
				return
			}
			// Only direct ownership bookkeeping on an unauthenticated zero session;
			// this does not call a successful core or synthesize SSH authentication.
			s := &ManagementSession{ownedCancel:takeManagementInputCancel(f)}
			if s.ownedCancel == nil || takeManagementInputCancel(f) != nil { t.Fatal("cancel not moved exactly once") }
			releaseManagementInputCancel(f)
			if child.Err() != nil { t.Fatal("entry defer cancelled transferred lifecycle") }
			if mode == "transfer-before-watchers" {
				if s.input != nil || released() != 0 { t.Fatal("bookkeeping fixture issued input or released before watchers") }
				s.workers.Wait() // Empty group: ownership is installed before any worker exists.
			}
			if mode == "entry-cleanup-after-transfer-does-not-cancel-mechanics" {
				cancelCaller()
				select { case <-child.Done(): case <-time.After(time.Second): t.Fatal("transferred lifecycle lost caller link") }
				if released() != 0 || s.ownedCancel == nil { t.Fatal("input defer stole session cleanup ownership") }
			}
			s.invalidate()
			if child.Err() == nil || s.ownedCancel != nil || !s.invalid || s.epoch != 1 { t.Fatal("first invalidation did not release transferred cancel") }
			if s.Close() != nil || s.Close() != nil || s.epoch != 1 || released() != 1 { t.Fatal("repeat invalidation changed epoch/cancel ownership") }
			if owner.Err() != nil { t.Fatal("session cancelled borrowed owner") }
			if proof, err := s.Consume(owner); proof != nil || err != ErrUnavailable { t.Fatal("cancel bookkeeping minted proof") }
			if (&ManagementConnectionBinding{session:s}).Recheck(owner) != ErrUnavailable { t.Fatal("cancel bookkeeping minted binding") }
		})
	}
}

// Only ordinary wire data: there is no enrolled key, authenticated source,
// actual native owner or successful management session in this fixture.
func managementExpectedBindingFixtureMR() managementBindingWire {
	return managementBindingWire{
		OperationID:strings.Repeat("a", 32), TargetFingerprint:strings.Repeat("1", 64), PublicationRevision:"7",
		ApprovedCardSHA256:strings.Repeat("2", 64), InstallerEnrollmentSHA256:strings.Repeat("3", 64), InstallerArtifactSHA256:strings.Repeat("4", 64),
		InstallerPID:71, InstallerStartTicks:100, InstallerParentPID:70, InstallerParentStartTicks:90,
		InstallerExePath:"/root/deployer", InstallerExeSHA256:strings.Repeat("5", 64), InstallerSourceSHA:strings.Repeat("6", 40),
		ScopeWire:[]byte("existing-unverified-scope"), OriginalCutoffUnix:uint64(time.Now().Add(time.Minute).Unix()), OriginalRecoveryDeadlineUnix:uint64(time.Now().Add(2*time.Minute).Unix()),
	}
}

func TestManagementExpectedBindingCanonicalCloneMR(t *testing.T) {
	for _, name := range []string{"nil", "empty", "oversize", "truncated", "trailing", "invalid-process", "noncanonical-revision", "invalid-scope", "valid-clone-data-only"} {
		t.Run(name, func(t *testing.T) {
			binding := managementExpectedBindingFixtureMR()
			switch name {
			case "invalid-process": binding.InstallerPID = 0
			case "noncanonical-revision": binding.PublicationRevision = "07"
			case "invalid-scope": binding.ScopeWire = nil
			}
			wire := ssh.Marshal(&binding)
			switch name {
			case "nil": wire = nil
			case "empty": wire = []byte{}
			case "oversize": wire = make([]byte, PayloadMaxBytes+1)
			case "truncated": wire = wire[:len(wire)-1]
			case "trailing": wire = append(wire, 0)
			}
			got, err := cloneManagementExpectedBindingWire(wire)
			if name != "valid-clone-data-only" {
				if got != nil || err != ErrUnavailable { t.Fatal("malformed expected tuple accepted") }
				return
			}
			before := bytes.Clone(wire)
			if err != nil || !bytes.Equal(got, before) || !managementExpectedBindingMatches(got, binding) { t.Fatal("valid ordinary tuple data was changed") }
			wire[0] ^= 1
			if !bytes.Equal(got, before) { t.Fatal("expected tuple retained an external slice alias") }
			clear(got)
		})
	}
}

func TestManagementExpectedBindingAll16FieldsMatchMR(t *testing.T) {
	for _, name := range []string{"equal-data-only", "operation-id", "target-fingerprint", "publication-revision", "approved-card-sha", "installer-enrollment-sha", "installer-artifact-sha", "installer-pid", "installer-start-ticks", "installer-parent-pid", "installer-parent-start-ticks", "installer-exe-path", "installer-exe-sha", "installer-source-sha", "scope-wire", "original-cutoff", "original-recovery-deadline"} {
		t.Run(name, func(t *testing.T) {
			actual := managementExpectedBindingFixtureMR()
			expected := ssh.Marshal(&actual)
			switch name {
			case "operation-id": actual.OperationID = strings.Repeat("b", 32)
			case "target-fingerprint": actual.TargetFingerprint = strings.Repeat("f", 64)
			case "publication-revision": actual.PublicationRevision = "8"
			case "approved-card-sha": actual.ApprovedCardSHA256 = strings.Repeat("f", 64)
			case "installer-enrollment-sha": actual.InstallerEnrollmentSHA256 = strings.Repeat("f", 64)
			case "installer-artifact-sha": actual.InstallerArtifactSHA256 = strings.Repeat("f", 64)
			case "installer-pid": actual.InstallerPID++
			case "installer-start-ticks": actual.InstallerStartTicks++
			case "installer-parent-pid": actual.InstallerParentPID++
			case "installer-parent-start-ticks": actual.InstallerParentStartTicks++
			case "installer-exe-path": actual.InstallerExePath = "/root/other-deployer"
			case "installer-exe-sha": actual.InstallerExeSHA256 = strings.Repeat("f", 64)
			case "installer-source-sha": actual.InstallerSourceSHA = strings.Repeat("f", 40)
			case "scope-wire": actual.ScopeWire = []byte("different-unverified-scope")
			case "original-cutoff": actual.OriginalCutoffUnix++
			case "original-recovery-deadline": actual.OriginalRecoveryDeadlineUnix++
			}
			if managementExpectedBindingMatches(expected, actual) != (name == "equal-data-only") { t.Fatal("one of the original tuple16 fields was ignored") }
		})
	}
}

func TestManagementRecheckExpectedUnavailableNeverMintsBindingMR(t *testing.T) {
	for _, name := range []string{"nil-receiver", "missing-context", "cancelled-context", "unbounded-context", "zero-binding", "raw-session", "unconsumed", "epoch-drift"} {
		t.Run(name, func(t *testing.T) {
			owner, ownerCancel := context.WithTimeout(context.Background(), time.Minute); defer ownerCancel()
			ctx := owner
			binding := managementExpectedBindingFixtureMR()
			wire := ssh.Marshal(&binding)
			proof := &ManagementConnectionBinding{}
			switch name {
			case "nil-receiver": proof = nil
			case "missing-context": ctx = nil
			case "cancelled-context": ownerCancel()
			case "unbounded-context": ctx = context.Background()
			case "raw-session", "unconsumed", "epoch-drift":
				deadline, _ := owner.Deadline()
				session := &ManagementSession{input:&managementFrozenInput{ctx:owner, deadline:deadline, bindingWire:bytes.Clone(wire), originals:&heldManagementInstalledOriginals{binding:binding, ownerContext:owner}}, deadline:deadline, bound:true, consumed:name != "unconsumed", epoch:1}
				proof.session = session; proof.epoch = 1
				if name == "epoch-drift" { proof.epoch = 2 }
				defer session.Close()
			}
			// The raw session cases are not positive live-epoch fixtures: the
			// independent source gate can reject them before epoch comparison.
			if proof.RecheckExpected(ctx, wire) != ErrUnavailable { t.Fatal("untrusted expected data minted a management binding") }
		})
	}
}


func TestManagementInstalledUnixSourceFirstNKPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second); defer cancel()
	cancelled, stop := context.WithCancel(ctx); stop()
	for _, name := range []string{"nil_frozen", "nil_actual_originals", "cancelled_owner", "unbounded_owner", "raw_unix_pointer_without_actual_source"} {
		t.Run(name, func(t *testing.T) {
			raw := &net.UnixConn{}
			o := &heldManagementInstalledOriginals{approvedUnix: raw, ownerContext: ctx}
			f := &managementFrozenInput{ctx: ctx, deadline: time.Now().Add(time.Second), originals: o}
			caller := ctx
			switch name {
			case "nil_frozen": f = nil
			case "nil_actual_originals": f.originals = nil
			case "cancelled_owner": caller = cancelled; o.ownerContext = cancelled
			case "unbounded_owner": caller = context.Background(); o.ownerContext = caller
			}
			if stream, err := newManagementInstalledStream(caller, f); stream != nil || err != ErrUnavailable { t.Fatal("raw Unix became authenticated carrier") }
			if o.approvedUnix != raw || ctx.Err() != nil { t.Fatal("source refusal adopted raw carrier or cancelled owner") }
		})
	}
}

func TestInstalledManagementClientPhaseRefusalNKPC(t *testing.T) {
	for _, name := range []string{"prechild_zero_native", "prechild_wellformed_native_missing_source", "prechild_paused_without_owner", "phase_two_nil_caller", "phase_two_foreign_native", "phase_two_hash_mismatch", "missing_actual_source_once", "already_binding", "already_transferred", "closed_owner", "pending_core_unavailable"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second); defer cancel()
			calls := 0
			input := &ManagementClientInput{state: managementClientHeld, ownerContext: ctx, ownedCancel: func() { calls++ }}
			expected := PreBinding{}
			paused := d101custody.Original{Bytes: []byte("unverified13"), SHA256: Hash([]byte("unverified13"))}
			caller := ctx
			switch name {
			case "prechild_zero_native": input = nil; paused = d101custody.Original{}
			case "prechild_wellformed_native_missing_source":
				input = nil; paused = d101custody.Original{}
				now := time.Now().UTC().Add(-time.Second)
				expected = PreBinding{SchemaVersion: 1, OperationID: strings.Repeat("c", 32), TargetFingerprint: strings.Repeat("d", 64),
					PublicationRevision: "7", OriginalCutoffUnix: now.Add(time.Hour).Unix(), PreAcquisitionApprovalRef: native9Ref("/fixture/actual-original", []byte("unverified original")),
					IssuerIdentity: "unverified-issuer", IssuerSPKISHA256: Hash([]byte("unverified issuer metadata")),
					Keeper: Keeper{Process: native9Process(), BirthNonce: strings.Repeat("e", 32), FD: 9,
						Lock: NativePin{Device: 1, Inode: 44, OwnerUID: 0, Mode: 0600, Links: 1, ParentDevice: 1, ParentInode: 3}}, IssuedAtUTC: now.Format(time.RFC3339Nano)}
				if !ValidBinding(expected) { t.Fatal("negative constraint shape invalid") }
			case "prechild_paused_without_owner": input = nil
			case "phase_two_nil_caller": caller = nil
			case "phase_two_foreign_native": expected.OperationID = "foreign"
			case "phase_two_hash_mismatch": paused.SHA256 = "wrong"
			case "already_binding": input.state = managementClientBinding; input.bindingDone = make(chan struct{}); close(input.bindingDone)
			case "already_transferred": input.state = managementClientTransferred
			case "closed_owner": if input.Close() != nil { t.Fatal("empty input close failed") }
			case "pending_core_unavailable":
				stream := &managementRefusedStream{}
				if session, err := OpenManagementClient(ctx, stream, input); session != nil || err != ErrUnavailable || stream.touches != 0 { t.Fatal("pending owner entered core transport") }
				if input.Close() != nil || calls != 1 { t.Fatal("pending owner cleanup lost") }
				return
			}
			if held, session, wire, err := OpenInstalledManagementClient(caller, expected, input, paused); held != nil || session != nil || wire != nil || err != ErrUnavailable { t.Fatal("invalid phase minted owner/session/expectation") }
			if input == nil { return }
			if name == "already_binding" || name == "already_transferred" {
				if calls != 0 { t.Fatal("competing/repeated call closed another transition") }
			} else if calls != 1 || input.state != managementClientClosed { t.Fatal("failed first transition did not close own preparation") }
			if _, _, _, err := OpenInstalledManagementClient(ctx, input.expectedNative, input, paused); err != ErrUnavailable { t.Fatal("repeated phase acquired owner") }
			if input.Close() != nil || calls != 1 { t.Fatal("cleanup was not once") }
		})
	}
}

func TestInstalledManagementClientCloseOwnershipNKPC(t *testing.T) {
	for _, name := range []string{"nil_input", "unprepared", "held_own_cancel", "transferred_same_session", "close_joins_binding"} {
		t.Run(name, func(t *testing.T) {
			native, stopNative := context.WithCancel(context.Background()); defer stopNative()
			client, stopClient := context.WithCancel(native); defer stopClient()
			calls := 0
			originals := &managementOriginalSet{}
			input := &ManagementClientInput{state: managementClientHeld,
				source: &heldInstalledManagementClientSource{originals: &heldManagementInstalledOriginals{integrity: originals}},
				ownerContext: client, ownedCancel: func() { calls++; stopClient() }}
			switch name {
			case "nil_input": input = nil
			case "unprepared": input.state = managementClientUnprepared
			case "transferred_same_session":
				input.state = managementClientTransferred; input.coreOwned = true
				input.session = &ManagementSession{ownedOriginals: originals, ownedCancel: input.ownedCancel}
				input.ownedCancel = nil
			case "close_joins_binding":
				input.state = managementClientBinding
				input.bindingDone = make(chan struct{})
				cancelled, returned := make(chan struct{}), make(chan error, 1)
				input.ownedCancel = func() { calls++; stopClient(); close(cancelled) }
				var doneOnce sync.Once
				finish := func() { doneOnce.Do(func() { close(input.bindingDone) }) }; defer finish()
				go func() { returned <- input.Close() }()
				select { case <-cancelled: case <-time.After(time.Second): t.Fatal("Close did not interrupt binding") }
				select { case <-returned: t.Fatal("Close returned before binding joined"); default: }
				finish()
				select { case err := <-returned: if err != nil { t.Fatal(err) }; case <-time.After(time.Second): t.Fatal("Close did not join binding") }
			}
			if input.Close() != nil || input.Close() != nil { t.Fatal("owned empty cleanup failed") }
			if native.Err() != nil { t.Fatal("client Close cancelled native owner") }
			if input == nil { if calls != 0 || originals.closed { t.Fatal("nil input adopted resources") }; return }
			if calls != 1 || client.Err() == nil || !originals.closed || input.state != managementClientClosed { t.Fatal("client originals/cancel cleanup not once") }
			if input.session != nil && !input.session.invalid { t.Fatal("transferred session was not closed") }
		})
	}
}
