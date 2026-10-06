package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const resetD101HostSessionSocket = "/etc/opensamguk/d101/host-session.sock"
const resetD101PreparedDomain = "OPENSAMGUK-D101-PREPARED-V1\n"

// Independent installed public verification and live authority only. No key is
// learned from the socket response; private signing keys never enter relay mode.
// Socket/UID/PID/inode facts are transport observations, not this authenticator.
type resetD101LiveSessionAuthenticator func(context.Context, string, string, string, resetD101RelayPeerObservation) error
type resetD101HostRelayInstallation struct {
	expected      resetD101PreparedProof
	keyID         string
	publicSPKI    []byte
	publicSPKISHA string
	authenticate  resetD101LiveSessionAuthenticator
}

var resetD101ReviewedHostRelay *resetD101HostRelayInstallation

type resetD101HostPreparedRelay struct {
	policy        resetD101HostRelayInstallation
	publicKey     ed25519.PublicKey
	credential    string
	client        *http.Client
	slots         chan struct{}
	admissionMu   sync.Mutex
	acceptedAtUTC string
}

func newResetD101HostPreparedRelay(p *resetD101HostRelayInstallation, credential string) (*resetD101HostPreparedRelay, error) {
	if p == nil || p.authenticate == nil || !validResetD101ServiceToken(credential) || !resetD101KeyID.MatchString(p.keyID) {
		return nil, errResetD101InstallationNotSupplied
	}
	key, err := resetD101PinnedPublicKey(p.publicSPKI, p.publicSPKISHA)
	if err != nil || !lifecycleJobIDRe.MatchString(p.expected.OperationID) ||
		!resetEvidenceSHA.MatchString(p.expected.ApprovalPlanSHA) || !resetEvidenceSHA.MatchString(p.expected.ExecutionReceiptSHA) {
		return nil, errResetExecutionEvidence
	}
	policy := *p
	policy.publicSPKI = bytes.Clone(p.publicSPKI)
	policy.expected.ImageDigests = cloneResetD101Strings(p.expected.ImageDigests)
	return &resetD101HostPreparedRelay{policy: policy, publicKey: key, credential: credential, slots: make(chan struct{}, 2)}, nil
}

// Existing getter ABI, original body/signature bytes, and original deadline.
// There is no container getter, stale original, redirect, proxy or cache fallback.
func (r *resetD101HostPreparedRelay) Read(ctx context.Context, op, planSHA, receiptSHA string) ([]byte, string, error) {
	return r.readWithCallTransport(ctx, op, planSHA, receiptSHA, func(call *resetD101RelayCall) http.RoundTripper { return call.transport() })
}

// Explicit transport seam is private to isolated fixtures; production above
// always captures the actual connected UNIX descriptor and retained native FDs.
func (r *resetD101HostPreparedRelay) readWithCallTransport(ctx context.Context, op, planSHA, receiptSHA string, transport func(*resetD101RelayCall) http.RoundTripper) ([]byte, string, error) {
	return r.readWithCallTransportClock(ctx, op, planSHA, receiptSHA, transport, time.Now)
}

// The clock seam belongs only to deterministic boundary fixtures. Production
// Read and transport entry above always use the actual wall clock.
func (r *resetD101HostPreparedRelay) readWithCallTransportClock(ctx context.Context, op, planSHA, receiptSHA string, transport func(*resetD101RelayCall) http.RoundTripper, clock func() time.Time) ([]byte, string, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || r.policy.authenticate == nil || transport == nil || clock == nil ||
		op != r.policy.expected.OperationID || planSHA != r.policy.expected.ApprovalPlanSHA || receiptSHA != r.policy.expected.ExecutionReceiptSHA {
		return nil, "", errResetExecutionEvidence
	}
	select {
	case r.slots <- struct{}{}:
	default:
		return nil, "", errResetExecutionEvidence
	}
	defer func() { <-r.slots }()
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	call := &resetD101RelayCall{ctx: bounded, policy: r.policy, op: op, plan: planSHA, receipt: receiptSHA}
	defer call.close()
	client := &http.Client{Transport: transport(call), Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if client.Transport == nil {
		return nil, "", errResetExecutionEvidence
	}
	request, err := http.NewRequestWithContext(bounded, http.MethodGet,
		"http://d101-host/operations/"+op+"/prepared-proof/"+planSHA+"/"+receiptSHA, nil)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	request.Header.Set("Authorization", "Bearer "+r.credential)
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	defer response.Body.Close()
	if call.witness == nil || call.checkNative == nil || call.checkNative(bounded) != nil || response.StatusCode != http.StatusOK || response.ContentLength > resetD101ResultMaxBytes {
		return nil, "", errResetExecutionEvidence
	}
	for _, field := range []string{"Cache-Control", "Content-Type", "X-D101-Prepared-Proof", "X-D101-Prepared-Sha256"} {
		if len(response.Header.Values(field)) != 1 {
			return nil, "", errResetExecutionEvidence
		}
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Type") != "application/json" {
		return nil, "", errResetExecutionEvidence
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, resetD101ResultMaxBytes+1))
	if err != nil || len(wire) == 0 || len(wire) > resetD101ResultMaxBytes || bounded.Err() != nil ||
		response.Header.Get("X-D101-Prepared-Sha256") != resetD101OriginalSHA(wire) {
		return nil, "", errResetExecutionEvidence
	}
	proof, err := decodeResetD101PreparedProof(wire)
	header := response.Header.Get("X-D101-Prepared-Proof")
	parts := strings.Split(header, ".")
	if err != nil || len(parts) != 2 || parts[0] != r.policy.keyID || requireResetD101RelayPreparedBinding(proof, r.policy.expected, clock()) != nil {
		return nil, "", errResetExecutionEvidence
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != parts[1] ||
		!ed25519.Verify(r.publicKey, append([]byte(resetD101PreparedDomain), wire...), signature) ||
		call.authenticate(r.policy, op, planSHA, receiptSHA) != nil || bounded.Err() != nil ||
		requireResetD101RelayPreparedBinding(proof, r.policy.expected, clock()) != nil {
		return nil, "", errResetExecutionEvidence
	}
	// Only authenticated, signed, canonical admission values reach this CAS.
	// Restart loses memory but never renews the immutable proof's time/cutoff;
	// mandatory actual host admission authentication must succeed again.
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	if call.authenticate(r.policy, op, planSHA, receiptSHA) != nil || requireResetD101RelayPreparedBinding(proof, r.policy.expected, clock()) != nil || bounded.Err() != nil {
		return nil, "", errResetExecutionEvidence
	}
	previous := r.acceptedAtUTC
	if previous != "" && previous != proof.AcceptedAtUTC {
		return nil, "", errResetExecutionEvidence
	}
	if previous == "" {
		r.acceptedAtUTC = proof.AcceptedAtUTC
	}
	// Only this call's pending CAS can be rolled back while holding the mutex.
	// No rejected/canceled/native-lost witness publishes a new admission value.
	if call.authenticate(r.policy, op, planSHA, receiptSHA) != nil || requireResetD101RelayPreparedBinding(proof, r.policy.expected, clock()) != nil || bounded.Err() != nil {
		r.acceptedAtUTC = previous
		return nil, "", errResetExecutionEvidence
	}

	return wire, header, nil
}

func requireResetD101RelayPreparedBinding(proof, expected resetD101PreparedProof, now time.Time) error {
	prepared, e1 := resetC4UTC(proof.PreparedAtUTC)
	accepted, e2 := resetC4UTC(proof.AcceptedAtUTC)
	if e1 != nil || e2 != nil || accepted.UTC().Format(time.RFC3339Nano) != proof.AcceptedAtUTC || prepared.UTC().Format(time.RFC3339Nano) != proof.PreparedAtUTC || now.Before(prepared) || now.Sub(prepared) >= resetPreflightMaxAge || accepted.After(prepared) ||
		now.Unix() >= proof.DestructiveCutoffUnix {
		return errResetExecutionEvidence
	}
	// These two values arise from this preparation's actual native journal.
	// Signature plus mandatory live host authentication bind them; all remaining
	// fields, including first admission and original cutoff, match installed pins.
	proof.PreparedAtUTC, expected.PreparedAtUTC = "", ""
	proof.PreparedJournalSHA, expected.PreparedJournalSHA = "", ""
	if expected.AcceptedAtUTC == "" {
		proof.AcceptedAtUTC = ""
	}
	if !reflect.DeepEqual(proof, expected) {
		return errResetExecutionEvidence
	}
	return nil
}

// No loadConfig, operation-store open/Recover, coordinator or signing factory.
func resetD101PreparedRelayHandler(credential string, installation *resetD101HostRelayInstallation) http.Handler {
	relay, _ := newResetD101HostPreparedRelay(installation, credential)
	prepared := resetD101HostSessionHandler(credential, relay.Read)
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if request.URL.Path != "/healthz" {
			prepared.ServeHTTP(w, request)
			return
		}
		if request.Method != http.MethodGet || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.RawPath != "" || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid health request"})
			return
		}
		if relay == nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "host relay unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "relay"})
	})
}

// Value-only native observations. Mandatory independent authenticator binds
// these to the actual keeper/source/admission and original uninterrupted life.
// SO_PEERCRED/PID/exe hash, even together, never authorize a session.
type resetD101RelayPeerObservation struct {
	DialDescriptor                                               uintptr
	PID, UID, GID                                                int32
	ParentPID                                                    int64
	Start, ParentStart                                           uint64
	ExecutablePath, ExecutableSHA                                string
	SocketDevice, SocketInode, ExecutableDevice, ExecutableInode uint64
}
type resetD101RelayPeerWitness struct {
	liveConn                             *net.UnixConn
	socket, stat, executable, parentStat *os.File
	observation                          resetD101RelayPeerObservation
	executableInfo                       os.FileInfo
}
type resetD101RelayCall struct {
	policy            resetD101HostRelayInstallation
	op, plan, receipt string
	ctx               context.Context
	mu                sync.Mutex
	dialed, closed    bool
	conn              net.Conn
	witness           *resetD101RelayPeerWitness
	checkNative       func(context.Context) error
}

// Transport close/cancel stops IO but retains the actual Dial FD until the
// call's final owner closure. No new FD is substituted after body EOF.
type resetD101RelayHeldConn struct{ net.Conn }

func (c *resetD101RelayHeldConn) Close() error { return c.Conn.SetDeadline(time.Now()) }
func (c *resetD101RelayCall) transport() *http.Transport {
	return &http.Transport{DisableKeepAlives: true, ResponseHeaderTimeout: 2 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.closed || c.dialed || network != "tcp" || address != "d101-host:80" || ctx.Err() != nil {
				return nil, errResetExecutionEvidence
			}
			c.dialed = true
			conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", resetD101HostSessionSocket)
			if err != nil {
				return nil, errResetExecutionEvidence
			}
			c.conn = conn
			unix, ok := conn.(*net.UnixConn)
			if !ok {
				return nil, errResetExecutionEvidence
			}
			raw, err := unix.SyscallConn()
			if err != nil {
				return nil, errResetExecutionEvidence
			}
			var socket *os.File
			var dialFD uintptr
			var captureErr error
			err = raw.Control(func(fd uintptr) {
				dialFD = fd
				duplicate, e := syscall.Dup(int(fd))
				if e != nil {
					captureErr = e
					return
				}
				syscall.CloseOnExec(duplicate)
				socket = os.NewFile(uintptr(duplicate), "held-actual-dial-socket")
			})
			if err != nil || captureErr != nil || socket == nil {
				if socket != nil {
					_ = socket.Close()
				}
				return nil, errResetExecutionEvidence
			}
			w, err := captureResetD101RelayPeer(ctx, socket, unix, dialFD)
			if err != nil {
				_ = socket.Close()
				return nil, errResetExecutionEvidence
			}
			c.witness = w
			c.checkNative = w.recheck
			if c.authenticate(c.policy, c.op, c.plan, c.receipt) != nil {
				return nil, errResetExecutionEvidence
			}
			return &resetD101RelayHeldConn{conn}, nil
		}}
}
func (c *resetD101RelayCall) authenticate(p resetD101HostRelayInstallation, op, plan, receipt string) error {
	if c == nil || c.witness == nil || c.checkNative == nil || c.checkNative(c.ctx) != nil || p.authenticate == nil ||
		p.authenticate(c.ctx, op, plan, receipt, c.witness.observation) != nil || c.checkNative(c.ctx) != nil || c.ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	return nil
}
func (c *resetD101RelayCall) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	if c.conn != nil {
		_ = c.conn.Close()
	}
	if c.witness != nil {
		c.witness.close()
	}
}
func (w *resetD101RelayPeerWitness) close() {
	if w != nil {
		for _, f := range []*os.File{w.socket, w.stat, w.executable, w.parentStat} {
			if f != nil {
				_ = f.Close()
			}
		}
	}
}
func resetD101RelayPeerCredentials(file *os.File) ([3]int32, error) {
	var credential [3]int32
	size := uint32(12)
	// Linux native entry only. No fallback guesses a credential on other hosts.
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || file == nil {
		return credential, errResetExecutionEvidence
	}
	_, _, err := syscall.Syscall6(syscall.SYS_GETSOCKOPT, file.Fd(), 1, 17, uintptr(unsafe.Pointer(&credential[0])), uintptr(unsafe.Pointer(&size)), 0)
	runtime.KeepAlive(file)
	if err != 0 || size != 12 || credential[0] <= 0 {
		return [3]int32{}, errResetExecutionEvidence
	}
	return credential, nil
}
func resetD101RelayReadProcess(file *os.File, pid int64) (int64, uint64, error) {
	if file == nil {
		return 0, 0, errResetExecutionEvidence
	}
	raw := make([]byte, 4097)
	n, err := file.ReadAt(raw, 0)
	if err != io.EOF || n == 0 || n > 4096 {
		return 0, 0, errResetExecutionEvidence
	}
	text := string(raw[:n])
	left := strings.Index(text, " (")
	right := strings.LastIndex(text, ") ")
	if left <= 0 || right <= left {
		return 0, 0, errResetExecutionEvidence
	}
	actual, e1 := strconv.ParseInt(text[:left], 10, 64)
	parts := strings.Fields(text[right+2:])
	if e1 != nil || actual != pid || len(parts) < 20 || parts[0] == "Z" || parts[0] == "X" {
		return 0, 0, errResetExecutionEvidence
	}
	parent, e2 := strconv.ParseInt(parts[1], 10, 64)
	start, e3 := strconv.ParseUint(parts[19], 10, 64)
	if e2 != nil || e3 != nil || parent <= 0 || start == 0 {
		return 0, 0, errResetExecutionEvidence
	}
	return parent, start, nil
}
func resetD101RelayReadExecutable(ctx context.Context, file *os.File) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || file == nil {
		return nil, errResetExecutionEvidence
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 32<<20 {
		return nil, errResetExecutionEvidence
	}
	wire := make([]byte, info.Size()+1)
	n, err := file.ReadAt(wire, 0)
	if err != io.EOF || int64(n) != info.Size() || ctx.Err() != nil {
		return nil, errResetExecutionEvidence
	}
	return wire[:n], nil
}
func captureResetD101RelayPeer(ctx context.Context, socket *os.File, conn *net.UnixConn, dialFD uintptr) (result *resetD101RelayPeerWitness, err error) {
	w := &resetD101RelayPeerWitness{socket: socket, liveConn: conn}
	defer func() {
		if err != nil {
			w.close()
		}
	}()
	creds, err := resetD101RelayPeerCredentials(socket)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	socketInfo, err := socket.Stat()
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 {
		return nil, errResetExecutionEvidence
	}
	st, ok := socketInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errResetExecutionEvidence
	}
	pid := int64(creds[0])
	prefix := "/proc/" + strconv.FormatInt(pid, 10)
	w.stat, err = os.Open(prefix + "/stat")
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	parent, start, err := resetD101RelayReadProcess(w.stat, pid)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	w.parentStat, err = os.Open("/proc/" + strconv.FormatInt(parent, 10) + "/stat")
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	_, parentStart, err := resetD101RelayReadProcess(w.parentStat, parent)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	path, err := os.Readlink(prefix + "/exe")
	if err != nil || !strings.HasPrefix(path, "/") || strings.HasSuffix(path, " (deleted)") {
		return nil, errResetExecutionEvidence
	}
	w.executable, err = os.Open(prefix + "/exe")
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	w.executableInfo, err = w.executable.Stat()
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	exe, ok := w.executableInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errResetExecutionEvidence
	}
	wire, err := resetD101RelayReadExecutable(ctx, w.executable)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	w.observation = resetD101RelayPeerObservation{dialFD, creds[0], creds[1], creds[2], parent, start, parentStart, path, resetD101OriginalSHA(wire), uint64(st.Dev), uint64(st.Ino), uint64(exe.Dev), uint64(exe.Ino)}
	if w.recheck(ctx) != nil {
		return nil, errResetExecutionEvidence
	}
	return w, nil
}
func (w *resetD101RelayPeerWitness) recheck(ctx context.Context) error {
	if w == nil || w.liveConn == nil || w.socket == nil || w.stat == nil || w.executable == nil || w.parentStat == nil || ctx == nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	o := w.observation
	raw, err := w.liveConn.SyscallConn()
	if err != nil {
		return errResetExecutionEvidence
	}
	matched := false
	if raw.Control(func(fd uintptr) {
		var st syscall.Stat_t
		matched = fd == o.DialDescriptor && syscall.Fstat(int(fd), &st) == nil && uint64(st.Dev) == o.SocketDevice && uint64(st.Ino) == o.SocketInode
	}) != nil || !matched {
		return errResetExecutionEvidence
	}
	creds, e1 := resetD101RelayPeerCredentials(w.socket)
	parent, start, e2 := resetD101RelayReadProcess(w.stat, int64(o.PID))
	_, parentStart, e3 := resetD101RelayReadProcess(w.parentStat, o.ParentPID)
	actualExe, e4 := w.executable.Stat()
	visible, e5 := os.Stat(fmt.Sprintf("/proc/%d/exe", o.PID))
	path, e6 := os.Readlink(fmt.Sprintf("/proc/%d/exe", o.PID))
	wire, e7 := resetD101RelayReadExecutable(ctx, w.executable)
	socket, e8 := w.socket.Stat()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || e7 != nil || e8 != nil || creds != [3]int32{o.PID, o.UID, o.GID} || parent != o.ParentPID || start != o.Start || parentStart != o.ParentStart ||
		path != o.ExecutablePath || !os.SameFile(w.executableInfo, actualExe) || !os.SameFile(actualExe, visible) || actualExe.Size() != w.executableInfo.Size() || !actualExe.ModTime().Equal(w.executableInfo.ModTime()) || resetD101OriginalSHA(wire) != o.ExecutableSHA || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	native, ok := socket.Sys().(*syscall.Stat_t)
	if !ok || uint64(native.Dev) != o.SocketDevice || uint64(native.Ino) != o.SocketInode {
		return errResetExecutionEvidence
	}
	return nil
}
