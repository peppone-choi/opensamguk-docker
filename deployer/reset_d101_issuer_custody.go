package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101operatorauth"
	"opensamguk-deployer/internal/d101origin"
)

const resetD101IssuerLedgerDirectory = "/etc/opensamguk/d101/current-operator"

// Data/native facts are not keeper, policy, issuer or installer authority.
// Directory pins and quota/retention owner must be independently approved.
type resetD101IssuerDirectoryPin struct{ device, inode uint64 }
type resetD101NativeIssuerEmitter interface {
	IssueAndRetain(context.Context, *os.File, d101operatorauth.TechnicalIssuance) error
}
type resetD101IssuerLedgerInputs struct {
	operationID, jwtLogicalID, retentionOwner string
	policy                                    d101operatorauth.ReviewedPolicy
	directoryPin, oncePin                     resetD101IssuerDirectoryPin
	byteBudget, reserveBytes                  uint64
	retentionSeconds                          int64
	authenticate                              func(context.Context, *os.File, string, string) error
	emitter                                   resetD101NativeIssuerEmitter
}
type resetD101NativeIssuerCustody struct {
	mu                                                                      sync.Mutex
	inputs                                                                  resetD101IssuerLedgerInputs
	reservation, token, claim                                               []byte
	claimName                                                               string
	issued                                                                  bool
	reservationAttempted, tokenAttempted, claimAttempted, emissionAttempted bool
}

func newResetD101NativeIssuerCustody(v resetD101IssuerLedgerInputs) (*resetD101NativeIssuerCustody, error) {
	_, retained := v.emitter.(resetD101IssuerRetainedOriginals)
	if v.authenticate == nil || v.emitter == nil || (reflect.ValueOf(v.emitter).Kind() == reflect.Pointer && reflect.ValueOf(v.emitter).IsNil()) ||
		!retained ||
		!lifecycleJobIDRe.MatchString(v.operationID) || v.policy.Scope.OperationID != v.operationID ||
		!resetD101IssuerIdentity.MatchString(v.jwtLogicalID) || !strings.HasPrefix(v.jwtLogicalID, "raw:") ||
		!resetD101IssuerIdentity.MatchString(v.retentionOwner) || v.retentionSeconds < 7*24*60*60 ||
		v.byteBudget == 0 || v.byteBudget > 1<<30 || v.reserveBytes < 10<<30 ||
		v.directoryPin.device == 0 || v.directoryPin.inode == 0 || v.oncePin.device == 0 || v.oncePin.inode == 0 {
		return nil, errResetD101InstallationNotSupplied
	}
	if _, err := d101operatorauth.NewVerifier(v.policy); err != nil {
		return nil, errResetExecutionEvidence
	}
	v.policy = cloneResetD101TechnicalPolicy(v.policy)
	return &resetD101NativeIssuerCustody{inputs: v}, nil
}

func (c *resetD101NativeIssuerCustody) Authenticate(ctx context.Context, fd *os.File, op, phase string) (result error) {
	// A failed phase cannot leave issued descriptors available for a later
	// release attempt. Closing preserves every durable original and partial.
	var retained resetD101IssuerRetainedOriginals
	if c != nil {
		retained, _ = c.inputs.emitter.(resetD101IssuerRetainedOriginals)
	}
	defer func() {
		if result != nil && retained != nil {
			_ = retained.CloseRetained()
		}
	}()
	if c == nil || ctx == nil || ctx.Err() != nil || fd == nil || fd.Fd() != 9 || op != c.inputs.operationID || c.inputs.authenticate == nil {
		return errResetExecutionEvidence
	}
	if c.inputs.authenticate(ctx, fd, op, phase) != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	if phase == "issuer-pre-ready" || phase == "issuer-reserved" {
		availability, ok := c.inputs.emitter.(resetD101IssuerOriginalAvailability)
		if !ok || availability.AuthenticateAvailability(ctx, fd, cloneResetD101TechnicalPolicy(c.inputs.policy)) != nil || ctx.Err() != nil {
			return errResetExecutionEvidence
		}
	}
	root, err := openResetD101IssuerDirectory(resetD101IssuerLedgerDirectory, c.inputs.directoryPin, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	defer root.Close()
	once, err := openResetD101IssuerDirectory(filepath.Join(resetD101IssuerLedgerDirectory, ".once"), c.inputs.oncePin, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	defer once.Close()
	if resetD101IssuerLedgerBudget(root, once, c.inputs.byteBudget, c.inputs.reserveBytes, 0) != nil {
		return errResetExecutionEvidence
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, check := range []struct {
		dir  *os.File
		name string
		wire []byte
	}{{root, "op-" + op + ".reserve", c.reservation}, {root, "jwt-" + op + ".original", c.token}, {once, c.claimName, c.claim}} {
		if len(check.wire) > 0 && requireResetD101IssuerOwnedOriginal(check.dir, check.name, check.wire, 0) != nil {
			return errResetExecutionEvidence
		}
	}
	if phase == "issuer-release" && (!c.issued || len(c.claim) == 0 || len(c.token) == 0) {
		return errResetExecutionEvidence
	}
	retainedPhase := phase == "issuer-emission-retained" || phase == "issuer-release"
	if retainedPhase && (retained == nil || retained.AuthenticateRetained(ctx, fd, op, phase) != nil) {
		return errResetExecutionEvidence
	}
	if c.inputs.authenticate(ctx, fd, op, phase+"-after-native") != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	// The independent provider's final check cannot substitute for custody of
	// the actual three output descriptors. Recheck them after that callback.
	if retainedPhase && (retained.AuthenticateRetained(ctx, fd, op, phase) != nil || ctx.Err() != nil) {
		return errResetExecutionEvidence
	}
	if phase == "issuer-release" && retained.CloseRetained() != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func (c *resetD101NativeIssuerCustody) ReserveOperation(ctx context.Context, fd *os.File, policy d101operatorauth.ReviewedPolicy) error {
	if c == nil || c.Authenticate(ctx, fd, c.inputs.operationID, "issuer-before-reservation") != nil || !reflect.DeepEqual(policy, c.inputs.policy) {
		return errResetExecutionEvidence
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reservationAttempted || len(c.reservation) != 0 {
		return errResetExecutionEvidence
	}
	c.reservationAttempted = true
	// This has no pre-token JTI, and is an internal ledger, not an approval wire.
	wire, err := json.Marshal(struct {
		OperationID, PolicySHA, RetentionOwner string
		CreatedAtUTC                           string
		RetainAtLeastSeconds                   int64
	}{c.inputs.operationID, resetD101IssuerPolicySHA(policy), c.inputs.retentionOwner, time.Now().UTC().Format(time.RFC3339Nano), c.inputs.retentionSeconds})
	if err != nil {
		return errResetExecutionEvidence
	}
	root, err := openResetD101IssuerDirectory(resetD101IssuerLedgerDirectory, c.inputs.directoryPin, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	defer root.Close()
	// A failed/partial write stays present. A new process cannot replace it.
	if writeResetD101IssuerExclusive(root, "op-"+c.inputs.operationID+".reserve", wire, 0) != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	c.reservation = bytes.Clone(wire)
	return nil
}

func (c *resetD101NativeIssuerCustody) RetainJWT(ctx context.Context, fd *os.File, wire []byte, ref d101operatorauth.Reference) error {
	if c == nil || c.Authenticate(ctx, fd, c.inputs.operationID, "issuer-before-token-retention") != nil || len(wire) == 0 || len(wire) > 64<<10 || bytes.ContainsAny(wire, "\r\n\t ") ||
		ref.LogicalID != c.inputs.jwtLogicalID || ref.SHA256 != resetD101OriginalSHA(wire) || ref.ByteLength != uint64(len(wire)) || ref.MediaType != "text/plain" {
		return errResetExecutionEvidence
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.reservation) == 0 || c.tokenAttempted || len(c.token) != 0 {
		return errResetExecutionEvidence
	}
	c.tokenAttempted = true
	root, err := openResetD101IssuerDirectory(resetD101IssuerLedgerDirectory, c.inputs.directoryPin, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	defer root.Close()
	if requireResetD101IssuerOwnedOriginal(root, "op-"+c.inputs.operationID+".reserve", c.reservation, 0) != nil ||
		writeResetD101IssuerExclusive(root, "jwt-"+c.inputs.operationID+".original", wire, 0) != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	c.token = bytes.Clone(wire)
	return nil
}

func (c *resetD101NativeIssuerCustody) ClaimAuthenticatedIssuance(ctx context.Context, fd *os.File, issuance d101operatorauth.TechnicalIssuance) error {
	if c == nil || c.Authenticate(ctx, fd, c.inputs.operationID, "issuer-before-jti-claim") != nil {
		return errResetExecutionEvidence
	}
	scope, e1 := issuance.Scope()
	event, e2 := issuance.Event()
	approval, e3 := issuance.Issuer(d101operatorauth.ApprovalIssuerRole)
	receipt, e4 := issuance.Issuer(d101operatorauth.ApprovedReceiptIssuerRole)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || scope != c.inputs.policy.Scope || !reflect.DeepEqual(approval, c.inputs.policy.ApprovalIssuer) || !reflect.DeepEqual(receipt, c.inputs.policy.ReceiptIssuer) {
		return errResetExecutionEvidence
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.reservation) == 0 || len(c.token) == 0 || c.claimAttempted || len(c.claim) != 0 || event.AuthenticationOriginal.SHA256 != resetD101OriginalSHA(c.token) ||
		event.AuthenticationOriginal.LogicalID != c.inputs.jwtLogicalID || event.AuthenticationOriginal.ByteLength != uint64(len(c.token)) || event.AuthenticationOriginal.MediaType != "text/plain" || event.ActorID != c.inputs.policy.ActorID || event.RunID != c.inputs.policy.RunID ||
		event.WorkflowSHA != c.inputs.policy.WorkflowSHA || event.RunAttempt != 1 || event.ScopeDecisionOriginal != scope.FinalCard || !resetD101IssuerIdentity.MatchString(event.JTI) {
		return errResetExecutionEvidence
	}
	c.claimAttempted = true
	// C1 verifies the fixed official issuer before producing this typed event.
	// One global file for that issuer/JTI prevents reuse in another operation.
	claimSHA := resetD101OriginalSHA([]byte("https://token.actions.githubusercontent.com\x00" + event.JTI))
	wire, err := json.Marshal(struct {
		OperationID, IssuerJTIHash, PolicySHA, AuthenticationSHA, ApprovalIssuerSPKI, ReceiptIssuerSPKI string
		Scope                                                                                           d101operatorauth.TechnicalScope
	}{c.inputs.operationID, claimSHA, resetD101IssuerPolicySHA(c.inputs.policy), event.AuthenticationOriginal.SHA256, approval.PublicKeySPKISHA256, receipt.PublicKeySPKISHA256, scope})
	if err != nil {
		return errResetExecutionEvidence
	}
	once, err := openResetD101IssuerDirectory(filepath.Join(resetD101IssuerLedgerDirectory, ".once"), c.inputs.oncePin, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	defer once.Close()
	name := "issuer-jti-" + claimSHA + ".claim"
	if writeResetD101IssuerExclusive(once, name, wire, 0) != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	c.claimName = name
	c.claim = bytes.Clone(wire)
	return nil
}

func (c *resetD101NativeIssuerCustody) IssueAndRetainOriginals(ctx context.Context, fd *os.File, issuance d101operatorauth.TechnicalIssuance) (result error) {
	defer func() {
		if result != nil && c != nil {
			if retained, ok := c.inputs.emitter.(resetD101IssuerRetainedOriginals); ok {
				_ = retained.CloseRetained()
			}
		}
	}()
	if c == nil || c.inputs.emitter == nil || c.Authenticate(ctx, fd, c.inputs.operationID, "issuer-before-emission") != nil {
		return errResetExecutionEvidence
	}
	c.mu.Lock()
	claimed := len(c.claim) > 0 && !c.issued && !c.emissionAttempted
	if claimed {
		c.emissionAttempted = true
	}
	c.mu.Unlock()
	if !claimed || c.inputs.emitter.IssueAndRetain(ctx, fd, issuance) != nil || ctx.Err() != nil || c.Authenticate(ctx, fd, c.inputs.operationID, "issuer-emission-retained") != nil {
		return errResetExecutionEvidence
	}
	c.mu.Lock()
	c.issued = true
	c.mu.Unlock()
	return nil
}

func resetD101IssuerPolicySHA(policy d101operatorauth.ReviewedPolicy) string {
	wire, _ := json.Marshal(policy)
	return resetD101OriginalSHA(wire)
}

func openResetD101IssuerDirectory(path string, pin resetD101IssuerDirectoryPin, uid uint32) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || pin.device == 0 || pin.inode == 0 {
		return nil, errResetExecutionEvidence
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return nil, errResetExecutionEvidence
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	dir := os.NewFile(uintptr(fd), path)
	if requireResetD101IssuerDirectory(dir, pin, uid) != nil {
		dir.Close()
		return nil, errResetExecutionEvidence
	}
	return dir, nil
}

func requireResetD101IssuerDirectory(dir *os.File, pin resetD101IssuerDirectoryPin, uid uint32) error {
	actual, e1 := dir.Stat()
	visible, e2 := os.Lstat(dir.Name())
	if e1 != nil || e2 != nil || !actual.IsDir() || actual.Mode().Perm() != 0700 || !os.SameFile(actual, visible) {
		return errResetExecutionEvidence
	}
	stat, ok := actual.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || uint64(stat.Dev) != pin.device || uint64(stat.Ino) != pin.inode {
		return errResetExecutionEvidence
	}
	return nil
}

func resetD101IssuerFileMetadata(info os.FileInfo, uid uint32) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Nlink == 1
}

func writeResetD101IssuerExclusive(dir *os.File, name string, wire []byte, uid uint32) error {
	if dir == nil || name == "" || filepath.Base(name) != name || name == "." || name == ".." || len(wire) == 0 || len(wire) > 64<<10 {
		return errResetExecutionEvidence
	}
	info, err := dir.Stat()
	if err != nil {
		return errResetExecutionEvidence
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errResetExecutionEvidence
	}
	pin := resetD101IssuerDirectoryPin{uint64(stat.Dev), uint64(stat.Ino)}
	if requireResetD101IssuerDirectory(dir, pin, uid) != nil {
		return errResetExecutionEvidence
	}
	path := filepath.Join(dir.Name(), name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0400)
	if err != nil {
		return errResetExecutionEvidence
	}
	// Never unlink or overwrite on failure, including directory-sync uncertainty.
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !resetD101IssuerFileMetadata(before, uid) {
		return errResetExecutionEvidence
	}
	if n, err := file.Write(wire); err != nil || n != len(wire) || file.Sync() != nil {
		return errResetExecutionEvidence
	}
	after, err := file.Stat()
	visible, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !resetD101IssuerFileMetadata(after, uid) || !os.SameFile(before, after) || !os.SameFile(after, visible) || after.Size() != int64(len(wire)) || file.Close() != nil ||
		requireResetD101IssuerDirectory(dir, pin, uid) != nil || dir.Sync() != nil || requireResetD101IssuerOwnedOriginal(dir, name, wire, uid) != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func requireResetD101IssuerOwnedOriginal(dir *os.File, name string, expected []byte, uid uint32) error {
	if dir == nil || len(expected) == 0 || len(expected) > 64<<10 || filepath.Base(name) != name {
		return errResetExecutionEvidence
	}
	before, e1 := os.Lstat(filepath.Join(dir.Name(), name))
	if e1 != nil || !resetD101IssuerFileMetadata(before, uid) {
		return errResetExecutionEvidence
	}
	file, err := os.OpenFile(filepath.Join(dir.Name(), name), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !resetD101IssuerFileMetadata(actual, uid) || !os.SameFile(before, actual) || actual.Size() != int64(len(expected)) {
		return errResetExecutionEvidence
	}
	wire, err := io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
	after, e1 := file.Stat()
	visible, e2 := os.Lstat(filepath.Join(dir.Name(), name))
	if err != nil || e1 != nil || e2 != nil || !bytes.Equal(wire, expected) || !resetD101IssuerFileMetadata(after, uid) || !os.SameFile(actual, after) || !os.SameFile(after, visible) || after.Size() != actual.Size() || !after.ModTime().Equal(actual.ModTime()) {
		return errResetExecutionEvidence
	}
	return nil
}

func resetD101IssuerLedgerBudget(root, once *os.File, cap, reserve uint64, uid uint32) error {
	if root == nil || once == nil || cap == 0 || cap > 1<<30 || reserve < 10<<30 || reserve > ^uint64(0)-3*(64<<10) {
		return errResetExecutionEvidence
	}
	var total uint64
	for _, directory := range []*os.File{root, once} {
		// Fresh auxiliary directory stream; keeper FD9 is not closed/reopened.
		stream, err := os.OpenFile(directory.Name(), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return errResetExecutionEvidence
		}
		names, err := stream.Readdirnames(1025)
		_ = stream.Close()
		if len(names) > 1024 || err != nil && err != io.EOF {
			return errResetExecutionEvidence
		}
		for _, name := range names {
			if directory == root && name == ".once" {
				continue
			}
			validName := false
			if directory == root {
				validName = (strings.HasPrefix(name, "op-") && strings.HasSuffix(name, ".reserve") && lifecycleJobIDRe.MatchString(strings.TrimSuffix(strings.TrimPrefix(name, "op-"), ".reserve"))) ||
					(strings.HasPrefix(name, "jwt-") && strings.HasSuffix(name, ".original") && lifecycleJobIDRe.MatchString(strings.TrimSuffix(strings.TrimPrefix(name, "jwt-"), ".original")))
			} else {
				validName = strings.HasPrefix(name, "issuer-jti-") && strings.HasSuffix(name, ".claim") && resetEvidenceSHA.MatchString(strings.TrimSuffix(strings.TrimPrefix(name, "issuer-jti-"), ".claim"))
			}
			info, err := os.Lstat(filepath.Join(directory.Name(), name))
			if !validName || err != nil || !resetD101IssuerFileMetadata(info, uid) || info.Size() <= 0 {
				return errResetExecutionEvidence
			}
			n := uint64(info.Size())
			if n > cap-total {
				return errResetExecutionEvidence
			}
			total += n
		}
	}
	// Maximum one invocation: reservation + JWT + claim, each <=64KiB. Keep
	// that room before READY; native emitter's own evidence budget is separate.
	if cap-total < 3*(64<<10) {
		return errResetExecutionEvidence
	}
	var free syscall.Statfs_t
	if syscall.Fstatfs(int(root.Fd()), &free) != nil || uint64(free.Bsize) == 0 {
		return errResetExecutionEvidence
	}
	available := uint64(free.Bavail)
	block := uint64(free.Bsize)
	if available > ^uint64(0)/block || available*block < reserve+3*(64<<10) {
		return errResetExecutionEvidence
	}
	return nil
}

// Private per-GET native audit only. This is not a new signed wire/profile, and
// neither response SHA nor this unsigned record is independent capture proof.
type resetD101HostPreparedCustodyPins struct {
	operationID, directory, retentionOwner, purposeKeyID, purposeSPKISHA string
	directoryPin                                                         resetD101IssuerDirectoryPin
	installedSourceRef, nativeSessionRef, nativeKeeperWriterRef          resetD101FinalRawReference
	byteBudget, reserveBytes                                             uint64
	retentionSeconds                                                     int64
	authenticate                                                         func(context.Context, *os.File, string, string) error
}
type resetD101HostPreparedCustody struct {
	mu             sync.Mutex
	pins           resetD101HostPreparedCustodyPins
	sequence       uint64
	previousCommit []byte
	previousName   string
	previousInfo   os.FileInfo
	pending        bool
	stopped        bool
}
type resetD101PreparedPrivateRecord struct {
	Version                     int                        `json:"version"`
	OperationID                 string                     `json:"operationId"`
	ApprovalPlanSHA             string                     `json:"approvalPlanSHA"`
	ExecutionReceiptSHA         string                     `json:"executionReceiptSHA"`
	AcceptedAtUTC               string                     `json:"acceptedAtUTC"`
	PreparedJournalSHA          string                     `json:"preparedJournalSHA"`
	InstalledSourceRef          resetD101FinalRawReference `json:"installedSourceRef"`
	NativeSessionRef            resetD101FinalRawReference `json:"nativeSessionRef"`
	NativeKeeperWriterRef       resetD101FinalRawReference `json:"nativeKeeperWriterRef"`
	PurposeKeyID                string                     `json:"purposeKeyId"`
	PurposePublicSPKISHA        string                     `json:"purposePublicSpkiSHA"`
	RequestStartedAtUTC         string                     `json:"requestStartedAtUTC"`
	CaptureStartedAtUTC         string                     `json:"captureStartedAtUTC"`
	CaptureCompletedAtUTC       string                     `json:"captureCompletedAtUTC"`
	CaptureObservedAtUTC        string                     `json:"captureObservedAtUTC"`
	CaptureNonce                string                     `json:"captureNonce"`
	CaptureWholeSHA             string                     `json:"captureWholeSHA"`
	CaptureRetainedRef          resetD101FinalRawReference `json:"captureRetainedRef"`
	CaptureNativePin            d101custody.NativeFilePin  `json:"captureNativePin"`
	ResponseBodyWholeSHA        string                     `json:"responseBodyWholeSHA"`
	ResponseProofHeaderWholeSHA string                     `json:"responseProofHeaderWholeSHA"`
	ResponseBodyRef             resetD101FinalRawReference `json:"responseBodyRef"`
	ResponseProofHeaderRef      resetD101FinalRawReference `json:"responseProofHeaderRef"`
	SignedResponseWholeSHA      string                     `json:"signedResponseWholeSHA"`
	RequestSequence             uint64                     `json:"requestSequence"`
	PreviousCommitWholeSHA      string                     `json:"previousCommitWholeSHA"`
}

func newResetD101HostPreparedCustody(p resetD101HostPreparedCustodyPins) (*resetD101HostPreparedCustody, error) {
	if !lifecycleJobIDRe.MatchString(p.operationID) || p.authenticate == nil || !filepath.IsAbs(p.directory) || filepath.Clean(p.directory) != p.directory ||
		p.directoryPin.device == 0 || p.directoryPin.inode == 0 || !resetD101IssuerIdentity.MatchString(p.retentionOwner) || p.retentionSeconds < 7*24*60*60 ||
		p.byteBudget == 0 || p.byteBudget > 1<<30 || p.reserveBytes < 10<<30 || p.reserveBytes > ^uint64(0)-4*(64<<10) ||
		!resetD101KeyID.MatchString(p.purposeKeyID) || !resetEvidenceSHA.MatchString(p.purposeSPKISHA) {
		return nil, errResetD101InstallationNotSupplied
	}
	for _, ref := range []resetD101FinalRawReference{p.installedSourceRef, p.nativeSessionRef, p.nativeKeeperWriterRef} {
		if !strings.HasPrefix(ref.LogicalID, "raw:") || !resetD101IssuerIdentity.MatchString(ref.LogicalID) || !resetEvidenceSHA.MatchString(ref.SHA) || ref.ByteLength == 0 || ref.ByteLength > 64<<10 || ref.MediaType != "application/json" {
			return nil, errResetExecutionEvidence
		}
	}
	return &resetD101HostPreparedCustody{pins: p}, nil
}

func (c *resetD101HostPreparedCustody) retain(ctx context.Context, fd *os.File, binding resetExecutionPhaseBinding, accepted, requestStarted time.Time, w *resetD101AuthenticatedCaptureWitness, body []byte, header string) (*resetD101PreparedNativeReceipt, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || fd == nil || fd.Fd() != 9 || w == nil || c.pins.authenticate == nil || binding.OperationID != c.pins.operationID ||
		!reflect.DeepEqual(w.binding, binding) || !w.requestStarted.Equal(requestStarted) || accepted.IsZero() || accepted.Unix() != binding.AcceptedAtUnix ||
		w.recheckNative() != nil || c.pins.authenticate(ctx, fd, binding.OperationID, "prepared-custody-before") != nil || ctx.Err() != nil {
		return nil, errResetExecutionEvidence
	}
	proof, err := decodeResetD101PreparedProof(body)
	observed, observeErr := decodeResetD101CurrentFreeze(w.observation.original)
	if err != nil || observeErr != nil || proof.OperationID != binding.OperationID || proof.ApprovalPlanSHA != binding.Evidence.ApprovalPlanSHA || proof.ExecutionReceiptSHA != binding.Evidence.ExecutionReceiptSHA ||
		proof.AcceptedAtUTC != accepted.UTC().Format(time.RFC3339Nano) || proof.TargetFingerprint != resetRequestFingerprint("pep", binding.Target) ||
		proof.VerifyingRevision != observed.PublicationRevision || proof.TargetFingerprint != observed.TargetFingerprint || !observed.WriterFreezeHeld || observed.OperationID != proof.OperationID ||
		w.capture.captureNonce != w.observation.captureNonce || !lifecycleJobIDRe.MatchString(w.capture.captureNonce) || w.capture.wholeSHA != resetD101OriginalSHA(w.observation.original) ||
		!w.capture.collectorStarted.Equal(w.observation.started) || !w.capture.completed.Equal(w.observation.ended) || w.observation.started.Before(requestStarted) ||
		observed.ObservedAt.Before(w.observation.started) || observed.ObservedAt.After(w.observation.ended) || w.observation.ended.After(time.Now()) ||
		len(strings.Split(header, ".")) != 2 || strings.Split(header, ".")[0] != c.pins.purposeKeyID {
		return nil, errResetExecutionEvidence
	}
	prepared, timeErr := resetC4UTC(proof.PreparedAtUTC)
	if timeErr != nil || time.Now().Before(prepared) || time.Since(prepared) >= resetPreflightMaxAge || time.Now().Unix() >= proof.DestructiveCutoffUnix {
		return nil, errResetExecutionEvidence
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped || c.pending || c.sequence == ^uint64(0) {
		return nil, errResetExecutionEvidence
	}
	dir, err := openResetD101IssuerDirectory(c.pins.directory, c.pins.directoryPin, 0)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	defer dir.Close()
	if c.sequence == 0 {
		// Never restart an existing operation's private sequence automatically.
		stream, err := os.Open(c.pins.directory)
		if err != nil {
			return nil, errResetExecutionEvidence
		}
		names, err := stream.Readdirnames(1025)
		_ = stream.Close()
		if len(names) > 1024 || err != nil && err != io.EOF {
			return nil, errResetExecutionEvidence
		}
		for _, name := range names {
			if strings.HasPrefix(name, "get-"+binding.OperationID+"-") {
				return nil, errResetExecutionEvidence
			}
		}
	} else {
		visible, err := os.Lstat(filepath.Join(dir.Name(), c.previousName))
		if err != nil || c.previousInfo == nil || !os.SameFile(c.previousInfo, visible) ||
			requireResetD101IssuerOwnedOriginal(dir, c.previousName, c.previousCommit, 0) != nil {
			return nil, errResetExecutionEvidence
		}
	}
	if resetD101PreparedDirectoryBudget(dir, c.pins.byteBudget, c.pins.reserveBytes) != nil {
		return nil, errResetExecutionEvidence
	}
	c.pending = true
	stem := "get-" + binding.OperationID + "-" + w.capture.captureNonce
	ref := func(id string, wire []byte) resetD101FinalRawReference {
		return resetD101FinalRawReference{LogicalID: "raw:" + id, SHA: resetD101OriginalSHA(wire), ByteLength: uint64(len(wire)), MediaType: "application/json"}
	}
	bodyRef, headerRef := ref(stem+"-body", body), ref(stem+"-header", []byte(header))
	headerRef.MediaType = "text/plain"
	record := resetD101PreparedPrivateRecord{Version: 1, OperationID: binding.OperationID, ApprovalPlanSHA: proof.ApprovalPlanSHA, ExecutionReceiptSHA: proof.ExecutionReceiptSHA,
		AcceptedAtUTC: proof.AcceptedAtUTC, PreparedJournalSHA: proof.PreparedJournalSHA, InstalledSourceRef: c.pins.installedSourceRef, NativeSessionRef: c.pins.nativeSessionRef, NativeKeeperWriterRef: c.pins.nativeKeeperWriterRef,
		PurposeKeyID: c.pins.purposeKeyID, PurposePublicSPKISHA: c.pins.purposeSPKISHA, RequestStartedAtUTC: requestStarted.UTC().Format(time.RFC3339Nano),
		CaptureStartedAtUTC: w.observation.started.UTC().Format(time.RFC3339Nano), CaptureCompletedAtUTC: w.observation.ended.UTC().Format(time.RFC3339Nano), CaptureObservedAtUTC: observed.ObservedAt.UTC().Format(time.RFC3339Nano),
		CaptureNonce: w.capture.captureNonce, CaptureWholeSHA: w.capture.wholeSHA,
		CaptureRetainedRef: ref("current-freeze-"+binding.OperationID+"-"+w.capture.captureNonce, w.observation.original), CaptureNativePin: w.observation.retainedPin,
		ResponseBodyWholeSHA: bodyRef.SHA, ResponseProofHeaderWholeSHA: headerRef.SHA, ResponseBodyRef: bodyRef, ResponseProofHeaderRef: headerRef,
		SignedResponseWholeSHA: resetD101SignedResponseTupleSHA(body, []byte(header)), RequestSequence: c.sequence + 1, PreviousCommitWholeSHA: resetD101OriginalSHA(c.previousCommit)}
	if c.sequence == 0 {
		record.PreviousCommitWholeSHA = ""
	}
	receipt, err := retainResetD101PreparedNativeRecord(ctx, dir, stem, record, body, []byte(header), 0)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	receipt.validUntil = prepared.Add(resetPreflightMaxAge)
	if cutoff := time.Unix(proof.DestructiveCutoffUnix, 0); cutoff.Before(receipt.validUntil) {
		receipt.validUntil = cutoff
	}
	if receipt.recheck(ctx) != nil || w.recheckNative() != nil || c.pins.authenticate(ctx, fd, binding.OperationID, "prepared-custody-after") != nil ||
		receipt.recheck(ctx) != nil || w.recheckNative() != nil || ctx.Err() != nil {
		receipt.close()
		return nil, errResetExecutionEvidence
	}
	// Pending stays set through the caller's final authentication. Failure or
	// uncertainty after any native write must hold the same operation.
	receipt.complete = func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.stopped || !c.pending || c.sequence+1 != record.RequestSequence || receipt.recheck(ctx) != nil {
			return errResetExecutionEvidence
		}
		c.sequence++
		c.previousCommit = bytes.Clone(receipt.commitWire)
		c.previousName = stem + ".commit"
		c.previousInfo = receipt.originals[3].info
		c.pending = false
		return nil
	}
	return receipt, nil
}

func (c *resetD101HostPreparedCustody) hold() {
	if c != nil {
		c.mu.Lock()
		c.stopped = true
		c.pending = true
		c.mu.Unlock()
	}
}

// The timestamp describes the preceding record's completed sync/readback. It
// does not describe this commit's own completion, kernel commit instant, or HTTP
// delivery. All tuple fields are repeated exactly for the private audit link.
type resetD101PreparedPrivateCommit struct {
	Version                 int                            `json:"version"`
	CommittedRecordWholeSHA string                         `json:"committedRecordWholeSHA"`
	RecordCommittedAtUTC    string                         `json:"recordCommittedAtUTC"`
	Record                  resetD101PreparedPrivateRecord `json:"record"`
}
type resetD101PreparedHeldOriginal struct {
	file *os.File
	info os.FileInfo
	wire []byte
}
type resetD101PreparedNativeReceipt struct {
	dir        *os.File
	pin        resetD101IssuerDirectoryPin
	uid        uint32
	originals  []resetD101PreparedHeldOriginal
	recordWire []byte
	commitWire []byte
	complete   func() error
	validUntil time.Time
}

func (r *resetD101PreparedNativeReceipt) close() {
	if r == nil {
		return
	}
	for _, original := range r.originals {
		_ = original.file.Close()
	}
	if r.dir != nil {
		_ = r.dir.Close()
	}
}
func (r *resetD101PreparedNativeReceipt) recheck(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil || !r.validUntil.IsZero() && !time.Now().Before(r.validUntil) || len(r.originals) != 4 || r.dir == nil || requireResetD101IssuerDirectory(r.dir, r.pin, r.uid) != nil {
		return errResetExecutionEvidence
	}
	for _, original := range r.originals {
		if recheckResetD101PreparedHeldOriginal(original, r.uid) != nil || ctx.Err() != nil {
			return errResetExecutionEvidence
		}
	}
	var commit resetD101PreparedPrivateCommit
	if json.Unmarshal(r.commitWire, &commit) != nil || commit.Version != 1 || commit.CommittedRecordWholeSHA != resetD101OriginalSHA(r.recordWire) {
		return errResetExecutionEvidence
	}
	wire, err := json.Marshal(commit.Record)
	observed, timeErr := resetC4UTC(commit.RecordCommittedAtUTC)
	if err != nil || !bytes.Equal(wire, r.recordWire) || timeErr != nil || observed.UTC().Format(time.RFC3339Nano) != commit.RecordCommittedAtUTC || time.Now().Before(observed) || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	return nil
}
func recheckResetD101PreparedHeldOriginal(o resetD101PreparedHeldOriginal, uid uint32) error {
	if o.file == nil || o.info == nil || len(o.wire) == 0 || len(o.wire) > 64<<10 {
		return errResetExecutionEvidence
	}
	before, err := o.file.Stat()
	visible, pathErr := os.Lstat(o.file.Name())
	if err != nil || pathErr != nil || !resetD101IssuerFileMetadata(before, uid) || !os.SameFile(o.info, before) || !os.SameFile(before, visible) || before.Size() != int64(len(o.wire)) || !before.ModTime().Equal(o.info.ModTime()) {
		return errResetExecutionEvidence
	}
	wire := make([]byte, len(o.wire)+1)
	n, readErr := o.file.ReadAt(wire, 0)
	after, statErr := o.file.Stat()
	visibleAfter, visibleErr := os.Lstat(o.file.Name())
	if readErr != io.EOF || n != len(o.wire) || !bytes.Equal(wire[:n], o.wire) || statErr != nil || visibleErr != nil ||
		!resetD101IssuerFileMetadata(after, uid) || !os.SameFile(before, after) || !os.SameFile(after, visibleAfter) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return errResetExecutionEvidence
	}
	return nil
}
func writeResetD101PreparedHeldOriginal(ctx context.Context, dir *os.File, pin resetD101IssuerDirectoryPin, name string, wire []byte, uid uint32) (resetD101PreparedHeldOriginal, error) {
	if ctx == nil || ctx.Err() != nil || dir == nil || !validResetD101PreparedPrivateName(name) || len(wire) == 0 || len(wire) > 64<<10 || requireResetD101IssuerDirectory(dir, pin, uid) != nil {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	file, err := os.OpenFile(filepath.Join(dir.Name(), name), os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0400)
	if err != nil {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	owned := false
	defer func() {
		if !owned {
			_ = file.Close()
		}
	}()
	before, err := file.Stat()
	if err != nil || !resetD101IssuerFileMetadata(before, uid) || ctx.Err() != nil {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	if n, err := file.Write(wire); err != nil || n != len(wire) || file.Sync() != nil || dir.Sync() != nil || ctx.Err() != nil {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || requireResetD101IssuerDirectory(dir, pin, uid) != nil {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	o := resetD101PreparedHeldOriginal{file: file, info: after, wire: bytes.Clone(wire)}
	if recheckResetD101PreparedHeldOriginal(o, uid) != nil || ctx.Err() != nil {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	owned = true
	return o, nil
}
func retainResetD101PreparedNativeRecord(ctx context.Context, dir *os.File, stem string, record resetD101PreparedPrivateRecord, body, header []byte, uid uint32) (*resetD101PreparedNativeReceipt, error) {
	if ctx == nil || ctx.Err() != nil || dir == nil || !validResetD101PreparedPrivateName(stem+".record") ||
		stem != "get-"+record.OperationID+"-"+record.CaptureNonce || record.Version != 1 || record.RequestSequence == 0 ||
		record.ResponseBodyWholeSHA != resetD101OriginalSHA(body) || record.ResponseProofHeaderWholeSHA != resetD101OriginalSHA(header) || record.SignedResponseWholeSHA != resetD101SignedResponseTupleSHA(body, header) {
		return nil, errResetExecutionEvidence
	}
	info, err := dir.Stat()
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errResetExecutionEvidence
	}
	pin := resetD101IssuerDirectoryPin{uint64(stat.Dev), uint64(stat.Ino)}
	dup, err := syscall.Dup(int(dir.Fd()))
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	syscall.CloseOnExec(dup)
	r := &resetD101PreparedNativeReceipt{dir: os.NewFile(uintptr(dup), dir.Name()), pin: pin, uid: uid}
	success := false
	defer func() {
		if !success {
			r.close()
		}
	}()
	wire, err := json.Marshal(record)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	for _, item := range []struct {
		suffix string
		wire   []byte
	}{{".body", body}, {".header", header}, {".record", wire}} {
		o, err := writeResetD101PreparedHeldOriginal(ctx, r.dir, pin, stem+item.suffix, item.wire, uid)
		if err != nil {
			return nil, errResetExecutionEvidence
		}
		r.originals = append(r.originals, o)
	}
	// This observation is reached only after the actual .record sync/readback.
	commit := resetD101PreparedPrivateCommit{Version: 1, CommittedRecordWholeSHA: resetD101OriginalSHA(wire), RecordCommittedAtUTC: time.Now().UTC().Format(time.RFC3339Nano), Record: record}
	commitWire, err := json.Marshal(commit)
	if err != nil || ctx.Err() != nil {
		return nil, errResetExecutionEvidence
	}
	o, err := writeResetD101PreparedHeldOriginal(ctx, r.dir, pin, stem+".commit", commitWire, uid)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	r.originals = append(r.originals, o)
	r.recordWire, r.commitWire = bytes.Clone(wire), bytes.Clone(commitWire)
	if r.recheck(ctx) != nil {
		return nil, errResetExecutionEvidence
	}
	success = true
	return r, nil
}
func validResetD101PreparedPrivateName(name string) bool {
	for _, suffix := range []string{".body", ".header", ".record", ".commit"} {
		if !strings.HasSuffix(name, suffix) || !strings.HasPrefix(name, "get-") {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(name, "get-"), suffix), "-")
		return len(parts) == 2 && lifecycleJobIDRe.MatchString(parts[0]) && lifecycleJobIDRe.MatchString(parts[1])
	}
	return false
}

func resetD101SignedResponseTupleSHA(body, header []byte) string {
	wire := make([]byte, 0, 16+len(body)+len(header))
	wire = binary.BigEndian.AppendUint64(wire, uint64(len(body)))
	wire = append(wire, body...)
	wire = binary.BigEndian.AppendUint64(wire, uint64(len(header)))
	wire = append(wire, header...)
	return resetD101OriginalSHA(wire)
}

func resetD101PreparedDirectoryBudget(dir *os.File, cap, reserve uint64) error {
	if dir == nil || cap == 0 || cap > 1<<30 || reserve < 10<<30 || reserve > ^uint64(0)-4*(64<<10) {
		return errResetExecutionEvidence
	}
	stream, err := os.OpenFile(dir.Name(), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	defer stream.Close()
	actual, e1 := stream.Stat()
	expected, e2 := dir.Stat()
	if e1 != nil || e2 != nil || !os.SameFile(actual, expected) {
		return errResetExecutionEvidence
	}
	names, err := stream.Readdirnames(1025)
	if len(names) > 1024 || err != nil && err != io.EOF {
		return errResetExecutionEvidence
	}
	var total uint64
	for _, name := range names {
		info, err := os.Lstat(filepath.Join(dir.Name(), name))
		if err != nil || !validResetD101PreparedPrivateName(name) || !resetD101IssuerFileMetadata(info, 0) || info.Size() <= 0 || uint64(info.Size()) > cap-total {
			return errResetExecutionEvidence
		}
		total += uint64(info.Size())
	}
	if cap-total < 4*(64<<10) {
		return errResetExecutionEvidence
	}
	var free syscall.Statfs_t
	if syscall.Fstatfs(int(dir.Fd()), &free) != nil || uint64(free.Bsize) == 0 || uint64(free.Bavail) > ^uint64(0)/uint64(free.Bsize) || uint64(free.Bavail)*uint64(free.Bsize) < reserve+4*(64<<10) {
		return errResetExecutionEvidence
	}
	return nil
}

// Mandatory pre-READY native availability, without inventing a current event.
// The existing issuer entry reserves before R and claims the actual authenticated
// JTI before this concrete emitter is ever called.
type resetD101IssuerOriginalAvailability interface {
	AuthenticateAvailability(context.Context, *os.File, d101operatorauth.ReviewedPolicy) error
}
type resetD101IssuerRetainedOriginals interface {
	AuthenticateRetained(context.Context, *os.File, string, string) error
	CloseRetained() error
}
type resetD101IssuerEmissionOutput struct {
	directory string
	pin       resetD101IssuerDirectoryPin
}
type resetD101NativeIssuerEmissionInputs struct {
	policy                              d101operatorauth.ReviewedPolicy
	semantic                            resetD101IssuerSemanticSource
	approvalKey, receiptKey             resetD101SigningKeyPins
	approvalKeyNative, receiptKeyNative d101custody.NativeFilePin
	origin, attestation, provenance     resetD101IssuerEmissionOutput
	retentionOwner                      string
	retentionSeconds                    int64
	byteBudget, reserveBytes            uint64
	// Actual source/policy/history/upstream/native availability and final native
	// semantics, independent of this adapter's shape/codec/signature checks.
	authenticate   func(context.Context, *os.File, string, string) error
	verifyRetained func(context.Context, *os.File, d101operatorauth.TechnicalIssuance, resetD101IssuerSemanticSnapshot, []byte, []byte, []byte) error
}
type resetD101NativeIssuerEmission struct {
	mu        sync.Mutex
	inputs    resetD101NativeIssuerEmissionInputs
	attempted bool
	stopped   atomic.Bool
	retained  *resetD101IssuerRetainedEmission
}

type resetD101IssuerRetainedEmission struct {
	dirs     []*os.File
	held     []resetD101PreparedHeldOriginal
	issuance d101operatorauth.TechnicalIssuance
	semantic *resetD101IssuerEmissionSemanticSource
}

// No path reopen, descriptor substitution, signing or unsigned recapture occurs
// after emission. The same actual three descriptors survive both final phases.
func (e *resetD101NativeIssuerEmission) AuthenticateRetained(ctx context.Context, fd *os.File, op, phase string) error {
	return e.authenticateRetainedWithNative(ctx, fd, op, phase, 0, e.authenticate)
}

// The explicit UID/native seam is private to portable custody fixtures. The
// production method always uses root and its mandatory Linux/source/key auth.
func (e *resetD101NativeIssuerEmission) authenticateRetainedWithNative(ctx context.Context, fd *os.File, op, phase string, uid uint32, native func(context.Context, *os.File, string) error) (result error) {
	if e == nil {
		return errResetExecutionEvidence
	}
	if !e.mu.TryLock() {
		e.stopped.Store(true)
		return errResetExecutionEvidence
	}
	defer func() {
		if result != nil {
			e.stopped.Store(true)
		}
		if e.stopped.Load() {
			_ = e.closeRetainedLocked()
		}
		e.mu.Unlock()
	}()
	if e.stopped.Load() || ctx == nil || ctx.Err() != nil || native == nil || e.inputs.verifyRetained == nil || op != e.inputs.policy.Scope.OperationID ||
		(phase != "issuer-emission-retained" && phase != "issuer-release") || e.retained == nil || e.retained.semantic == nil || len(e.retained.dirs) != 3 || len(e.retained.held) != 3 {
		return errResetExecutionEvidence
	}
	r := e.retained
	check := func() error {
		if e.stopped.Load() {
			return errResetExecutionEvidence
		}
		for i, output := range []resetD101IssuerEmissionOutput{e.inputs.origin, e.inputs.attestation, e.inputs.provenance} {
			if r.dirs[i] == nil || r.held[i].file == nil || r.dirs[i].Name() != output.directory || r.held[i].file.Name() != filepath.Join(output.directory, op+".json") ||
				requireResetD101IssuerDirectory(r.dirs[i], output.pin, uid) != nil || recheckResetD101PreparedHeldOriginal(r.held[i], uid) != nil || ctx.Err() != nil {
				return errResetExecutionEvidence
			}
		}
		return r.semantic.RecheckAuthenticatedUnsigned(ctx, r.issuance, r.semantic.frozen)
	}
	if native(ctx, fd, phase+"-retained-before") != nil || check() != nil {
		return errResetExecutionEvidence
	}
	snapshot, err := freezeResetD101IssuerSemanticSnapshot(r.semantic.frozen)
	before, e1 := json.Marshal(snapshot)
	if err != nil || e1 != nil || e.inputs.verifyRetained(ctx, fd, r.issuance, snapshot, bytes.Clone(r.held[0].wire), bytes.Clone(r.held[1].wire), bytes.Clone(r.held[2].wire)) != nil {
		return errResetExecutionEvidence
	}
	after, err := json.Marshal(snapshot)
	if err != nil || !bytes.Equal(before, after) || check() != nil || native(ctx, fd, phase+"-retained-after") != nil || check() != nil || ctx.Err() != nil || e.stopped.Load() {
		return errResetExecutionEvidence
	}
	return nil
}

func (e *resetD101NativeIssuerEmission) CloseRetained() error {
	if e == nil {
		return errResetExecutionEvidence
	}
	e.stopped.Store(true)
	if !e.mu.TryLock() {
		// The active emission/authentication defer closes its own descriptors
		// when it sees stopped. Never wait behind an external authenticator.
		return errResetExecutionEvidence
	}
	defer e.mu.Unlock()
	return e.closeRetainedLocked()
}

func (e *resetD101NativeIssuerEmission) closeRetainedLocked() error {
	r := e.retained
	e.retained = nil
	if r == nil {
		return nil
	}
	var result error
	for _, o := range r.held {
		if o.file != nil {
			if err := o.file.Close(); err != nil && result == nil {
				result = err
			}
		}
	}
	for _, d := range r.dirs {
		if d != nil {
			if err := d.Close(); err != nil && result == nil {
				result = err
			}
		}
	}
	return result
}

func newResetD101NativeIssuerEmission(p resetD101NativeIssuerEmissionInputs) (*resetD101NativeIssuerEmission, error) {
	if p.semantic == nil || reflect.ValueOf(p.semantic).Kind() == reflect.Pointer && reflect.ValueOf(p.semantic).IsNil() || p.authenticate == nil || p.verifyRetained == nil ||
		!resetD101IssuerIdentity.MatchString(p.retentionOwner) || p.retentionSeconds < 7*24*60*60 || p.byteBudget == 0 || p.byteBudget > 1<<30 || p.reserveBytes < 10<<30 || p.reserveBytes > ^uint64(0)-3*(64<<10) {
		return nil, errResetD101InstallationNotSupplied
	}
	if _, err := d101operatorauth.NewVerifier(p.policy); err != nil {
		return nil, errResetExecutionEvidence
	}
	p.policy = cloneResetD101TechnicalPolicy(p.policy)
	seen := map[string]bool{}
	seenPin := map[resetD101IssuerDirectoryPin]bool{}
	for _, output := range []resetD101IssuerEmissionOutput{p.origin, p.attestation, p.provenance} {
		if !filepath.IsAbs(output.directory) || filepath.Clean(output.directory) != output.directory || output.pin.device == 0 || output.pin.inode == 0 || seen[output.directory] || seenPin[output.pin] {
			return nil, errResetExecutionEvidence
		}
		seen[output.directory] = true
		seenPin[output.pin] = true
	}
	if p.origin.pin.device != p.attestation.pin.device || p.origin.pin.device != p.provenance.pin.device {
		return nil, errResetExecutionEvidence
	}
	for _, item := range []struct {
		key    resetD101SigningKeyPins
		native d101custody.NativeFilePin
		issuer d101operatorauth.IssuerPins
	}{
		{p.approvalKey, p.approvalKeyNative, p.policy.ApprovalIssuer}, {p.receiptKey, p.receiptKeyNative, p.policy.ReceiptIssuer},
	} {
		if !filepath.IsAbs(item.key.Directory) || filepath.Clean(item.key.Directory) != item.key.Directory || !lifecycleJobIDRe.MatchString(item.key.CustodyID) || !resetD101KeyID.MatchString(item.key.KeyID) ||
			item.key.PublicKeySpkiSHA != item.issuer.PublicKeySPKISHA256 || item.key.PublicKeySpkiSHA == p.policy.RootPurposeSPKISHA256 || !resetEvidenceSHA.MatchString(item.key.EnvelopeSHA) || item.native.SHA256 != item.key.EnvelopeSHA ||
			item.native.OwnerUID != 0 || item.native.FileMode != 0400 || item.native.LinkCount != 1 || item.native.ParentOwnerUID != 0 || item.native.ParentMode != 0700 {
			return nil, errResetExecutionEvidence
		}
	}
	if p.approvalKey.KeyID == p.receiptKey.KeyID || p.approvalKey.PublicKeySpkiSHA == p.receiptKey.PublicKeySpkiSHA || p.approvalKey.Directory == p.receiptKey.Directory && p.approvalKey.CustodyID == p.receiptKey.CustodyID {
		return nil, errResetExecutionEvidence
	}
	return &resetD101NativeIssuerEmission{inputs: p}, nil
}

func (e *resetD101NativeIssuerEmission) authenticate(ctx context.Context, fd *os.File, phase string) error {
	if e == nil || ctx == nil || ctx.Err() != nil || runtime.GOOS != "linux" || os.Geteuid() != 0 || fd == nil || fd.Fd() != 9 || e.inputs.authenticate == nil ||
		rootBuiltSourceSHA != e.inputs.policy.Scope.DockerSourceSHA || time.Now().Unix() >= e.inputs.policy.CutoffUnix || e.inputs.authenticate(ctx, fd, e.inputs.policy.Scope.OperationID, phase+"-before") != nil {
		return errResetExecutionEvidence
	}
	for _, item := range []struct {
		key    resetD101SigningKeyPins
		native d101custody.NativeFilePin
	}{{e.inputs.approvalKey, e.inputs.approvalKeyNative}, {e.inputs.receiptKey, e.inputs.receiptKeyNative}} {
		wire, native, err := d101custody.CapturePrivateOriginalPin(filepath.Join(item.key.Directory, item.key.CustodyID+".json"), 64<<10)
		if err != nil || native != item.native || wire.SHA256 != item.key.EnvelopeSHA || ctx.Err() != nil {
			return errResetExecutionEvidence
		}
	}
	if e.inputs.authenticate(ctx, fd, e.inputs.policy.Scope.OperationID, phase+"-after") != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func (e *resetD101NativeIssuerEmission) AuthenticateAvailability(ctx context.Context, fd *os.File, policy d101operatorauth.ReviewedPolicy) error {
	if e == nil || e.stopped.Load() || !reflect.DeepEqual(policy, e.inputs.policy) || e.authenticate(ctx, fd, "issuer-original-availability") != nil {
		return errResetExecutionEvidence
	}
	if !e.mu.TryLock() {
		return errResetExecutionEvidence
	}
	defer e.mu.Unlock()
	if e.attempted {
		return errResetExecutionEvidence
	}
	var total uint64
	for _, output := range []resetD101IssuerEmissionOutput{e.inputs.origin, e.inputs.attestation, e.inputs.provenance} {
		dir, err := openResetD101IssuerDirectory(output.directory, output.pin, 0)
		if err != nil {
			return errResetExecutionEvidence
		}
		err = resetD101IssuerEmissionDirectoryBudget(ctx, dir, e.inputs.policy.Scope.OperationID, e.inputs.byteBudget, e.inputs.reserveBytes, &total)
		_ = dir.Close()
		if err != nil {
			return errResetExecutionEvidence
		}
	}
	return e.authenticate(ctx, fd, "issuer-original-availability-final")
}

// Retain the exact frozen snapshot that the C1 factory authenticated; never
// recapture another unsigned subject after signing or mutate its references.
type resetD101IssuerEmissionSemanticSource struct {
	actual   resetD101IssuerSemanticSource
	frozen   resetD101IssuerSemanticSnapshot
	captured bool
}

func (s *resetD101IssuerEmissionSemanticSource) CaptureAuthenticatedUnsigned(ctx context.Context, issuance d101operatorauth.TechnicalIssuance) (resetD101IssuerSemanticSnapshot, error) {
	if s == nil || s.actual == nil || s.captured {
		return resetD101IssuerSemanticSnapshot{}, errResetExecutionEvidence
	}
	snapshot, err := s.actual.CaptureAuthenticatedUnsigned(ctx, issuance)
	if err != nil {
		return resetD101IssuerSemanticSnapshot{}, err
	}
	s.frozen, err = freezeResetD101IssuerSemanticSnapshot(snapshot)
	if err != nil {
		return resetD101IssuerSemanticSnapshot{}, err
	}
	s.captured = true
	return freezeResetD101IssuerSemanticSnapshot(s.frozen)
}
func (s *resetD101IssuerEmissionSemanticSource) RecheckAuthenticatedUnsigned(ctx context.Context, issuance d101operatorauth.TechnicalIssuance, snapshot resetD101IssuerSemanticSnapshot) error {
	if s == nil || !s.captured || ctx == nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	a, err := json.Marshal(s.frozen)
	b, e2 := json.Marshal(snapshot)
	if err != nil || e2 != nil || !bytes.Equal(a, b) {
		return errResetExecutionEvidence
	}
	copy, err := freezeResetD101IssuerSemanticSnapshot(s.frozen)
	if err != nil || s.actual.RecheckAuthenticatedUnsigned(ctx, issuance, copy) != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	after, err := json.Marshal(copy)
	if err != nil || !bytes.Equal(a, after) {
		return errResetExecutionEvidence
	}
	return nil
}

func (e *resetD101NativeIssuerEmission) IssueAndRetain(ctx context.Context, fd *os.File, issuance d101operatorauth.TechnicalIssuance) (result error) {
	if e == nil {
		return errResetExecutionEvidence
	}
	defer func() {
		if result != nil {
			_ = e.CloseRetained()
		}
	}()
	if e.stopped.Load() || e.authenticate(ctx, fd, "issuer-semantic-before") != nil {
		return errResetExecutionEvidence
	}
	scope, e1 := issuance.Scope()
	approval, e2 := issuance.Issuer(d101operatorauth.ApprovalIssuerRole)
	receipt, e3 := issuance.Issuer(d101operatorauth.ApprovedReceiptIssuerRole)
	if e1 != nil || e2 != nil || e3 != nil || scope != e.inputs.policy.Scope || !reflect.DeepEqual(approval, e.inputs.policy.ApprovalIssuer) || !reflect.DeepEqual(receipt, e.inputs.policy.ReceiptIssuer) {
		return errResetExecutionEvidence
	}
	if !e.mu.TryLock() {
		return errResetExecutionEvidence
	}
	defer func() {
		if result != nil {
			e.stopped.Store(true)
		}
		if e.stopped.Load() {
			_ = e.closeRetainedLocked()
		}
		e.mu.Unlock()
	}()
	if e.attempted || e.stopped.Load() {
		return errResetExecutionEvidence
	}
	var total uint64
	for _, output := range []resetD101IssuerEmissionOutput{e.inputs.origin, e.inputs.attestation, e.inputs.provenance} {
		dir, err := openResetD101IssuerDirectory(output.directory, output.pin, 0)
		if err != nil {
			return errResetExecutionEvidence
		}
		err = resetD101IssuerEmissionDirectoryBudget(ctx, dir, scope.OperationID, e.inputs.byteBudget, e.inputs.reserveBytes, &total)
		_ = dir.Close()
		if err != nil {
			return errResetExecutionEvidence
		}
	}
	e.attempted = true
	semantic := &resetD101IssuerEmissionSemanticSource{actual: e.inputs.semantic}
	batch, err := newResetD101IssuerUnsignedBatch(ctx, issuance, semantic)
	if err != nil || !semantic.captured || e.authenticate(ctx, fd, "issuer-semantic-both-valid") != nil {
		return errResetExecutionEvidence
	}
	approvalUnsigned, receiptUnsigned := batch.ApprovalPayload(), batch.ReceiptAttestation()
	if len(approvalUnsigned) == 0 || len(receiptUnsigned) == 0 {
		return errResetExecutionEvidence
	}
	// BOTH semantic batches are valid before either private key is used.
	approvalKey, err := readResetD101SigningKey(e.inputs.approvalKey)
	if err != nil {
		return errResetExecutionEvidence
	}
	defer approvalKey.close()
	receiptKey, err := readResetD101SigningKey(e.inputs.receiptKey)
	if err != nil {
		return errResetExecutionEvidence
	}
	defer receiptKey.close()
	if e.authenticate(ctx, fd, "issuer-key-custody-before-sign") != nil {
		return errResetExecutionEvidence
	}
	origin, err := signResetD101IssuerRoleEnvelope(&approvalKey, approval, e.inputs.policy.RootPurposeSPKISHA256, approvalUnsigned)
	if err != nil {
		return errResetExecutionEvidence
	}
	attestation, err := signResetD101IssuerRoleEnvelope(&receiptKey, receipt, e.inputs.policy.RootPurposeSPKISHA256, receiptUnsigned)
	if err != nil || e.authenticate(ctx, fd, "issuer-role2-signed") != nil || semantic.RecheckAuthenticatedUnsigned(ctx, issuance, semantic.frozen) != nil {
		return errResetExecutionEvidence
	}
	var dirs []*os.File
	var held []resetD101PreparedHeldOriginal
	transferred := false
	defer func() {
		if transferred {
			return
		}
		for _, o := range held {
			_ = o.file.Close()
		}
		for _, d := range dirs {
			_ = d.Close()
		}
	}()
	for _, output := range []resetD101IssuerEmissionOutput{e.inputs.origin, e.inputs.attestation, e.inputs.provenance} {
		dir, err := openResetD101IssuerDirectory(output.directory, output.pin, 0)
		if err != nil {
			return errResetExecutionEvidence
		}
		dirs = append(dirs, dir)
	}
	for i, wire := range [][]byte{origin, attestation} {
		o, err := writeResetD101IssuerEmissionHeld(ctx, dirs[i], scope.OperationID, wire, 0)
		if err != nil {
			return errResetExecutionEvidence
		}
		held = append(held, o)
	}
	// Only ACTUAL retained signed envelope bytes can supply the provenance RawRef.
	if recheckResetD101PreparedHeldOriginal(held[0], 0) != nil || recheckResetD101PreparedHeldOriginal(held[1], 0) != nil ||
		verifyResetD101IssuerRoleEnvelope(origin, approvalUnsigned, approval, e.inputs.policy.RootPurposeSPKISHA256) != nil {
		return errResetExecutionEvidence
	}
	provenance, err := batch.ProvenanceAfterRetainedAttestation(ctx, held[1].wire)
	if err != nil {
		return errResetExecutionEvidence
	}
	var value resetD101ApprovedReceiptProvenance
	if resetD101SemanticDecode(provenance, &value) != nil || value.Scope.OperationID != scope.OperationID || value.Issuer.ScopeAttestationRef.SHA != resetD101OriginalSHA(held[1].wire) {
		return errResetExecutionEvidence
	}
	profile := semantic.frozen.OriginInstallation.Profile
	binding, err := d101origin.VerifyCryptographicBinding(held[0].wire, semantic.frozen.OriginDependencies[profile.LogicalID], d101origin.ExpectedBinding{Role: d101origin.ApprovalIssuer, OperationID: scope.OperationID, ProfileSHA256: profile.SHA256, ScopeOriginal: semantic.frozen.OriginInstallation.ScopeOriginal}, time.Now())
	if err != nil || !bytes.Equal(binding.PayloadOriginal(), approvalUnsigned) {
		return errResetExecutionEvidence
	}
	// This existing envelope reference is filled only from the actual retained
	// signed origin. Its logical ID was independently approved in the snapshot.
	installedOrigin := semantic.frozen.OriginInstallation
	installedOrigin.Envelope.SHA256 = resetD101OriginalSHA(held[0].wire)
	installedOrigin.Envelope.ByteLength = uint64(len(held[0].wire))
	installedOrigin.Envelope.MediaType = "application/json"
	if _, err := d101origin.ParseUnverifiedRecords(binding, semantic.frozen.OriginOriginal, semantic.frozen.OriginCustodyOriginal, installedOrigin, time.Now()); err != nil ||
		verifyResetD101IssuerRoleEnvelope(held[1].wire, receiptUnsigned, receipt, e.inputs.policy.RootPurposeSPKISHA256) != nil {
		return errResetExecutionEvidence
	}
	o, err := writeResetD101IssuerEmissionHeld(ctx, dirs[2], scope.OperationID, provenance, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	held = append(held, o)
	check := func() error {
		for i, o := range held {
			if requireResetD101IssuerDirectory(dirs[i], []resetD101IssuerEmissionOutput{e.inputs.origin, e.inputs.attestation, e.inputs.provenance}[i].pin, 0) != nil || recheckResetD101PreparedHeldOriginal(o, 0) != nil || ctx.Err() != nil {
				return errResetExecutionEvidence
			}
		}
		return semantic.RecheckAuthenticatedUnsigned(ctx, issuance, semantic.frozen)
	}
	finalSnapshot, err := freezeResetD101IssuerSemanticSnapshot(semantic.frozen)
	before, e4 := json.Marshal(finalSnapshot)
	if err != nil || e4 != nil || check() != nil || e.inputs.verifyRetained(ctx, fd, issuance, finalSnapshot, bytes.Clone(held[0].wire), bytes.Clone(held[1].wire), bytes.Clone(held[2].wire)) != nil {
		return errResetExecutionEvidence
	}
	after, err := json.Marshal(finalSnapshot)
	if err != nil || !bytes.Equal(before, after) || check() != nil || e.authenticate(ctx, fd, "issuer-final-retained") != nil || check() != nil || ctx.Err() != nil || e.stopped.Load() {
		return errResetExecutionEvidence
	}
	e.retained = &resetD101IssuerRetainedEmission{dirs: dirs, held: held, issuance: issuance, semantic: semantic}
	transferred = true
	return nil
}

func signResetD101IssuerRoleEnvelope(key *resetD101SigningKey, issuer d101operatorauth.IssuerPins, rootSPKI string, unsigned []byte) ([]byte, error) {
	if key == nil || len(key.private) != ed25519.PrivateKeySize || key.publicKeySpkiSHA != issuer.PublicKeySPKISHA256 || issuer.PublicKeySPKISHA256 == rootSPKI || !resetEvidenceSHA.MatchString(rootSPKI) || len(unsigned) == 0 || len(unsigned) > 32<<10 {
		return nil, errResetExecutionEvidence
	}
	domain := ""
	switch issuer.Role {
	case d101operatorauth.ApprovalIssuerRole:
		domain = d101operatorauth.ApprovalOriginDomain
	case d101operatorauth.ApprovedReceiptIssuerRole:
		domain = resetD101ApprovedReceiptAttestationDomain
	default:
		return nil, errResetExecutionEvidence
	}
	pub, err := resetD101PinnedPublicKey(issuer.PublicKeySPKI, issuer.PublicKeySPKISHA256)
	if err != nil || !bytes.Equal(key.private.Public().(ed25519.PublicKey), pub) {
		return nil, errResetExecutionEvidence
	}
	sig := ed25519.Sign(key.private, append([]byte(domain), unsigned...))
	wire, err := json.Marshal(resetD101SignedHostOriginal{SchemaVersion: 1, OriginalBytesBase64url: base64.RawURLEncoding.EncodeToString(unsigned), SignatureBase64url: base64.RawURLEncoding.EncodeToString(sig)})
	if err != nil || verifyResetD101IssuerRoleEnvelope(wire, unsigned, issuer, rootSPKI) != nil {
		return nil, errResetExecutionEvidence
	}
	return wire, nil
}
func verifyResetD101IssuerRoleEnvelope(wire, unsigned []byte, issuer d101operatorauth.IssuerPins, rootSPKI string) error {
	if issuer.PublicKeySPKISHA256 == rootSPKI || !resetEvidenceSHA.MatchString(rootSPKI) {
		return errResetExecutionEvidence
	}
	domain := ""
	switch issuer.Role {
	case d101operatorauth.ApprovalIssuerRole:
		domain = d101operatorauth.ApprovalOriginDomain
	case d101operatorauth.ApprovedReceiptIssuerRole:
		domain = resetD101ApprovedReceiptAttestationDomain
	default:
		return errResetExecutionEvidence
	}
	var envelope resetD101SignedHostOriginal
	if resetD101SemanticDecode(wire, &envelope) != nil || envelope.SchemaVersion != 1 {
		return errResetExecutionEvidence
	}
	body, e1 := base64.RawURLEncoding.Strict().DecodeString(envelope.OriginalBytesBase64url)
	sig, e2 := base64.RawURLEncoding.Strict().DecodeString(envelope.SignatureBase64url)
	key, e3 := resetD101PinnedPublicKey(issuer.PublicKeySPKI, issuer.PublicKeySPKISHA256)
	if e1 != nil || e2 != nil || e3 != nil || !bytes.Equal(body, unsigned) || len(sig) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(body) != envelope.OriginalBytesBase64url || base64.RawURLEncoding.EncodeToString(sig) != envelope.SignatureBase64url || !ed25519.Verify(key, append([]byte(domain), body...), sig) {
		return errResetExecutionEvidence
	}
	return nil
}

func writeResetD101IssuerEmissionHeld(ctx context.Context, dir *os.File, op string, wire []byte, uid uint32) (resetD101PreparedHeldOriginal, error) {
	if ctx == nil || ctx.Err() != nil || dir == nil || !lifecycleJobIDRe.MatchString(op) || len(wire) == 0 || len(wire) > 64<<10 {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	info, err := dir.Stat()
	if err != nil {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	pin := resetD101IssuerDirectoryPin{uint64(st.Dev), uint64(st.Ino)}
	if requireResetD101IssuerDirectory(dir, pin, uid) != nil {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	file, err := os.OpenFile(filepath.Join(dir.Name(), op+".json"), os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0400)
	if err != nil {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	owned := false
	defer func() {
		if !owned {
			_ = file.Close()
		}
	}()
	before, err := file.Stat()
	if err != nil || !resetD101IssuerFileMetadata(before, uid) {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	if n, err := file.Write(wire); err != nil || n != len(wire) || file.Sync() != nil || dir.Sync() != nil || ctx.Err() != nil {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || requireResetD101IssuerDirectory(dir, pin, uid) != nil {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	o := resetD101PreparedHeldOriginal{file: file, info: after, wire: bytes.Clone(wire)}
	if recheckResetD101PreparedHeldOriginal(o, uid) != nil || ctx.Err() != nil {
		return resetD101PreparedHeldOriginal{}, errResetExecutionEvidence
	}
	owned = true
	return o, nil
}
func resetD101IssuerEmissionDirectoryBudget(ctx context.Context, dir *os.File, op string, cap, reserve uint64, total *uint64) error {
	if ctx == nil || ctx.Err() != nil || dir == nil || total == nil || cap == 0 || cap > 1<<30 || *total > cap || reserve < 10<<30 || reserve > ^uint64(0)-3*(64<<10) {
		return errResetExecutionEvidence
	}
	if _, err := os.Lstat(filepath.Join(dir.Name(), op+".json")); !os.IsNotExist(err) {
		return errResetExecutionEvidence
	}
	stream, err := os.OpenFile(dir.Name(), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	defer stream.Close()
	a, e1 := dir.Stat()
	b, e2 := stream.Stat()
	if e1 != nil || e2 != nil || !os.SameFile(a, b) {
		return errResetExecutionEvidence
	}
	names, err := stream.Readdirnames(1025)
	if len(names) > 1024 || err != nil && err != io.EOF {
		return errResetExecutionEvidence
	}
	for _, name := range names {
		info, err := os.Lstat(filepath.Join(dir.Name(), name))
		if err != nil || !strings.HasSuffix(name, ".json") || !lifecycleJobIDRe.MatchString(strings.TrimSuffix(name, ".json")) || !resetD101IssuerFileMetadata(info, 0) || info.Size() <= 0 || uint64(info.Size()) > cap-*total {
			return errResetExecutionEvidence
		}
		*total += uint64(info.Size())
	}
	var free syscall.Statfs_t
	if cap-*total < 3*(64<<10) || syscall.Fstatfs(int(dir.Fd()), &free) != nil || uint64(free.Bsize) == 0 || uint64(free.Bavail) > ^uint64(0)/uint64(free.Bsize) || uint64(free.Bavail)*uint64(free.Bsize) < reserve+3*(64<<10) || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	return nil
}
