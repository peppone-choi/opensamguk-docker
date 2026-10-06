package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101operatorauth"
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
	if v.authenticate == nil || v.emitter == nil || (reflect.ValueOf(v.emitter).Kind() == reflect.Pointer && reflect.ValueOf(v.emitter).IsNil()) ||
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

func (c *resetD101NativeIssuerCustody) Authenticate(ctx context.Context, fd *os.File, op, phase string) error {
	if c == nil || ctx == nil || ctx.Err() != nil || fd == nil || fd.Fd() != 9 || op != c.inputs.operationID || c.inputs.authenticate == nil {
		return errResetExecutionEvidence
	}
	if c.inputs.authenticate(ctx, fd, op, phase) != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
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
	if c.inputs.authenticate(ctx, fd, op, phase+"-after-native") != nil || ctx.Err() != nil {
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

func (c *resetD101NativeIssuerCustody) IssueAndRetainOriginals(ctx context.Context, fd *os.File, issuance d101operatorauth.TechnicalIssuance) error {
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
