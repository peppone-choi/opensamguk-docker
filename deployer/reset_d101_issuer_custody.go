package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

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
