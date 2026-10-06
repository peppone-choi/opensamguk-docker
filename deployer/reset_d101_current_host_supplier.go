package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101hostlaunch"
)

// Native facts only. The mandatory installed authenticator must separately
// verify the actual keeper/launcher, uninterrupted same-OFD lifetime and every
// writer component. Raw8, child success and this observation grant no authority.
type resetD101CurrentHostObservation struct {
	original       []byte
	retainedPath   string
	retainedPin    d101custody.NativeFilePin
	visiblePin     d101custody.NativeFilePin
	started, ended time.Time
	captureNonce   string
}

type resetD101CurrentHostAuthenticator func(context.Context, resetExecutionPhaseBinding, resetD101CurrentHostObservation) error

type resetD101CurrentHostSupplier struct {
	mu         sync.Mutex
	descriptor *os.File
	launcher   d101hostlaunch.Pins
	pins       resetD101CurrentFreezePins
	verify     resetD101CurrentHostAuthenticator
}

func newResetD101CurrentHostSupplier(descriptor *os.File, launcher d101hostlaunch.Pins, pins resetD101CurrentFreezePins, verify resetD101CurrentHostAuthenticator) (resetD101CurrentFreezeSupplier, error) {
	if descriptor == nil || descriptor.Fd() != 9 || verify == nil || runtime.GOOS != "linux" || os.Geteuid() != 0 ||
		!lifecycleJobIDRe.MatchString(pins.operationID) || !resetEvidenceSHA.MatchString(pins.targetFingerprint) ||
		!resetEvidenceSHA.MatchString(pins.approvalPlanSHA) || !resetEvidenceSHA.MatchString(pins.freezeSHA) ||
		!filepath.IsAbs(pins.directory) || filepath.Clean(pins.directory) != pins.directory ||
		pins.parentDevice == 0 || pins.parentInode == 0 || pins.destructiveCutoff.IsZero() ||
		!resetEvidenceSHA.MatchString(launcher.Helper.SHA256) || !resetEvidenceSHA.MatchString(launcher.Reader.SHA256) || launcher.Lock.Inode == 0 {
		return nil, errResetD101InstallationNotSupplied
	}
	// No recursion through an installed phase supplier and no FD9 ownership
	// transfer. The host operation's keeper retains descriptor lifetime.
	pins.supplier = nil
	return &resetD101CurrentHostSupplier{descriptor: descriptor, launcher: launcher, pins: pins, verify: verify}, nil
}

func (s *resetD101CurrentHostSupplier) CaptureAfter(ctx context.Context, binding resetExecutionPhaseBinding, started time.Time) (resetD101CurrentFreezeCapture, error) {
	empty := resetD101CurrentFreezeCapture{}
	if s == nil || ctx == nil || ctx.Err() != nil || s.verify == nil || started.IsZero() ||
		binding.OperationID != s.pins.operationID || resetRequestFingerprint("pep", binding.Target) != s.pins.targetFingerprint ||
		binding.Evidence.ApprovalPlanSHA != s.pins.approvalPlanSHA || !time.Now().Before(s.pins.destructiveCutoff) {
		return empty, errResetExecutionEvidence
	}
	// One child per installed host session. Queue time remains inside the
	// caller's guard deadline; no capture can receive a renewed cutoff.
	if !s.mu.TryLock() {
		return empty, errResetExecutionEvidence
	}
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return empty, errResetExecutionEvidence
	}
	dir, err := os.OpenFile(s.pins.directory, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return empty, errResetExecutionEvidence
	}
	defer dir.Close() // auxiliary directory only, never keeper FD9
	checkDirectory := func() bool {
		fdInfo, e1 := dir.Stat()
		pathInfo, e2 := os.Lstat(s.pins.directory)
		if e1 != nil || e2 != nil || !os.SameFile(fdInfo, pathInfo) || !fdInfo.IsDir() || fdInfo.Mode().Perm() != 0700 {
			return false
		}
		native, ok := fdInfo.Sys().(*syscall.Stat_t)
		return ok && native.Uid == 0 && uint64(native.Dev) == s.pins.parentDevice && uint64(native.Ino) == s.pins.parentInode
	}
	if !checkDirectory() {
		return empty, errResetExecutionEvidence
	}
	before, err := dir.Readdirnames(1025)
	if len(before) > 1024 || err != nil && err != io.EOF {
		return empty, errResetExecutionEvidence
	}
	result, err := d101hostlaunch.RunCurrent(ctx, s.descriptor, s.launcher)
	if err != nil || ctx.Err() != nil || result.StartedAt().Before(started) || !checkDirectory() {
		return empty, errResetExecutionEvidence
	}
	// Fresh auxiliary directory stream; do not rely on directory Seek semantics.
	// This never reopens the production lock descriptor.
	afterDir, err := os.OpenFile(s.pins.directory, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return empty, errResetExecutionEvidence
	}
	defer afterDir.Close()
	afterInfo, e1 := afterDir.Stat()
	beforeInfo, e2 := dir.Stat()
	if e1 != nil || e2 != nil || !os.SameFile(afterInfo, beforeInfo) || !checkDirectory() {
		return empty, errResetExecutionEvidence
	}
	after, err := afterDir.Readdirnames(1025)
	if len(after) > 1024 || err != nil && err != io.EOF {
		return empty, errResetExecutionEvidence
	}
	names, err := resetD101NewRetainedCaptureNames(s.pins.operationID, before, after)
	if err != nil || len(names) != 1 || !checkDirectory() {
		return empty, errResetExecutionEvidence
	}
	name := names[0]
	stem := "current-freeze-" + s.pins.operationID + "-"
	nonce := strings.TrimSuffix(strings.TrimPrefix(name, stem), ".original")
	path := filepath.Join(s.pins.directory, name)
	wire := result.Original()
	sha := resetD101OriginalSHA(wire)
	retained, retainedPin, err := d101custody.CapturePrivateOriginalPin(path, resetD101CurrentFreezeLimit)
	visiblePath := filepath.Join(s.pins.directory, "current-freeze-"+s.pins.operationID)
	visible, visiblePin, visibleErr := d101custody.CapturePrivateOriginalPin(visiblePath, resetD101CurrentFreezeLimit)
	current, decodeErr := decodeResetD101CurrentFreeze(wire)
	if err != nil || visibleErr != nil || decodeErr != nil || !bytes.Equal(retained.Bytes, wire) || !bytes.Equal(visible.Bytes, wire) ||
		!resetD101CurrentFreezePinMatches(retainedPin, s.pins, sha) || !resetD101CurrentFreezePinMatches(visiblePin, s.pins, sha) ||
		retainedPin.Snapshot.Inode == visiblePin.Snapshot.Inode || current.ObservedAt.Before(result.StartedAt()) || current.ObservedAt.After(result.CompletedAt()) ||
		current.OperationID != s.pins.operationID || current.TargetFingerprint != s.pins.targetFingerprint ||
		current.PublicationRevision != s.pins.publicationRevision || current.WriterFreezeReceiptSHA != s.pins.freezeSHA ||
		ctx.Err() != nil || !checkDirectory() {
		return empty, errResetExecutionEvidence
	}
	observation := resetD101CurrentHostObservation{bytes.Clone(wire), path, retainedPin, visiblePin, result.StartedAt(), result.CompletedAt(), nonce}
	if s.verify(ctx, binding, observation) != nil || ctx.Err() != nil || !checkDirectory() {
		return empty, errResetExecutionEvidence
	}
	// Authenticator success cannot hide mutation of either native original.
	retainedAfter, retainedAfterPin, e1 := d101custody.CapturePrivateOriginalPin(path, resetD101CurrentFreezeLimit)
	visibleAfter, visibleAfterPin, e2 := d101custody.CapturePrivateOriginalPin(visiblePath, resetD101CurrentFreezeLimit)
	if e1 != nil || e2 != nil || retainedAfterPin != retainedPin || visibleAfterPin != visiblePin ||
		!bytes.Equal(retainedAfter.Bytes, wire) || !bytes.Equal(visibleAfter.Bytes, wire) || ctx.Err() != nil || !checkDirectory() {
		return empty, errResetExecutionEvidence
	}
	runtime.KeepAlive(s.descriptor)
	return resetD101CurrentFreezeCapture{nonce, sha, result.StartedAt(), result.CompletedAt()}, nil
}

// Only a newly issued filename can carry this invocation's private nonce.
// Existing files, including byte-identical old captures, are never adopted.
func resetD101NewRetainedCaptureNames(op string, before, after []string) ([]string, error) {
	if !lifecycleJobIDRe.MatchString(op) || len(before) > 1024 || len(after) > 1024 {
		return nil, errResetExecutionEvidence
	}
	old := make(map[string]bool, len(before))
	for _, name := range before {
		old[name] = true
	}
	stem := "current-freeze-" + op + "-"
	var names []string
	seen := map[string]bool{}
	for _, name := range after {
		if seen[name] {
			return nil, errResetExecutionEvidence
		}
		seen[name] = true
		if old[name] || !strings.HasPrefix(name, stem) || !strings.HasSuffix(name, ".original") {
			continue
		}
		nonce := strings.TrimSuffix(strings.TrimPrefix(name, stem), ".original")
		if !lifecycleJobIDRe.MatchString(nonce) || filepath.Base(name) != name {
			return nil, errResetExecutionEvidence
		}
		names = append(names, name)
	}
	return names, nil
}
