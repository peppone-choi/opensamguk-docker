package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"time"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101evidencetransport"
)

// Fixed installed producer only. No request/env registration, permission flag,
// or data callback supplies this installation. Main intentionally remains nil.
// verify must authenticate the actual approved collector/current producer,
// source/image/process, native pins and retained inventory against independent
// originals. A record's own source SHA/UID/shape is never that authentication.
type resetD101PreStopNativeInstallation struct {
	sourceSHA    string
	parentDevice uint64
	parentInode  uint64
	oldInputs    resetD101OldWorldCaptureInputs
	verify       func(context.Context, resetD101PreStopNativeBinding) error
}

type resetD101PreStopNativeBinding struct {
	intent     resetDecodedApprovalIntent
	plan       resetApprovalPlan
	planSHA    string
	gatewaySHA string
	original   resetD101PreStopNativeOriginal
	nativePin  d101custody.NativeFilePin
	parent     d101custody.PrivateSnapshot
}

func (c config) requireResetD101PreStopProducer(ctx context.Context, binding resetD101PreStopNativeBinding) error {
	i := c.d101PreStopNativeInstallation
	if ctx == nil || ctx.Err() != nil || i == nil || i.verify == nil || !gitSHA40.MatchString(i.sourceSHA) || i.parentDevice == 0 || i.parentInode == 0 ||
		binding.parent.Device != i.parentDevice || binding.parent.Inode != i.parentInode || requireResetIntentPlan(binding.intent, binding.plan) != nil ||
		!resetEvidenceSHA.MatchString(binding.planSHA) || !resetEvidenceSHA.MatchString(binding.gatewaySHA) {
		return errResetExecutionEvidence
	}
	if i.verify(ctx, binding) != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func resetD101NativeSnapshot(info os.FileInfo) (d101custody.PrivateSnapshot, error) {
	stat, ok := resetPrivateFileStat(info)
	if !ok || info.Size() < 0 || stat.Dev == 0 || stat.Ino == 0 || info.ModTime().UnixNano() <= 0 {
		return d101custody.PrivateSnapshot{}, errResetExecutionEvidence
	}
	return d101custody.PrivateSnapshot{Device: uint64(stat.Dev), Inode: uint64(stat.Ino), ByteLength: uint64(info.Size()), ModifiedAtUnixNano: info.ModTime().UnixNano()}, nil
}

func openResetD101NativeDirectory(directory string, uid uint32) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, nil, errResetExecutionEvidence
	}
	resolved, err := filepath.EvalSymlinks(directory)
	before, statErr := os.Lstat(directory)
	if err != nil || resolved != directory || statErr != nil || !resetD101NativeDirectoryInfo(before, uid) {
		return nil, nil, errResetExecutionEvidence
	}
	fd, err := syscall.Open(directory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, errResetExecutionEvidence
	}
	file := os.NewFile(uintptr(fd), directory)
	actual, err := file.Stat()
	if err != nil || !resetD101NativeDirectoryInfo(actual, uid) || !resetD101SameStat(before, actual) {
		file.Close()
		return nil, nil, errResetExecutionEvidence
	}
	return file, actual, nil
}

func resetD101NativeDirectoryInfo(info os.FileInfo, uid uint32) bool {
	stat, ok := resetPrivateFileStat(info)
	return ok && info.IsDir() && info.Mode().Perm() == 0700 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && stat.Uid == uid
}

func resetD101NativeFileInfo(info os.FileInfo, uid uint32, allowEmpty bool) bool {
	stat, ok := resetPrivateFileStat(info)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0400 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		stat.Uid == uid && stat.Nlink == 1 && info.Size() >= 0 && (allowEmpty || info.Size() > 0) && uint64(info.Size()) <= d101evidencetransport.OriginalMaxBytes
}

func resetD101SameStat(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && a.Mode() == b.Mode()
}

// One reserved leaf/FD, no retry/reopen/overwrite/remove and no directory install.
// An incomplete stream is deliberately unreadable by the complete proof parser.
type resetD101PreStopNativeStream struct {
	file         *os.File
	directory    *os.File
	parent       os.FileInfo
	fileIdentity os.FileInfo
	uid          uint32
	header       resetD101PreStopNativeBody
	pending      *resetD101PreStopNativeFrame
	frames       int
	openCommand  bool
	failed       bool
	finished     bool
	openLeaf     func(*os.File, string, int, uint32) (*os.File, error)
}

func openResetD101PreStopNativeStream(directory, op string, header resetD101PreStopNativeBody, uid uint32) (*resetD101PreStopNativeStream, error) {
	return openResetD101PreStopNativeStreamWithLeafOpener(directory, op, header, uid, resetD101OpenNativeLeaf)
}

// Opener injection is private to isolated portable filesystem fixtures. The
// production caller above always uses the Linux FD-relative fixed opener.
func openResetD101PreStopNativeStreamWithLeafOpener(directory, op string, header resetD101PreStopNativeBody, uid uint32, openLeaf func(*os.File, string, int, uint32) (*os.File, error)) (*resetD101PreStopNativeStream, error) {
	if !lifecycleJobIDRe.MatchString(op) || header.OperationID != op {
		return nil, errResetExecutionEvidence
	}
	dir, _, err := openResetD101NativeDirectory(directory, uid)
	if err != nil {
		return nil, err
	}
	if openLeaf == nil {
		dir.Close()
		return nil, errResetExecutionEvidence
	}
	file, err := openLeaf(dir, op, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0400)
	if err != nil {
		dir.Close()
		return nil, errResetExecutionEvidence
	}
	info, fileErr := file.Stat()
	parent, parentErr := dir.Stat()
	s := &resetD101PreStopNativeStream{file: file, directory: dir, parent: parent, fileIdentity: info, uid: uid, header: header, openLeaf: openLeaf}
	// Reservation must reach native custody before any data or command. On all
	// errors the reserved leaf survives; ClosePreservingPartial never removes it.
	if fileErr != nil || parentErr != nil || !resetD101NativeFileInfo(info, uid, true) || !resetD101NativeDirectoryInfo(parent, uid) || dir.Sync() != nil || s.checkCustody() != nil {
		s.ClosePreservingPartial()
		return nil, errResetExecutionEvidence
	}
	prefix := struct {
		SchemaVersion int    `json:"schemaVersion"`
		OperationID   string `json:"operationId"`
		IntentSHA     string `json:"approvalIntentSha256"`
		PlanSHA       string `json:"approvalPlanSha256"`
		GatewaySHA    string `json:"gatewayPayloadSha256"`
		Revision      string `json:"verifyingRevision"`
		Canonical     string `json:"preResetOriginalsBytesBase64url"`
		CanonicalSHA  string `json:"preResetOriginalsSha256"`
	}{header.SchemaVersion, header.OperationID, header.ApprovalIntentSHA, header.ApprovalPlanSHA, header.GatewayPayloadSHA, header.VerifyingRevision, header.PreResetOriginalsBase64url, header.PreResetOriginalsSHA}
	wire, err := json.Marshal(prefix)
	if err != nil || s.writeSync(append(wire[:len(wire)-1], []byte(",\"observations\":[")...)) != nil {
		s.ClosePreservingPartial()
		return nil, errResetExecutionEvidence
	}
	return s, nil
}

func (s *resetD101PreStopNativeStream) checkCustody() error {
	if s == nil || s.file == nil || s.directory == nil || s.failed {
		return errResetExecutionEvidence
	}
	file, e1 := s.file.Stat()
	path, e2 := os.Lstat(s.file.Name())
	parent, e3 := s.directory.Stat()
	parentPath, e4 := os.Lstat(s.directory.Name())
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !resetD101NativeFileInfo(file, s.uid, true) || !resetD101NativeFileInfo(path, s.uid, true) ||
		!os.SameFile(s.fileIdentity, file) || !resetD101SameStat(file, path) || !resetD101NativeDirectoryInfo(parent, s.uid) ||
		!resetD101NativeDirectoryInfo(parentPath, s.uid) || !resetD101SameStat(s.parent, parent) || !resetD101SameStat(parent, parentPath) {
		return errResetExecutionEvidence
	}
	return nil
}

func (s *resetD101PreStopNativeStream) writeSync(part []byte) error {
	if s == nil || s.finished || s.failed || s.checkCustody() != nil {
		return errResetExecutionEvidence
	}
	info, err := s.file.Stat()
	if err != nil || uint64(info.Size())+uint64(len(part)) > d101evidencetransport.OriginalMaxBytes {
		s.failed = true
		return errResetExecutionEvidence
	}
	n, err := s.file.Write(part)
	if err != nil || n != len(part) || s.file.Sync() != nil || s.checkCustody() != nil {
		s.failed = true
		return errResetExecutionEvidence
	}
	return nil
}

func (s *resetD101PreStopNativeStream) QueueGuard(frame resetD101PreStopNativeFrame) error {
	if s == nil || s.pending != nil || s.openCommand || frame.Invocation != nil || s.finished || s.failed {
		return errResetExecutionEvidence
	}
	s.pending = &frame
	return nil
}

func (s *resetD101PreStopNativeStream) AppendNonCommand(frame resetD101PreStopNativeFrame) error {
	if s == nil || s.pending != nil || s.openCommand || frame.Invocation != nil || (s.frames != 0 && s.frames != 15 && s.frames != 16) {
		return errResetExecutionEvidence
	}
	wire, err := json.Marshal(frame)
	if s.frames > 0 {
		wire = append([]byte(","), wire...)
	}
	if err != nil || s.writeSync(wire) != nil {
		return errResetExecutionEvidence
	}
	s.frames++
	return nil
}

func (s *resetD101PreStopNativeStream) FlushNonCommand() error {
	if s == nil || s.pending == nil || s.openCommand {
		return errResetExecutionEvidence
	}
	frame := *s.pending
	s.pending = nil
	return s.AppendNonCommand(frame)
}

// This records the actual transport attempt boundary before launching Docker;
// it does not claim the kernel process birth timestamp or invent an exit result.
func (s *resetD101PreStopNativeStream) BeginInvocation(ctx context.Context, args []string) (func() error, error) {
	if ctx == nil || ctx.Err() != nil || s == nil || s.pending == nil || s.openCommand || s.frames < 1 || s.frames > 14 || len(args) == 0 {
		return nil, errResetExecutionEvidence
	}
	for _, arg := range args {
		if !utf8.ValidString(arg) {
			return nil, errResetExecutionEvidence
		}
	}
	argv, err := json.Marshal(append([]string{"docker"}, args...))
	frame := *s.pending
	guardEnd, guardErr := resetD101PreStopUTC(frame.CompletedAtUTC)
	started := time.Now().UTC()
	if err != nil || guardErr != nil || started.Before(guardEnd) || started.Sub(guardEnd) >= resetPreflightMaxAge {
		return nil, errResetExecutionEvidence
	}
	// Identity is derived from this actual transport invocation and native frame
	// ordinal; no caller label/index is substituted for executing argv.
	invocation := resetD101PreStopNativeInvocation{CommandID: "docker:" + args[0] + ":" + strconv.Itoa(s.frames), ArgvSHA: resetD101OriginalSHA(argv), StartedAtUTC: started.Format(time.RFC3339Nano), GuardObservationIndex: s.frames}
	frameWire, err := json.Marshal(frame)
	const suffix = ",\"invocation\":null}"
	if err != nil || !bytes.HasSuffix(frameWire, []byte(suffix)) {
		return nil, errResetExecutionEvidence
	}
	startWire, err := json.Marshal(struct {
		CommandID    string `json:"commandId"`
		ArgvSHA      string `json:"argvSha256"`
		StartedAtUTC string `json:"startedAtUtc"`
		Index        int    `json:"guardObservationIndex"`
	}{invocation.CommandID, invocation.ArgvSHA, invocation.StartedAtUTC, invocation.GuardObservationIndex})
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	part := append([]byte(","), frameWire[:len(frameWire)-len(suffix)]...)
	part = append(part, []byte(",\"invocation\":")...)
	part = append(part, startWire[:len(startWire)-1]...)
	if err != nil || s.writeSync(part) != nil || ctx.Err() != nil {
		return nil, errResetExecutionEvidence
	}
	s.openCommand = true
	ended := false
	return func() error {
		if ended || !s.openCommand {
			return errResetExecutionEvidence
		}
		ended = true
		completed := time.Now().UTC()
		if completed.Before(started) {
			return errResetExecutionEvidence
		}
		// Audit completion is retained even if execution failed/cutoff expired.
		// Only the owning caller can finish a successful whole proof afterwards.
		tail, _ := json.Marshal(completed.Format(time.RFC3339Nano))
		part := append([]byte(",\"completedAtUtc\":"), tail...)
		part = append(part, []byte("}}")...)
		if s.writeSync(part) != nil {
			return errResetExecutionEvidence
		}
		s.frames++
		s.openCommand = false
		s.pending = nil
		return nil
	}, nil
}

// Build the summary by re-reading completed native frames, never from a second
// in-memory chronology. No rewrite of this issuing FD is performed.
func (s *resetD101PreStopNativeStream) Finish(body resetD101PreStopNativeBody) error {
	if s == nil || s.pending != nil || s.openCommand || s.frames != 17 || s.failed || s.finished || s.checkCustody() != nil {
		return errResetExecutionEvidence
	}
	// The writer's FD is write-only; independently open the exact same reserved
	// native identity for this bounded read, without acquiring a second attempt.
	wire, _, err := readResetD101PreStopNativeFileWithLeafOpener(s.directory.Name(), body.OperationID, s.uid, s.openLeaf)
	var prefix struct {
		Observations []resetD101PreStopNativeFrame `json:"observations"`
	}
	if err != nil || json.Unmarshal(append(bytes.Clone(wire), []byte("]}")...), &prefix) != nil || len(prefix.Observations) != 17 {
		return errResetExecutionEvidence
	}
	body.Observations = prefix.Observations
	body.CommandEvidence.Invocations = nil
	for _, frame := range prefix.Observations {
		if frame.Invocation != nil {
			body.CommandEvidence.Invocations = append(body.CommandEvidence.Invocations, *frame.Invocation)
		}
	}
	if body.OperationID != s.header.OperationID || body.ApprovalIntentSHA != s.header.ApprovalIntentSHA || body.ApprovalPlanSHA != s.header.ApprovalPlanSHA || body.GatewayPayloadSHA != s.header.GatewayPayloadSHA ||
		body.VerifyingRevision != s.header.VerifyingRevision || body.PreResetOriginalsBase64url != s.header.PreResetOriginalsBase64url || body.PreResetOriginalsSHA != s.header.PreResetOriginalsSHA || len(body.CommandEvidence.Invocations) != 14 {
		return errResetExecutionEvidence
	}
	all, err := json.Marshal(body)
	var fields map[string]json.RawMessage
	if err != nil || json.Unmarshal(all, &fields) != nil {
		return errResetExecutionEvidence
	}
	for _, key := range []string{"schemaVersion", "operationId", "approvalIntentSha256", "approvalPlanSha256", "gatewayPayloadSha256", "verifyingRevision", "preResetOriginalsBytesBase64url", "preResetOriginalsSha256", "observations"} {
		delete(fields, key)
	}
	tail, err := json.Marshal(fields)
	if err != nil {
		return errResetExecutionEvidence
	}
	part := append([]byte("],"), tail[1:]...)
	if err != nil || s.writeSync(part) != nil || s.directory.Sync() != nil || s.checkCustody() != nil {
		return errResetExecutionEvidence
	}
	s.finished = true
	return nil
}

func (s *resetD101PreStopNativeStream) ClosePreservingPartial() {
	if s == nil {
		return
	}
	if s.file != nil {
		// A fresh but unexecuted guard is retained as an intentionally incomplete
		// frame, not falsely labeled as a fourth successful non-command frame.
		if !s.finished && !s.failed && s.pending != nil && !s.openCommand {
			frame, err := json.Marshal(s.pending)
			const suffix = ",\"invocation\":null}"
			if err == nil && bytes.HasSuffix(frame, []byte(suffix)) {
				part := append([]byte(","), frame[:len(frame)-len(suffix)]...)
				part = append(part, []byte(",\"invocation\":")...)
				_ = s.writeSync(part)
			}
		}
		_ = s.file.Sync()
		_ = s.file.Close()
		s.file = nil
	}
	if s.directory != nil {
		_ = s.directory.Sync()
		_ = s.directory.Close()
		s.directory = nil
	}
}

// Actual FD+path+parent FD before/after, bounded by the original64MiB limit.
// UID injection is private to isolated fixtures; every production call uses0.
func readResetD101PreStopNativeFile(directory, op string, uid uint32) ([]byte, d101custody.NativeFilePin, error) {
	return readResetD101PreStopNativeFileWithLeafOpener(directory, op, uid, resetD101OpenNativeLeaf)
}

func readResetD101PreStopNativeFileWithLeafOpener(directory, op string, uid uint32, openLeaf func(*os.File, string, int, uint32) (*os.File, error)) ([]byte, d101custody.NativeFilePin, error) {
	closed := d101custody.NativeFilePin{}
	if !lifecycleJobIDRe.MatchString(op) {
		return nil, closed, errResetExecutionEvidence
	}
	dir, beforeDir, err := openResetD101NativeDirectory(directory, uid)
	if err != nil {
		return nil, closed, err
	}
	defer dir.Close()
	if openLeaf == nil {
		return nil, closed, errResetExecutionEvidence
	}
	path := filepath.Join(directory, op+".json")
	file, err := openLeaf(dir, op, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, closed, errResetExecutionEvidence
	}
	defer file.Close()
	before, err := file.Stat()
	beforePath, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !resetD101NativeFileInfo(before, uid, false) || !resetD101SameStat(before, beforePath) {
		return nil, closed, errResetExecutionEvidence
	}
	wire, err := io.ReadAll(io.LimitReader(file, int64(d101evidencetransport.OriginalMaxBytes)+1))
	after, e1 := file.Stat()
	afterPath, e2 := os.Lstat(path)
	afterDir, e3 := dir.Stat()
	afterDirPath, e4 := os.Lstat(directory)
	if err != nil || int64(len(wire)) != before.Size() || e1 != nil || e2 != nil || e3 != nil || e4 != nil ||
		!resetD101NativeFileInfo(after, uid, false) || !resetD101NativeFileInfo(afterPath, uid, false) || !resetD101SameStat(before, after) || !resetD101SameStat(after, afterPath) ||
		!resetD101NativeDirectoryInfo(afterDir, uid) || !resetD101NativeDirectoryInfo(afterDirPath, uid) || !resetD101SameStat(beforeDir, afterDir) || !resetD101SameStat(afterDir, afterDirPath) {
		return nil, closed, errResetExecutionEvidence
	}
	fileSnapshot, e1 := resetD101NativeSnapshot(before)
	parentSnapshot, e2 := resetD101NativeSnapshot(beforeDir)
	if e1 != nil || e2 != nil {
		return nil, closed, errResetExecutionEvidence
	}
	sha := resetD101OriginalSHA(wire)
	return wire, d101custody.NativeFilePin{SHA256: sha, Snapshot: fileSnapshot, OwnerUID: uid, FileMode: 0400, LinkCount: 1, ParentSnapshot: parentSnapshot, ParentOwnerUID: uid, ParentMode: 0700}, nil
}

func (c config) readResetD101PreStopNativeProof(ctx context.Context, intent resetDecodedApprovalIntent, plan resetApprovalPlan, planSHA, gatewaySHA, expectedSHA string, uid uint32) (resetD101PreStopNativeOriginal, error) {
	closed := resetD101PreStopNativeOriginal{}
	if ctx == nil || ctx.Err() != nil || c.d101PreStopNativeInstallation == nil || !resetEvidenceSHA.MatchString(expectedSHA) {
		return closed, errResetExecutionEvidence
	}
	directory := filepath.Join(c.serversDir, ".deployer-reset-old-world")
	wire, pin, err := readResetD101PreStopNativeFile(directory, intent.Intent.OperationID, uid)
	if err != nil || pin.SHA256 != expectedSHA {
		return closed, errResetExecutionEvidence
	}
	value, err := decodeResetD101PreStopNative(wire, expectedSHA, intent, plan, planSHA, gatewaySHA, c.d101PreStopNativeInstallation.sourceSHA)
	input := c.d101PreStopNativeInstallation.oldInputs
	if err != nil || value.body.PostgresContainerID != input.PostgresContainerID || value.old.DatabaseName != input.Database || value.old.DatabaseUser != input.User {
		return closed, errResetExecutionEvidence
	}
	canonical, canonicalErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-pre-reset-originals"), intent.Intent.OperationID, uid)
	binding := resetD101PreStopNativeBinding{intent: intent, plan: plan, planSHA: planSHA, gatewaySHA: gatewaySHA, original: value, nativePin: pin, parent: pin.ParentSnapshot}
	if canonicalErr != nil || !bytes.Equal(canonical, value.canonical.Original()) || c.requireResetD101PreStopProducer(ctx, binding) != nil {
		return closed, errResetExecutionEvidence
	}
	after, afterPin, afterErr := readResetD101PreStopNativeFile(directory, intent.Intent.OperationID, uid)
	canonicalAfter, canonicalAfterErr := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-pre-reset-originals"), intent.Intent.OperationID, uid)
	if afterErr != nil || canonicalAfterErr != nil || !bytes.Equal(canonicalAfter, canonical) || !bytes.Equal(after, wire) || !reflect.DeepEqual(afterPin, pin) || ctx.Err() != nil {
		return closed, errResetExecutionEvidence
	}
	// Return a fresh decode from the retained FD bytes after authentication;
	// the verifier never owns mutable backing storage in the returned value.
	return decodeResetD101PreStopNative(after, expectedSHA, intent, plan, planSHA, gatewaySHA, c.d101PreStopNativeInstallation.sourceSHA)
}
