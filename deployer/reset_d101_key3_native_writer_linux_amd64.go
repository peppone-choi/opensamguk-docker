//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"opensamguk-deployer/internal/d101custody"
)

type resetD101Key3HeldDirectory struct {
	file     *os.File
	parent   *resetD101Key3HeldDirectory
	name     string
	identity resetD101Key3DirectoryIdentity
}
type resetD101Key3HeldOutput struct {
	file     *os.File
	parent   *resetD101Key3HeldDirectory
	name     string
	mode     uint32
	info     os.FileInfo
	original []byte
}
type resetD101Key3NativeTree struct {
	directories                                []*resetD101Key3HeldDirectory
	files                                      []*resetD101Key3HeldOutput
	base, onceParent, keysParent, publicParent *resetD101Key3HeldDirectory
}

func resetD101Key3DirectoryID(info os.FileInfo) (resetD101Key3DirectoryIdentity, error) {
	if info == nil || !info.IsDir() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return resetD101Key3DirectoryIdentity{}, errResetExecutionEvidence
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return resetD101Key3DirectoryIdentity{}, errResetExecutionEvidence
	}
	return resetD101Key3DirectoryIdentity{uint64(stat.Dev), uint64(stat.Ino), stat.Uid, uint32(info.Mode().Perm())}, nil
}
func (t *resetD101Key3NativeTree) close() {
	for _, f := range t.files {
		clear(f.original)
		_ = f.file.Close()
	}
	for i := len(t.directories) - 1; i >= 0; i-- {
		_ = t.directories[i].file.Close()
	}
}
func (t *resetD101Key3NativeTree) holdDirectory(parent *resetD101Key3HeldDirectory, name, path string, expected *resetD101Key3DirectoryIdentity) (*resetD101Key3HeldDirectory, error) {
	var fd int
	var err error
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	if parent == nil {
		fd, err = syscall.Open(path, flags, 0)
	} else {
		fd, err = syscall.Openat(int(parent.file.Fd()), name, flags, 0)
	}
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	id, e := resetD101Key3DirectoryID(info)
	if err != nil || e != nil || expected != nil && id != *expected {
		_ = f.Close()
		return nil, errResetExecutionEvidence
	}
	d := &resetD101Key3HeldDirectory{f, parent, name, id}
	t.directories = append(t.directories, d)
	return d, nil
}
func (t *resetD101Key3NativeTree) recheck() error {
	for _, d := range t.directories {
		info, err := d.file.Stat()
		id, e := resetD101Key3DirectoryID(info)
		if err != nil || e != nil || id != d.identity {
			return errResetExecutionEvidence
		}
		var fd int
		if d.parent == nil {
			fd, err = syscall.Open(d.file.Name(), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		} else {
			fd, err = syscall.Openat(int(d.parent.file.Fd()), d.name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		}
		if err != nil {
			return errResetExecutionEvidence
		}
		reopened := os.NewFile(uintptr(fd), d.file.Name())
		info, err = reopened.Stat()
		_ = reopened.Close()
		id, e = resetD101Key3DirectoryID(info)
		if err != nil || e != nil || id != d.identity {
			return errResetExecutionEvidence
		}
	}
	for _, f := range t.files {
		if f.recheck() != nil {
			return errResetExecutionEvidence
		}
	}
	return nil
}
func (f *resetD101Key3HeldOutput) recheck() error {
	info, err := f.file.Stat()
	if err != nil || !resetD101Key3OutputMetadata(info, f.mode, len(f.original)) || !os.SameFile(info, f.info) || info.Size() != f.info.Size() || !info.ModTime().Equal(f.info.ModTime()) {
		return errResetExecutionEvidence
	}
	fd, err := syscall.Openat(int(f.parent.file.Fd()), f.name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	current := os.NewFile(uintptr(fd), f.file.Name())
	defer current.Close()
	named, err := current.Stat()
	if err != nil || !resetD101Key3OutputMetadata(named, f.mode, len(f.original)) || !os.SameFile(info, named) || !info.ModTime().Equal(named.ModTime()) {
		return errResetExecutionEvidence
	}
	// ReadAt does not alter a shared descriptor offset. Exact bytes, not labels.
	wire := make([]byte, len(f.original))
	defer clear(wire)
	n, err := f.file.ReadAt(wire, 0)
	if n != len(wire) || err != nil && err != io.EOF || !bytes.Equal(wire, f.original) {
		return errResetExecutionEvidence
	}
	after, err := f.file.Stat()
	if err != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return errResetExecutionEvidence
	}
	return nil
}
func resetD101Key3OutputMetadata(info os.FileInfo, mode uint32, length int) bool {
	if info == nil || !info.Mode().IsRegular() || uint32(info.Mode().Perm()) != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() != int64(length) {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && st.Nlink == 1
}
func (f *resetD101Key3HeldOutput) pin() (pin resetD101Key3NativeFilePin, errorOut error) {
	if f.recheck() != nil {
		return pin, errResetExecutionEvidence
	}
	info, err := f.file.Stat()
	parent, e := f.parent.file.Stat()
	if err != nil || e != nil {
		return pin, errResetExecutionEvidence
	}
	return resetD101NativeInputPin(info, parent, f.original), nil
}

// An alias reuses the exact existing pin schema, without changing its reader.
type resetD101Key3NativeFilePin = d101custody.NativeFilePin

func resetD101Key3Absent(parent *resetD101Key3HeldDirectory, name string) error {
	fd, err := syscall.Openat(int(parent.file.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err == syscall.ENOENT {
		return nil
	}
	if err == nil {
		_ = syscall.Close(fd)
	}
	return errResetExecutionEvidence
}
func (t *resetD101Key3NativeTree) capacity(required uint64) error {
	var st syscall.Statfs_t
	if required == 0 || syscall.Fstatfs(int(t.base.file.Fd()), &st) != nil || st.Bsize <= 0 || st.Bavail > ^uint64(0)/uint64(st.Bsize) || st.Bavail*uint64(st.Bsize) < required {
		return errResetExecutionEvidence
	}
	return nil
}
func (t *resetD101Key3NativeTree) conflicts() error {
	if resetD101Key3Absent(t.onceParent, "key3-initialize") != nil {
		return errResetExecutionEvidence
	}
	for _, role := range []string{"root-purpose", "approval-issuer", "approved-receipt-issuer"} {
		if resetD101Key3Absent(t.keysParent, role) != nil || resetD101Key3Absent(t.publicParent, role+".spki") != nil {
			return errResetExecutionEvidence
		}
	}
	return resetD101Key3Absent(t.publicParent, "key3-generation.json")
}
func (t *resetD101Key3NativeTree) reserveFile(parent *resetD101Key3HeldDirectory, name string, mode uint32) (*resetD101Key3HeldOutput, error) {
	fd, err := syscall.Openat(int(parent.file.Fd()), name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, mode)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	f := os.NewFile(uintptr(fd), filepath.Join(parent.file.Name(), name))
	out := &resetD101Key3HeldOutput{file: f, parent: parent, name: name, mode: mode}
	t.files = append(t.files, out)
	// A private umask may restrict public mode; chmod the exclusively held FD.
	if f.Chmod(os.FileMode(mode)) != nil {
		return nil, errResetExecutionEvidence
	}
	out.info, err = f.Stat()
	if err != nil || !resetD101Key3OutputMetadata(out.info, mode, 0) {
		return nil, errResetExecutionEvidence
	}
	return out, nil
}

// Only this private kernel helper accepts fixture entropy and fault/trace
// callbacks. Production constructs the guard from actual held authentication,
// selects crypto/rand itself and supplies no caller-controlled callbacks.
type resetD101Key3KernelChecks struct {
	guard  func(context.Context) error
	before func(string) error
	after  func(string)
}

func (k resetD101Key3KernelChecks) check(ctx context.Context, t *resetD101Key3NativeTree) error {
	if ctx == nil || ctx.Err() != nil || k.guard == nil || k.guard(ctx) != nil || t.recheck() != nil {
		return errResetExecutionEvidence
	}
	return nil
}
func (k resetD101Key3KernelChecks) event(name string) error {
	if k.before != nil && k.before(name) != nil {
		return errResetExecutionEvidence
	}
	return nil
}
func (k resetD101Key3KernelChecks) synced(f *os.File, name string) error {
	if k.event("before-"+name) != nil || f.Sync() != nil {
		return errResetExecutionEvidence
	}
	if k.after != nil {
		k.after(name)
	}
	return nil
}
func (t *resetD101Key3NativeTree) fill(ctx context.Context, f *resetD101Key3HeldOutput, wire []byte, k resetD101Key3KernelChecks, name string) error {
	if k.check(ctx, t) != nil || len(wire) == 0 || f.original != nil || k.event("before-write-"+name) != nil {
		return errResetExecutionEvidence
	}
	n, err := f.file.Write(wire)
	// Retain the exact attempted bytes, even on a partial write. No retry.
	f.original = append([]byte(nil), wire...)
	f.info, _ = f.file.Stat()
	if err != nil || n != len(wire) || f.info == nil || k.synced(f.file, name+"-file-fsync") != nil || f.recheck() != nil || k.synced(f.parent.file, name+"-parent-fsync") != nil || k.check(ctx, t) != nil {
		return errResetExecutionEvidence
	}
	return nil
}

type resetD101Key3PrivateRoleReceipt struct {
	Role             string                     `json:"role"`
	CustodyID        string                     `json:"custodyId"`
	KeyID            string                     `json:"keyId"`
	EnvelopeSHA256   string                     `json:"envelopeSha256"`
	PublicSPKISHA256 string                     `json:"publicSpkiSha256"`
	PrivateNativePin resetD101Key3NativeFilePin `json:"privateNativePin"`
	PublicNativePin  resetD101Key3NativeFilePin `json:"publicNativePin"`
}
type resetD101Key3IntentReceipt struct {
	SchemaVersion        uint32 `json:"schemaVersion"`
	Kind                 string `json:"kind"`
	CeremonyCardSHA256   string `json:"ceremonyCardSha256"`
	CeremonyID           string `json:"ceremonyId"`
	HostInstanceID       string `json:"hostInstanceId"`
	SourceSHA            string `json:"sourceSha"`
	BinarySHA256         string `json:"binarySha256"`
	ExecutionScopeSHA256 string `json:"executionScopeSha256"`
	DriverPID            int    `json:"driverPid"`
	DriverStartTicks     uint64 `json:"driverStartTicks"`
	StartedAtUnixNano    int64  `json:"startedAtUnixNano"`
}
type resetD101Key3CompleteReceipt struct {
	SchemaVersion       uint32                             `json:"schemaVersion"`
	Kind                string                             `json:"kind"`
	IntentSHA256        string                             `json:"intentSha256"`
	ManifestSHA256      string                             `json:"manifestSha256"`
	CompletedAtUnixNano int64                              `json:"completedAtUnixNano"`
	Roles               [3]resetD101Key3PrivateRoleReceipt `json:"roles"`
}

func resetD101Key3SelfStartTicks() (uint64, error) {
	file, err := os.Open("/proc/self/stat")
	if err != nil {
		return 0, errResetExecutionEvidence
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, resetD101Key3CardMaxBytes+1))
	if err != nil || len(b) > resetD101Key3CardMaxBytes {
		return 0, errResetExecutionEvidence
	}
	end := strings.LastIndex(string(b), ") ")
	if end < 0 {
		return 0, errResetExecutionEvidence
	}
	fields := strings.Fields(string(b[end+2:]))
	if len(fields) <= 19 {
		return 0, errResetExecutionEvidence
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, errResetExecutionEvidence
	}
	return start, nil
}

func writeResetD101Key3Kernel(ctx context.Context, t *resetD101Key3NativeTree, session *resetD101Key3AuthenticatedSession, binding resetD101Key3NativeInitializationBinding, required uint64, entropy io.Reader, k resetD101Key3KernelChecks) (result resetD101Key3NativeInitializationOutcome) {
	result.err = errResetExecutionEvidence
	if session == nil || entropy == nil || k.check(ctx, t) != nil || t.capacity(required) != nil || t.conflicts() != nil {
		return result
	}
	startTicks, err := resetD101Key3SelfStartTicks()
	if err != nil {
		return result
	}
	started := time.Now()
	c := session.expected.Card
	intentValue := resetD101Key3IntentReceipt{1, "KEY3_ATTEMPT", session.expected.CardSHA, c.CeremonyID, c.HostInstanceID, c.InitializerSourceSHA, c.InitializerBinarySHA256, binding.executionScopeSHA, os.Getpid(), startTicks, started.UnixNano()}
	wire, err := json.Marshal(intentValue)
	if err != nil || k.check(ctx, t) != nil || k.event("before-once-mkdir") != nil {
		return result
	}
	// The fixed GLOBAL once excludes a changed card as well as same-card retry.
	err = syscall.Mkdirat(int(t.onceParent.file.Fd()), "key3-initialize", 0700)
	if err == syscall.EEXIST {
		return result
	}
	result.attempted = true // all other outcomes are conservatively retained
	if err != nil {
		return result
	}
	once, err := t.holdDirectory(t.onceParent, "key3-initialize", filepath.Join(t.onceParent.file.Name(), "key3-initialize"), nil)
	if err != nil || once.identity.Mode != 0700 || once.identity.Device != t.onceParent.identity.Device {
		return result
	}
	stage := "once-intent"
	defer func() {
		if result.complete || result.err == nil || k.check(ctx, t) != nil {
			return
		}
		// Best effort factual failure record. If auth/metadata has expired, preserve
		// the existing attempt instead of creating an unapproved follow-on record.
		failure, _ := json.Marshal(struct {
			SchemaVersion uint32 `json:"schemaVersion"`
			Kind          string `json:"kind"`
			Stage         string `json:"stage"`
			CardSHA256    string `json:"cardSha256"`
		}{1, "HOLD_RETAIN_NO_RETRY", stage, session.expected.CardSHA})
		f, e := t.reserveFile(once, "failure.json", 0400)
		if e == nil {
			_ = t.fill(ctx, f, failure, k, "failure")
		}
	}()
	intent, err := t.reserveFile(once, "intent.json", 0400)
	if err != nil || t.fill(ctx, intent, wire, k, "intent") != nil || k.synced(t.onceParent.file, "once-parent-fsync") != nil || k.check(ctx, t) != nil || t.capacity(required) != nil {
		return result
	}
	// No entropy can occur above this point. Intent file, once directory, and
	// its parent were really fsynced, re-read and remain held at this boundary.
	stage = "private-parents"
	var parents [3]*resetD101Key3HeldDirectory
	for i, role := range []string{"root-purpose", "approval-issuer", "approved-receipt-issuer"} {
		if k.check(ctx, t) != nil || k.event("before-role-mkdir-"+role) != nil || syscall.Mkdirat(int(t.keysParent.file.Fd()), role, 0700) != nil {
			return result
		}
		parents[i], err = t.holdDirectory(t.keysParent, role, filepath.Join(t.keysParent.file.Name(), role), nil)
		if err != nil || parents[i].identity.Mode != 0700 || parents[i].identity.Device != t.keysParent.identity.Device || k.synced(parents[i].file, role+"-directory-fsync") != nil || k.synced(t.keysParent.file, role+"-keys-parent-fsync") != nil {
			return result
		}
	}
	if k.check(ctx, t) != nil || t.capacity(required) != nil || k.event("before-entropy") != nil || k.check(ctx, t) != nil || t.capacity(required) != nil {
		return result
	}
	stage = "entropy"
	material, err := prepareResetD101UntrustedKey3(entropy)
	if err != nil {
		return result
	}
	defer func() {
		for i := range material {
			material[i].close()
		}
	}()
	if k.check(ctx, t) != nil {
		return result
	}
	var private [3]*resetD101Key3HeldOutput
	var public [3]*resetD101Key3HeldOutput
	stage = "private-write"
	for i, m := range material {
		private[i], err = t.reserveFile(parents[i], m.custodyID+".json", 0400)
		if err != nil || t.fill(ctx, private[i], m.privateEnvelope, k, "private-"+m.role) != nil {
			return result
		}
		// Reuse the existing production UID0 reader without changing it. This
		// readback grants no purpose/signing authority and the key is closed now.
		key, e := readResetD101SigningKey(resetD101SigningKeyPins{parents[i].file.Name(), m.custodyID, m.envelopeSHA, m.keyID, m.publicSPKISHA})
		if e != nil {
			return result
		}
		key.close()
		if k.check(ctx, t) != nil {
			return result
		}
	}
	stage = "public-write"
	for i, m := range material {
		public[i], err = t.reserveFile(t.publicParent, m.role+".spki", 0444)
		if err != nil || t.fill(ctx, public[i], m.publicDER, k, "public-"+m.role) != nil {
			return result
		}
	}
	// Reserve the manifest BEFORE freezing public parent snapshots. Otherwise
	// creating its name would invalidate parent mtime pins embedded in itself.
	manifest, err := t.reserveFile(t.publicParent, "key3-generation.json", 0444)
	if err != nil || k.check(ctx, t) != nil {
		return result
	}
	manifestValue := resetD101Key3GeneratedPublicManifest{SchemaVersion: 1, Kind: "KEY3_GENERATION_UNOBSERVED", CeremonyID: c.CeremonyID, CeremonyCardSHA256: session.expected.CardSHA, HostInstanceID: c.HostInstanceID,
		InitializerSourceSHA: c.InitializerSourceSHA, InitializerBinarySHA256: c.InitializerBinarySHA256, HumanApprovalSHA256: c.HumanApprovalOriginalRef.SHA256, CustodianAssignmentSHA256: c.CustodianAssignmentOriginalRef.SHA256,
		PrivateRetentionSHA256: c.PrivateRetentionOriginalRef.SHA256, ExecutionScopeSHA256: binding.executionScopeSHA, StartedAtUnixNano: started.UnixNano(), CompletedAtUnixNano: time.Now().UnixNano()}
	completed := resetD101Key3CompleteReceipt{SchemaVersion: 1, Kind: "KEY3_COMPLETE_UNOBSERVED", IntentSHA256: resetD101OriginalSHA(wire)}
	for i, m := range material {
		pri, e1 := private[i].pin()
		pub, e2 := public[i].pin()
		if e1 != nil || e2 != nil {
			return result
		}
		manifestValue.Roles[i] = resetD101Key3GeneratedPublicRole{m.role, m.custodyID, m.keyID, m.envelopeSHA, base64.RawURLEncoding.EncodeToString(m.publicDER), m.publicSPKISHA, pub}
		completed.Roles[i] = resetD101Key3PrivateRoleReceipt{m.role, m.custodyID, m.keyID, m.envelopeSHA, m.publicSPKISHA, pri, pub}
	}
	stage = "public-manifest"
	publicWire, err := json.Marshal(manifestValue)
	if err != nil || t.fill(ctx, manifest, publicWire, k, "manifest") != nil {
		return result
	}
	stage = "private-completion"
	completed.ManifestSHA256 = resetD101OriginalSHA(publicWire)
	completed.CompletedAtUnixNano = time.Now().UnixNano()
	completionWire, err := json.Marshal(completed)
	if err != nil {
		return result
	}
	completion, err := t.reserveFile(once, "complete.json", 0400)
	if err != nil || t.fill(ctx, completion, completionWire, k, "completion") != nil || k.check(ctx, t) != nil {
		return result
	}
	result.complete = true
	result.err = nil
	return result
}

func openResetD101Key3ProductionTree(e resetD101Key3NativeInitializationExpected) (*resetD101Key3NativeTree, error) {
	t := &resetD101Key3NativeTree{}
	failed := true
	defer func() {
		if failed {
			t.close()
		}
	}()
	root, err := t.holdDirectory(nil, "", "/", nil)
	if err != nil {
		return nil, err
	}
	current := root
	for _, name := range []string{"etc", "opensamguk", "d101"} {
		var pin *resetD101Key3DirectoryIdentity
		if name == "d101" {
			pin = &e.BaseDirectory
		}
		current, err = t.holdDirectory(current, name, filepath.Join(current.file.Name(), name), pin)
		if err != nil {
			return nil, err
		}
	}
	t.base = current
	t.onceParent, err = t.holdDirectory(t.base, ".once", filepath.Join(t.base.file.Name(), ".once"), &e.OnceParent)
	if err != nil {
		return nil, err
	}
	t.keysParent, err = t.holdDirectory(t.base, "keys", filepath.Join(t.base.file.Name(), "keys"), &e.KeysParent)
	if err != nil {
		return nil, err
	}
	t.publicParent, err = t.holdDirectory(t.base, "key-public", filepath.Join(t.base.file.Name(), "key-public"), &e.PublicParent)
	if err != nil || t.recheck() != nil {
		return nil, errResetExecutionEvidence
	}
	failed = false
	return t, nil
}

func initializeResetD101Key3Native(ctx context.Context, session *resetD101Key3AuthenticatedSession, e resetD101Key3NativeInitializationExpected, b resetD101Key3NativeInitializationBinding, source resetD101Key3NativeInitializationSource) resetD101Key3NativeInitializationOutcome {
	denied := resetD101Key3NativeInitializationOutcome{err: errResetD101InstallationNotSupplied}
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || resetD101Key3SourceMissing(source) || requireResetD101Key3NativeBinding(b, session, e, time.Now()) != nil || session.recheck(ctx) != nil || source.Recheck(ctx, session, e, b) != nil {
		return denied
	}
	t, err := openResetD101Key3ProductionTree(e)
	if err != nil {
		return denied
	}
	defer t.close()
	// Retain the independently pinned installed artifact, and prove it is this
	// running executable before once/entropy. Follow only the fixed kernel proc
	// executable link; no supplied path, env or UID override exists.
	parentID := resetD101Key3DirectoryIdentity{e.InstallerPin.ParentSnapshot.Device, e.InstallerPin.ParentSnapshot.Inode, 0, 0700}
	helper, err := t.holdDirectory(t.base, "native-helper", filepath.Join(t.base.file.Name(), "native-helper"), &parentID)
	if err != nil {
		return denied
	}
	fd, err := syscall.Openat(int(helper.file.Fd()), "deployer", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return denied
	}
	artifact := os.NewFile(uintptr(fd), filepath.Join(helper.file.Name(), "deployer"))
	defer artifact.Close()
	running, err := os.Open("/proc/self/exe")
	if err != nil {
		return denied
	}
	defer running.Close()
	limit := e.InstallerPin.Snapshot.ByteLength
	// Match the existing custody reader's executable budget; no new capacity or
	// time policy is invented. Length itself is independently pinned.
	if limit == 0 || limit > 64<<20 {
		return denied
	}
	original, err := io.ReadAll(io.LimitReader(artifact, int64(limit)+1))
	defer clear(original)
	a, e1 := artifact.Stat()
	r, e2 := running.Stat()
	p, e3 := helper.file.Stat()
	if err != nil || e1 != nil || e2 != nil || e3 != nil || uint64(len(original)) != limit || !os.SameFile(a, r) || !resetD101Key3OutputMetadata(a, 0500, len(original)) || resetD101NativeInputPin(a, p, original) != e.InstallerPin {
		return denied
	}
	held := &resetD101Key3HeldOutput{artifact, helper, "deployer", 0500, a, original}
	guard := func(current context.Context) error {
		if current == nil || current.Err() != nil || session.recheck(current) != nil || t.capacity(e.MinimumAvailableBytes) != nil || requireResetD101Key3NativeBinding(b, session, e, time.Now()) != nil || source.Recheck(current, session, e, b) != nil ||
			requireResetD101Key3NativeBinding(b, session, e, time.Now()) != nil || held.recheck() != nil {
			return errResetExecutionEvidence
		}
		live, err := running.Stat()
		pin, err2 := artifact.Stat()
		parent, err3 := helper.file.Stat()
		if err != nil || err2 != nil || err3 != nil || !os.SameFile(live, pin) || !reflect.DeepEqual(resetD101NativeInputPin(pin, parent, original), e.InstallerPin) {
			return errResetExecutionEvidence
		}
		return nil
	}
	if guard(ctx) != nil {
		return denied
	}
	mask := syscall.Umask(0077)
	defer syscall.Umask(mask)
	return writeResetD101Key3Kernel(ctx, t, session, b, e.MinimumAvailableBytes, rand.Reader, resetD101Key3KernelChecks{guard: guard})
}
