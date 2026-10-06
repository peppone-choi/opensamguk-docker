package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"opensamguk-deployer/internal/d101custody"
)

const resetD101InstallationAnchorPath = "/etc/opensamguk/d101/installation-anchor.spki"

var resetD101CurrentAuthorityLeaves = [...]string{
	"writer-freeze-receipt.bin", "installed-writer-inventory.bin", "keeper-session.bin",
	"console-admission.bin", "root-admission.bin", "old-services.bin", "turn-flush.bin",
	"publisher.bin", "postgres-admission.bin",
}

// Independently frozen private installation data. No value is learned from a
// file just read. These observations cannot authenticate an issuer or lifetime.
type resetD101NativeInstallExpected struct {
	operationID string
	anchorDER   []byte
	anchorPin   d101custody.NativeFilePin
	leaves      map[string]d101custody.NativeFilePin
}

var resetD101ReviewedNativeInstallExpected *resetD101NativeInstallExpected

type resetD101NativeHeldInput struct {
	file, directory         *os.File
	fileInfo, directoryInfo os.FileInfo
	wire                    []byte
	pin                     d101custody.NativeFilePin
	checkAncestors          func(string, uint32) error
}

func (h *resetD101NativeHeldInput) close() {
	if h != nil {
		if h.file != nil {
			_ = h.file.Close()
		}
		if h.directory != nil {
			_ = h.directory.Close()
		}
	}
}

// Native snapshots are data only, even when all bytes and descriptors match.
func resetD101NativeInputMetadata(info os.FileInfo, uid uint32, mode uint32, directory bool) bool {
	if info == nil || uint32(info.Mode().Perm()) != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid && ((directory && info.IsDir()) || (!directory && info.Mode().IsRegular() && st.Nlink == 1 && info.Size() > 0 && info.Size() <= 64<<10))
}
func resetD101NativeInputPin(file, parent os.FileInfo, wire []byte) d101custody.NativeFilePin {
	f := file.Sys().(*syscall.Stat_t)
	d := parent.Sys().(*syscall.Stat_t)
	return d101custody.NativeFilePin{SHA256: resetD101OriginalSHA(wire),
		Snapshot: d101custody.PrivateSnapshot{Device: uint64(f.Dev), Inode: uint64(f.Ino), ByteLength: uint64(file.Size()), ModifiedAtUnixNano: file.ModTime().UnixNano()},
		OwnerUID: f.Uid, FileMode: uint32(file.Mode().Perm()), LinkCount: uint64(f.Nlink),
		ParentSnapshot: d101custody.PrivateSnapshot{Device: uint64(d.Dev), Inode: uint64(d.Ino), ByteLength: uint64(parent.Size()), ModifiedAtUnixNano: parent.ModTime().UnixNano()},
		ParentOwnerUID: d.Uid, ParentMode: uint32(parent.Mode().Perm())}
}
func resetD101NativeInputAncestors(path string, uid uint32) error {
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errResetExecutionEvidence
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uid || info.Mode().Perm()&0022 != 0 {
			return errResetExecutionEvidence
		}
		if p == "/" {
			break
		}
	}
	return nil
}
func openResetD101NativeInput(ctx context.Context, path string, expected d101custody.NativeFilePin, mode uint32, uid uint32) (*resetD101NativeHeldInput, error) {
	return openResetD101NativeInputWithAncestors(ctx, path, expected, mode, uid, resetD101NativeInputAncestors)
}

// Explicit ancestor seam is restricted to isolated filesystem fixtures.
func openResetD101NativeInputWithAncestors(ctx context.Context, path string, expected d101custody.NativeFilePin, mode uint32, uid uint32, ancestors func(string, uint32) error) (held *resetD101NativeHeldInput, result error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !resetEvidenceSHA.MatchString(expected.SHA256) ||
		expected.OwnerUID != uid || expected.FileMode != mode || expected.LinkCount != 1 || expected.ParentOwnerUID != uid || expected.ParentMode != 0700 ||
		expected.Snapshot.Device == 0 || expected.Snapshot.Inode == 0 || expected.Snapshot.ByteLength == 0 || expected.Snapshot.ByteLength > 64<<10 ||
		expected.ParentSnapshot.Device == 0 || expected.ParentSnapshot.Inode == 0 || mode != 0400 && mode != 0444 {
		return nil, errResetExecutionEvidence
	}
	if ancestors == nil || ancestors(path, uid) != nil {
		return nil, errResetExecutionEvidence
	}
	h := &resetD101NativeHeldInput{pin: expected, checkAncestors: ancestors}
	defer func() {
		if result != nil {
			h.close()
		}
	}()
	fd, err := syscall.Open(filepath.Dir(path), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	h.directory = os.NewFile(uintptr(fd), filepath.Dir(path))
	fd, err = syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	h.file = os.NewFile(uintptr(fd), path)
	h.fileInfo, err = h.file.Stat()
	if err != nil || !resetD101NativeInputMetadata(h.fileInfo, uid, mode, false) {
		return nil, errResetExecutionEvidence
	}
	h.directoryInfo, err = h.directory.Stat()
	if err != nil || !resetD101NativeInputMetadata(h.directoryInfo, uid, 0700, true) {
		return nil, errResetExecutionEvidence
	}
	h.wire, err = io.ReadAll(io.LimitReader(h.file, 64<<10+1))
	if err != nil || resetD101NativeInputPin(h.fileInfo, h.directoryInfo, h.wire) != expected || h.recheck(ctx, uid) != nil {
		return nil, errResetExecutionEvidence
	}
	return h, nil
}
func (h *resetD101NativeHeldInput) recheck(ctx context.Context, uid uint32) error {
	if h == nil || h.file == nil || h.directory == nil || ctx == nil || ctx.Err() != nil || h.checkAncestors == nil || h.checkAncestors(h.file.Name(), uid) != nil {
		return errResetExecutionEvidence
	}
	before, e1 := h.file.Stat()
	parent, e2 := h.directory.Stat()
	visible, e3 := os.Lstat(h.file.Name())
	visibleParent, e4 := os.Lstat(h.directory.Name())
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !resetD101NativeInputMetadata(before, uid, h.pin.FileMode, false) || !resetD101NativeInputMetadata(parent, uid, 0700, true) ||
		!os.SameFile(h.fileInfo, before) || !os.SameFile(before, visible) || !os.SameFile(h.directoryInfo, parent) || !os.SameFile(parent, visibleParent) {
		return errResetExecutionEvidence
	}
	wire := make([]byte, len(h.wire)+1)
	n, err := h.file.ReadAt(wire, 0)
	after, e5 := h.file.Stat()
	afterParent, e6 := h.directory.Stat()
	afterVisible, e7 := os.Lstat(h.file.Name())
	afterVisibleParent, e8 := os.Lstat(h.directory.Name())
	if err != io.EOF || n != len(h.wire) || !bytes.Equal(wire[:n], h.wire) || e5 != nil || e6 != nil || e7 != nil || e8 != nil ||
		!resetD101NativeInputMetadata(after, uid, h.pin.FileMode, false) || !resetD101NativeInputMetadata(afterParent, uid, 0700, true) || !os.SameFile(before, after) || !os.SameFile(after, afterVisible) || !os.SameFile(parent, afterParent) || !os.SameFile(afterParent, afterVisibleParent) ||
		resetD101NativeInputPin(before, parent, h.wire) != h.pin || resetD101NativeInputPin(after, afterParent, h.wire) != h.pin || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	return nil
}
func validateResetD101NativeInstallExpected(v *resetD101NativeInstallExpected) error {
	if v == nil || !lifecycleJobIDRe.MatchString(v.operationID) || len(v.leaves) != len(resetD101CurrentAuthorityLeaves) || len(v.anchorDER) == 0 || resetD101OriginalSHA(v.anchorDER) != v.anchorPin.SHA256 {
		return errResetD101InstallationNotSupplied
	}
	if _, err := x509.ParsePKIXPublicKey(v.anchorDER); err != nil {
		return errResetExecutionEvidence
	}
	for _, leaf := range resetD101CurrentAuthorityLeaves {
		p, ok := v.leaves[leaf]
		if !ok || !resetEvidenceSHA.MatchString(p.SHA256) || p.OwnerUID != 0 || p.FileMode != 0400 || p.LinkCount != 1 || p.ParentOwnerUID != 0 || p.ParentMode != 0700 || p.Snapshot.Inode == 0 || p.ParentSnapshot.Inode == 0 {
			return errResetExecutionEvidence
		}
	}
	return nil
}

// No codec/issuer/source has been supplied for authority9. This fixed native
// negative loader may observe matching private bytes but NEVER returns authority.
func readResetD101NativeInstallNegative(ctx context.Context, op string) error {
	input := resetD101ReviewedNativeInstallExpected
	var v *resetD101NativeInstallExpected
	if input != nil {
		frozen := *input
		frozen.anchorDER = bytes.Clone(input.anchorDER)
		frozen.leaves = make(map[string]d101custody.NativeFilePin, len(input.leaves))
		for name, pin := range input.leaves {
			frozen.leaves[name] = pin
		}
		v = &frozen
	}
	if ctx == nil || ctx.Err() != nil || runtime.GOOS != "linux" || os.Geteuid() != 0 || validateResetD101NativeInstallExpected(v) != nil || op != v.operationID {
		return errResetD101InstallationNotSupplied
	}
	anchor, err := openResetD101NativeInput(ctx, resetD101InstallationAnchorPath, v.anchorPin, 0400, 0)
	if err != nil {
		return err
	}
	defer anchor.close()
	if !bytes.Equal(anchor.wire, v.anchorDER) {
		return errResetExecutionEvidence
	}
	held := make([]*resetD101NativeHeldInput, 0, len(resetD101CurrentAuthorityLeaves))
	defer func() {
		for _, h := range held {
			h.close()
		}
	}()
	for _, leaf := range resetD101CurrentAuthorityLeaves {
		path := filepath.Join("/etc/opensamguk/d101/current-authority", op, leaf)
		h, err := openResetD101NativeInput(ctx, path, v.leaves[leaf], 0400, 0)
		if err != nil {
			return err
		}
		held = append(held, h)
	}
	for _, h := range held {
		if h.recheck(ctx, 0) != nil {
			return errResetExecutionEvidence
		}
	}
	if anchor.recheck(ctx, 0) != nil {
		return errResetExecutionEvidence
	}
	return errResetD101InstallationNotSupplied
}
