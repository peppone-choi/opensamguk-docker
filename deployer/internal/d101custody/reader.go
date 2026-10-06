// Package d101custody reads only fixed installed private files. It does not
// approve a receipt, choose a source, sign, install a key or perform mutations.
package d101custody

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var ErrUnavailable = errors.New("D101 private source unavailable")

type Original struct {
	Bytes  []byte
	SHA256 string
}

// Actual descriptor observations for the r1 custody record. These values are
// data, not origin authentication or an installed signing authority.
type NativeFilePin struct {
	SHA256         string          `json:"sha256"`
	Snapshot       PrivateSnapshot `json:"nativeSnapshot"`
	OwnerUID       uint32          `json:"ownerUid"`
	FileMode       uint32          `json:"fileMode"`
	LinkCount      uint64          `json:"linkCount"`
	ParentSnapshot PrivateSnapshot `json:"parentSnapshot"`
	ParentOwnerUID uint32          `json:"parentOwnerUid"`
	ParentMode     uint32          `json:"parentMode"`
}

func CapturePrivateOriginalPin(path string, limit int64) (Original, NativeFilePin, error) {
	return capturePrivateFilePin(path, limit, 0, 0400)
}
func CapturePrivateExecutablePin(path string, limit int64) (Original, NativeFilePin, error) {
	return capturePrivateFilePin(path, limit, 0, 0500)
}
func capturePrivateFilePin(path string, limit int64, uid uint32, mode os.FileMode) (Original, NativeFilePin, error) {
	var pin NativeFilePin
	original, err := readPrivateModeNativeCapture(path, limit, uid, mode, nil, &pin)
	return original, pin, err
}

// Production ownership is root. UID injection is private to this package tests.
func ReadPrivate(path string, limit int64) (Original, error) { return readPrivate(path, limit, 0) }

// Only the fixed, independently SHA-pinned helper uses executable mode 0500.
// This does not execute it or accept a caller's alternative file permissions.
func ReadPrivateExecutable(path string, limit int64) (Original, error) {
	return readPrivateMode(path, limit, 0, 0500)
}

func CapturePrivateExecutable(path string, limit int64) (Original, PrivateSnapshot, error) {
	var snapshot PrivateSnapshot
	original, err := readPrivateModeCapture(path, limit, 0, 0500, &snapshot)
	return original, snapshot, err
}

func readPrivate(path string, limit int64, uid uint32) (Original, error) {
	return readPrivateMode(path, limit, uid, 0400)
}

func readPrivateMode(path string, limit int64, uid uint32, mode os.FileMode) (Original, error) {
	return readPrivateModeCapture(path, limit, uid, mode, nil)
}
func readPrivateModeCapture(path string, limit int64, uid uint32, mode os.FileMode, snapshot *PrivateSnapshot) (Original, error) {
	return readPrivateModeNativeCapture(path, limit, uid, mode, snapshot, nil)
}
func readPrivateModeNativeCapture(path string, limit int64, uid uint32, mode os.FileMode, snapshot *PrivateSnapshot, nativePin *NativeFilePin) (Original, error) {
	closed := Original{}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || limit <= 0 || limit > 64<<20 || mode != 0400 && mode != 0500 {
		return closed, ErrUnavailable
	}
	parent := filepath.Dir(path)
	canonical, err := filepath.EvalSymlinks(parent)
	if err != nil || canonical != parent {
		return closed, ErrUnavailable
	}
	beforeDir, err := os.Lstat(parent)
	if err != nil || !privateDirectory(beforeDir, uid) {
		return closed, ErrUnavailable
	}
	var parentFile *os.File
	if nativePin != nil {
		dirFD, err := syscall.Open(parent, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err != nil {
			return closed, ErrUnavailable
		}
		parentFile = os.NewFile(uintptr(dirFD), parent)
		defer parentFile.Close()
		actualDir, err := parentFile.Stat()
		if err != nil || !privateDirectory(actualDir, uid) || !os.SameFile(beforeDir, actualDir) ||
			beforeDir.Size() != actualDir.Size() || !beforeDir.ModTime().Equal(actualDir.ModTime()) {
			return closed, ErrUnavailable
		}
		beforeDir = actualDir // Parent snapshot comes from the actual open FD.
	}
	beforePath, err := os.Lstat(path)
	if err != nil || !privateFileMode(beforePath, limit, uid, mode) {
		return closed, ErrUnavailable
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return closed, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	// Actual descriptor metadata, independently of the path's earlier labels.
	before, err := file.Stat()
	if err != nil || !privateFileMode(before, limit, uid, mode) || !os.SameFile(beforePath, before) {
		return closed, ErrUnavailable
	}
	wire, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(wire)) != before.Size() {
		return closed, ErrUnavailable
	}
	after, err := file.Stat()
	afterPath, pathErr := os.Lstat(path)
	afterDir, dirErr := os.Lstat(parent)
	if err != nil || pathErr != nil || dirErr != nil ||
		!privateFileMode(after, limit, uid, mode) || !privateFileMode(afterPath, limit, uid, mode) ||
		!privateDirectory(afterDir, uid) || !os.SameFile(before, after) ||
		!os.SameFile(before, afterPath) || !os.SameFile(beforeDir, afterDir) ||
		before.Size() != after.Size() || before.Size() != afterPath.Size() ||
		!before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(afterPath.ModTime()) ||
		!beforeDir.ModTime().Equal(afterDir.ModTime()) {
		return closed, ErrUnavailable
	}
	if parentFile != nil {
		actualAfterDir, err := parentFile.Stat()
		if err != nil || !privateDirectory(actualAfterDir, uid) || !os.SameFile(beforeDir, actualAfterDir) ||
			!os.SameFile(actualAfterDir, afterDir) || beforeDir.Size() != actualAfterDir.Size() || beforeDir.Size() != afterDir.Size() ||
			!beforeDir.ModTime().Equal(actualAfterDir.ModTime()) || !beforeDir.ModTime().Equal(afterDir.ModTime()) {
			return closed, ErrUnavailable
		}
	}
	sum := sha256.Sum256(wire)
	if snapshot != nil {
		value, err := privateSnapshot(before)
		if err != nil {
			return closed, ErrUnavailable
		}
		*snapshot = value
	}
	if nativePin != nil {
		fileSnapshot, fileErr := privateSnapshot(before)
		parentSnapshot, parentErr := privateSnapshot(beforeDir)
		fileStat, fileOK := before.Sys().(*syscall.Stat_t)
		parentStat, parentOK := beforeDir.Sys().(*syscall.Stat_t)
		if fileErr != nil || parentErr != nil || !fileOK || !parentOK {
			return closed, ErrUnavailable
		}
		*nativePin = NativeFilePin{hex.EncodeToString(sum[:]), fileSnapshot, fileStat.Uid, uint32(before.Mode().Perm()), uint64(fileStat.Nlink),
			parentSnapshot, parentStat.Uid, uint32(beforeDir.Mode().Perm())}
	}
	return Original{wire, hex.EncodeToString(sum[:])}, nil
}

func privateDirectory(info os.FileInfo, uid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && info.IsDir() && info.Mode().Perm() == 0700 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}
func privateFile(info os.FileInfo, limit int64, uid uint32) bool {
	return privateFileMode(info, limit, uid, 0400)
}
func privateFileMode(info os.FileInfo, limit int64, uid uint32, mode os.FileMode) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Nlink == 1 && info.Mode().IsRegular() &&
		info.Mode().Perm() == mode && info.Size() > 0 && info.Size() <= limit &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}
