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

// Production ownership is root. UID injection is private to this package tests.
func ReadPrivate(path string, limit int64) (Original, error) { return readPrivate(path, limit, 0) }

func readPrivate(path string, limit int64, uid uint32) (Original, error) {
	closed := Original{}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || limit <= 0 || limit > 64<<20 {
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
	beforePath, err := os.Lstat(path)
	if err != nil || !privateFile(beforePath, limit, uid) {
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
	if err != nil || !privateFile(before, limit, uid) || !os.SameFile(beforePath, before) {
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
		!privateFile(after, limit, uid) || !privateFile(afterPath, limit, uid) ||
		!privateDirectory(afterDir, uid) || !os.SameFile(before, after) ||
		!os.SameFile(before, afterPath) || !os.SameFile(beforeDir, afterDir) ||
		before.Size() != after.Size() || before.Size() != afterPath.Size() ||
		!before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(afterPath.ModTime()) ||
		!beforeDir.ModTime().Equal(afterDir.ModTime()) {
		return closed, ErrUnavailable
	}
	sum := sha256.Sum256(wire)
	return Original{wire, hex.EncodeToString(sum[:])}, nil
}

func privateDirectory(info os.FileInfo, uid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && info.IsDir() && info.Mode().Perm() == 0700 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}
func privateFile(info os.FileInfo, limit int64, uid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Nlink == 1 && info.Mode().IsRegular() &&
		info.Mode().Perm() == 0400 && info.Size() > 0 && info.Size() <= limit &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}
