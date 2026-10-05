package d101custody

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// A fixed 1MiB raw part encodes below the existing 2MiB helper pipe ceiling.
// The full original remains bounded at 64MiB. Parts never attest a full SHA:
// the consumer must assemble/hash all parts against its independently pinned
// original and require the same capture-index SHA for the entire transfer.
const PrivateOriginalPartBytes uint64 = 1 << 20
const PrivateOriginalMaxBytes uint64 = 64 << 20

type PrivateSnapshot struct {
	Device             uint64 `json:"device"`
	Inode              uint64 `json:"inode"`
	ByteLength         uint64 `json:"byteLength"`
	ModifiedAtUnixNano int64  `json:"modifiedAtUnixNano"`
}
type PrivatePart struct {
	Bytes      []byte
	PartSHA256 string
	Snapshot   PrivateSnapshot
	PartIndex  uint64
	Offset     uint64
}

// The approved capture installer freezes this identity together with the
// actual whole SHA from this one native read. No future intent/card is read.
func CapturePrivateOriginal(path string, limit int64) (Original, PrivateSnapshot, error) {
	return capturePrivateOriginal(path, limit, 0)
}
func capturePrivateOriginal(path string, limit int64, uid uint32) (Original, PrivateSnapshot, error) {
	part, err := readPrivateSegment(path, limit, nil, 0, uid, true)
	if err != nil {
		return Original{}, PrivateSnapshot{}, ErrUnavailable
	}
	return Original{part.Bytes, part.PartSHA256}, part.Snapshot, nil
}
func ReadPrivatePart(path string, expected PrivateSnapshot, partIndex uint64) (PrivatePart, error) {
	return readPrivateSegment(path, int64(PrivateOriginalMaxBytes), &expected, partIndex, 0, false)
}
func privateSnapshot(info os.FileInfo) (PrivateSnapshot, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Size() <= 0 || uint64(info.Size()) > PrivateOriginalMaxBytes || uint64(stat.Dev) == 0 || uint64(stat.Ino) == 0 || info.ModTime().UnixNano() <= 0 {
		return PrivateSnapshot{}, ErrUnavailable
	}
	return PrivateSnapshot{uint64(stat.Dev), uint64(stat.Ino), uint64(info.Size()), info.ModTime().UnixNano()}, nil
}

// UID injection stays package-private and is used only by isolated file tests.
func readPrivateSegment(path string, limit int64, expected *PrivateSnapshot, partIndex uint64, uid uint32, full bool) (PrivatePart, error) {
	closed := PrivatePart{}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || limit <= 0 || uint64(limit) > PrivateOriginalMaxBytes || (full && (expected != nil || partIndex != 0)) || (!full && expected == nil) {
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
	before, err := file.Stat()
	if err != nil || !privateFile(before, limit, uid) || !os.SameFile(beforePath, before) {
		return closed, ErrUnavailable
	}
	snapshot, err := privateSnapshot(before)
	if err != nil || (expected != nil && snapshot != *expected) {
		return closed, ErrUnavailable
	}
	count := snapshot.ByteLength
	offset := uint64(0)
	if !full {
		if partIndex > (snapshot.ByteLength-1)/PrivateOriginalPartBytes {
			return closed, ErrUnavailable
		}
		offset = partIndex * PrivateOriginalPartBytes
		count = snapshot.ByteLength - offset
		if count > PrivateOriginalPartBytes {
			count = PrivateOriginalPartBytes
		}
	}
	// SectionReader/Pread reads only this fixed part; repeated transport calls
	// do not reread/hash a 64MiB original to emit each 1MiB part.
	wire, err := io.ReadAll(io.NewSectionReader(file, int64(offset), int64(count)))
	if err != nil || uint64(len(wire)) != count {
		return closed, ErrUnavailable
	}
	after, err := file.Stat()
	afterPath, pathErr := os.Lstat(path)
	afterDir, dirErr := os.Lstat(parent)
	if err != nil || pathErr != nil || dirErr != nil || !privateFile(after, limit, uid) || !privateFile(afterPath, limit, uid) || !privateDirectory(afterDir, uid) ||
		!os.SameFile(before, after) || !os.SameFile(before, afterPath) || !os.SameFile(beforeDir, afterDir) || before.Size() != after.Size() || before.Size() != afterPath.Size() ||
		!before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(afterPath.ModTime()) || !beforeDir.ModTime().Equal(afterDir.ModTime()) {
		return closed, ErrUnavailable
	}
	observed, err := privateSnapshot(after)
	observedPath, pathErr := privateSnapshot(afterPath)
	if err != nil || pathErr != nil || observed != snapshot || observedPath != snapshot {
		return closed, ErrUnavailable
	}
	sum := sha256.Sum256(wire)
	return PrivatePart{wire, hex.EncodeToString(sum[:]), snapshot, partIndex, offset}, nil
}
