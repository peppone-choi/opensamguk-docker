package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const resetD101SelectedByteLimit uint64 = 64 << 20

var errResetD101SelectedBytes = errors.New("선택 원문 바이트 검증 실패")

type resetD101RawBytePin struct {
	SHA256     string
	ByteLength uint64
}

type resetD101SelectedBytePins struct {
	Directory string
	Pins      map[string]resetD101RawBytePin
}

type resetD101SelectedBytes struct {
	bytes    map[string][]byte
	observed map[string]resetD101RawBytePin
}

func (selected resetD101SelectedBytes) Bytes(leaf string) ([]byte, bool) {
	wire, ok := selected.bytes[leaf]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), wire...), true
}

func (selected resetD101SelectedBytes) ObservedPins() map[string]resetD101RawBytePin {
	pins := make(map[string]resetD101RawBytePin, len(selected.observed))
	for leaf, pin := range selected.observed {
		pins[leaf] = pin
	}
	return pins
}

func readResetD101SelectedBytes(pins resetD101SelectedBytePins) (resetD101SelectedBytes, error) {
	return readResetD101SelectedBytesWithCustodyUID(pins, 0)
}

// Tests substitute their UID; production custody is always root-owned.
// These observations describe bytes only, never approval or provenance.
func readResetD101SelectedBytesWithCustodyUID(pins resetD101SelectedBytePins, uid uint32) (resetD101SelectedBytes, error) {
	leaves := [...]string{"tiles.json", "world.json", "roads.json", "selected-scenario.json", "classpath-scenario.json"}
	if len(pins.Pins) != len(leaves) || !filepath.IsAbs(pins.Directory) || filepath.Clean(pins.Directory) != pins.Directory {
		return resetD101SelectedBytes{}, errResetD101SelectedBytes
	}
	expected := make(map[string]resetD101RawBytePin, len(leaves))
	for _, leaf := range leaves {
		pin, ok := pins.Pins[leaf]
		digest, err := hex.DecodeString(pin.SHA256)
		if !ok || err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != pin.SHA256 ||
			pin.ByteLength == 0 || pin.ByteLength > resetD101SelectedByteLimit {
			return resetD101SelectedBytes{}, errResetD101SelectedBytes
		}
		expected[leaf] = pin
	}
	dir, err := resetD101SelectedDirectory(pins.Directory, uid)
	if err != nil {
		return resetD101SelectedBytes{}, err
	}
	result := resetD101SelectedBytes{bytes: make(map[string][]byte, len(leaves)), observed: make(map[string]resetD101RawBytePin, len(leaves))}
	infos := make(map[string]os.FileInfo, len(leaves))
	for _, leaf := range leaves {
		wire, info, err := readResetD101SelectedLeaf(filepath.Join(pins.Directory, leaf), expected[leaf], uid)
		if err != nil {
			return resetD101SelectedBytes{}, err
		}
		sum := sha256.Sum256(wire)
		observed := resetD101RawBytePin{SHA256: hex.EncodeToString(sum[:]), ByteLength: uint64(len(wire))}
		if observed != expected[leaf] {
			return resetD101SelectedBytes{}, errResetD101SelectedBytes
		}
		result.bytes[leaf], result.observed[leaf], infos[leaf] = wire, observed, info
	}
	// Recheck the entire captured set before returning any bytes.
	for _, leaf := range leaves {
		after, err := os.Lstat(filepath.Join(pins.Directory, leaf))
		before := infos[leaf]
		if err != nil || !resetD101SelectedFile(after, expected[leaf].ByteLength, uid) ||
			!os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
			return resetD101SelectedBytes{}, errResetD101SelectedBytes
		}
	}
	after, err := resetD101SelectedDirectory(pins.Directory, uid)
	if err != nil || !os.SameFile(dir, after) || !dir.ModTime().Equal(after.ModTime()) {
		return resetD101SelectedBytes{}, errResetD101SelectedBytes
	}
	return result, nil
}

func resetD101SelectedDirectory(directory string, uid uint32) (os.FileInfo, error) {
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return nil, errResetD101SelectedBytes
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, errResetD101SelectedBytes
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid {
		return nil, errResetD101SelectedBytes
	}
	return info, nil
}

func resetD101SelectedFile(info os.FileInfo, length uint64, uid uint32) bool {
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		info.Size() <= 0 || uint64(info.Size()) != length || uint64(info.Size()) > resetD101SelectedByteLimit {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Nlink == 1
}

func readResetD101SelectedLeaf(path string, pin resetD101RawBytePin, uid uint32) ([]byte, os.FileInfo, error) {
	// The directory has private custody; O_NOFOLLOW rejects leaf symlinks.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, errResetD101SelectedBytes
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !resetD101SelectedFile(before, pin.ByteLength, uid) {
		return nil, nil, errResetD101SelectedBytes
	}
	wire, err := io.ReadAll(io.LimitReader(file, int64(pin.ByteLength)+1))
	if err != nil || uint64(len(wire)) != pin.ByteLength {
		return nil, nil, errResetD101SelectedBytes
	}
	after, err := file.Stat()
	if err != nil || !resetD101SelectedFile(after, pin.ByteLength, uid) || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		return nil, nil, errResetD101SelectedBytes
	}
	return wire, after, nil
}
