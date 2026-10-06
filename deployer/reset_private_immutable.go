package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
)

// Custody primitive only, never an issuer/approval/PUBLIC gate. The future
// approved host issuer must validate all source/runtime/tick/role/freeze proofs
// before calling this; no production call site is connected.
func writeResetImmutablePrivateBytes(directory, operationID, expectedSHA string, wire []byte) error {
	return writeResetImmutablePrivateBytesWithUID(directory, operationID, expectedSHA, wire, 0)
}

// The UID seam belongs to isolated file fixtures. It is never request input.
func writeResetImmutablePrivateBytesWithUID(directory, operationID, expectedSHA string, wire []byte, uid uint32) error {
	return writeResetImmutablePrivateBytesWithSync(directory, operationID, expectedSHA, wire, uid, syncResetPrivateDirectory)
}

// Directory sync injection is only for an isolated post-link failure fixture.
func writeResetImmutablePrivateBytesWithSync(directory, operationID, expectedSHA string, wire []byte, uid uint32, syncDirectory func(string) error) error {
	return publishResetImmutablePrivateBytes(directory, operationID, expectedSHA, wire, uid, syncDirectory, true)
}

// A physical recovery claim must never replay, including identical original
// bytes. Existing or uncertain custody consumes the one attempt and stays closed.
func createResetImmutablePrivateBytes(directory, operationID, expectedSHA string, wire []byte, uid uint32) error {
	return publishResetImmutablePrivateBytes(directory, operationID, expectedSHA, wire, uid, syncResetPrivateDirectory, false)
}

func publishResetImmutablePrivateBytes(directory, operationID, expectedSHA string, wire []byte, uid uint32, syncDirectory func(string) error, allowReplay bool) error {
	op, err := normalizeLifecycleOperationID(operationID)
	sum := sha256.Sum256(wire)
	if syncDirectory == nil || err != nil || op == "" || op != operationID || !filepath.IsAbs(directory) || !resetEvidenceSHA.MatchString(expectedSHA) ||
		len(wire) == 0 || len(wire) > resetEvidenceMaxBytes || hex.EncodeToString(sum[:]) != expectedSHA {
		return errResetExecutionEvidence
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != filepath.Clean(directory) {
		return errResetExecutionEvidence
	}
	before, err := os.Lstat(directory)
	if err != nil || !before.IsDir() || before.Mode().Perm() != 0700 {
		return errResetExecutionEvidence
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid {
		return errResetExecutionEvidence
	}
	leaf := filepath.Join(directory, operationID+".json")
	if _, err = os.Lstat(leaf); err == nil {
		if !allowReplay {
			return errResetExecutionEvidence
		}
		existing, readErr := readResetPrivateCustody(directory, operationID, uid)
		if readErr != nil || !bytes.Equal(existing, wire) {
			return errResetExecutionEvidence
		}
		return nil // Exact immutable replay. Expiry/content is not renewed.
	} else if !os.IsNotExist(err) {
		return errResetExecutionEvidence
	}
	file, err := os.CreateTemp(directory, "."+operationID+"-receipt-")
	if err != nil {
		return errResetExecutionEvidence
	}
	temporary := file.Name()
	cleanupTemporary := true
	defer func() {
		if cleanupTemporary {
			_ = os.Remove(temporary)
		}
	}() // Only this invocation's known private leaf.
	defer file.Close()
	if _, err = file.Write(wire); err != nil {
		return errResetExecutionEvidence
	}
	if file.Chmod(0400) != nil || file.Sync() != nil {
		return errResetExecutionEvidence
	}
	if file.Close() != nil {
		return errResetExecutionEvidence
	}
	after, err := os.Lstat(directory)
	afterStat, afterOK := resetPrivateFileStat(after)
	if err != nil || !os.SameFile(before, after) || !after.IsDir() || after.Mode().Perm() != 0700 || !afterOK || afterStat.Uid != uid {
		return errResetExecutionEvidence
	}
	// link is an atomic create-if-absent; rename would overwrite a concurrent
	// operation issuer. Readers require nlink=1, so the temporary 2-link phase
	// fails closed until the exact temporary leaf is unlinked and dir fsynced.
	if err = os.Link(temporary, leaf); err != nil {
		if !os.IsExist(err) || !allowReplay {
			return errResetExecutionEvidence
		}
		existing, readErr := readResetPrivateCustody(directory, operationID, uid)
		if readErr != nil || !bytes.Equal(existing, wire) {
			return errResetExecutionEvidence
		}
		return nil
	}
	// After the canonical link exists, an unconfirmed directory write halts.
	// Retain the 2-link custody state instead of promoting a failed write into
	// a readable nlink=1 receipt by an unconditional cleanup on error.
	cleanupTemporary = false
	if syncDirectory(directory) != nil {
		return errResetExecutionEvidence
	}
	if os.Remove(temporary) != nil {
		return errResetExecutionEvidence
	}
	if syncDirectory(directory) != nil {
		return errResetExecutionEvidence
	}
	existing, err := readResetPrivateCustody(directory, operationID, uid)
	if err != nil || !bytes.Equal(existing, wire) {
		return errResetExecutionEvidence
	}
	return nil
}
func resetPrivateFileStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	v, ok := info.Sys().(*syscall.Stat_t)
	return v, ok
}
func syncResetPrivateDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return errResetExecutionEvidence
	}
	defer file.Close()
	if file.Sync() != nil {
		return errResetExecutionEvidence
	}
	return nil
}
