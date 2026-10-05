package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestResetImmutablePrivateBytesPostLinkSyncFailureRetainsClosedCustody(t *testing.T) {
	directory := t.TempDir()
	_ = os.Chmod(directory, 0700)
	op := strings.Repeat("d", 32)
	wire := []byte(`{"version":1}`)
	uid := uint32(os.Getuid())
	calls := 0
	err := writeResetImmutablePrivateBytesWithSync(directory, op, resetPrivateWireSHA(wire), wire, uid, func(string) error {
		calls++
		return errors.New("synthetic directory sync unavailable")
	})
	if err == nil || calls != 1 {
		t.Fatal("unconfirmed publication continued")
	}
	if _, err := readResetPrivateCustody(directory, op, uid); err == nil {
		t.Fatal("failed write promoted into readable custody")
	}
	entries, _ := os.ReadDir(directory)
	if len(entries) != 2 {
		t.Fatal("unknown linked state was automatically removed")
	}
}

func resetPrivateWireSHA(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func TestResetImmutablePrivateBytesPublishExactOnceWithoutRenewal(t *testing.T) {
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("fixture private dir")
	}
	op := strings.Repeat("a", 32)
	wire := []byte(`{"version":1,"expiresAtUnix":100}`)
	uid := uint32(os.Getuid())
	if writeResetImmutablePrivateBytesWithUID(directory, op, resetPrivateWireSHA(wire), wire, uid) != nil {
		t.Fatal("initial exact private write refused")
	}
	leaf := filepath.Join(directory, op+".json")
	before, err := os.Stat(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != 0400 {
		t.Fatal("receipt not immutable mode")
	}
	if writeResetImmutablePrivateBytesWithUID(directory, op, resetPrivateWireSHA(wire), wire, uid) != nil {
		t.Fatal("exact replay refused")
	}
	after, _ := os.Stat(leaf)
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("replay rewrote/renewed receipt")
	}
	renewed := []byte(`{"version":1,"expiresAtUnix":200}`)
	if writeResetImmutablePrivateBytesWithUID(directory, op, resetPrivateWireSHA(renewed), renewed, uid) == nil {
		t.Fatal("same operation content renewed")
	}
	observed, err := readResetPrivateCustody(directory, op, uid)
	if err != nil || !bytes.Equal(observed, wire) {
		t.Fatal("original receipt changed")
	}
	entries, _ := os.ReadDir(directory)
	if len(entries) != 1 || entries[0].Name() != op+".json" {
		t.Fatal("private temporary leaf leaked")
	}
}

func TestResetImmutablePrivateBytesConcurrentDifferentIssuerHasOneWinner(t *testing.T) {
	directory := t.TempDir()
	_ = os.Chmod(directory, 0700)
	op := strings.Repeat("b", 32)
	uid := uint32(os.Getuid())
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	wires := [][]byte{[]byte(`{"version":1,"proof":"first"}`), []byte(`{"version":1,"proof":"second"}`)}
	for _, wire := range wires {
		group.Add(1)
		go func(wire []byte) {
			defer group.Done()
			<-start
			results <- writeResetImmutablePrivateBytesWithUID(directory, op, resetPrivateWireSHA(wire), wire, uid)
		}(wire)
	}
	close(start)
	group.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	observed, err := readResetPrivateCustody(directory, op, uid)
	if successes != 1 || err != nil || (!bytes.Equal(observed, wires[0]) && !bytes.Equal(observed, wires[1])) {
		t.Fatal("atomic one-winner publication lost")
	}
}

func TestResetImmutablePrivateBytesRejectsCustodyAndHashWithoutOverwrite(t *testing.T) {
	for _, mode := range []string{"directory-mode", "wrong-owner", "symlink-parent", "symlink-leaf", "hardlink-leaf", "leaf-mode", "wrong-sha", "empty", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			_ = os.Chmod(directory, 0700)
			op := strings.Repeat("c", 32)
			uid := uint32(os.Getuid())
			wire := []byte(`{"version":1}`)
			hash := resetPrivateWireSHA(wire)
			leaf := filepath.Join(directory, op+".json")
			switch mode {
			case "directory-mode":
				_ = os.Chmod(directory, 0755)
			case "wrong-owner":
				uid++
			case "symlink-parent":
				alias := filepath.Join(t.TempDir(), "alias")
				if os.Symlink(directory, alias) != nil {
					t.Fatal("fixture symlink")
				}
				directory = alias
			case "symlink-leaf":
				target := filepath.Join(directory, "original")
				_ = os.WriteFile(target, []byte("retained"), 0400)
				if os.Symlink(target, leaf) != nil {
					t.Fatal("fixture symlink")
				}
			case "hardlink-leaf":
				_ = os.WriteFile(leaf, wire, 0400)
				if os.Link(leaf, filepath.Join(directory, "retained")) != nil {
					t.Fatal("fixture hardlink")
				}
			case "leaf-mode":
				_ = os.WriteFile(leaf, wire, 0600)
			case "wrong-sha":
				hash = strings.Repeat("f", 64)
			case "empty":
				wire = nil
				hash = resetPrivateWireSHA(wire)
			case "oversized":
				wire = bytes.Repeat([]byte("x"), resetEvidenceMaxBytes+1)
				hash = resetPrivateWireSHA(wire)
			}
			if writeResetImmutablePrivateBytesWithUID(directory, op, hash, wire, uid) == nil {
				t.Fatal("invalid custody/input accepted")
			}
			if mode == "symlink-leaf" {
				original, _ := os.ReadFile(filepath.Join(filepath.Dir(leaf), "original"))
				if string(original) != "retained" {
					t.Fatal("symlink target overwritten")
				}
			}
		})
	}
}
