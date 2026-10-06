package main

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func resetD101IssuerLedgerTestDirectory(t *testing.T) (*os.File, resetD101IssuerDirectoryPin) {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(path, 0700) != nil {
		t.Fatal("fixture directory")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	pin := resetD101IssuerDirectoryPin{uint64(stat.Dev), uint64(stat.Ino)}
	dir, err := openResetD101IssuerDirectory(path, pin, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	return dir, pin
}

func TestIssuerLedgerExclusiveOriginalSurvivesNewWriterAndRejectsMutation(t *testing.T) {
	for _, name := range []string{"same-name-replay", "symlink", "hardlink", "wrong-mode", "content-mutation", "oversize"} {
		t.Run(name, func(t *testing.T) {
			dir, _ := resetD101IssuerLedgerTestDirectory(t)
			uid := uint32(os.Getuid())
			wire := []byte("synthetic-private-original")
			if name == "oversize" {
				if writeResetD101IssuerExclusive(dir, "entry", bytes.Repeat([]byte{'a'}, (64<<10)+1), uid) == nil {
					t.Fatal("oversize")
				}
				return
			}
			if writeResetD101IssuerExclusive(dir, "entry", wire, uid) != nil || requireResetD101IssuerOwnedOriginal(dir, "entry", wire, uid) != nil {
				t.Fatal("durable original")
			}
			path := filepath.Join(dir.Name(), "entry")
			switch name {
			case "same-name-replay":
				// A fresh writer, without process flags, sees the durable O_EXCL guard.
				other, err := os.Open(dir.Name())
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				if writeResetD101IssuerExclusive(other, "entry", []byte("replacement"), uid) == nil || requireResetD101IssuerOwnedOriginal(dir, "entry", wire, uid) != nil {
					t.Fatal("durable replay replaced original")
				}
				return
			case "symlink":
				if os.Remove(path) != nil || os.Symlink("outside", path) != nil {
					t.Fatal("fixture symlink")
				}
			case "hardlink":
				if os.Link(path, filepath.Join(dir.Name(), "alias")) != nil {
					t.Fatal("fixture link")
				}
			case "wrong-mode":
				if os.Chmod(path, 0600) != nil {
					t.Fatal("fixture mode")
				}
			case "content-mutation":
				if os.Chmod(path, 0600) != nil || os.WriteFile(path, []byte("mutated"), 0600) != nil || os.Chmod(path, 0400) != nil {
					t.Fatal("fixture mutation")
				}
			}
			if requireResetD101IssuerOwnedOriginal(dir, "entry", wire, uid) == nil {
				t.Fatal("mutated native original was accepted")
			}
		})
	}
}

func TestIssuerLedgerDirectoryAndBudgetRejectUnknownOrOverflow(t *testing.T) {
	for _, name := range []string{"pin-drift", "parent-symlink", "unknown-child", "cap-full", "reserve-overflow"} {
		t.Run(name, func(t *testing.T) {
			root, pin := resetD101IssuerLedgerTestDirectory(t)
			uid := uint32(os.Getuid())
			if name == "pin-drift" {
				pin.inode++
				if dir, err := openResetD101IssuerDirectory(root.Name(), pin, uid); err == nil {
					dir.Close()
					t.Fatal("wrong parent inode")
				}
				return
			}
			if name == "parent-symlink" {
				alias := filepath.Join(t.TempDir(), "alias")
				if os.Symlink(root.Name(), alias) != nil {
					t.Fatal("fixture symlink")
				}
				if dir, err := openResetD101IssuerDirectory(alias, pin, uid); err == nil {
					dir.Close()
					t.Fatal("aliased namespace")
				}
				return
			}
			oncePath := filepath.Join(root.Name(), ".once")
			if os.Mkdir(oncePath, 0700) != nil {
				t.Fatal("fixture once")
			}
			once, err := os.Open(oncePath)
			if err != nil {
				t.Fatal(err)
			}
			defer once.Close()
			cap, reserve := uint64(1<<30), uint64(10<<30)
			switch name {
			case "unknown-child":
				if os.Mkdir(filepath.Join(root.Name(), "unapproved"), 0700) != nil {
					t.Fatal("fixture")
				}
			case "cap-full":
				cap = 1
			case "reserve-overflow":
				reserve = ^uint64(0)
			}
			if resetD101IssuerLedgerBudget(root, once, cap, reserve, uid) == nil {
				t.Fatal("unknown/budget unsafe namespace accepted")
			}
		})
	}
}
