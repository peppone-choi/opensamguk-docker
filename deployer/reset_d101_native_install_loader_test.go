package main

import (
	"context"
	"opensamguk-deployer/internal/d101custody"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nativeInstallInputFixture(t *testing.T) (string, d101custody.NativeFilePin, uint32) {
	t.Helper()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("fixture parent")
	}
	path := filepath.Join(dir, "original.bin")
	if os.WriteFile(path, []byte("unknown-original-codec"), 0400) != nil {
		t.Fatal("fixture file")
	}
	f, _ := os.Stat(path)
	d, _ := os.Stat(dir)
	uid := uint32(os.Geteuid())
	return path, resetD101NativeInputPin(f, d, []byte("unknown-original-codec")), uid
}
func TestNativeInstallHeldInputRejectsIdentityAndByteDrift(t *testing.T) {
	for _, mode := range []string{"replacement", "bytes", "closed", "parent-replacement", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			path, pin, uid := nativeInstallInputFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// Private temporary directory fixture only; no root ancestor authority.
			h, err := openResetD101NativeInputWithAncestors(ctx, path, pin, 0400, uid, func(string, uint32) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer h.close()
			switch mode {
			case "replacement":
				if os.Rename(path, path+".old") != nil || os.WriteFile(path, h.wire, 0400) != nil {
					t.Fatal("replace")
				}
			case "bytes":
				if os.Chmod(path, 0600) != nil || os.WriteFile(path, []byte("changed-original-codec"), 0400) != nil || os.Chmod(path, 0400) != nil {
					t.Fatal("mutate")
				}
			case "closed":
				_ = h.file.Close()
			case "parent-replacement":
				parent := filepath.Dir(path)
				if os.Rename(parent, parent+".old") != nil || os.Mkdir(parent, 0700) != nil || os.WriteFile(path, h.wire, 0400) != nil {
					t.Fatal("parent replace")
				}
				defer os.RemoveAll(parent + ".old")
			case "cancel":
				cancel()
			}
			if h.recheck(ctx, uid) == nil {
				t.Fatal("native drift accepted")
			}
		})
	}
}
func TestNativeInstallIndependentPinsAreNeverLearnedFromReadback(t *testing.T) {
	path, pin, uid := nativeInstallInputFixture(t)
	pin.SHA256 = strings.Repeat("f", 64)
	if h, err := openResetD101NativeInputWithAncestors(context.Background(), path, pin, 0400, uid, func(string, uint32) error { return nil }); err == nil || h != nil {
		if h != nil {
			h.close()
		}
		t.Fatal("adopted target SHA")
	}
	pin.Snapshot.Inode = 0
	if h, err := openResetD101NativeInput(context.Background(), path, pin, 0400, uid); err == nil || h != nil {
		t.Fatal("missing independent pin accepted")
	}
}
func TestNativeInstallAuthorityAbsentNeverPublishesHostSources(t *testing.T) {
	if p, err := resetD101InstalledHostOperationSupplier(context.Background(), nil, strings.Repeat("a", 32)); err == nil || p != nil {
		t.Fatal("operation authority synthesized")
	}
	if p, err := resetD101InstalledHostIssuerSupplier(context.Background(), nil, strings.Repeat("a", 32)); err == nil || p != nil {
		t.Fatal("issuer authority synthesized")
	}
	if readResetD101NativeInstallNegative(nil, strings.Repeat("a", 32)) == nil {
		t.Fatal("nil context")
	}
}
