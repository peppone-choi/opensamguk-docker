//go:build linux && amd64

package main

import (
	"context"
	"opensamguk-deployer/internal/d101native"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNative9KeeperSameOFDActualOwnerLifetime(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("NOT_RUN: isolated Linux UID0 native fixture required")
	}
	path := filepath.Join(t.TempDir(), "fixture.lock")
	first, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	dupFD, err := syscall.Dup(int(first.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	duplicate := os.NewFile(uintptr(dupFD), "owned-fixture-duplicate")
	defer duplicate.Close()
	observer, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	if syscall.Flock(int(observer.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
		t.Fatal("live same OFD ownership lost")
	}
	if first.Close() != nil {
		t.Fatal("keeper original close failed")
	}
	if syscall.Flock(int(observer.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
		t.Fatal("duplicate owner mistaken for actual last release")
	}
	if duplicate.Close() != nil {
		t.Fatal("last owned duplicate close failed")
	}
	if syscall.Flock(int(observer.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		t.Fatal("actual last OFD owner did not release lock")
	}
	// Kernel release is a fact; no completion can be created without its actual
	// signed terminal, observer original and independently authenticated source.
	installer := &resetD101NativeAuthorityInstaller{}
	if _, err := installer.overallCompletion(context.Background()); err == nil {
		t.Fatal("kernel release alone forged completion")
	}
}
func TestNative9KeeperPartialAndOriginalCutoffHold(t *testing.T) {
	k := &resetD101NativeKeeper{pre: &resetD101NativePreAcquisition{binding: d101native.PreBinding{OriginalCutoffUnix: time.Now().Unix() - 1}}, installer: &resetD101NativeAuthorityInstaller{}, attempted: true, acquired: true}
	if k.check(context.Background()) == nil {
		t.Fatal("expired original cutoff renewed")
	}
	if !k.attempted || !k.acquired || k.closed {
		t.Fatal("partial owner state erased")
	}
	if _, _, err := k.stage(context.Background(), 12); err == nil {
		t.Fatal("partial attempt fabricated issuer receipt")
	}
	if k.releaseActual(context.Background(), nil) == nil || k.closed {
		t.Fatal("missing terminal/source caused premature release")
	}
	if runResetD101NativeKeeper(context.Background(), strings.Repeat("a", 32), false, nil, nil) != 2 {
		t.Fatal("missing real input entered keeper")
	}
}
func TestNative9KeeperPhaseOrderRetainsOriginalChain(t *testing.T) {
	if resetD101NativeSequenceLeaf(0) != "acquisition.bin" || resetD101NativeSequenceLeaf(11) != "issuer-running.bin" || resetD101NativeSequenceLeaf(12) != "issuer-done.bin" || resetD101NativeSequenceLeaf(13) != "physical-running.bin" || resetD101NativeSequenceLeaf(14) != "terminal.bin" || resetD101NativeSequenceLeaf(15) != "" {
		t.Fatal("native chain phases changed")
	}
	k := &resetD101NativeKeeper{pre: &resetD101NativePreAcquisition{}}
	if k.bindHeader(12, &d101native.IssuerDone{}) == nil {
		t.Fatal("future receipt advanced absent previous chain")
	}
	if len(k.refs) != 0 {
		t.Fatal("denied stage changed chain")
	}
}
