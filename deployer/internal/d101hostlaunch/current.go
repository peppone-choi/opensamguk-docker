// Package d101hostlaunch runs the existing reviewed host reader under its
// caller's already held FD9. It grants no freeze/issuer/operation authority.
package d101hostlaunch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101freeze"
)

const helperPath = "/etc/opensamguk/d101/native-helper/d101-host-reader"
const readerPath = "/etc/opensamguk/d101/reader-installation.json"
const action = "read-current-freeze"
const maxOutput = 64 << 10

var ErrUnavailable = errors.New("fixed host current reader unavailable")
var ErrUncertain = errors.New("fixed host current reader outcome uncertain; keeper retains FD9")

// Independently reviewed expected native inputs. No argv/env/file-response
// selects a binary, lock, anchor or new signing purpose.
type Pins struct {
	Helper d101custody.NativeFilePin
	Reader d101custody.NativeFilePin
	Lock   d101freeze.ProductionLockPins
}

// Result holds raw8 data only. Its body/sample/exit status never authenticates
// the historical actor, uninterrupted OFD or any other writer component.
type Result struct {
	original           []byte
	started, completed time.Time
}

func (r Result) Original() []byte       { return bytes.Clone(r.original) }
func (r Result) StartedAt() time.Time   { return r.started }
func (r Result) CompletedAt() time.Time { return r.completed }

// RunCurrent never opens/reacquires/duplicates/unlocks/closes FD9. Child FD9
// inherits the same open-file description through ExtraFiles[6]. Only the
// separate read-only executable descriptor is opened and closed here.
// Any uncertain child result returns to the existing keeper without releasing
// its lock; keeper lifetime/recovery remain mandatory outside this adapter.
func RunCurrent(ctx context.Context, descriptor *os.File, pins Pins) (Result, error) {
	empty := Result{}
	if ctx == nil || ctx.Err() != nil || runtime.GOOS != "linux" || descriptor == nil || descriptor.Fd() != 9 || pins.Lock.Inode == 0 {
		return empty, ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	helper, hp, err := d101custody.CapturePrivateExecutablePin(helperPath, 32<<20)
	if err != nil || hp != pins.Helper || helper.SHA256 != pins.Helper.SHA256 {
		return empty, ErrUnavailable
	}
	reader, rp, err := d101custody.CapturePrivateOriginalPin(readerPath, maxOutput)
	if err != nil || rp != pins.Reader || reader.SHA256 != pins.Reader.SHA256 {
		return empty, ErrUnavailable
	}
	if _, err = d101freeze.ObserveInheritedProductionLock(bounded, descriptor, pins.Lock); err != nil {
		return empty, ErrUnavailable
	}
	fd, err := syscall.Open(helperPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return empty, ErrUnavailable
	}
	executable := os.NewFile(uintptr(fd), helperPath)
	defer executable.Close()
	checkExecutable := func() bool {
		info, e := executable.Stat()
		if e != nil {
			return false
		}
		native, ok := info.Sys().(*syscall.Stat_t)
		return ok && info.Mode().IsRegular() && native.Uid == 0 && native.Nlink == 1 && info.Mode().Perm() == 0500 &&
			uint64(native.Dev) == hp.Snapshot.Device && uint64(native.Ino) == hp.Snapshot.Inode && uint64(info.Size()) == hp.Snapshot.ByteLength && info.ModTime().UnixNano() == hp.Snapshot.ModifiedAtUnixNano
	}
	if !checkExecutable() {
		return empty, ErrUnavailable
	}
	// Execute the checked OPEN descriptor rather than race a mutable pathname.
	// Child fd3 names only this auxiliary executable; the reader sees inherited9.
	command := exec.CommandContext(bounded, "/proc/self/fd/3", action)
	command.Args[0] = helperPath
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	command.ExtraFiles = make([]*os.File, 7)
	command.ExtraFiles[0] = executable
	command.ExtraFiles[6] = descriptor
	var output limitedOutput
	output.limit = maxOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	started := time.Now()
	err = command.Run()
	completed := time.Now()
	runtime.KeepAlive(descriptor)
	if err != nil || bounded.Err() != nil || output.overflow || len(output.bytes) == 0 || !checkExecutable() {
		return empty, ErrUncertain
	}
	afterHelper, afterHP, e1 := d101custody.CapturePrivateExecutablePin(helperPath, 32<<20)
	afterReader, afterRP, e2 := d101custody.CapturePrivateOriginalPin(readerPath, maxOutput)
	_, e3 := d101freeze.ObserveInheritedProductionLock(bounded, descriptor, pins.Lock)
	if e1 != nil || e2 != nil || e3 != nil || afterHP != hp || afterRP != rp || !bytes.Equal(afterHelper.Bytes, helper.Bytes) || !bytes.Equal(afterReader.Bytes, reader.Bytes) || bounded.Err() != nil {
		return empty, ErrUncertain
	}
	return Result{bytes.Clone(output.bytes), started, completed}, nil
}

type limitedOutput struct {
	bytes    []byte
	limit    int
	overflow bool
}

func (w *limitedOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-len(w.bytes) {
		w.overflow = true
		return 0, ErrUncertain
	}
	w.bytes = append(w.bytes, p...)
	return len(p), nil
}
