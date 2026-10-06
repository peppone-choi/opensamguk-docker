// Package d101freeze collects native observations without granting freeze authority.
package d101freeze

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	productionLockPath   = "/tmp/opensamguk-production.lock"
	productionFDInfoPath = "/proc/self/fdinfo/9"
	productionLockFD     = uintptr(9)
	maxFDInfoBytes       = 64 * 1024
)

// ProductionLockPins must come from the independently pinned installation.
type ProductionLockPins struct {
	DeviceMajor uint64
	DeviceMinor uint64
	Inode       uint64
}

// UnverifiedProductionLock is a pair of matching native samples, not a lease,
// writer-freeze verdict, issuer identity, or proof of uninterrupted lock custody.
// The keeper owns FD9's open-file-description continuity and release policy.
type UnverifiedProductionLock struct {
	fdInfo     []byte
	observedAt time.Time
}

func (v UnverifiedProductionLock) FDInfoOriginal() []byte { return bytes.Clone(v.fdInfo) }
func (v UnverifiedProductionLock) ObservedAt() time.Time  { return v.observedAt }

// ObserveInheritedProductionLock observes only the caller's existing FD9. It
// never opens the production lock pathname, reads/seeks/writes that descriptor,
// or acquires, converts, unlocks, duplicates, or closes it. No helper PID equality
// is required: native fdinfo may report an owner PID of zero.
func ObserveInheritedProductionLock(ctx context.Context, fd *os.File, pins ProductionLockPins) (UnverifiedProductionLock, error) {
	if err := liveContext(ctx); err != nil {
		return UnverifiedProductionLock{}, err
	}
	if runtime.GOOS != "linux" {
		return UnverifiedProductionLock{}, errors.New("production lock observation requires Linux")
	}
	if fd == nil {
		return UnverifiedProductionLock{}, errors.New("missing inherited production descriptor")
	}
	source := lockSource{
		platform: runtime.GOOS, descriptor: fd.Fd(),
		fstat: func() (lockStat, error) {
			info, err := fd.Stat()
			if err != nil {
				return lockStat{}, err
			}
			return nativeLockStat(info)
		},
		lstat: func() (lockStat, error) {
			info, err := os.Lstat(productionLockPath)
			if err != nil {
				return lockStat{}, err
			}
			return nativeLockStat(info)
		},
		fdinfo: func() ([]byte, error) {
			// Only this auxiliary proc read stream is closed, never inherited FD9.
			f, err := os.Open(productionFDInfoPath)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			return io.ReadAll(io.LimitReader(f, maxFDInfoBytes+1))
		},
		now: time.Now,
	}
	return observeProductionLock(ctx, pins, source)
}

// These private seams permit portable fixtures; callers cannot substitute a
// native collector or its fixed paths through the public API.
type lockStat struct {
	pins    ProductionLockPins
	regular bool
	nlink   uint64
}
type lockSource struct {
	platform   string
	descriptor uintptr
	fstat      func() (lockStat, error)
	lstat      func() (lockStat, error)
	fdinfo     func() ([]byte, error)
	now        func() time.Time
}

func liveContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("missing observation context")
	}
	return ctx.Err()
}

func observeProductionLock(ctx context.Context, pins ProductionLockPins, s lockSource) (UnverifiedProductionLock, error) {
	deny := func(err error) (UnverifiedProductionLock, error) { return UnverifiedProductionLock{}, err }
	if err := liveContext(ctx); err != nil {
		return deny(err)
	}
	if s.platform != "linux" || s.descriptor != productionLockFD || pins.Inode == 0 || pins.DeviceMajor > 0xffffffff || pins.DeviceMinor > 0xffffffff {
		return deny(errors.New("unavailable production descriptor or independent pins"))
	}
	if s.fstat == nil || s.lstat == nil || s.fdinfo == nil || s.now == nil {
		return deny(errors.New("missing native observation source"))
	}
	checkStat := func(read func() (lockStat, error)) error {
		if err := liveContext(ctx); err != nil {
			return err
		}
		st, err := read()
		if err != nil {
			return errors.New("native production lock stat unavailable")
		}
		if err := liveContext(ctx); err != nil {
			return err
		}
		if !st.regular || st.nlink != 1 || st.pins != pins {
			return errors.New("native production lock identity mismatch")
		}
		return nil
	}
	readInfo := func() ([]byte, error) {
		if err := liveContext(ctx); err != nil {
			return nil, err
		}
		raw, err := s.fdinfo()
		if err != nil {
			return nil, errors.New("native production fdinfo unavailable")
		}
		if err := liveContext(ctx); err != nil {
			return nil, err
		}
		// Own the sample before another collector call can mutate its backing bytes.
		raw = bytes.Clone(raw)
		if err := validateFDInfo(raw, pins); err != nil {
			return nil, err
		}
		return raw, nil
	}
	// Stat both identities before and after the two independently read fdinfo
	// samples. Equality cannot exclude an unlock/reacquire between observations.
	if err := checkStat(s.fstat); err != nil {
		return deny(err)
	}
	if err := checkStat(s.lstat); err != nil {
		return deny(err)
	}
	before, err := readInfo()
	if err != nil {
		return deny(err)
	}
	after, err := readInfo()
	if err != nil {
		return deny(err)
	}
	if !bytes.Equal(before, after) {
		return deny(errors.New("production fdinfo changed during observation"))
	}
	if err := checkStat(s.fstat); err != nil {
		return deny(err)
	}
	if err := checkStat(s.lstat); err != nil {
		return deny(err)
	}
	observedAt := s.now().UTC()
	if err := liveContext(ctx); err != nil {
		return deny(err)
	}
	if observedAt.IsZero() {
		return deny(errors.New("missing native observation time"))
	}
	return UnverifiedProductionLock{fdInfo: before, observedAt: observedAt}, nil
}

// Native stat fields are read without OS-specific build files so unsupported
// platforms can compile and return unavailable before performing native reads.
func nativeLockStat(info os.FileInfo) (lockStat, error) {
	if info == nil || !info.Mode().IsRegular() {
		return lockStat{}, errors.New("production lock is not a regular file")
	}
	v := reflect.ValueOf(info.Sys())
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return lockStat{}, errors.New("missing native stat")
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return lockStat{}, errors.New("unsupported native stat")
	}
	field := func(name string) (uint64, bool) {
		f := v.FieldByName(name)
		switch f.Kind() {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return f.Uint(), true
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if f.Int() >= 0 {
				return uint64(f.Int()), true
			}
		}
		return 0, false
	}
	dev, devOK := field("Dev")
	ino, inoOK := field("Ino")
	nlink, linkOK := field("Nlink")
	if !devOK || !inoOK || !linkOK {
		return lockStat{}, errors.New("missing native device/inode/link count")
	}
	// Linux userspace dev_t encoding, including the high major/minor bits.
	major := (dev >> 8 & 0xfff) | (dev >> 32 & 0xfffff000)
	minor := (dev & 0xff) | (dev >> 12 & 0xffffff00)
	return lockStat{pins: ProductionLockPins{DeviceMajor: major, DeviceMinor: minor, Inode: ino}, regular: true, nlink: nlink}, nil
}

func decimal(s string, bits int) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, bits)
	if err != nil || strconv.FormatUint(v, 10) != s {
		return 0, errors.New("malformed native integer")
	}
	return v, nil
}

func validateFDInfo(raw []byte, pins ProductionLockPins) error {
	bad := errors.New("malformed or mismatched production fdinfo")
	if len(raw) == 0 || len(raw) > maxFDInfoBytes || raw[len(raw)-1] != '\n' {
		return bad
	}
	for _, b := range raw {
		if b != '\n' && b != '\t' && (b < 32 || b > 126) {
			return bad
		}
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw[:len(raw)-1]), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || seen[key] {
			return bad
		}
		seen[key] = true
		fields := strings.Fields(value)
		switch key {
		case "ino":
			if len(fields) != 1 {
				return bad
			}
			ino, err := decimal(fields[0], 64)
			if err != nil || ino != pins.Inode {
				return bad
			}
		case "pos", "mnt_id":
			if len(fields) != 1 {
				return bad
			}
			if _, err := decimal(fields[0], 64); err != nil {
				return bad
			}
		case "flags":
			if len(fields) != 1 || len(fields[0]) == 0 {
				return bad
			}
			for _, c := range fields[0] {
				if c < '0' || c > '7' {
					return bad
				}
			}
			if _, err := strconv.ParseUint(fields[0], 8, 32); err != nil {
				return bad
			}
		case "lock":
			if len(fields) != 8 || fields[0] != "1:" || fields[1] != "FLOCK" || fields[2] != "ADVISORY" || fields[3] != "WRITE" || fields[6] != "0" || fields[7] != "EOF" {
				return bad
			}
			if _, err := decimal(fields[4], 32); err != nil {
				return bad
			}
			device := strings.Split(fields[5], ":")
			if len(device) != 3 {
				return bad
			}
			for i, expected := range []uint64{pins.DeviceMajor, pins.DeviceMinor} {
				n, err := strconv.ParseUint(device[i], 16, 32)
				if err != nil || n != expected || fmt.Sprintf("%02x", n) != device[i] {
					return bad
				}
			}
			ino, err := decimal(device[2], 64)
			if err != nil || ino != pins.Inode {
				return bad
			}
		default:
			return bad
		}
	}
	for _, key := range []string{"pos", "flags", "mnt_id", "ino", "lock"} {
		if !seen[key] {
			return bad
		}
	}
	return nil
}
