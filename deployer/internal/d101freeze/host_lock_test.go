package d101freeze

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

var fixturePins = ProductionLockPins{DeviceMajor: 8, DeviceMinor: 1, Inode: 12345}

func fixtureFDInfo(pid string) []byte {
	return []byte("pos:\t0\nflags:\t0100002\nmnt_id:\t19\nino:\t12345\nlock:\t1: FLOCK  ADVISORY  WRITE " + pid + " 08:01:12345 0 EOF\n")
}

func fixtureSource(events *[]string) lockSource {
	stat := lockStat{pins: fixturePins, regular: true, nlink: 1}
	return lockSource{
		platform: "linux", descriptor: 9,
		fstat:  func() (lockStat, error) { *events = append(*events, "fstat"); return stat, nil },
		lstat:  func() (lockStat, error) { *events = append(*events, "lstat"); return stat, nil },
		fdinfo: func() ([]byte, error) { *events = append(*events, "fdinfo"); return fixtureFDInfo("0"), nil },
		now: func() time.Time {
			*events = append(*events, "clock")
			return time.Date(2026, 10, 6, 12, 0, 0, 17, time.FixedZone("fixture", 9*3600))
		},
	}
}

func requireDenied(t *testing.T, v UnverifiedProductionLock, err error) {
	t.Helper()
	if err == nil || len(v.FDInfoOriginal()) != 0 || !v.ObservedAt().IsZero() {
		t.Fatalf("expected error and zero unverified observation; err=%v", err)
	}
}

// Portable positive samples are parser fixtures, never actual Linux FD9 proof.
func TestProductionLockFDInfoFixtures(t *testing.T) {
	for _, pid := range []string{"0", "359", "4294967295"} {
		t.Run("owner_"+pid, func(t *testing.T) {
			if err := validateFDInfo(fixtureFDInfo(pid), fixturePins); err != nil {
				t.Fatal(err)
			}
		})
	}
	base := string(fixtureFDInfo("0"))
	cases := map[string]string{
		"missing_lock":        strings.Split(base, "lock:")[0],
		"duplicate_lock":      base + "lock:\t1: FLOCK ADVISORY WRITE 0 08:01:12345 0 EOF\n",
		"duplicate_inode":     base + "ino:\t12345\n",
		"read":                strings.Replace(base, "WRITE", "READ", 1),
		"posix":               strings.Replace(base, "FLOCK", "POSIX", 1),
		"ofd":                 strings.Replace(base, "FLOCK", "OFDLCK", 1),
		"mandatory":           strings.Replace(base, "ADVISORY", "MANDATORY", 1),
		"unlocked":            strings.Replace(base, "WRITE", "UNLCK", 1),
		"blocked":             strings.Replace(base, "1: FLOCK", "1: -> FLOCK", 1),
		"range_start":         strings.Replace(base, "0 EOF", "1 EOF", 1),
		"range_end":           strings.Replace(base, "EOF", "100", 1),
		"major":               strings.Replace(base, "08:01", "09:01", 1),
		"minor":               strings.Replace(base, "08:01", "08:02", 1),
		"lock_inode":          strings.Replace(base, "08:01:12345", "08:01:12346", 1),
		"fd_inode":            strings.Replace(base, "ino:\t12345", "ino:\t12346", 1),
		"bad_pid":             strings.Replace(base, "WRITE 0", "WRITE -1", 1),
		"overflow_pid":        strings.Replace(base, "WRITE 0", "WRITE 4294967296", 1),
		"extra_token":         strings.Replace(base, "EOF", "EOF extra", 1),
		"malformed_device":    strings.Replace(base, "08:01:12345", "08:01", 1),
		"noncanonical_device": strings.Replace(base, "08:01", "8:01", 1),
		"noncanonical_inode":  strings.ReplaceAll(base, "12345", "012345"),
		"missing_inode":       strings.Replace(base, "ino:\t12345\n", "", 1),
		"unknown_field":       base + "extra:\t1\n",
		"crlf":                strings.ReplaceAll(base, "\n", "\r\n"),
		"nul":                 base + "\x00\n",
		"empty_line":          base + "\n",
		"truncated":           strings.TrimSuffix(base, "\n"),
		"missing_flags":       strings.Replace(base, "flags:\t0100002\n", "", 1),
		"malformed_flags":     strings.Replace(base, "0100002", "0190002", 1),
		"malformed_position":  strings.Replace(base, "pos:\t0", "pos:\t-1", 1),
		"overflow_mount":      strings.Replace(base, "mnt_id:\t19", "mnt_id:\t18446744073709551616", 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if validateFDInfo([]byte(raw), fixturePins) == nil {
				t.Fatal("accepted malformed/mismatched fixture")
			}
		})
	}
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte("x"), maxFDInfoBytes+1)} {
		if validateFDInfo(raw, fixturePins) == nil {
			t.Fatal("accepted unavailable/oversized fdinfo")
		}
	}
}

func TestProductionLockObservationCopiesAndOrder(t *testing.T) {
	var events []string
	s := fixtureSource(&events)
	shared := fixtureFDInfo("0")
	s.fdinfo = func() ([]byte, error) { events = append(events, "fdinfo"); return shared, nil }
	v, err := observeProductionLock(context.Background(), fixturePins, s)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"fstat", "lstat", "fdinfo", "fdinfo", "fstat", "lstat", "clock"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("order=%v", events)
	}
	if !v.ObservedAt().Equal(s.now()) || v.ObservedAt().Location() != time.UTC {
		t.Fatal("native completion timestamp not retained in UTC")
	}
	copy1 := v.FDInfoOriginal()
	copy1[0] = 'X'
	shared[0] = 'Y'
	if !bytes.Equal(v.FDInfoOriginal(), fixtureFDInfo("0")) {
		t.Fatal("native original aliases source/caller memory")
	}
	var zero UnverifiedProductionLock
	if zero.FDInfoOriginal() != nil || !zero.ObservedAt().IsZero() {
		t.Fatal("zero value fabricated an observation")
	}
}

func TestProductionLockRejectsUnavailableSource(t *testing.T) {
	for _, name := range []string{"platform", "descriptor", "inode", "major_overflow", "minor_overflow", "fstat_missing", "lstat_missing", "fdinfo_missing", "clock_missing", "zero_time"} {
		t.Run(name, func(t *testing.T) {
			var events []string
			s := fixtureSource(&events)
			pins := fixturePins
			switch name {
			case "platform":
				s.platform = "darwin"
			case "descriptor":
				s.descriptor = 8
			case "inode":
				pins.Inode = 0
			case "major_overflow":
				pins.DeviceMajor = 1 << 32
			case "minor_overflow":
				pins.DeviceMinor = 1 << 32
			case "fstat_missing":
				s.fstat = nil
			case "lstat_missing":
				s.lstat = nil
			case "fdinfo_missing":
				s.fdinfo = nil
			case "clock_missing":
				s.now = nil
			case "zero_time":
				s.now = func() time.Time { return time.Time{} }
			}
			v, err := observeProductionLock(context.Background(), pins, s)
			requireDenied(t, v, err)
		})
	}
	v, err := ObserveInheritedProductionLock(context.Background(), nil, fixturePins)
	requireDenied(t, v, err)
}

func TestProductionLockRejectsStatMismatchAndReadErrors(t *testing.T) {
	for _, stage := range []string{"fstat_before", "lstat_before", "fstat_after", "lstat_after"} {
		for _, fault := range []string{"error", "not_regular", "unlinked", "hardlink", "inode", "major", "minor"} {
			t.Run(stage+"/"+fault, func(t *testing.T) {
				var events []string
				s := fixtureSource(&events)
				fc, pc := 0, 0
				read := func(label string, call int) (lockStat, error) {
					st := lockStat{pins: fixturePins, regular: true, nlink: 1}
					if fmt.Sprintf("%s_%s", label, map[int]string{1: "before", 2: "after"}[call]) != stage {
						return st, nil
					}
					switch fault {
					case "error":
						return lockStat{}, errors.New("fixture stat unavailable")
					case "not_regular":
						st.regular = false
					case "unlinked":
						st.nlink = 0
					case "hardlink":
						st.nlink = 2
					case "inode":
						st.pins.Inode++
					case "major":
						st.pins.DeviceMajor++
					case "minor":
						st.pins.DeviceMinor++
					}
					return st, nil
				}
				s.fstat = func() (lockStat, error) { fc++; return read("fstat", fc) }
				s.lstat = func() (lockStat, error) { pc++; return read("lstat", pc) }
				v, err := observeProductionLock(context.Background(), fixturePins, s)
				requireDenied(t, v, err)
			})
		}
	}
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprintf("fdinfo_error_%d", failAt), func(t *testing.T) {
			var events []string
			s := fixtureSource(&events)
			calls := 0
			s.fdinfo = func() ([]byte, error) {
				calls++
				if calls == failAt {
					return nil, errors.New("fixture read failed")
				}
				return fixtureFDInfo("0"), nil
			}
			v, err := observeProductionLock(context.Background(), fixturePins, s)
			requireDenied(t, v, err)
		})
	}
}

func TestProductionLockRejectsChangedSamplesAndExpiredContext(t *testing.T) {
	for _, replacement := range []string{"owner", "position", "missing", "backing_mutated"} {
		t.Run("changed_"+replacement, func(t *testing.T) {
			var events []string
			s := fixtureSource(&events)
			calls := 0
			shared := fixtureFDInfo("0")
			s.fdinfo = func() ([]byte, error) {
				calls++
				if calls == 1 {
					return shared, nil
				}
				switch replacement {
				case "owner":
					return fixtureFDInfo("359"), nil
				case "position":
					return bytes.Replace(fixtureFDInfo("0"), []byte("pos:\t0"), []byte("pos:\t1"), 1), nil
				case "missing":
					return nil, nil
				case "backing_mutated":
					copy(shared, fixtureFDInfo("1"))
					return shared, nil
				}
				panic("unknown fixture")
			}
			v, err := observeProductionLock(context.Background(), fixturePins, s)
			requireDenied(t, v, err)
		})
	}
	for _, stage := range []string{"before", "fstat1", "lstat1", "fdinfo1", "fdinfo2", "fstat2", "lstat2", "clock"} {
		t.Run("cancel_"+stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var events []string
			s := fixtureSource(&events)
			fc, pc, rc := 0, 0, 0
			if stage == "before" {
				cancel()
			}
			s.fstat = func() (lockStat, error) {
				fc++
				if stage == fmt.Sprintf("fstat%d", fc) {
					cancel()
				}
				return lockStat{pins: fixturePins, regular: true, nlink: 1}, nil
			}
			s.lstat = func() (lockStat, error) {
				pc++
				if stage == fmt.Sprintf("lstat%d", pc) {
					cancel()
				}
				return lockStat{pins: fixturePins, regular: true, nlink: 1}, nil
			}
			s.fdinfo = func() ([]byte, error) {
				rc++
				if stage == fmt.Sprintf("fdinfo%d", rc) {
					cancel()
				}
				return fixtureFDInfo("0"), nil
			}
			s.now = func() time.Time {
				if stage == "clock" {
					cancel()
				}
				return time.Now()
			}
			v, err := observeProductionLock(ctx, fixturePins, s)
			requireDenied(t, v, err)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
		})
	}
	var events []string
	s := fixtureSource(&events)
	v, err := observeProductionLock(nil, fixturePins, s)
	requireDenied(t, v, err)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	v, err = observeProductionLock(ctx, fixturePins, s)
	requireDenied(t, v, err)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost deadline: %v", err)
	}
}

type fixtureFileInfo struct {
	native any
	mode   os.FileMode
}

func (f fixtureFileInfo) Name() string       { return "fixture" }
func (f fixtureFileInfo) Size() int64        { return 0 }
func (f fixtureFileInfo) Mode() os.FileMode  { return f.mode }
func (f fixtureFileInfo) ModTime() time.Time { return time.Time{} }
func (f fixtureFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fixtureFileInfo) Sys() any           { return f.native }

func TestProductionLockNativeStatFixtures(t *testing.T) {
	for _, pins := range []ProductionLockPins{fixturePins, {DeviceMajor: 0, DeviceMinor: 19, Inode: 1}, {DeviceMajor: 0x12345, DeviceMinor: 0x6789a, Inode: 12345}} {
		t.Run(fmt.Sprintf("%x_%x", pins.DeviceMajor, pins.DeviceMinor), func(t *testing.T) {
			dev := (pins.DeviceMajor&0xfff)<<8 | (pins.DeviceMajor&0xfffff000)<<32 | (pins.DeviceMinor & 0xff) | (pins.DeviceMinor&0xffffff00)<<12
			native := &struct{ Dev, Ino, Nlink uint64 }{dev, pins.Inode, 1}
			st, err := nativeLockStat(fixtureFileInfo{native: native})
			if err != nil || st.pins != pins || !st.regular || st.nlink != 1 {
				t.Fatalf("native decode=%+v err=%v", st, err)
			}
		})
	}
	var absent *struct{ Dev, Ino, Nlink uint64 }
	for _, f := range []os.FileInfo{nil, fixtureFileInfo{native: absent}, fixtureFileInfo{native: 42}, fixtureFileInfo{native: struct{ Ino uint64 }{1}}, fixtureFileInfo{native: struct{ Dev, Ino, Nlink int64 }{-1, 1, 1}}, fixtureFileInfo{native: struct{ Dev, Ino, Nlink uint64 }{1, 1, 1}, mode: os.ModeSymlink}, fixtureFileInfo{mode: os.ModeDir}} {
		if _, err := nativeLockStat(f); err == nil {
			t.Fatal("accepted unsupported/nonregular native stat")
		}
	}
}
