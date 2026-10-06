package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101freeze"
)

const currentFreezeAction = "read-current-freeze"
const currentFreezeMaxBytes = 64 << 10
const currentFreezeTimeout = 2 * time.Second

var currentFreezeSlots = make(chan struct{}, 2)
var currentFreezeOp = regexp.MustCompile(`^[0-9a-f]{32}$`)
var currentFreezeSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
var currentFreezeKeys = []string{"observedAt", "serverId", "operationId", "targetFingerprint", "publicationState", "publicationRevision", "writerFreezeReceiptSha256", "writerFreezeHeld"}

type currentFreezeWire struct {
	ObservedAt             string `json:"observedAt"`
	ServerID               string `json:"serverId"`
	OperationID            string `json:"operationId"`
	TargetFingerprint      string `json:"targetFingerprint"`
	PublicationState       string `json:"publicationState"`
	PublicationRevision    string `json:"publicationRevision"`
	WriterFreezeReceiptSHA string `json:"writerFreezeReceiptSha256"`
	WriterFreezeHeld       bool   `json:"writerFreezeHeld"`
}

func decodeCurrentFreeze(wire []byte) (currentFreezeWire, error) {
	var value currentFreezeWire
	if len(wire) == 0 || len(wire) > currentFreezeMaxBytes || !utf8.Valid(wire) || exactJSON(wire, currentFreezeKeys, &value) != nil {
		return currentFreezeWire{}, d101custody.ErrUnavailable
	}
	observed, err := time.Parse(time.RFC3339Nano, value.ObservedAt)
	revision, revErr := strconv.ParseInt(value.PublicationRevision, 10, 64)
	if err != nil || !strings.HasSuffix(value.ObservedAt, "Z") || observed.IsZero() || value.ServerID != "pep" || !currentFreezeOp.MatchString(value.OperationID) || !currentFreezeSHA.MatchString(value.TargetFingerprint) || !currentFreezeSHA.MatchString(value.WriterFreezeReceiptSHA) || value.PublicationState != "VERIFYING" || !value.WriterFreezeHeld || revErr != nil || revision <= 0 || strconv.FormatInt(revision, 10) != value.PublicationRevision {
		return currentFreezeWire{}, d101custody.ErrUnavailable
	}
	return value, nil
}

// The actual installed supplier authenticates launcher/process/source, same-OFD
// continuity and ALL publication/console/publisher/inflight/other-writer originals
// collected after started. Native FD samples themselves remain unverified data.
type currentFreezeHostSupplier interface {
	CollectAuthenticated(context.Context, time.Time, d101freeze.UnverifiedProductionLock) ([]byte, error)
}
type currentFreezeHostInstallation struct {
	installationSHA     string
	operationID         string
	captureNonce        string
	targetFingerprint   string
	publicationRevision string
	freezeSHA           string
	destructiveCutoff   time.Time
	directory           string
	parentDevice        uint64
	parentInode         uint64
	descriptor          *os.File
	lockPins            d101freeze.ProductionLockPins
	supplier            currentFreezeHostSupplier
}

// Actual reviewed private Go input. Its expected pins and mandatory writer
// authenticator are never adopted from reader JSON, argv or environment.
var reviewedCurrentFreezeHostInputs *currentFreezeHostInstallation

// Retain the wrapper for the helper process's whole lifetime. It wraps only the
// already inherited descriptor: no pathname open/reacquire/duplicate/unlock or
// Close is performed. The external launcher owns continuity/release policy.
var inheritedCurrentFreezeDescriptor struct {
	sync.Mutex
	file *os.File
}

func fixedCurrentFreezeHostInstallation(original d101custody.Original) (currentFreezeHostInstallation, error) {
	return fixedCurrentFreezeHostInstallationWithInput(original, reviewedCurrentFreezeHostInputs, runtime.GOOS)
}

// Explicit data/platform inputs are private portable fixture seams; the
// production entry above always uses its reviewed compiled input and GOOS.
func fixedCurrentFreezeHostInstallationWithInput(original d101custody.Original, input *currentFreezeHostInstallation, platform string) (currentFreezeHostInstallation, error) {
	if platform != "linux" || input == nil {
		return currentFreezeHostInstallation{}, d101custody.ErrUnavailable
	}
	pins := *input
	if original.SHA256 != pins.installationSHA || !currentFreezeSHA.MatchString(pins.installationSHA) ||
		pins.supplier == nil || (reflect.ValueOf(pins.supplier).Kind() == reflect.Pointer && reflect.ValueOf(pins.supplier).IsNil()) ||
		!currentFreezeOp.MatchString(pins.operationID) || !currentFreezeSHA.MatchString(pins.targetFingerprint) ||
		!currentFreezeSHA.MatchString(pins.freezeSHA) || pins.parentDevice == 0 || pins.parentInode == 0 ||
		pins.lockPins.Inode == 0 || pins.destructiveCutoff.IsZero() || !filepath.IsAbs(pins.directory) || filepath.Clean(pins.directory) != pins.directory {
		return currentFreezeHostInstallation{}, d101custody.ErrUnavailable
	}
	inheritedCurrentFreezeDescriptor.Lock()
	defer inheritedCurrentFreezeDescriptor.Unlock()
	if inheritedCurrentFreezeDescriptor.file == nil {
		inheritedCurrentFreezeDescriptor.file = os.NewFile(9, "inherited-production-lock")
	}
	pins.descriptor = inheritedCurrentFreezeDescriptor.file
	if pins.descriptor == nil || pins.descriptor.Fd() != 9 {
		return currentFreezeHostInstallation{}, d101custody.ErrUnavailable
	}
	// This is only a private capture lifetime, never a human approval/operation
	// UUID. Every capture retains a new O_EXCL original without overwriting old.
	var capture [16]byte
	if _, err := rand.Read(capture[:]); err != nil {
		return currentFreezeHostInstallation{}, d101custody.ErrUnavailable
	}
	pins.captureNonce = hex.EncodeToString(capture[:])
	return pins, nil
}
func readCurrentFreeze(read privateReader) ([]byte, error) {
	if read == nil {
		return nil, d101custody.ErrUnavailable
	}
	installationOriginal, err := read(installationPath, currentFreezeMaxBytes)
	if err != nil {
		return nil, d101custody.ErrUnavailable
	}
	var reader installation
	if exactJSON(installationOriginal.Bytes, []string{"schemaVersion", "kind", "manifestFile", "clockFile", "originalFiles", "rootTokenFile", "selectedEnvelopeFile"}, &reader) != nil || reader.SchemaVersion != 1 || reader.Kind != "D101_NATIVE_READER_BINDINGS_V1" || len(reader.OriginalFiles) != len(originalIDs) {
		return nil, d101custody.ErrUnavailable
	}
	for _, id := range originalIDs {
		if reader.OriginalFiles[id] == "" {
			return nil, d101custody.ErrUnavailable
		}
	}
	pins, err := fixedCurrentFreezeHostInstallation(installationOriginal)
	if err != nil {
		return nil, d101custody.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), currentFreezeTimeout)
	defer cancel()
	return readCurrentFreezeWithInstallation(ctx, pins, read, time.Now, d101freeze.ObserveInheritedProductionLock, publishCurrentFreeze)
}

type currentFreezeLockReader func(context.Context, *os.File, d101freeze.ProductionLockPins) (d101freeze.UnverifiedProductionLock, error)
type currentFreezePublisher func(context.Context, currentFreezeHostInstallation, []byte) error

// Injectable native functions are confined to internal fixture calls. Main uses
// the actual inherited FD9 collector and root-private publisher above.
func readCurrentFreezeWithInstallation(ctx context.Context, pins currentFreezeHostInstallation, read privateReader, clock func() time.Time, observe currentFreezeLockReader, publish currentFreezePublisher) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || pins.supplier == nil || (reflect.ValueOf(pins.supplier).Kind() == reflect.Pointer && reflect.ValueOf(pins.supplier).IsNil()) || pins.descriptor == nil || pins.descriptor.Fd() != 9 || !currentFreezeOp.MatchString(pins.operationID) || !currentFreezeOp.MatchString(pins.captureNonce) || !currentFreezeSHA.MatchString(pins.installationSHA) || !currentFreezeSHA.MatchString(pins.targetFingerprint) || !currentFreezeSHA.MatchString(pins.freezeSHA) || pins.publicationRevision == "" || pins.destructiveCutoff.IsZero() || !filepath.IsAbs(pins.directory) || filepath.Clean(pins.directory) != pins.directory || pins.parentDevice == 0 || pins.parentInode == 0 || read == nil || clock == nil || observe == nil || publish == nil {
		return nil, d101custody.ErrUnavailable
	}
	select {
	case currentFreezeSlots <- struct{}{}:
		defer func() { <-currentFreezeSlots }()
	default:
		return nil, d101custody.ErrUnavailable
	}
	started := clock()
	deadline := started.Add(currentFreezeTimeout)
	if pins.destructiveCutoff.Before(deadline) {
		deadline = pins.destructiveCutoff
	}
	if !started.Before(deadline) {
		return nil, d101custody.ErrUnavailable
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	original, err := read(installationPath, currentFreezeMaxBytes)
	if err != nil || original.SHA256 != pins.installationSHA {
		return nil, d101custody.ErrUnavailable
	}
	lock, err := observe(bounded, pins.descriptor, pins.lockPins)
	if err != nil || bounded.Err() != nil {
		return nil, d101custody.ErrUnavailable
	}
	wire, err := pins.supplier.CollectAuthenticated(bounded, started, lock)
	wire = bytes.Clone(wire)
	value, decodeErr := decodeCurrentFreeze(wire)
	observed, timeErr := time.Parse(time.RFC3339Nano, value.ObservedAt)
	now := clock()
	after, readErr := read(installationPath, currentFreezeMaxBytes)
	if err != nil || decodeErr != nil || timeErr != nil || readErr != nil || after.SHA256 != original.SHA256 || !bytes.Equal(after.Bytes, original.Bytes) || bounded.Err() != nil || !now.Before(deadline) || observed.Before(started) || observed.After(now) || value.OperationID != pins.operationID || value.TargetFingerprint != pins.targetFingerprint || value.PublicationRevision != pins.publicationRevision || value.WriterFreezeReceiptSHA != pins.freezeSHA {
		return nil, d101custody.ErrUnavailable
	}
	if publish(bounded, pins, wire) != nil || bounded.Err() != nil || !clock().Before(deadline) {
		return nil, d101custody.ErrUnavailable
	}
	return wire, nil
}

// Only a verified host capture reaches this writer. It does not unlock/close FD9
// or create its parent, originals/index/preflight, a key, an issuer or a daemon.
func publishCurrentFreeze(ctx context.Context, pins currentFreezeHostInstallation, wire []byte) error {
	if runtime.GOOS != "linux" {
		return d101custody.ErrUnavailable
	}
	dir, err := os.OpenFile(pins.directory, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return d101custody.ErrUnavailable
	}
	defer dir.Close()
	prefix := fmt.Sprintf("/proc/self/fd/%d", dir.Fd())
	return publishCurrentFreezeWithDirectory(ctx, pins, wire, dir, prefix, 0)
}

// The directory-prefix seam permits portable filesystem fixtures; the host
// entry above always uses the already open Linux directory FD, never a reopen.
func publishCurrentFreezeWithDirectory(ctx context.Context, pins currentFreezeHostInstallation, wire []byte, dir *os.File, prefix string, uid uint32) error {
	if ctx == nil || ctx.Err() != nil || dir == nil || !currentFreezeOp.MatchString(pins.operationID) || !currentFreezeOp.MatchString(pins.captureNonce) || decodeCurrentFreezeOnly(wire) != nil {
		return d101custody.ErrUnavailable
	}
	check := func() bool {
		native, err := dir.Stat()
		path, pathErr := os.Lstat(pins.directory)
		if err != nil || pathErr != nil || !os.SameFile(native, path) || !native.IsDir() || native.Mode().Perm() != 0700 {
			return false
		}
		st, ok := native.Sys().(*syscall.Stat_t)
		return ok && st.Uid == uid && uint64(st.Dev) == pins.parentDevice && uint64(st.Ino) == pins.parentInode
	}
	value, decodeErr := decodeCurrentFreeze(wire)
	if decodeErr != nil || value.OperationID != pins.operationID || !check() {
		return d101custody.ErrUnavailable
	}
	stem := "current-freeze-" + pins.operationID
	original := filepath.Join(prefix, stem+"-"+pins.captureNonce+".original")
	temp := filepath.Join(prefix, stem+"-"+pins.captureNonce+".tmp")
	visible := filepath.Join(prefix, stem)
	write := func(path string) error {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0400)
		if err != nil {
			return d101custody.ErrUnavailable
		}
		// Partial originals/temps survive failure; no cleanup hides uncertain writes.
		// Inspect the issuing FD before closing it; path metadata is not its proof.
		n, writeErr := f.Write(wire)
		syncErr := f.Sync()
		issued, statErr := f.Stat()
		pathInfo, pathErr := os.Lstat(path)
		closeErr := f.Close()
		if n != len(wire) || writeErr != nil || syncErr != nil || statErr != nil || pathErr != nil || closeErr != nil || ctx.Err() != nil || !check() || !os.SameFile(issued, pathInfo) || issued.Size() != pathInfo.Size() || !issued.ModTime().Equal(pathInfo.ModTime()) {
			return d101custody.ErrUnavailable
		}
		info, err := os.Lstat(path)
		if err != nil {
			return d101custody.ErrUnavailable
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uid || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || info.Size() != int64(len(wire)) {
			return d101custody.ErrUnavailable
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, wire) {
			return d101custody.ErrUnavailable
		}
		return nil
	}
	if write(original) != nil || write(temp) != nil {
		return d101custody.ErrUnavailable
	}
	if info, err := os.Lstat(visible); err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uid || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 {
			return d101custody.ErrUnavailable
		}
	} else if !os.IsNotExist(err) {
		return d101custody.ErrUnavailable
	}
	if ctx.Err() != nil || !check() || os.Rename(temp, visible) != nil || dir.Sync() != nil || !check() {
		return d101custody.ErrUnavailable
	}
	return nil
}
func decodeCurrentFreezeOnly(wire []byte) error { _, err := decodeCurrentFreeze(wire); return err }
