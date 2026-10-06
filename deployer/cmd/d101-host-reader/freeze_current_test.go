package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101custody"
)

func hostCurrentFixtureWire(t *testing.T, now time.Time, op string) []byte {
	t.Helper()
	raw, err := json.Marshal(currentFreezeWire{ObservedAt: now.UTC().Format(time.RFC3339Nano), ServerID: "pep", OperationID: op, TargetFingerprint: strings.Repeat("a", 64), PublicationState: "VERIFYING", PublicationRevision: "2", WriterFreezeReceiptSHA: strings.Repeat("b", 64), WriterFreezeHeld: true})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestHostCurrentFreezeStrict8(t *testing.T) {
	raw := hostCurrentFixtureWire(t, time.Now(), strings.Repeat("1", 32))
	if _, err := decodeCurrentFreeze(raw); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{"duplicate": append([]byte(`{"serverId":"pep",`), raw[1:]...), "trailing": append(bytes.Clone(raw), []byte(` {}`)...), "extra-nonce": bytes.Replace(raw, []byte(`"writerFreezeHeld":true`), []byte(`"writerFreezeHeld":true,"captureNonce":"extra"`), 1), "null": bytes.Replace(raw, []byte(`"writerFreezeHeld":true`), []byte(`"writerFreezeHeld":null`), 1), "wrong-type": bytes.Replace(raw, []byte(`"writerFreezeHeld":true`), []byte(`"writerFreezeHeld":"true"`), 1), "not-held": bytes.Replace(raw, []byte(`"writerFreezeHeld":true`), []byte(`"writerFreezeHeld":false`), 1), "revision": bytes.Replace(raw, []byte(`"publicationRevision":"2"`), []byte(`"publicationRevision":"02"`), 1), "bad-utf8": append(bytes.Clone(raw), 0xff), "oversized": bytes.Repeat([]byte(" "), currentFreezeMaxBytes+1)}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeCurrentFreeze(value); err == nil {
				t.Fatal("invalid strict8 accepted")
			}
		})
	}
}
func TestHostCurrentFreezeUninstalledActionCannotPublish(t *testing.T) {
	originals := map[string]string{}
	for _, id := range originalIDs {
		originals[id] = "/fixed/" + id
	}
	raw, err := json.Marshal(installation{SchemaVersion: 1, Kind: "D101_NATIVE_READER_BINDINGS_V1", ManifestFile: "/fixed/manifest", ClockFile: "/fixed/clock", OriginalFiles: originals, RootTokenFile: "/fixed/token", SelectedEnvelopeFile: "/fixed/selected"})
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	read := func(path string, _ int64) (d101custody.Original, error) {
		reads++
		if path != installationPath {
			t.Fatal("caller-selected path")
		}
		return d101custody.Original{Bytes: raw, SHA256: strings.Repeat("a", 64)}, nil
	}
	wire, err := readFixed(currentFreezeAction, installationPath, read)
	if err == nil || len(wire) != 0 || reads != 1 {
		t.Fatal("JSON root/private labels fabricated installed current authority", err, reads)
	}
	wire, err = readFixed(currentFreezeAction, "/other-installation", read)
	if err == nil || len(wire) != 0 || reads != 1 {
		t.Fatal("action selected an alternative installation")
	}
}
func TestHostCurrentFreezeRetainsEveryOriginalAndRefreshesVisibleCopy(t *testing.T) {
	dirPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(dirPath, 0700) != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("native fixture stat")
	}
	pins := currentFreezeHostInstallation{operationID: strings.Repeat("1", 32), captureNonce: strings.Repeat("2", 32), directory: dirPath, parentDevice: uint64(st.Dev), parentInode: uint64(st.Ino)}
	first := hostCurrentFixtureWire(t, time.Now(), pins.operationID)
	if err := publishCurrentFreezeWithDirectory(context.Background(), pins, first, dir, dirPath, uint32(os.Getuid())); err != nil {
		t.Fatal("first fixture capture", err)
	}
	stem := filepath.Join(dirPath, "current-freeze-"+pins.operationID)
	original := stem + "-" + pins.captureNonce + ".original"
	before, err := os.Stat(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishCurrentFreezeWithDirectory(context.Background(), pins, first, dir, dirPath, uint32(os.Getuid())); err == nil {
		t.Fatal("O_EXCL original nonce reuse accepted")
	}
	pins.captureNonce = strings.Repeat("3", 32)
	second := hostCurrentFixtureWire(t, time.Now().Add(time.Millisecond), pins.operationID)
	if err := publishCurrentFreezeWithDirectory(context.Background(), pins, second, dir, dirPath, uint32(os.Getuid())); err != nil {
		t.Fatal("second fixture capture", err)
	}
	retained, err := os.ReadFile(original)
	if err != nil || !bytes.Equal(retained, first) {
		t.Fatal("first original changed", err)
	}
	visible, err := os.ReadFile(stem)
	if err != nil || !bytes.Equal(visible, second) {
		t.Fatal("current did not refresh", err)
	}
	after, err := os.Stat(original)
	visibleInfo, visibleErr := os.Stat(stem)
	newOriginal, originalErr := os.Stat(stem + "-" + pins.captureNonce + ".original")
	if err != nil || visibleErr != nil || originalErr != nil || !os.SameFile(before, after) || os.SameFile(newOriginal, visibleInfo) || after.Sys().(*syscall.Stat_t).Nlink != 1 || visibleInfo.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatal("original mutation/hardlink visible alias")
	}
	if _, err = os.Stat(filepath.Join(dirPath, pins.operationID+".json")); !os.IsNotExist(err) {
		t.Fatal("immutable op preflight touched")
	}
}
func TestHostCurrentFreezePublisherRejectsParentAndVisibleAliases(t *testing.T) {
	for _, name := range []string{"parent-pin", "symlink-visible", "hardlink-visible", "cancelled", "wrong-operation"} {
		t.Run(name, func(t *testing.T) {
			dirPath, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil || os.Chmod(dirPath, 0700) != nil {
				t.Fatal(err)
			}
			dir, err := os.Open(dirPath)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			info, err := dir.Stat()
			if err != nil {
				t.Fatal(err)
			}
			st := info.Sys().(*syscall.Stat_t)
			pins := currentFreezeHostInstallation{operationID: strings.Repeat("1", 32), captureNonce: strings.Repeat("2", 32), directory: dirPath, parentDevice: uint64(st.Dev), parentInode: uint64(st.Ino)}
			raw := hostCurrentFixtureWire(t, time.Now(), pins.operationID)
			stem := filepath.Join(dirPath, "current-freeze-"+pins.operationID)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "parent-pin":
				pins.parentInode++
			case "symlink-visible":
				if os.Symlink("other", stem) != nil {
					t.Fatal("fixture symlink")
				}
			case "hardlink-visible":
				other := filepath.Join(dirPath, "other")
				if os.WriteFile(other, raw, 0400) != nil || os.Link(other, stem) != nil {
					t.Fatal("fixture hardlink")
				}
			case "cancelled":
				cancel()
			case "wrong-operation":
				raw = hostCurrentFixtureWire(t, time.Now(), strings.Repeat("9", 32))
			}
			if err := publishCurrentFreezeWithDirectory(ctx, pins, raw, dir, dirPath, uint32(os.Getuid())); err == nil {
				t.Fatal("invalid publish accepted")
			}
		})
	}
}
