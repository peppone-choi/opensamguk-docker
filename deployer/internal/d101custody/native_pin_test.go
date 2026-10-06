package d101custody

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrivateNativePinCapturesActualFileAndParentDescriptors(t *testing.T) {
	for _, mode := range []os.FileMode{0400, 0500} {
		t.Run(mode.String(), func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil || os.Chmod(dir, 0700) != nil {
				t.Fatal("canonical private directory", err)
			}
			path := filepath.Join(dir, "fixed-original")
			wire := []byte("synthetic-only whole native original")
			if os.WriteFile(path, wire, mode) != nil {
				t.Fatal("fixture")
			}
			original, pin, err := capturePrivateFilePin(path, 64<<10, uint32(os.Getuid()), mode)
			if err != nil || original.SHA256 != pin.SHA256 || string(original.Bytes) != string(wire) ||
				pin.OwnerUID != uint32(os.Getuid()) || pin.ParentOwnerUID != uint32(os.Getuid()) ||
				pin.FileMode != uint32(mode) || pin.ParentMode != 0700 || pin.LinkCount != 1 {
				t.Fatal("actual native pin unavailable", err)
			}
			fileInfo, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			parentInfo, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			fileStat := fileInfo.Sys().(*syscall.Stat_t)
			parentStat := parentInfo.Sys().(*syscall.Stat_t)
			if pin.Snapshot.Device != uint64(fileStat.Dev) || pin.Snapshot.Inode != uint64(fileStat.Ino) ||
				pin.Snapshot.ByteLength != uint64(len(wire)) || pin.Snapshot.ModifiedAtUnixNano != fileInfo.ModTime().UnixNano() ||
				pin.ParentSnapshot.Device != uint64(parentStat.Dev) || pin.ParentSnapshot.Inode != uint64(parentStat.Ino) ||
				pin.ParentSnapshot.ByteLength != uint64(parentInfo.Size()) || pin.ParentSnapshot.ModifiedAtUnixNano != parentInfo.ModTime().UnixNano() {
				t.Fatal("pin not bound to actual native file and parent metadata")
			}
			encoded, err := json.Marshal(pin)
			var fields map[string]json.RawMessage
			if err != nil || json.Unmarshal(encoded, &fields) != nil || len(fields) != 8 {
				t.Fatal("fdPin8 shape")
			}
			// A hard link invalidates nlink custody even though all bytes/SHA
			// and the original path are unchanged.
			if os.Link(path, filepath.Join(dir, "alias")) != nil {
				t.Fatal("hard-link fixture")
			}
			if _, _, err := capturePrivateFilePin(path, 64<<10, uint32(os.Getuid()), mode); err == nil {
				t.Fatal("aliased private original accepted")
			}
		})
	}
}
