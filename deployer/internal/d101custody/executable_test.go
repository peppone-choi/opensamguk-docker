package d101custody

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateExecutableKeepsNativeSnapshotAndExactMode(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("directory")
	}
	path := filepath.Join(dir, "fixed-native-helper")
	wire := []byte("synthetic native executable original")
	if os.WriteFile(path, wire, 0500) != nil {
		t.Fatal("fixture")
	}
	uid := uint32(os.Getuid())
	var snapshot PrivateSnapshot
	original, err := readPrivateModeCapture(path, 32<<20, uid, 0500, &snapshot)
	if err != nil || original.SHA256 == "" || string(original.Bytes) != string(wire) || snapshot.Inode == 0 || snapshot.Device == 0 || snapshot.ByteLength != uint64(len(wire)) {
		t.Fatal("missing actual FD snapshot")
	}
	if _, err = readPrivate(path, 32<<20, uid); err == nil {
		t.Fatal("executable accepted as data original")
	}
	for _, mode := range []os.FileMode{0400, 0700, 0555} {
		t.Run(mode.String(), func(t *testing.T) {
			if os.Chmod(path, mode) != nil {
				t.Fatal("fixture chmod")
			}
			if _, err := readPrivateModeCapture(path, 32<<20, uid, 0500, nil); err == nil {
				t.Fatal("wrong executable mode accepted")
			}
		})
	}
}
