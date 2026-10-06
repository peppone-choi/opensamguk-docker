package d101custody

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateReaderReturnsActualDescriptorBytesAndRejectsDrift(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(root, 0700) != nil {
		t.Fatal("fixture directory")
	}
	path := filepath.Join(root, "original.json")
	wire := []byte("SYNTHETIC_ONLY original")
	if os.WriteFile(path, wire, 0400) != nil {
		t.Fatal("fixture original")
	}
	observed, err := readPrivate(path, 1024, uint32(os.Getuid()))
	if err != nil || !bytes.Equal(observed.Bytes, wire) || len(observed.SHA256) != 64 {
		t.Fatal("actual isolated descriptor refused")
	}
	for _, mode := range []string{"public", "hardlink", "symlink", "directory", "empty", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			dir, _ := filepath.EvalSymlinks(t.TempDir())
			_ = os.Chmod(dir, 0700)
			leaf := filepath.Join(dir, "original.json")
			_ = os.WriteFile(leaf, wire, 0400)
			switch mode {
			case "public":
				_ = os.Chmod(leaf, 0444)
			case "hardlink":
				_ = os.Link(leaf, filepath.Join(dir, "second.json"))
			case "symlink":
				_ = os.Remove(leaf)
				_ = os.Symlink(path, leaf)
			case "directory":
				_ = os.Remove(leaf)
				_ = os.Mkdir(leaf, 0400)
			case "empty":
				_ = os.Chmod(leaf, 0600)
				_ = os.WriteFile(leaf, nil, 0400)
				_ = os.Chmod(leaf, 0400)
			case "oversize":
				_ = os.Chmod(leaf, 0600)
				_ = os.WriteFile(leaf, make([]byte, 1025), 0400)
				_ = os.Chmod(leaf, 0400)
			}
			if _, err := readPrivate(leaf, 1024, uint32(os.Getuid())); err == nil {
				t.Fatal("invalid native custody accepted")
			}
		})
	}
}

func TestPrivateReaderRefusesParentAliasModeAndWrongUID(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.Chmod(root, 0700)
	path := filepath.Join(root, "original.json")
	_ = os.WriteFile(path, []byte("{}"), 0400)
	uid := uint32(os.Getuid())
	if _, err := readPrivate(path, 1024, uid+1); err == nil {
		t.Fatal("wrong uid")
	}
	_ = os.Chmod(root, 0755)
	if _, err := readPrivate(path, 1024, uid); err == nil {
		t.Fatal("public directory")
	}
	_ = os.Chmod(root, 0700)
	outer, _ := filepath.EvalSymlinks(t.TempDir())
	alias := filepath.Join(outer, "alias")
	_ = os.Symlink(root, alias)
	if _, err := readPrivate(filepath.Join(alias, "original.json"), 1024, uid); err == nil {
		t.Fatal("parent alias")
	}
}
