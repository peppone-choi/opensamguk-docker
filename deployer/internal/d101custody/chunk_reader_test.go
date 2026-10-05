package d101custody

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func privatePartFixture(t *testing.T, wire []byte) (string, uint32) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("fixture custody")
	}
	path := filepath.Join(directory, "original.bin")
	if os.WriteFile(path, wire, 0400) != nil {
		t.Fatal("fixture original")
	}
	return path, uint32(os.Getuid())
}
func TestPrivatePartAssemblesExactOriginalBeyondHelperPipeLimit(t *testing.T) {
	wire := bytes.Repeat([]byte("ACTUAL isolated native byte fixture\n"), 70000)
	path, uid := privatePartFixture(t, wire)
	original, snapshot, err := capturePrivateOriginal(path, int64(PrivateOriginalMaxBytes), uid)
	if err != nil || !bytes.Equal(original.Bytes, wire) || snapshot.ByteLength <= 2<<20 {
		t.Fatal("whole fixture snapshot refused", err)
	}
	if inspectPrivateSnapshot(path, snapshot, uid) != nil {
		t.Fatal("actual snapshot audit refused")
	}
	combined := []byte{}
	for partIndex := uint64(0); partIndex <= (snapshot.ByteLength-1)/PrivateOriginalPartBytes; partIndex++ {
		part, err := readPrivateSegment(path, int64(PrivateOriginalMaxBytes), &snapshot, partIndex, uid, false)
		if err != nil || part.Snapshot != snapshot || part.Offset != partIndex*PrivateOriginalPartBytes || part.PartIndex != partIndex || len(part.Bytes) == 0 || uint64(len(part.Bytes)) > PrivateOriginalPartBytes || len(base64.RawURLEncoding.EncodeToString(part.Bytes)) >= 2<<20 {
			t.Fatal("fixed bounded part refused", err)
		}
		sum := sha256.Sum256(part.Bytes)
		if hex.EncodeToString(sum[:]) != part.PartSHA256 {
			t.Fatal("part hash was a full-SHA label")
		}
		combined = append(combined, part.Bytes...)
	}
	sum := sha256.Sum256(combined)
	if !bytes.Equal(combined, wire) || hex.EncodeToString(sum[:]) != original.SHA256 {
		t.Fatal("mixed or partial original")
	}
}
func TestPrivatePartRejectsUnknownSnapshotReplacementAndInvalidPart(t *testing.T) {
	for _, mode := range []string{"inode", "device", "length", "mtime", "empty", "part-range", "overflow", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			wire := bytes.Repeat([]byte("native snapshot"), 100)
			path, uid := privatePartFixture(t, wire)
			_, snapshot, err := capturePrivateOriginal(path, int64(PrivateOriginalMaxBytes), uid)
			if err != nil {
				t.Fatal(err)
			}
			partIndex := uint64(0)
			switch mode {
			case "inode":
				snapshot.Inode++
			case "device":
				snapshot.Device++
			case "length":
				snapshot.ByteLength++
			case "mtime":
				snapshot.ModifiedAtUnixNano++
			case "empty":
				snapshot = PrivateSnapshot{}
			case "part-range":
				partIndex = 1
			case "overflow":
				partIndex = ^uint64(0)
			case "replacement":
				if os.Remove(path) != nil || os.WriteFile(path, wire, 0400) != nil {
					t.Fatal("fixture replacement")
				}
			}
			if mode != "part-range" && mode != "overflow" && inspectPrivateSnapshot(path, snapshot, uid) == nil {
				t.Fatal("changed snapshot accepted by audit")
			}
			if part, err := readPrivateSegment(path, int64(PrivateOriginalMaxBytes), &snapshot, partIndex, uid, false); err == nil || len(part.Bytes) != 0 {
				t.Fatal("unobserved snapshot emitted bytes")
			}
		})
	}
}
func TestPrivatePartRetainsNativeCustodyRules(t *testing.T) {
	for _, mode := range []string{"file-write", "parent-write", "hardlink", "symlink", "parent-alias", "wrong-owner", "missing"} {
		t.Run(mode, func(t *testing.T) {
			path, uid := privatePartFixture(t, []byte("native custody original"))
			_, snapshot, err := capturePrivateOriginal(path, int64(PrivateOriginalMaxBytes), uid)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "file-write":
				if os.Chmod(path, 0600) != nil {
					t.Fatal("fixture mode")
				}
			case "parent-write":
				if os.Chmod(filepath.Dir(path), 0777) != nil {
					t.Fatal("fixture mode")
				}
			case "hardlink":
				if os.Link(path, path+"-link") != nil {
					t.Fatal("fixture link")
				}
			case "symlink":
				alias := path + "-alias"
				if os.Symlink(path, alias) != nil {
					t.Fatal("fixture alias")
				}
				path = alias
			case "parent-alias":
				alias := filepath.Dir(path) + "-alias"
				if os.Symlink(filepath.Dir(path), alias) != nil {
					t.Fatal("fixture parent alias")
				}
				path = filepath.Join(alias, filepath.Base(path))
			case "wrong-owner":
				uid++
			case "missing":
				if os.Remove(path) != nil {
					t.Fatal("fixture remove")
				}
			}
			if inspectPrivateSnapshot(path, snapshot, uid) == nil {
				t.Fatal("unsafe snapshot audit accepted")
			}
			if part, err := readPrivateSegment(path, int64(PrivateOriginalMaxBytes), &snapshot, 0, uid, false); err == nil || len(part.Bytes) != 0 {
				t.Fatal("unsafe native bytes emitted")
			}
		})
	}
}
