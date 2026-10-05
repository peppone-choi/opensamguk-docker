package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Isolated synthetic retained bytes only; no Docker, pg_restore or live data.
func resetRecoveryBackupFixture(t *testing.T) (string, map[string][]byte, resetSpaceBudget, map[string]string, uint32) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0700) != nil {
		t.Fatal("private fixture directory")
	}
	wires := map[string][]byte{
		"server.env": []byte("SERVER_ID=pep\nSERVER_GENERATION=\n"), "shared.env": []byte("synthetic=private\n"),
		"old-source.sha": []byte(strings.Repeat("a", 40) + "\n"), "scenario-inventory.txt": []byte("NO_EXTERNAL_CANDIDATE_IMAGE_PIN_RETAINED\n"),
		"postgres.dump": []byte("PGDMPsynthetic"), "postgres-list.txt": []byte("; Synthetic pg_restore list; not a physical dump\n"),
		"game-postgres.list": []byte("./\n./PG_VERSION\n"), "game-redis.list": []byte("./\n./dump.rdb\n"),
	}
	wires["compose.tar.gz"] = resetRecoveryTestArchive(t, []*tar.Header{
		{Name: "docker-compose.server.yml", Typeflag: tar.TypeReg, Size: 1}, {Name: "docker-compose.shared.yml", Typeflag: tar.TypeReg, Size: 1}, {Name: "infra/nginx/nginx.conf", Typeflag: tar.TypeReg, Size: 1},
	})
	wires["game-postgres.tar.gz"] = resetRecoveryTestArchive(t, []*tar.Header{{Name: "./", Typeflag: tar.TypeDir}, {Name: "./PG_VERSION", Typeflag: tar.TypeReg, Size: 1}})
	wires["game-redis.tar.gz"] = resetRecoveryTestArchive(t, []*tar.Header{{Name: "./", Typeflag: tar.TypeDir}, {Name: "./dump.rdb", Typeflag: tar.TypeReg, Size: 1}})
	pins := map[string]string{}
	var rows strings.Builder
	for _, service := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		pins[service] = "sha256:" + strings.Repeat("b", 64)
		repositories, _ := json.Marshal([]string{"synthetic.test/image@" + pins[service]})
		rows.WriteString(service + "\tsha256:" + strings.Repeat("c", 64) + "\t" + string(repositories) + "\n")
	}
	wires["old-images.tsv"] = []byte(rows.String())
	limit := uint64(1024 * 1024)
	budget := resetSpaceBudget{BackupBytes: &limit, RecoveryBytes: &limit}
	return directory, wires, budget, pins, uint32(os.Getuid())
}

func resetRecoveryTestArchive(t *testing.T, headers []*tar.Header) []byte {
	t.Helper()
	var buffer bytes.Buffer
	zipped := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(zipped)
	for _, header := range headers {
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg && header.Size > 0 {
			if _, err := archive.Write(bytes.Repeat([]byte("x"), int(header.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if archive.Close() != nil || zipped.Close() != nil {
		t.Fatal("fixture archive close")
	}
	return buffer.Bytes()
}

func writeResetRecoveryBackupFixture(t *testing.T, directory string, wires map[string][]byte) string {
	t.Helper()
	var manifest strings.Builder
	for _, leaf := range append(append([]string(nil), resetRecoveryBackupLeaves...), "old-external-scenario.json") {
		wire, found := wires[leaf]
		if !found {
			continue
		}
		if err := os.WriteFile(filepath.Join(directory, leaf), wire, 0400); err != nil {
			t.Fatal(err)
		}
		manifest.WriteString(resetD101OriginalSHA(wire) + "  " + leaf + "\n")
	}
	wire := []byte(manifest.String())
	if os.WriteFile(filepath.Join(directory, "checksums.sha256"), wire, 0400) != nil {
		t.Fatal("fixture manifest")
	}
	return resetD101OriginalSHA(wire)
}

func TestResetRecoveryBackupVerifiesOriginalBundleWithoutMutation(t *testing.T) {
	directory, wires, budget, pins, uid := resetRecoveryBackupFixture(t)
	wires["old-external-scenario.json"] = []byte(`{"synthetic":"old"}`)
	sha := writeResetRecoveryBackupFixture(t, directory, wires)
	backup, err := verifyResetRecoveryBackup(context.Background(), directory, sha, budget, pins, uid)
	if err != nil || backup.directory != directory || backup.manifestSHA != sha {
		t.Fatal("synthetic original data bundle refused", err)
	}
	for leaf, original := range wires {
		observed, err := os.ReadFile(filepath.Join(directory, leaf))
		if err != nil || !bytes.Equal(original, observed) {
			t.Fatal("read-only validation changed retained bytes")
		}
	}
}

func TestResetRecoveryBackupRefusesInvalidCustodyBindingAndActualContents(t *testing.T) {
	for _, mode := range []string{"wrong-manifest", "changed-bytes", "missing-leaf", "duplicate-manifest", "unexpected-leaf", "wrong-pin", "duplicate-service", "wrong-old-source", "wrong-env", "duplicate-env", "wrong-dump", "empty-pg-list", "wrong-tar-list", "bad-gzip-crc", "trailing-stream", "no-pg-version", "directory-pg-version", "missing-compose", "compressed-budget", "expanded-budget", "missing-budget", "wrong-owner", "directory-mode", "symlink-parent", "symlink-leaf", "hardlink-leaf", "writable-leaf", "fifo-leaf", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			directory, wires, budget, pins, uid := resetRecoveryBackupFixture(t)
			switch mode {
			case "missing-leaf":
				delete(wires, "postgres.dump")
			case "wrong-pin":
				pins["game-api"] = "sha256:" + strings.Repeat("d", 64)
			case "duplicate-service":
				wires["old-images.tsv"] = append(wires["old-images.tsv"], bytes.Split(wires["old-images.tsv"], []byte("\n"))[0]...)
				wires["old-images.tsv"] = append(wires["old-images.tsv"], '\n')
			case "wrong-old-source":
				wires["old-source.sha"] = []byte("UNKNOWN\n")
			case "wrong-env":
				wires["server.env"] = []byte("SERVER_ID=other\n")
			case "duplicate-env":
				wires["server.env"] = []byte("SERVER_ID=pep\nSERVER_ID=pep\n")
			case "wrong-dump":
				wires["postgres.dump"] = []byte("notPGDMP")
			case "empty-pg-list":
				wires["postgres-list.txt"] = []byte(" \n")
			case "wrong-tar-list":
				wires["game-postgres.list"] = []byte("./\n./NOT_PG_VERSION\n")
			case "bad-gzip-crc":
				wire := wires["game-postgres.tar.gz"]
				wire[len(wire)-8] ^= 1
			case "trailing-stream":
				wires["game-postgres.tar.gz"] = append(wires["game-postgres.tar.gz"], wires["game-redis.tar.gz"]...)
			case "no-pg-version":
				wires["game-postgres.tar.gz"] = resetRecoveryTestArchive(t, []*tar.Header{{Name: "./", Typeflag: tar.TypeDir}})
				wires["game-postgres.list"] = []byte("./\n")
			case "directory-pg-version":
				wires["game-postgres.tar.gz"] = resetRecoveryTestArchive(t, []*tar.Header{{Name: "./", Typeflag: tar.TypeDir}, {Name: "./PG_VERSION", Typeflag: tar.TypeDir}})
			case "missing-compose":
				wires["compose.tar.gz"] = resetRecoveryTestArchive(t, []*tar.Header{{Name: "docker-compose.server.yml", Typeflag: tar.TypeReg, Size: 1}})
			}
			sha := writeResetRecoveryBackupFixture(t, directory, wires)
			ctx := context.Background()
			switch mode {
			case "wrong-manifest":
				sha = strings.Repeat("f", 64)
			case "changed-bytes":
				_ = os.Remove(filepath.Join(directory, "shared.env"))
				_ = os.WriteFile(filepath.Join(directory, "shared.env"), []byte("different"), 0400)
			case "duplicate-manifest", "unexpected-leaf":
				wire, _ := os.ReadFile(filepath.Join(directory, "checksums.sha256"))
				leaf := "server.env"
				if mode == "unexpected-leaf" {
					leaf = "../outside"
				}
				wire = append(wire, []byte(strings.Repeat("a", 64)+"  "+leaf+"\n")...)
				_ = os.Remove(filepath.Join(directory, "checksums.sha256"))
				_ = os.WriteFile(filepath.Join(directory, "checksums.sha256"), wire, 0400)
				sha = resetD101OriginalSHA(wire)
			case "compressed-budget":
				value := uint64(1)
				budget.BackupBytes = &value
			case "expanded-budget":
				value := uint64(1)
				budget.RecoveryBytes = &value
			case "missing-budget":
				budget.RecoveryBytes = nil
			case "wrong-owner":
				uid++
			case "directory-mode":
				_ = os.Chmod(directory, 0755)
			case "symlink-parent":
				alias := filepath.Join(t.TempDir(), "alias")
				if os.Symlink(directory, alias) != nil {
					t.Fatal("fixture symlink")
				}
				directory = alias
			case "symlink-leaf":
				leaf := filepath.Join(directory, "shared.env")
				_ = os.Remove(leaf)
				if os.Symlink(filepath.Join(directory, "server.env"), leaf) != nil {
					t.Fatal("fixture symlink")
				}
			case "hardlink-leaf":
				if os.Link(filepath.Join(directory, "shared.env"), filepath.Join(directory, "retained-link")) != nil {
					t.Fatal("fixture hardlink")
				}
			case "writable-leaf":
				_ = os.Chmod(filepath.Join(directory, "shared.env"), 0600)
			case "fifo-leaf":
				leaf := filepath.Join(directory, "shared.env")
				_ = os.Remove(leaf)
				if syscall.Mkfifo(leaf, 0400) != nil {
					t.Fatal("fixture fifo")
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := verifyResetRecoveryBackup(ctx, directory, sha, budget, pins, uid); err == nil {
				t.Fatal("invalid retained bundle accepted")
			}
		})
	}
}

func TestResetRecoveryArchiveRejectsUnsafeMembersWithMatchingChecksums(t *testing.T) {
	for _, header := range []*tar.Header{
		{Name: "../outside", Typeflag: tar.TypeReg, Size: 1}, {Name: "/absolute", Typeflag: tar.TypeReg, Size: 1}, {Name: "safe/../outside", Typeflag: tar.TypeReg, Size: 1},
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "outside"}, {Name: "link", Typeflag: tar.TypeLink, Linkname: "PG_VERSION"}, {Name: "device", Typeflag: tar.TypeChar},
		{Name: "line\nbreak", Typeflag: tar.TypeReg, Size: 1},
	} {
		t.Run(header.Name, func(t *testing.T) {
			directory, wires, budget, pins, uid := resetRecoveryBackupFixture(t)
			wires["game-postgres.tar.gz"] = resetRecoveryTestArchive(t, []*tar.Header{{Name: "./", Typeflag: tar.TypeDir}, {Name: "./PG_VERSION", Typeflag: tar.TypeReg, Size: 1}, header})
			wires["game-postgres.list"] = []byte("./\n./PG_VERSION\n" + header.Name + "\n")
			sha := writeResetRecoveryBackupFixture(t, directory, wires)
			if _, err := verifyResetRecoveryBackup(context.Background(), directory, sha, budget, pins, uid); err == nil {
				t.Fatal("unsafe tar member accepted despite original checksum match")
			}
		})
	}
}
