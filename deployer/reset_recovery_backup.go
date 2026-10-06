package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

// This verifies the retained data bundle produced by d101_backup.sh. It does
// not verify human approval, pg_restore execution, old runtime, registry or
// settlement, and is not a physical restore implementation.
type resetRecoveryBackup struct {
	directory   string
	manifestSHA string
}

var resetRecoveryBackupLeaves = []string{
	"server.env", "shared.env", "compose.tar.gz", "old-source.sha", "old-images.tsv", "scenario-inventory.txt",
	"postgres.dump", "postgres-list.txt", "game-postgres.tar.gz", "game-postgres.list", "game-redis.tar.gz", "game-redis.list",
}

func verifyResetRecoveryBackup(ctx context.Context, directory, manifestSHA string, budget resetSpaceBudget, oldPins map[string]string, uid uint32) (resetRecoveryBackup, error) {
	closed := resetRecoveryBackup{}
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(directory) || !resetEvidenceSHA.MatchString(manifestSHA) || !validResetFiveImageDigests(oldPins) ||
		budget.BackupBytes == nil || budget.RecoveryBytes == nil || *budget.BackupBytes == 0 || *budget.RecoveryBytes == 0 ||
		*budget.BackupBytes >= math.MaxInt64 || *budget.RecoveryBytes >= math.MaxInt64 {
		return closed, errResetExecutionEvidence
	}
	resolved, err := filepath.EvalSymlinks(directory)
	info, statErr := os.Lstat(directory)
	stat, ok := resetPrivateFileStat(info)
	if err != nil || resolved != filepath.Clean(directory) || statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !ok || stat.Uid != uid {
		return closed, errResetExecutionEvidence
	}
	manifest, err := readResetRecoverySmallFile(ctx, directory, "checksums.sha256", resetEvidenceMaxBytes, uid)
	if err != nil || resetD101OriginalSHA(manifest) != manifestSHA || !strings.HasSuffix(string(manifest), "\n") {
		return closed, errResetExecutionEvidence
	}
	expected := make(map[string]string)
	allowed := make(map[string]bool)
	for _, leaf := range resetRecoveryBackupLeaves {
		allowed[leaf] = true
	}
	allowed["old-external-scenario.json"] = true
	for _, line := range strings.Split(strings.TrimSuffix(string(manifest), "\n"), "\n") {
		if len(line) < 67 || line[64:66] != "  " || !resetEvidenceSHA.MatchString(line[:64]) || !allowed[line[66:]] || expected[line[66:]] != "" {
			return closed, errResetExecutionEvidence
		}
		expected[line[66:]] = line[:64]
	}
	for _, leaf := range resetRecoveryBackupLeaves {
		if expected[leaf] == "" {
			return closed, errResetExecutionEvidence
		}
	}
	if uint64(len(manifest)) > *budget.BackupBytes {
		return closed, errResetExecutionEvidence
	}
	remaining := *budget.BackupBytes - uint64(len(manifest))
	for leaf, hash := range expected {
		file, err := openResetRecoveryFile(directory, leaf, remaining, uid)
		if err != nil {
			return closed, errResetExecutionEvidence
		}
		hasher := sha256.New()
		n, readErr := io.Copy(hasher, io.LimitReader(resetRecoveryContextReader{ctx, file}, int64(remaining)+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || n < 0 || uint64(n) > remaining || hex.EncodeToString(hasher.Sum(nil)) != hash {
			return closed, errResetExecutionEvidence
		}
		remaining -= uint64(n)
	}
	// This is the actual captured old runtime pin set, not a new desired image
	// tag or the backup receipt's self-reported integrity label.
	pinsWire, err := readResetRecoverySmallFile(ctx, directory, "old-images.tsv", resetEvidenceMaxBytes, uid)
	if err != nil || requireResetRecoveryOldPins(pinsWire, oldPins) != nil {
		return closed, errResetExecutionEvidence
	}
	source, err := readResetRecoverySmallFile(ctx, directory, "old-source.sha", 41, uid)
	if err != nil || len(source) != 41 || source[40] != '\n' || !gitSHA40.MatchString(string(source[:40])) {
		return closed, errResetExecutionEvidence
	}
	env, err := readResetRecoverySmallFile(ctx, directory, "server.env", resetEvidenceMaxBytes, uid)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	serverIDs := 0
	for _, line := range strings.Split(string(env), "\n") {
		if strings.HasPrefix(line, "SERVER_ID=") {
			serverIDs++
			if line != "SERVER_ID=pep" {
				return closed, errResetExecutionEvidence
			}
		}
	}
	if serverIDs != 1 {
		return closed, errResetExecutionEvidence
	}
	dump, err := openResetRecoveryFile(directory, "postgres.dump", *budget.BackupBytes, uid)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	magic := make([]byte, 5)
	_, err = io.ReadFull(dump, magic)
	closeErr := dump.Close()
	if err != nil || closeErr != nil || string(magic) != "PGDMP" {
		return closed, errResetExecutionEvidence
	}
	pgList, err := readResetRecoverySmallFile(ctx, directory, "postgres-list.txt", 16*1024*1024, uid)
	if err != nil || len(strings.TrimSpace(string(pgList))) == 0 {
		return closed, errResetExecutionEvidence
	}
	remainingExpanded := *budget.RecoveryBytes
	for _, leaf := range []string{"compose.tar.gz", "game-postgres.tar.gz", "game-redis.tar.gz"} {
		names, expanded, err := verifyResetRecoveryArchive(ctx, directory, leaf, *budget.BackupBytes, remainingExpanded, uid)
		if err != nil || expanded > remainingExpanded {
			return closed, errResetExecutionEvidence
		}
		remainingExpanded -= expanded
		if leaf != "compose.tar.gz" {
			list, err := readResetRecoverySmallFile(ctx, directory, strings.TrimSuffix(leaf, ".tar.gz")+".list", 16*1024*1024, uid)
			if err != nil || string(list) != strings.Join(names, "\n")+"\n" {
				return closed, errResetExecutionEvidence
			}
		}
	}
	if ctx.Err() != nil {
		return closed, errResetExecutionEvidence
	}
	return resetRecoveryBackup{directory: directory, manifestSHA: manifestSHA}, nil
}

func requireResetRecoveryOldPins(wire []byte, pins map[string]string) error {
	if !strings.HasSuffix(string(wire), "\n") {
		return errResetExecutionEvidence
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSuffix(string(wire), "\n"), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) != 3 || seen[parts[0]] || pins[parts[0]] == "" || !resetManifestDigest.MatchString(parts[1]) {
			return errResetExecutionEvidence
		}
		var repositories []string
		if json.Unmarshal([]byte(parts[2]), &repositories) != nil {
			return errResetExecutionEvidence
		}
		matched := false
		for _, repository := range repositories {
			if strings.HasSuffix(repository, "@"+pins[parts[0]]) {
				matched = true
			}
		}
		if !matched {
			return errResetExecutionEvidence
		}
		seen[parts[0]] = true
	}
	if len(seen) != 5 {
		return errResetExecutionEvidence
	}
	return nil
}

func openResetRecoveryFile(directory, leaf string, limit uint64, uid uint32) (*os.File, error) {
	if leaf == "" || filepath.Base(leaf) != leaf || leaf == "." || leaf == ".." {
		return nil, errResetExecutionEvidence
	}
	fd, err := syscall.Open(filepath.Join(directory, leaf), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	file := os.NewFile(uintptr(fd), leaf)
	info, err := file.Stat()
	stat, ok := resetPrivateFileStat(info)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || !ok || stat.Uid != uid || stat.Nlink != 1 || info.Size() < 0 || uint64(info.Size()) > limit {
		file.Close()
		return nil, errResetExecutionEvidence
	}
	return file, nil
}

func readResetRecoverySmallFile(ctx context.Context, directory, leaf string, limit uint64, uid uint32) ([]byte, error) {
	file, err := openResetRecoveryFile(directory, leaf, limit, uid)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	wire, err := io.ReadAll(io.LimitReader(resetRecoveryContextReader{ctx, file}, int64(limit)+1))
	if err != nil || uint64(len(wire)) > limit {
		return nil, errResetExecutionEvidence
	}
	return wire, nil
}

type resetRecoveryContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r resetRecoveryContextReader) Read(p []byte) (int, error) {
	if r.ctx == nil || r.ctx.Err() != nil {
		return 0, errResetExecutionEvidence
	}
	return r.reader.Read(p)
}

func verifyResetRecoveryArchive(ctx context.Context, directory, leaf string, compressedLimit, expandedLimit uint64, uid uint32) ([]string, uint64, error) {
	file, err := openResetRecoveryFile(directory, leaf, compressedLimit, uid)
	if err != nil {
		return nil, 0, errResetExecutionEvidence
	}
	defer file.Close()
	buffer := bufio.NewReader(resetRecoveryContextReader{ctx, file})
	zipped, err := gzip.NewReader(buffer)
	if err != nil {
		return nil, 0, errResetExecutionEvidence
	}
	defer zipped.Close()
	zipped.Multistream(false)
	limited := &io.LimitedReader{R: resetRecoveryContextReader{ctx, zipped}, N: int64(expandedLimit) + 1}
	archive := tar.NewReader(limited)
	names := []string{}
	namesBytes := 0
	seen := make(map[string]bool)
	regular := make(map[string]bool)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil || len(names) >= 100000 || len(header.Name) > 4096 || strings.ContainsAny(header.Name, "\n\r\\\x00") || strings.HasPrefix(header.Name, "/") ||
			(header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir) || header.Linkname != "" {
			return nil, 0, errResetExecutionEvidence
		}
		for _, component := range strings.Split(header.Name, "/") {
			if component == ".." {
				return nil, 0, errResetExecutionEvidence
			}
		}
		canonical := path.Clean(header.Name)
		namesBytes += len(header.Name) + 1
		if namesBytes > 16*1024*1024 {
			return nil, 0, errResetExecutionEvidence
		}
		if seen[canonical] {
			return nil, 0, errResetExecutionEvidence
		}
		seen[canonical] = true
		if header.Typeflag == tar.TypeReg {
			regular[canonical] = true
		}
		names = append(names, header.Name)
	}
	// Force the gzip footer/CRC check and reject trailing gzip streams or bytes.
	if _, err := io.Copy(resetRecoveryZeroPadding{}, limited); err != nil || limited.N <= 0 {
		return nil, 0, errResetExecutionEvidence
	}
	if _, err := buffer.Peek(1); err != io.EOF || len(names) == 0 || ctx.Err() != nil {
		return nil, 0, errResetExecutionEvidence
	}
	if (leaf == "game-postgres.tar.gz" && !regular["PG_VERSION"]) || (leaf == "game-redis.tar.gz" && !regular["dump.rdb"]) {
		return nil, 0, errResetExecutionEvidence
	}
	if leaf == "compose.tar.gz" {
		for _, required := range []string{"docker-compose.server.yml", "docker-compose.shared.yml", "infra/nginx/nginx.conf"} {
			if !regular[required] {
				return nil, 0, errResetExecutionEvidence
			}
		}
	}
	return names, expandedLimit + 1 - uint64(limited.N), nil
}

type resetRecoveryZeroPadding struct{}

func (resetRecoveryZeroPadding) Write(p []byte) (int, error) {
	for _, value := range p {
		if value != 0 {
			return 0, errResetExecutionEvidence
		}
	}
	return len(p), nil
}
