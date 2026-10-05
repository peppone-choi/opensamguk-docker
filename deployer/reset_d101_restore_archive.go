package main

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// An actual retained read-only pg_restore --list job, before any DB restore.
// Native checksums alone never produce this observation. No retry/removal of
// a failed/unknown job is performed; the operation-derived name stays retained.
type resetD101RestoreArchiveObservation struct {
	ContainerID       string
	ImageID           string
	BackupManifestSHA string
	ListOriginalSHA   string
	StartedAt         time.Time
	CompletedAt       time.Time
	Original          []byte
}

func (c config) observeResetD101RestoreArchive(ctx context.Context, binding resetD101RecoveryBinding, guard func(context.Context) error) (resetD101RestoreArchiveObservation, error) {
	return c.observeResetD101RestoreArchiveWithCustodyUID(ctx, binding, guard, 0)
}
func (c config) observeResetD101RestoreArchiveWithCustodyUID(ctx context.Context, binding resetD101RecoveryBinding, guard func(context.Context) error, uid uint32) (resetD101RestoreArchiveObservation, error) {
	closed := resetD101RestoreArchiveObservation{}
	intent, err := decodeResetApprovalIntent(binding.intent.originalBytes(), binding.intent.SHA)
	if ctx == nil || ctx.Err() != nil || guard == nil || err != nil || requireResetIntentPlan(intent, binding.evidence.Plan) != nil || binding.operation.OperationID != intent.Intent.OperationID || binding.operation.D101IntentSHA != intent.SHA || binding.backup.manifestSHA != binding.evidence.Preflight.BackupManifestSHA || !filepath.IsAbs(c.composeDir) || filepath.Clean(c.composeDir) != c.composeDir || !filepath.IsAbs(c.composeHostDir) || filepath.Clean(c.composeHostDir) != c.composeHostDir || strings.ContainsAny(c.composeHostDir, ",\r\n") {
		return closed, errResetExecutionEvidence
	}
	op := intent.Intent.OperationID
	local := filepath.Join(c.composeDir, "backups", "pep", op)
	host := filepath.Join(c.composeHostDir, "backups", "pep", op)
	if binding.backup.directory != local {
		return closed, errResetExecutionEvidence
	}
	bounded, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
	defer cancel()
	started := time.Now()
	command := func(run func(context.Context) (string, error)) (string, error) {
		if bounded.Err() != nil || !time.Now().Before(time.Unix(intent.Intent.RecoveryDeadlineUnix, 0)) || guard(bounded) != nil {
			return "", errResetExecutionEvidence
		}
		result, err := run(bounded)
		if err != nil || bounded.Err() != nil || !time.Now().Before(time.Unix(intent.Intent.RecoveryDeadlineUnix, 0)) {
			return "", errResetExecutionEvidence
		}
		return result, nil
	}
	before, err := verifyResetRecoveryBackup(bounded, local, binding.backup.manifestSHA, binding.evidence.Plan.SpaceBudget, intent.Intent.OldImageDigests, uid)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	expected, err := readResetRecoverySmallFile(bounded, local, "postgres-list.txt", resetEvidenceMaxBytes, uid)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	args := []string{"create", "--pull=never", "--name", "d101-restore-list-" + op, "--network", "none", "--user", "0:0",
		"--mount", "type=bind,src=" + filepath.Join(host, "postgres.dump") + ",dst=/run/d101/backup.dump,readonly",
		"--mount", "type=tmpfs,destination=/var/lib/postgresql/data,tmpfs-size=1048576,tmpfs-mode=0700",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--entrypoint", "pg_restore", "postgres@" + intent.Intent.OldImageDigests["game-postgres"], "--list", "/run/d101/backup.dump"}
	created, err := command(func(ctx context.Context) (string, error) { return c.runServerDockerContext(ctx, args...) })
	id := strings.TrimSpace(created)
	if err != nil || !resetEvidenceSHA.MatchString(id) {
		return closed, errResetExecutionEvidence
	}
	var job resetD101CapsJob
	if _, err = command(func(ctx context.Context) (string, error) {
		var e error
		job, e = c.observeResetD101CapsJob(ctx, id)
		return "", e
	}); err != nil || job.Running || job.Status != "created" || job.Network != "none" || !validResetD101RestoreArchiveMounts(job, filepath.Join(host, "postgres.dump")) {
		return closed, errResetExecutionEvidence
	}
	if _, err = command(func(ctx context.Context) (string, error) {
		return "", c.requireResetD101CapsImage(ctx, job.ImageID, intent.Intent.OldImageDigests["game-postgres"])
	}); err != nil {
		return closed, errResetExecutionEvidence
	}
	if _, err = command(func(ctx context.Context) (string, error) { return "", c.requireResetD101RestoreArchiveCommand(ctx, id) }); err != nil {
		return closed, errResetExecutionEvidence
	}
	output, err := command(func(ctx context.Context) (string, error) {
		return c.runServerDockerContext(ctx, "start", "--attach", id)
	})
	if err != nil || len(output) == 0 || len(output) > resetEvidenceMaxBytes || !bytes.Equal([]byte(output), expected) {
		return closed, errResetExecutionEvidence
	}
	var after resetD101CapsJob
	if _, err = command(func(ctx context.Context) (string, error) {
		var e error
		after, e = c.observeResetD101CapsJob(ctx, id)
		return "", e
	}); err != nil || after.Running || after.Status != "exited" || after.ExitCode != 0 || after.ImageID != job.ImageID || after.Network != "none" || !validResetD101RestoreArchiveMounts(after, filepath.Join(host, "postgres.dump")) {
		return closed, errResetExecutionEvidence
	}
	if _, err = command(func(ctx context.Context) (string, error) { return "", c.requireResetD101RestoreArchiveCommand(ctx, id) }); err != nil {
		return closed, errResetExecutionEvidence
	}
	verified, err := verifyResetRecoveryBackup(bounded, local, before.manifestSHA, binding.evidence.Plan.SpaceBudget, intent.Intent.OldImageDigests, uid)
	completed := time.Now()
	if err != nil || verified.manifestSHA != before.manifestSHA || bounded.Err() != nil || completed.Sub(started) >= resetPreflightMaxAge || !completed.Before(time.Unix(intent.Intent.RecoveryDeadlineUnix, 0)) || guard(bounded) != nil {
		return closed, errResetExecutionEvidence
	}
	return resetD101RestoreArchiveObservation{id, job.ImageID, before.manifestSHA, resetD101OriginalSHA([]byte(output)), started, completed, append([]byte(nil), []byte(output)...)}, nil
}

func validResetD101RestoreArchiveMounts(job resetD101CapsJob, host string) bool {
	if len(job.Mounts) != 2 {
		return false
	}
	dump, temporary := 0, 0
	for _, m := range job.Mounts {
		if m.Type == "bind" && m.Source == host && m.Destination == "/run/d101/backup.dump" && !m.RW {
			dump++
		} else if m.Type == "tmpfs" && m.Source == "" && m.Destination == "/var/lib/postgresql/data" && m.RW {
			temporary++
		} else {
			return false
		}
	}
	return dump == 1 && temporary == 1
}
func (c config) requireResetD101RestoreArchiveCommand(ctx context.Context, id string) error {
	wire, err := c.runServerDockerContext(ctx, "inspect", "--format", `{"id":{{json .Id}},"path":{{json .Path}},"args":{{json .Args}},"user":{{json .Config.User}}}`, id)
	var observed struct {
		ID   string   `json:"id"`
		Path string   `json:"path"`
		Args []string `json:"args"`
		User string   `json:"user"`
	}
	if err != nil || len(wire) > 4096 || requireResetIntentShape([]byte(wire), reflect.TypeOf(observed)) != nil || decodeResetPrivateJSON([]byte(wire), &observed) != nil || observed.ID != id || observed.Path != "pg_restore" || !reflect.DeepEqual(observed.Args, []string{"--list", "/run/d101/backup.dump"}) || observed.User != "0:0" {
		return errResetExecutionEvidence
	}
	return nil
}
