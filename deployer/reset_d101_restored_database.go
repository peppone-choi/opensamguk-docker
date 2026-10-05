package main

import (
	"context"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
)

// Separate old-world observation. New-world caps/generation0 validation cannot
// establish restoration of the previous generation/scenario/tick. This SELECT
// deliberately excludes complete config/meta, credentials and account rows.
const resetD101RestoredDatabaseSQL = `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='2000ms';
SELECT json_build_object(
 'schemaVersion',1,'kind','D101_RESTORED_DATABASE_OBSERVATION_V1',
 'databaseName',current_database(),'databaseUser',current_user,
 'serverAddress',host(inet_server_addr()),'serverPort',inet_server_port(),
 'transactionReadOnly',current_setting('transaction_read_only'),
 'transactionIsolation',current_setting('transaction_isolation'),
 'worldRowCount',(SELECT count(*) FROM world_state),'worldId',w.id,
 'scenarioCode',w.scenario_code,'tickSeconds',w.tick_seconds,
 'generationType',jsonb_typeof(w.meta->'server_generation'),
 'generationRaw',left((w.meta->'server_generation')::text,128),
 'observedAtUtc',to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
FROM world_state w WHERE w.id=1;
ROLLBACK;`

type resetD101RestoredDatabaseOriginal struct {
	SchemaVersion        int    `json:"schemaVersion"`
	Kind                 string `json:"kind"`
	DatabaseName         string `json:"databaseName"`
	DatabaseUser         string `json:"databaseUser"`
	ServerAddress        string `json:"serverAddress"`
	ServerPort           int    `json:"serverPort"`
	TransactionReadOnly  string `json:"transactionReadOnly"`
	TransactionIsolation string `json:"transactionIsolation"`
	WorldRowCount        int    `json:"worldRowCount"`
	WorldID              int    `json:"worldId"`
	ScenarioCode         string `json:"scenarioCode"`
	TickSeconds          int    `json:"tickSeconds"`
	GenerationType       string `json:"generationType"`
	GenerationRaw        string `json:"generationRaw"`
	ObservedAtUTC        string `json:"observedAtUtc"`
}

func decodeResetD101RestoredDatabase(wire []byte, database, user, address string, started, completed time.Time) (resetD101RestoredDatabaseOriginal, error) {
	var value resetD101RestoredDatabaseOriginal
	if len(wire) == 0 || len(wire) > 16*1024 || !utf8.Valid(wire) || requireResetIntentShape(wire, reflect.TypeOf(value)) != nil ||
		decodeResetPrivateJSON(wire, &value) != nil || value.SchemaVersion != 1 || value.Kind != "D101_RESTORED_DATABASE_OBSERVATION_V1" ||
		value.DatabaseName != database || value.DatabaseUser != user || value.ServerAddress != address || value.ServerPort != 5432 ||
		value.TransactionReadOnly != "on" || value.TransactionIsolation != "repeatable read" || value.WorldRowCount != 1 || value.WorldID != 1 ||
		!regexp.MustCompile(`^scenario_[0-9]+$`).MatchString(value.ScenarioCode) || value.TickSeconds <= 0 || value.TickSeconds > 2147483647 || value.GenerationType != "number" {
		return resetD101RestoredDatabaseOriginal{}, errResetExecutionEvidence
	}
	generation, err := strconv.ParseInt(value.GenerationRaw, 10, 32)
	observed, observedErr := resetD101RecoveryUTC(value.ObservedAtUTC)
	if err != nil || generation < 0 || strconv.FormatInt(generation, 10) != value.GenerationRaw || observedErr != nil ||
		completed.Before(started) || completed.Sub(started) >= resetPreflightMaxAge || observed.Before(started) || observed.After(completed) {
		return resetD101RestoredDatabaseOriginal{}, errResetExecutionEvidence
	}
	return value, nil
}

// This comparison belongs after verification of the actual retained pre-reset
// old snapshot. It supplies no default generation, scenario or tick and does
// not turn a caller snapshot/hash into approval or a RECOVERED closure.
func requireResetD101RestoredDatabaseMatchesOld(value resetD101RestoredDatabaseOriginal, registry resetD101OldCanonicalRegistry, oldTickSeconds int) error {
	if registry.ID != "pep" || registry.Generation < 0 || !regexp.MustCompile(`^scenario_[0-9]+$`).MatchString(registry.ScenarioCode) ||
		oldTickSeconds <= 0 || oldTickSeconds > 2147483647 || value.WorldID != 1 || value.GenerationType != "number" ||
		value.GenerationRaw != strconv.Itoa(registry.Generation) || value.ScenarioCode != registry.ScenarioCode || value.TickSeconds != oldTickSeconds {
		return errResetExecutionEvidence
	}
	return nil
}

// Static transport inputs of the future fixed executor. These are never read
// from a request/env and are not authority. Its approved recoveryPlan must bind
// the actual old snapshot and these paths/resources before connecting an invoker.
type resetD101RestoredDatabaseInputs struct {
	PostgresContainerID string
	Project             string
	Network             string
	Database            string
	User                string
	LocalPassFile       string
	HostPassFile        string
	PassFileSHA         string
}
type resetD101RestoredDatabaseObservation struct {
	original      []byte
	sha           string
	value         resetD101RestoredDatabaseOriginal
	postgresID    string
	postgresImage string
	jobID         string
	jobImage      string
	started       time.Time
	completed     time.Time
}

// Actual retained psql job and independent Docker/native observations only.
// It never runs pg_restore, writes a receipt or declares recovery successful.
// No production installer/invoker is connected.
func (c config) collectResetD101RestoredDatabase(ctx context.Context, attempt resetD101SucceededRestore, input resetD101RestoredDatabaseInputs) (resetD101RestoredDatabaseObservation, error) {
	closed := resetD101RestoredDatabaseObservation{}
	identifier := regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	resource := regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	if ctx == nil || ctx.Err() != nil || !resetEvidenceSHA.MatchString(input.PostgresContainerID) || !resource.MatchString(input.Project) ||
		!resource.MatchString(input.Network) || !identifier.MatchString(input.Database) || !identifier.MatchString(input.User) ||
		!filepath.IsAbs(input.LocalPassFile) || !filepath.IsAbs(input.HostPassFile) || !resetEvidenceSHA.MatchString(input.PassFileSHA) ||
		strings.ContainsAny(input.HostPassFile, ",\r\n") || c.requireResetD101SucceededRestore(ctx, attempt, true) != nil {
		return closed, errResetExecutionEvidence
	}
	// Docker must bind the host-side path of this exact native original.
	host, err := resetD101SeedHostPath(c, input.LocalPassFile)
	if err != nil || host != input.HostPassFile {
		return closed, errResetExecutionEvidence
	}
	pass, err := d101custody.ReadPrivate(input.LocalPassFile, 16*1024)
	if err != nil || pass.SHA256 != input.PassFileSHA {
		return closed, errResetExecutionEvidence
	}
	defer clear(pass.Bytes)
	started := time.Now()
	bounded, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
	defer cancel()
	command := func(run func(context.Context) (string, error)) (string, error) {
		if c.requireResetD101SucceededRestore(bounded, attempt, true) != nil {
			return "", errResetExecutionEvidence
		}
		out, err := run(bounded)
		if err != nil || bounded.Err() != nil {
			return "", errResetExecutionEvidence
		}
		return out, nil
	}
	var pg resetRuntimeContainer
	if _, err = command(func(ctx context.Context) (string, error) {
		var e error
		pg, e = c.observeResetD101RestoredPostgres(ctx, input.PostgresContainerID, input.Project)
		return "", e
	}); err != nil {
		return closed, errResetExecutionEvidence
	}
	pin := attempt.binding.intent.Intent.OldImageDigests["game-postgres"]
	if _, err = command(func(ctx context.Context) (string, error) {
		return "", c.requireResetD101CapsImage(ctx, pg.ImageID, pin)
	}); err != nil {
		return closed, errResetExecutionEvidence
	}
	var address string
	if _, err = command(func(ctx context.Context) (string, error) {
		var e error
		address, e = c.observeResetD101CapsAddress(ctx, pg.ID, input.Network)
		return "", e
	}); err != nil {
		return closed, errResetExecutionEvidence
	}
	psqlArgs := []string{"-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-h", address, "-p", "5432", "-U", input.User, "-d", input.Database, "-c", resetD101RestoredDatabaseSQL}
	args := []string{"create", "--pull=never", "--name", "d101-restored-db-" + attempt.binding.operation.OperationID, "--network", input.Network, "--user", "0:0",
		"--mount", "type=bind,src=" + input.HostPassFile + ",dst=/run/d101/pgpass,readonly",
		"--mount", "type=tmpfs,destination=/var/lib/postgresql/data,tmpfs-size=1048576,tmpfs-mode=0700",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--env", "PGPASSFILE=/run/d101/pgpass",
		"--entrypoint", "psql", "postgres@" + pin}
	args = append(args, psqlArgs...)
	out, err := command(func(ctx context.Context) (string, error) { return c.runServerDockerContext(ctx, args...) })
	id := strings.TrimSpace(out)
	if err != nil || !resetEvidenceSHA.MatchString(id) {
		return closed, errResetExecutionEvidence
	}
	var job resetD101CapsJob
	if _, err = command(func(ctx context.Context) (string, error) {
		var e error
		job, e = c.observeResetD101CapsJob(ctx, id)
		return "", e
	}); err != nil || job.Running || job.Status != "created" || job.Network != input.Network || !validResetD101CapsMount(job, input.HostPassFile) {
		return closed, errResetExecutionEvidence
	}
	if _, err = command(func(ctx context.Context) (string, error) {
		return "", c.requireResetD101CapsImage(ctx, job.ImageID, pin)
	}); err != nil {
		return closed, errResetExecutionEvidence
	}
	if _, err = command(func(ctx context.Context) (string, error) {
		return "", c.requireResetD101RestoredPSQLCommand(ctx, id, psqlArgs)
	}); err != nil {
		return closed, errResetExecutionEvidence
	}
	wire, err := command(func(ctx context.Context) (string, error) {
		return c.runServerDockerContext(ctx, "start", "--attach", id)
	})
	if err != nil || len(wire) == 0 || len(wire) > 16*1024 {
		return closed, errResetExecutionEvidence
	}
	var finished resetD101CapsJob
	if _, err = command(func(ctx context.Context) (string, error) {
		var e error
		finished, e = c.observeResetD101CapsJob(ctx, id)
		return "", e
	}); err != nil || finished.Running || finished.Status != "exited" || finished.ExitCode != 0 || finished.ImageID != job.ImageID || finished.Network != input.Network || !validResetD101CapsMount(finished, input.HostPassFile) {
		return closed, errResetExecutionEvidence
	}
	if _, err = command(func(ctx context.Context) (string, error) {
		return "", c.requireResetD101RestoredPSQLCommand(ctx, id, psqlArgs)
	}); err != nil {
		return closed, errResetExecutionEvidence
	}
	var after resetRuntimeContainer
	if _, err = command(func(ctx context.Context) (string, error) {
		var e error
		after, e = c.observeResetD101RestoredPostgres(ctx, pg.ID, input.Project)
		return "", e
	}); err != nil || !reflect.DeepEqual(pg, after) {
		return closed, errResetExecutionEvidence
	}
	var addressAfter string
	if _, err = command(func(ctx context.Context) (string, error) {
		var e error
		addressAfter, e = c.observeResetD101CapsAddress(ctx, pg.ID, input.Network)
		return "", e
	}); err != nil || addressAfter != address {
		return closed, errResetExecutionEvidence
	}
	passAfter, err := d101custody.ReadPrivate(input.LocalPassFile, 16*1024)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	defer clear(passAfter.Bytes)
	completed := time.Now()
	value, err := decodeResetD101RestoredDatabase([]byte(wire), input.Database, input.User, address, started, completed)
	if err != nil || passAfter.SHA256 != input.PassFileSHA || c.requireResetD101SucceededRestore(bounded, attempt, true) != nil {
		return closed, errResetExecutionEvidence
	}
	return resetD101RestoredDatabaseObservation{append([]byte(nil), []byte(wire)...), resetD101OriginalSHA([]byte(wire)), value, pg.ID, pg.ImageID, id, job.ImageID, started, completed}, nil
}

// Inspect exact CID/project/service only; new-generation env checks are absent.
func (c config) observeResetD101RestoredPostgres(ctx context.Context, id, project string) (resetRuntimeContainer, error) {
	out, err := c.runServerDockerContext(ctx, "inspect", "--format", `{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"status":{{json .State.Status}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}}}`, id)
	var value struct {
		ID      string `json:"id"`
		Image   string `json:"image"`
		Running bool   `json:"running"`
		Status  string `json:"status"`
		Project string `json:"project"`
		Service string `json:"service"`
	}
	if err != nil || len(out) > 4096 || requireResetIntentShape([]byte(out), reflect.TypeOf(value)) != nil || decodeResetPrivateJSON([]byte(out), &value) != nil ||
		value.ID != id || !resetManifestDigest.MatchString(value.Image) || !value.Running || value.Status != "running" || value.Project != project || value.Service != "game-postgres" {
		return resetRuntimeContainer{}, errResetExecutionEvidence
	}
	return resetRuntimeContainer{ID: id, ImageID: value.Image, Running: &value.Running, Status: value.Status, Project: project, Service: value.Service}, nil
}

func (c config) requireResetD101RestoredPSQLCommand(ctx context.Context, id string, args []string) error {
	out, err := c.runServerDockerContext(ctx, "inspect", "--format", `{"id":{{json .Id}},"path":{{json .Path}},"args":{{json .Args}},"user":{{json .Config.User}}}`, id)
	var value struct {
		ID   string   `json:"id"`
		Path string   `json:"path"`
		Args []string `json:"args"`
		User string   `json:"user"`
	}
	if err != nil || len(out) > 16*1024 || requireResetIntentShape([]byte(out), reflect.TypeOf(value)) != nil || decodeResetPrivateJSON([]byte(out), &value) != nil ||
		value.ID != id || value.Path != "psql" || value.User != "0:0" || !reflect.DeepEqual(value.Args, args) {
		return errResetExecutionEvidence
	}
	return nil
}
