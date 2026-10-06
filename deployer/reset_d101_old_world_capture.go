package main

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
)

// Pre-stop old-world data. CandidateAdmission requires stopped5 and cannot
// be used to capture the running old PG. This SELECT is not a recovery receipt. This SELECT
// deliberately excludes complete config/meta, credentials and account rows.
const resetD101OldWorldSQL = `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='2000ms';
SELECT json_build_object(
 'schemaVersion',1,'kind','D101_OLD_WORLD_DATABASE_OBSERVATION_V1',
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
ROLLBACK;
`

type resetD101OldWorldOriginal struct {
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

func decodeResetD101OldWorld(wire []byte, database, user, address string, started, completed time.Time) (resetD101OldWorldOriginal, error) {
	var value resetD101OldWorldOriginal
	if len(wire) == 0 || len(wire) > 16*1024 || !utf8.Valid(wire) || requireResetIntentShape(wire, reflect.TypeOf(value)) != nil ||
		decodeResetPrivateJSON(wire, &value) != nil || value.SchemaVersion != 1 || value.Kind != "D101_OLD_WORLD_DATABASE_OBSERVATION_V1" ||
		!regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`).MatchString(database) || !regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`).MatchString(user) ||
		net.ParseIP(address) == nil || net.ParseIP(address).To4() == nil || value.DatabaseName != database || value.DatabaseUser != user || value.ServerAddress != address || value.ServerPort != 5432 ||
		value.TransactionReadOnly != "on" || value.TransactionIsolation != "repeatable read" || value.WorldRowCount != 1 || value.WorldID != 1 ||
		!regexp.MustCompile(`^scenario_[0-9]+$`).MatchString(value.ScenarioCode) || value.TickSeconds <= 0 || value.TickSeconds > 2147483647 || value.GenerationType != "number" {
		return resetD101OldWorldOriginal{}, errResetExecutionEvidence
	}
	generation, err := strconv.ParseInt(value.GenerationRaw, 10, 32)
	observed, observedErr := resetD101RecoveryUTC(value.ObservedAtUTC)
	if err != nil || generation < 0 || strconv.FormatInt(generation, 10) != value.GenerationRaw || observedErr != nil ||
		started.IsZero() || completed.IsZero() || completed.Before(started) || completed.Sub(started) >= resetPreflightMaxAge || observed.Before(started) || observed.After(completed) {
		return resetD101OldWorldOriginal{}, errResetExecutionEvidence
	}
	return value, nil
}

// Fixed installed old PG/native custody inputs, never request/env authority.
// C8 retains the actual same-lease pre-stop scope and original before stop;
// no CandidateAdmission/stopped5 or postrestore snapshot supplies these inputs.
type resetD101OldWorldCaptureInputs struct {
	PostgresContainerID string
	Project             string
	Network             string
	Database            string
	User                string
	LocalPassFile       string
	HostPassFile        string
	PassFileSHA         string
}
type resetD101OldWorldObservation struct {
	original      []byte
	sha           string
	value         resetD101OldWorldOriginal
	postgresID    string
	postgresImage string
	jobID         string
	jobImage      string
	started       time.Time
	completed     time.Time
}

// Pre-stop read-only data; no runtime caller/installer is connected. C8 must
// supply its fixed actual same-lease/writerfreeze/phase/cutoff guard and retain
// external scope/custody before storage stop. A callback is not authority.
// Absent C8 source stays disconnected; arbitrary callback/PASS substitution is
// forbidden. Every reused observer below executes one physical Docker command.
// It never runs pg_restore, writes a receipt or declares recovery successful.
// No production installer/invoker is connected.
func (c config) collectResetD101OldWorld(ctx context.Context, intent resetDecodedApprovalIntent, input resetD101OldWorldCaptureInputs, beforeCommand func(context.Context) error) (resetD101OldWorldObservation, error) {
	closed := resetD101OldWorldObservation{}
	identifier := regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	resource := regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	if ctx == nil || ctx.Err() != nil || !resetEvidenceSHA.MatchString(input.PostgresContainerID) || !resource.MatchString(input.Project) ||
		!resource.MatchString(input.Network) || !identifier.MatchString(input.Database) || !identifier.MatchString(input.User) ||
		!filepath.IsAbs(input.LocalPassFile) || !filepath.IsAbs(input.HostPassFile) || !resetEvidenceSHA.MatchString(input.PassFileSHA) ||
		strings.ContainsAny(input.HostPassFile, ",\r\n") || beforeCommand == nil || !validResetD101OldWorldIntent(intent, time.Now()) {
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
	started := time.Now().UTC()
	deadline := started.Add(resetPreflightMaxAge)
	if cutoff := time.Unix(intent.Intent.DestructiveCutoffUnix, 0); cutoff.Before(deadline) {
		deadline = cutoff
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	command := func(run func(context.Context) (string, error)) (string, error) {
		return runResetD101OldWorldCommand(bounded, intent, beforeCommand, run)
	}

	var pg resetRuntimeContainer
	if _, err = command(func(ctx context.Context) (string, error) {
		var e error
		pg, e = c.observeResetD101RestoredPostgres(ctx, input.PostgresContainerID, input.Project)
		return "", e
	}); err != nil {
		return closed, errResetExecutionEvidence
	}
	pin := intent.Intent.OldImageDigests["game-postgres"]
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
	if !resetD101OldWorldPassMatches(pass.Bytes, address, input.Database, input.User) {
		return closed, errResetExecutionEvidence
	}
	psqlArgs := []string{"-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-h", address, "-p", "5432", "-U", input.User, "-d", input.Database, "-c", resetD101OldWorldSQL}
	args := []string{"create", "--pull=never", "--name", "d101-old-world-" + intent.Intent.OperationID, "--network", input.Network, "--user", "0:0",
		"--mount", "type=bind,src=" + input.HostPassFile + ",dst=/run/d101/pgpass,readonly",
		"--mount", "type=tmpfs,destination=/var/lib/postgresql/data,tmpfs-size=1048576,tmpfs-mode=0700",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--env", "PGPASSFILE=/run/d101/pgpass",
		"--entrypoint", "psql", "postgres@" + pin}
	args = append(args, psqlArgs...)
	out, err := command(func(ctx context.Context) (string, error) { return c.runServerDockerContext(ctx, args...) })
	id := strings.TrimSpace(out)
	if err != nil || !resetEvidenceSHA.MatchString(id) || id == pg.ID {
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
	if _, err = command(func(ctx context.Context) (string, error) {
		return "", c.requireResetD101CapsImage(ctx, after.ImageID, pin)
	}); err != nil {
		return closed, errResetExecutionEvidence
	}
	if _, err = command(func(ctx context.Context) (string, error) {
		return "", c.requireResetD101CapsImage(ctx, finished.ImageID, pin)
	}); err != nil {
		return closed, errResetExecutionEvidence
	}
	passAfter, err := d101custody.ReadPrivate(input.LocalPassFile, 16*1024)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	defer clear(passAfter.Bytes)
	completed := time.Now().UTC()
	value, err := decodeResetD101OldWorld([]byte(wire), input.Database, input.User, address, started, completed)
	if err != nil || passAfter.SHA256 != input.PassFileSHA || !bytes.Equal(pass.Bytes, passAfter.Bytes) ||
		!resetD101OldWorldPassMatches(passAfter.Bytes, addressAfter, input.Database, input.User) || bounded.Err() != nil || !validResetD101OldWorldIntent(intent, time.Now()) || beforeCommand(bounded) != nil {
		return closed, errResetExecutionEvidence
	}
	return resetD101OldWorldObservation{append([]byte(nil), []byte(wire)...), resetD101OriginalSHA([]byte(wire)), value, pg.ID, pg.ImageID, id, job.ImageID, started, completed}, nil
}

// Raw original and metadata remain observation data, never PASS or authority.
func (o resetD101OldWorldObservation) originalBytes() []byte { return bytes.Clone(o.original) }

func validResetD101OldWorldIntent(intent resetDecodedApprovalIntent, now time.Time) bool {
	fresh, err := decodeResetApprovalIntent(intent.originalBytes(), intent.SHA)
	return err == nil && reflect.DeepEqual(fresh, intent) && now.Unix() >= fresh.Intent.WindowOpensAtUnix && now.Before(time.Unix(fresh.Intent.DestructiveCutoffUnix, 0))
}

func runResetD101OldWorldCommand(ctx context.Context, intent resetDecodedApprovalIntent,
	beforeCommand func(context.Context) error, command func(context.Context) (string, error)) (string, error) {
	if ctx == nil || ctx.Err() != nil || beforeCommand == nil || command == nil || !validResetD101OldWorldIntent(intent, time.Now()) {
		return "", errResetExecutionEvidence
	}
	if beforeCommand(ctx) != nil || ctx.Err() != nil || !validResetD101OldWorldIntent(intent, time.Now()) {
		return "", errResetExecutionEvidence
	}
	out, err := command(ctx)
	if err != nil || ctx.Err() != nil || !validResetD101OldWorldIntent(intent, time.Now()) {
		return "", errResetExecutionEvidence
	}
	return out, nil
}

// The nullable canonical registry is separately retained by C8, unchanged.
// Actual restored generation/scenario/tick must equal actual pre-stop SQL even
// when canonical generation/scenario were null. No canonical/default fallback.
// C8's mandatory retained preproof verifier must precede this pure comparison.
func requireResetD101RestoredMatchesObservedOld(restored resetD101RestoredDatabaseOriginal, old resetD101OldWorldOriginal) error {
	if old.Kind != "D101_OLD_WORLD_DATABASE_OBSERVATION_V1" || restored.Kind != "D101_RESTORED_DATABASE_OBSERVATION_V1" || old.WorldID != 1 || restored.WorldID != 1 ||
		old.GenerationType != "number" || restored.GenerationType != "number" || old.GenerationRaw != restored.GenerationRaw || old.ScenarioCode != restored.ScenarioCode || old.TickSeconds != restored.TickSeconds {
		return errResetExecutionEvidence
	}
	generation, err := strconv.ParseInt(old.GenerationRaw, 10, 32)
	if err != nil || generation < 0 || strconv.FormatInt(generation, 10) != old.GenerationRaw || !regexp.MustCompile(`^scenario_[0-9]+$`).MatchString(old.ScenarioCode) || old.TickSeconds <= 0 || old.TickSeconds > 2147483647 {
		return errResetExecutionEvidence
	}
	return nil
}

// Never return/log the password. Exactly one endpoint-bound pgpass record;
// password colon/backslash use standard pgpass escaping, never a wildcard host.
func resetD101OldWorldPassMatches(wire []byte, address, database, user string) bool {
	if len(wire) == 0 || len(wire) > 16*1024 || !utf8.Valid(wire) {
		return false
	}
	line := bytes.TrimSuffix(wire, []byte("\n"))
	prefix := []byte(address + ":5432:" + database + ":" + user + ":")
	if !bytes.HasPrefix(line, prefix) || len(line) == len(prefix) || bytes.ContainsAny(line, "\r\n\x00") {
		return false
	}
	escaped := false
	for _, b := range line[len(prefix):] {
		if escaped {
			if b != ':' && b != '\\' {
				return false
			}
			escaped = false
			continue
		}
		if b == '\\' {
			escaped = true
			continue
		}
		if b == ':' {
			return false
		}
	}
	return !escaped
}
