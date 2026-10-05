package main

import (
	"context"
	"net"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
)

// Fixed reviewed installation original. PGPASSFILE is mounted read-only; the
// password is never an argv/env value, receipt field or diagnostic output.
type resetD101CandidateCapsPins struct {
	SchemaVersion     int               `json:"schemaVersion"`
	Kind              string            `json:"kind"`
	OperationID       string            `json:"operationId"`
	ApprovalIntentSHA string            `json:"approvalIntentSha256"`
	TargetFingerprint string            `json:"targetFingerprint"`
	AppSourceSHA      string            `json:"appSourceSha"`
	ImagePins         map[string]string `json:"imagePins"`
	DatabaseName      string            `json:"databaseName"`
	DatabaseUser      string            `json:"databaseUser"`
	LocalPassFile     string            `json:"localPassFile"`
	HostPassFile      string            `json:"hostPassFile"`
	PassFileSHA       string            `json:"passFileSha256"`
}
type resetD101CandidateCapsReader struct {
	original []byte
	sha      string
	pins     resetD101CandidateCapsPins
}

// Source construction only. The deployment installer must verify this SHA's
// reference in the actual approved commandPlan before supplying the reader.
func newResetD101CandidateCapsReader(original []byte, expectedSHA string) (*resetD101CandidateCapsReader, error) {
	var p resetD101CandidateCapsPins
	identifier := regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	if len(original) == 0 || len(original) > 16*1024 || !utf8.Valid(original) || !resetEvidenceSHA.MatchString(expectedSHA) ||
		resetD101OriginalSHA(original) != expectedSHA || requireResetIntentShape(original, reflect.TypeOf(p)) != nil ||
		decodeResetPrivateJSON(original, &p) != nil || p.SchemaVersion != 1 || p.Kind != "D101_CANDIDATE_DB_READER_V1" ||
		!lifecycleJobIDRe.MatchString(p.OperationID) || !resetEvidenceSHA.MatchString(p.ApprovalIntentSHA) ||
		!resetEvidenceSHA.MatchString(p.TargetFingerprint) || !gitSHA40.MatchString(p.AppSourceSHA) ||
		!validResetFiveImageDigests(p.ImagePins) || !identifier.MatchString(p.DatabaseName) || !identifier.MatchString(p.DatabaseUser) ||
		!filepath.IsAbs(p.LocalPassFile) || filepath.Clean(p.LocalPassFile) != p.LocalPassFile ||
		!filepath.IsAbs(p.HostPassFile) || filepath.Clean(p.HostPassFile) != p.HostPassFile || strings.ContainsAny(p.HostPassFile, ",\r\n") ||
		!resetEvidenceSHA.MatchString(p.PassFileSHA) {
		return nil, errResetExecutionEvidence
	}
	p.ImagePins = cloneResetD101Strings(p.ImagePins)
	return &resetD101CandidateCapsReader{append([]byte(nil), original...), expectedSHA, p}, nil
}

// The SQL returns only required scalar originals/types, counts and actual DB
// identity. Entire config/meta/credentials are never selected or printed.
const resetD101CandidateCapsSQL = `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='2000ms';
SELECT json_build_object(
 'schemaVersion',1,'kind','D101_CANDIDATE_DB_CAPS_V1',
 'databaseName',current_database(),'databaseUser',current_user,
 'serverAddress',host(inet_server_addr()),'serverPort',inet_server_port(),'transactionReadOnly',current_setting('transaction_read_only'),
 'transactionIsolation',current_setting('transaction_isolation'),
 'worldRowCount',(SELECT count(*) FROM world_state),'worldId',w.id,
 'scenarioCode',w.scenario_code,'tickSeconds',w.tick_seconds,
 'configMaxGeneralType',jsonb_typeof(w.config->'maxgeneral'),
 'configMaxGeneralRaw',left((w.config->'maxgeneral')::text,128),
 'gameEnvRowCount',(SELECT count(*) FROM game_kv WHERE world_id=1 AND "table"='game_env' AND namespace='game_env' AND key='maxgeneral'),
 'gameEnvMaxGeneralType',jsonb_typeof((SELECT value FROM game_kv WHERE world_id=1 AND "table"='game_env' AND namespace='game_env' AND key='maxgeneral' LIMIT 1)),
 'gameEnvMaxGeneralRaw',left((SELECT value::text FROM game_kv WHERE world_id=1 AND "table"='game_env' AND namespace='game_env' AND key='maxgeneral' LIMIT 1),128),
 'observedAtUtc',to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
FROM world_state w WHERE w.id=1;
ROLLBACK;`

type resetD101CandidateCapsObservation struct {
	SchemaVersion         int    `json:"schemaVersion"`
	Kind                  string `json:"kind"`
	DatabaseName          string `json:"databaseName"`
	DatabaseUser          string `json:"databaseUser"`
	ServerAddress         string `json:"serverAddress"`
	ServerPort            int    `json:"serverPort"`
	TransactionReadOnly   string `json:"transactionReadOnly"`
	TransactionIsolation  string `json:"transactionIsolation"`
	WorldRowCount         int    `json:"worldRowCount"`
	WorldID               int    `json:"worldId"`
	ScenarioCode          string `json:"scenarioCode"`
	TickSeconds           int    `json:"tickSeconds"`
	ConfigMaxGeneralType  string `json:"configMaxGeneralType"`
	ConfigMaxGeneralRaw   string `json:"configMaxGeneralRaw"`
	GameEnvRowCount       int    `json:"gameEnvRowCount"`
	GameEnvMaxGeneralType string `json:"gameEnvMaxGeneralType"`
	GameEnvMaxGeneralRaw  string `json:"gameEnvMaxGeneralRaw"`
	ObservedAtUTC         string `json:"observedAtUtc"`
}

func decodeResetD101CandidateCaps(wire []byte, database, user, address string, started, completed time.Time) (resetD101CandidateCapsObservation, error) {
	var value resetD101CandidateCapsObservation
	if len(wire) == 0 || len(wire) > 16*1024 || !utf8.Valid(wire) || requireResetIntentShape(wire, reflect.TypeOf(value)) != nil ||
		decodeResetPrivateJSON(wire, &value) != nil || value.SchemaVersion != 1 || value.Kind != "D101_CANDIDATE_DB_CAPS_V1" ||
		value.DatabaseName != database || value.DatabaseUser != user || value.ServerAddress != address || value.ServerPort != 5432 || value.TransactionReadOnly != "on" || value.TransactionIsolation != "repeatable read" ||
		value.WorldRowCount != 1 || value.WorldID != 1 || value.ScenarioCode != "scenario_3190" || value.TickSeconds != 3600 ||
		value.ConfigMaxGeneralType != "number" || value.ConfigMaxGeneralRaw != "50" || value.GameEnvRowCount != 1 ||
		value.GameEnvMaxGeneralType != "number" || value.GameEnvMaxGeneralRaw != "50" {
		return resetD101CandidateCapsObservation{}, errResetExecutionEvidence
	}
	observed, err := resetD101RecoveryUTC(value.ObservedAtUTC)
	if err != nil || observed.Before(started) || observed.After(completed) || completed.Sub(started) >= resetPreflightMaxAge {
		return resetD101CandidateCapsObservation{}, errResetExecutionEvidence
	}
	return value, nil
}

type resetD101CapsJob struct {
	ID              string               `json:"id"`
	ImageID         string               `json:"imageId"`
	Status          string               `json:"status"`
	Running         bool                 `json:"running"`
	ExitCode        int                  `json:"exitCode"`
	Mounts          []resetD101CapsMount `json:"mounts"`
	ReadOnly        bool
	Privileged      bool
	Network         string
	CapDrop         []string
	SecurityOptions []string
}
type resetD101CapsMount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

const resetD101CapsJobFormat = `{"id":{{json .Id}},"imageId":{{json .Image}},"status":{{json .State.Status}},"running":{{json .State.Running}},"exitCode":{{json .State.ExitCode}},"readOnly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"network":{{json .HostConfig.NetworkMode}},"capDrop":{{json .HostConfig.CapDrop}},"securityOptions":{{json .HostConfig.SecurityOpt}},"mounts":[{{range .Mounts}}{"Type":{{json .Type}},"Source":{{json .Source}},"Destination":{{json .Destination}},"RW":{{json .RW}}},{{end}}null]}`

// Mounts have additional Docker fields; decode their whitelist separately.
func (c config) observeResetD101CapsJob(ctx context.Context, id string) (resetD101CapsJob, error) {
	out, err := c.runServerDockerContext(ctx, "inspect", "--format", resetD101CapsJobFormat, id)
	var envelope struct {
		ID              string   `json:"id"`
		ImageID         string   `json:"imageId"`
		Status          string   `json:"status"`
		Running         bool     `json:"running"`
		ExitCode        int      `json:"exitCode"`
		ReadOnly        *bool    `json:"readOnly"`
		Privileged      *bool    `json:"privileged"`
		Network         string   `json:"network"`
		CapDrop         []string `json:"capDrop"`
		SecurityOptions []string `json:"securityOptions"`
		Mounts          []*struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"mounts"`
	}
	// Docker mount format below selects exact fields; unknown JSON is refused.
	if err != nil || len(out) > 16*1024 || requireResetIntentShape([]byte(out), reflect.TypeOf(envelope)) != nil || decodeResetPrivateJSON([]byte(out), &envelope) != nil || envelope.ID != id || !resetManifestDigest.MatchString(envelope.ImageID) || envelope.ReadOnly == nil || !*envelope.ReadOnly || envelope.Privileged == nil || *envelope.Privileged ||
		envelope.Network != "opensamguk-net" || len(envelope.CapDrop) != 1 || envelope.CapDrop[0] != "ALL" || len(envelope.SecurityOptions) != 1 ||
		(envelope.SecurityOptions[0] != "no-new-privileges" && envelope.SecurityOptions[0] != "no-new-privileges=true") {
		return resetD101CapsJob{}, errResetExecutionEvidence
	}
	job := resetD101CapsJob{ID: envelope.ID, ImageID: envelope.ImageID, Status: envelope.Status, Running: envelope.Running, ExitCode: envelope.ExitCode, ReadOnly: *envelope.ReadOnly, Privileged: *envelope.Privileged, Network: envelope.Network, CapDrop: envelope.CapDrop, SecurityOptions: envelope.SecurityOptions}
	if len(envelope.Mounts) == 0 || envelope.Mounts[len(envelope.Mounts)-1] != nil {
		return resetD101CapsJob{}, errResetExecutionEvidence
	}
	for _, m := range envelope.Mounts[:len(envelope.Mounts)-1] {
		if m == nil {
			return resetD101CapsJob{}, errResetExecutionEvidence
		}
		job.Mounts = append(job.Mounts, resetD101CapsMount{m.Type, m.Source, m.Destination, m.RW})
	}
	return job, nil
}

type resetD101VerifiedCandidateCaps struct {
	original   []byte
	sha        string
	postgresID string
	completed  time.Time
	readerSHA  string
}

func (reader *resetD101CandidateCapsReader) observe(ctx context.Context, c config, a resetD101CandidateAdmission,
	seed resetD101CandidateSeedEvidence, guard func(context.Context) error) (resetD101VerifiedCandidateCaps, error) {
	closed := resetD101VerifiedCandidateCaps{}
	if reader == nil || ctx == nil || ctx.Err() != nil || guard == nil {
		return closed, errResetExecutionEvidence
	}
	p := reader.pins
	if p.OperationID != a.OperationID() || p.ApprovalIntentSHA != a.ApprovalIntentSHA() || p.TargetFingerprint != a.TargetFingerprint() ||
		p.AppSourceSHA != a.AppSourceSHA() || !reflect.DeepEqual(p.ImagePins, a.ImagePins()) || resetD101OriginalSHA(reader.original) != reader.sha ||
		!resetEvidenceSHA.MatchString(seed.PostgresContainerID) || seed.ActualGeneration != "0" ||
		!resetEvidenceSHA.MatchString(seed.GenerationProvenanceSHA) || seed.CompletedAt.Before(seed.StartedAt) ||
		seed.CompletedAt.After(time.Now()) {
		return closed, errResetExecutionEvidence
	}
	pass, err := d101custody.ReadPrivate(p.LocalPassFile, 16*1024)
	if err != nil || pass.SHA256 != p.PassFileSHA {
		return closed, errResetExecutionEvidence
	}
	defer clear(pass.Bytes)
	started := time.Now()
	bounded, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
	defer cancel()
	if guard(bounded) != nil {
		return closed, errResetExecutionEvidence
	}
	before, err := c.observeResetRuntimeContainer(bounded, "game-postgres")
	if err != nil || before.ID != seed.PostgresContainerID || c.requireResetD101CapsImage(bounded, before.ImageID, p.ImagePins["game-postgres"]) != nil {
		return closed, errResetExecutionEvidence
	}
	address, err := c.observeResetD101CapsAddress(bounded, before.ID)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	args := []string{"create", "--name", "d101-caps-" + a.OperationID(), "--network", "opensamguk-net",
		"--mount", "type=bind,src=" + p.HostPassFile + ",dst=/run/d101/pgpass,readonly",
		"--mount", "type=tmpfs,destination=/var/lib/postgresql/data,tmpfs-size=1048576,tmpfs-mode=0700",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--env", "PGPASSFILE=/run/d101/pgpass", "--entrypoint", "psql", "postgres@" + p.ImagePins["game-postgres"],
		"-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-h", address, "-p", "5432", "-U", p.DatabaseUser, "-d", p.DatabaseName, "-c", resetD101CandidateCapsSQL}
	if guard(bounded) != nil {
		return closed, errResetExecutionEvidence
	}
	out, err := c.runServerDockerContext(bounded, args...)
	id := strings.TrimSpace(out)
	if err != nil || !resetEvidenceSHA.MatchString(id) {
		return closed, errResetExecutionEvidence
	}
	// Deterministic job name prevents an uncertain observation from silently
	// starting another job. Retain failed/unknown jobs for exact reconciliation.
	job, err := c.observeResetD101CapsJob(bounded, id)
	if err != nil || job.Running || job.Status != "created" || !validResetD101CapsMount(job, p.HostPassFile) {
		return closed, errResetExecutionEvidence
	}
	if c.requireResetD101CapsImage(bounded, job.ImageID, p.ImagePins["game-postgres"]) != nil {
		return closed, errResetExecutionEvidence
	}
	if guard(bounded) != nil {
		return closed, errResetExecutionEvidence
	}
	wire, err := c.runServerDockerContext(bounded, "start", "--attach", id)
	if err != nil || len(wire) > 16*1024 {
		return closed, errResetExecutionEvidence
	}
	finished, err := c.observeResetD101CapsJob(bounded, id)
	if err != nil || finished.Running || finished.Status != "exited" || finished.ExitCode != 0 || finished.ImageID != job.ImageID || !validResetD101CapsMount(finished, p.HostPassFile) {
		return closed, errResetExecutionEvidence
	}
	after, err := c.observeResetRuntimeContainer(bounded, "game-postgres")
	passAfter, passErr := d101custody.ReadPrivate(p.LocalPassFile, 16*1024)
	if passErr == nil {
		defer clear(passAfter.Bytes)
	}
	addressAfter, addressErr := c.observeResetD101CapsAddress(bounded, before.ID)
	completed := time.Now()
	if err != nil || !reflect.DeepEqual(before, after) || addressErr != nil || addressAfter != address || passErr != nil || passAfter.SHA256 != p.PassFileSHA || bounded.Err() != nil ||
		!completed.Before(a.Cutoff()) {
		return closed, errResetExecutionEvidence
	}
	if _, err := decodeResetD101CandidateCaps([]byte(wire), p.DatabaseName, p.DatabaseUser, address, started, completed); err != nil {
		return closed, err
	}
	return resetD101VerifiedCandidateCaps{append([]byte(nil), []byte(wire)...), resetD101OriginalSHA([]byte(wire)), before.ID, completed, reader.sha}, nil
}
func validResetD101CapsMount(job resetD101CapsJob, hostPath string) bool {
	if len(job.Mounts) != 2 {
		return false
	}
	passCount, temporaryCount := 0, 0
	for _, m := range job.Mounts {
		if m.Type == "bind" && m.Source == hostPath && m.Destination == "/run/d101/pgpass" && !m.RW {
			passCount++
		} else if m.Type == "tmpfs" && m.Source == "" && m.Destination == "/var/lib/postgresql/data" && m.RW {
			temporaryCount++
		} else {
			return false
		}
	}
	return passCount == 1 && temporaryCount == 1
}

func (c config) requireResetD101CapsImage(ctx context.Context, id, pin string) error {
	out, err := c.runServerDockerContext(ctx, "image", "inspect", "--format", `{"repoDigests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}`, id)
	var image resetRuntimeImage
	if err != nil || len(out) > 16*1024 || requireResetIntentShape([]byte(out), reflect.TypeOf(image)) != nil || decodeResetPrivateJSON([]byte(out), &image) != nil || image.OS != "linux" || image.Architecture != "amd64" || !resetRuntimePinMatches(image.RepoDigests, "game-postgres", "", pin) {
		return errResetExecutionEvidence
	}
	return nil
}

// Bind the SQL connection to the inspected candidate CID's actual fixed-network
// address. DNS alias membership alone is not evidence that this CID answered.
func (c config) observeResetD101CapsAddress(ctx context.Context, id string) (string, error) {
	const format = `{"id":{{json .Id}},"address":{{json (index .NetworkSettings.Networks "opensamguk-net").IPAddress}}}`
	out, err := c.runServerDockerContext(ctx, "inspect", "--format", format, id)
	var value struct {
		ID      string `json:"id"`
		Address string `json:"address"`
	}
	if err != nil || len(out) > 1024 || requireResetIntentShape([]byte(out), reflect.TypeOf(value)) != nil || decodeResetPrivateJSON([]byte(out), &value) != nil || value.ID != id || net.ParseIP(value.Address) == nil || net.ParseIP(value.Address).To4() == nil {
		return "", errResetExecutionEvidence
	}
	return value.Address, nil
}
