package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// Candidate codec only. No issuer/worker/PUBLIC call site is connected.
// Matching JSON is not proof of execution, trusted producer provenance, image
// execution, or the stable projection algorithm. Those require actual sources.
type resetC4IsolatedProofBinding struct {
	OperationID                   string
	TargetFingerprint             string
	AppSourceSHA                  string
	ReferenceClasspathScenarioSHA string
	SelectedSource                resetC4SelectedSource
	ExpectedActiveRetainerRows    *uint64
}
type resetC4SelectedSource struct {
	Kind           string `json:"kind"`
	ScenarioCode   string `json:"scenarioCode"`
	RawBytesSHA    string `json:"rawBytesSha256"`
	RawByteLength  uint64 `json:"rawByteLength"`
	MapRawBytesSHA string `json:"mapRawBytesSha256"`
	TopologyHash   string `json:"topologyHash"`
}
type resetC4IsolatedProofCandidate struct {
	OperationID                   string                 `json:"operationId"`
	TargetFingerprint             string                 `json:"targetFingerprint"`
	SchemaVersion                 int                    `json:"schemaVersion"`
	EvidenceKind                  string                 `json:"evidenceKind"`
	EvidenceStatus                string                 `json:"evidenceStatus"`
	AppSourceSHA                  *string                `json:"appSourceSha"`
	ReferenceClasspathScenarioSHA string                 `json:"referenceClasspathScenarioSha256"`
	SelectedSource                *resetC4SelectedSource `json:"selectedSource"`
	Runs                          []resetC4IsolatedRun   `json:"runs"`
	MissingReasons                *[]string              `json:"missingReasons"`
}
type resetC4IsolatedRun struct {
	RunID                     string                   `json:"runId"`
	ObservedAtUTC             string                   `json:"observedAtUtc"`
	PostgresContainerID       string                   `json:"postgresContainerId"`
	RedisContainerID          string                   `json:"redisContainerId"`
	WorldID                   int                      `json:"worldId"`
	Generation                string                   `json:"generation"`
	ScenarioCode              string                   `json:"scenarioCode"`
	SelectedSourceRawBytesSHA string                   `json:"selectedSourceRawBytesSha256"`
	Settings                  resetC4IsolatedSettings  `json:"settings"`
	SeedRows                  resetC4IsolatedRows      `json:"seedRows"`
	FirstTick                 resetC4IsolatedFirstTick `json:"firstTick"`
	ColdRestart               resetC4IsolatedRestart   `json:"coldRestart"`
	StableStateSHA            string                   `json:"stableStateSha256"`
}
type resetC4IsolatedSettings struct {
	Year                      int    `json:"year"`
	Month                     int    `json:"month"`
	Phase                     int    `json:"phase"`
	TickSeconds               int    `json:"tickSeconds"`
	MaxGeneralConfig          int    `json:"maxGeneralConfig"`
	MaxGeneralGameEnv         int    `json:"maxGeneralGameEnv"`
	BlockGeneralCreateConfig  int    `json:"blockGeneralCreateConfig"`
	BlockGeneralCreateGameEnv int    `json:"blockGeneralCreateGameEnv"`
	FirstTurn                 string `json:"firstTurn"`
}
type resetC4IsolatedRows struct {
	General         uint64  `json:"general"`
	Nation          uint64  `json:"nation"`
	City            uint64  `json:"city"`
	GeneralPosition uint64  `json:"generalPosition"`
	Retainer        *uint64 `json:"retainer"`
	HumanOwner      *uint64 `json:"humanOwner"`
}
type resetC4IsolatedFirstTick struct {
	BoundaryAtUTC          string `json:"boundaryAtUtc"`
	HandledCount           uint64 `json:"handledCount"`
	FlushedLastTurnTimeUTC string `json:"flushedLastTurnTimeUtc"`
	NextBoundaryAtUTC      string `json:"nextBoundaryAtUtc"`
}
type resetC4IsolatedRestart struct {
	BeforeDaemonNonce          string  `json:"beforeDaemonNonce"`
	AfterDaemonNonce           string  `json:"afterDaemonNonce"`
	ReloadedLastTurnTimeUTC    string  `json:"reloadedLastTurnTimeUtc"`
	SameBoundaryReappliedCount *uint64 `json:"sameBoundaryReappliedCount"`
}

var resetC4CanonicalUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func validResetC4UUID(value string) bool {
	return resetC4CanonicalUUID.MatchString(value) && value != "00000000-0000-0000-0000-000000000000"
}
func resetC4UTC(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, errResetExecutionEvidence
	}
	observed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || observed.Unix() <= 0 {
		return time.Time{}, errResetExecutionEvidence
	}
	return observed, nil
}
func validResetC4SelectedSource(source resetC4SelectedSource) bool {
	return (source.Kind == "CLASSPATH" || source.Kind == "EXTERNAL") && source.ScenarioCode == "scenario_3190" &&
		resetEvidenceSHA.MatchString(source.RawBytesSHA) && source.RawByteLength > 0 &&
		resetEvidenceSHA.MatchString(source.MapRawBytesSHA) && resetEvidenceSHA.MatchString(source.TopologyHash)
}

// Hash the received original bytes before parsing; never reserialize to obtain
// the proof SHA. Current NOT_PRODUCED/null/static inventory samples are refused.
// The expected row count comes from active declarations in selected bytes;
// the 228 total roster declarations are not the stored retainer denominator.
func decodeResetC4IsolatedProofCandidate(wire []byte, expectedSHA string, binding resetC4IsolatedProofBinding, now time.Time) (resetC4IsolatedProofCandidate, error) {
	empty := resetC4IsolatedProofCandidate{}
	sum := sha256.Sum256(wire)
	if len(wire) == 0 || len(wire) > resetEvidenceMaxBytes || !resetEvidenceSHA.MatchString(expectedSHA) ||
		hex.EncodeToString(sum[:]) != expectedSHA || !gitSHA40.MatchString(binding.AppSourceSHA) ||
		!lifecycleJobIDRe.MatchString(binding.OperationID) || !resetEvidenceSHA.MatchString(binding.TargetFingerprint) ||
		!resetEvidenceSHA.MatchString(binding.ReferenceClasspathScenarioSHA) || !validResetC4SelectedSource(binding.SelectedSource) ||
		binding.ExpectedActiveRetainerRows == nil || *binding.ExpectedActiveRetainerRows > 384 {
		return empty, errResetExecutionEvidence
	}
	var candidate resetC4IsolatedProofCandidate
	if requireResetC4CandidateFields(wire, reflect.TypeOf(candidate)) != nil || decodeResetPrivateJSON(wire, &candidate) != nil || candidate.SchemaVersion != 1 ||
		candidate.OperationID != binding.OperationID || candidate.TargetFingerprint != binding.TargetFingerprint ||
		candidate.EvidenceKind != "C4_ISOLATED_3190_SEED_TICK" || candidate.EvidenceStatus != "OBSERVED_ISOLATED" ||
		candidate.AppSourceSHA == nil || *candidate.AppSourceSHA != binding.AppSourceSHA ||
		candidate.ReferenceClasspathScenarioSHA != binding.ReferenceClasspathScenarioSHA ||
		candidate.SelectedSource == nil || !reflect.DeepEqual(*candidate.SelectedSource, binding.SelectedSource) ||
		(binding.SelectedSource.Kind == "CLASSPATH" && binding.SelectedSource.RawBytesSHA != binding.ReferenceClasspathScenarioSHA) ||
		len(candidate.Runs) != 2 || candidate.MissingReasons == nil || len(*candidate.MissingReasons) != 0 {
		return empty, errResetExecutionEvidence
	}
	ids, nonces := map[string]bool{}, map[string]bool{}
	for _, run := range candidate.Runs {
		if !validResetC4UUID(run.RunID) || ids[run.RunID] || !resetEvidenceSHA.MatchString(run.PostgresContainerID) ||
			!resetEvidenceSHA.MatchString(run.RedisContainerID) || ids[run.PostgresContainerID] || ids[run.RedisContainerID] ||
			run.PostgresContainerID == run.RedisContainerID || run.WorldID != 1 || run.Generation != "0" ||
			run.ScenarioCode != "scenario_3190" || run.SelectedSourceRawBytesSHA != binding.SelectedSource.RawBytesSHA ||
			!resetEvidenceSHA.MatchString(run.StableStateSHA) {
			return empty, errResetExecutionEvidence
		}
		ids[run.RunID], ids[run.PostgresContainerID], ids[run.RedisContainerID] = true, true, true
		settings := run.Settings
		if settings.Year != 190 || settings.Month != 1 || settings.Phase != 1 || settings.TickSeconds != 3600 ||
			settings.MaxGeneralConfig != 50 || settings.MaxGeneralGameEnv != 50 ||
			settings.BlockGeneralCreateConfig != 1 || settings.BlockGeneralCreateGameEnv != 1 || settings.FirstTurn != "immediate" {
			return empty, errResetExecutionEvidence
		}
		rows := run.SeedRows
		if rows.General != 384 || rows.Nation != 21 || rows.City != 1428 || rows.GeneralPosition != rows.General ||
			rows.Retainer == nil || *rows.Retainer != *binding.ExpectedActiveRetainerRows ||
			rows.HumanOwner == nil || *rows.HumanOwner != 0 || run.FirstTick.HandledCount == 0 {
			return empty, errResetExecutionEvidence
		}
		restart := run.ColdRestart
		if !validResetC4UUID(restart.BeforeDaemonNonce) || !validResetC4UUID(restart.AfterDaemonNonce) ||
			restart.BeforeDaemonNonce == restart.AfterDaemonNonce || nonces[restart.BeforeDaemonNonce] ||
			nonces[restart.AfterDaemonNonce] || restart.SameBoundaryReappliedCount == nil || *restart.SameBoundaryReappliedCount != 0 {
			return empty, errResetExecutionEvidence
		}
		nonces[restart.BeforeDaemonNonce], nonces[restart.AfterDaemonNonce] = true, true
		observed, err := resetC4UTC(run.ObservedAtUTC)
		boundary, boundaryErr := resetC4UTC(run.FirstTick.BoundaryAtUTC)
		flushed, flushErr := resetC4UTC(run.FirstTick.FlushedLastTurnTimeUTC)
		next, nextErr := resetC4UTC(run.FirstTick.NextBoundaryAtUTC)
		reloaded, reloadErr := resetC4UTC(restart.ReloadedLastTurnTimeUTC)
		if err != nil || boundaryErr != nil || flushErr != nil || nextErr != nil || reloadErr != nil ||
			observed.After(now) || observed.Before(boundary) || !flushed.Equal(boundary) || !reloaded.Equal(boundary) ||
			!next.Equal(boundary.Add(time.Hour)) {
			return empty, errResetExecutionEvidence
		}
	}
	if candidate.Runs[0].StableStateSHA != candidate.Runs[1].StableStateSHA {
		return empty, errResetExecutionEvidence
	}
	return candidate, nil
}

// All candidate fields are required and non-null, including explicit zeros.
// encoding/json's case-insensitive struct matching must not accept key aliases.
func requireResetC4CandidateFields(wire []byte, shape reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(wire), []byte("null")) {
		return errResetExecutionEvidence
	}
	for shape.Kind() == reflect.Pointer {
		shape = shape.Elem()
	}
	switch shape.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(wire, &fields) != nil || len(fields) != shape.NumField() {
			return errResetExecutionEvidence
		}
		for index := 0; index < shape.NumField(); index++ {
			field := shape.Field(index)
			value, ok := fields[field.Tag.Get("json")]
			if !ok || requireResetC4CandidateFields(value, field.Type) != nil {
				return errResetExecutionEvidence
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(wire, &values) != nil {
			return errResetExecutionEvidence
		}
		for _, value := range values {
			if requireResetC4CandidateFields(value, shape.Elem()) != nil {
				return errResetExecutionEvidence
			}
		}
	}
	return nil
}
