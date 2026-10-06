package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"

	"opensamguk-deployer/internal/d101custody"
)

// Operation-scoped storage persists under its own Compose project and volumes.
// Live apps join this network; promotion never replaces the verified PG/Redis.
type resetD101CandidateResources struct {
	Project              string `json:"project"`
	Network              string `json:"network"`
	PostgresVolume       string `json:"postgresVolume"`
	RedisVolume          string `json:"redisVolume"`
	CandidateComposeFile string `json:"candidateComposeFile"`
	CandidateComposeSHA  string `json:"candidateComposeSha256"`
	LiveComposeFile      string `json:"liveComposeFile"`
	LiveComposeSHA       string `json:"liveComposeSha256"`
	CapsReaderFile       string `json:"capsReaderFile"`
}

func resetD101CandidateResourceNames(op string) resetD101CandidateResources {
	prefix := "d101-candidate-" + op
	return resetD101CandidateResources{Project: prefix, Network: prefix + "-net", PostgresVolume: prefix + "-pgdata", RedisVolume: prefix + "-redisdata"}
}
func (a resetD101CandidateAdmission) CandidateResources() resetD101CandidateResources {
	return a.resources
}
func (a resetD101CandidateAdmission) withCandidateResources(r resetD101CandidateResources) resetD101CandidateAdmission {
	a.resources = r
	return a
}
func validResetD101CandidateResources(r resetD101CandidateResources, op string) bool {
	names := resetD101CandidateResourceNames(op)
	return lifecycleJobIDRe.MatchString(op) && r.Project == names.Project && r.Network == names.Network && r.PostgresVolume == names.PostgresVolume && r.RedisVolume == names.RedisVolume &&
		filepath.IsAbs(r.CandidateComposeFile) && filepath.Clean(r.CandidateComposeFile) == r.CandidateComposeFile && filepath.IsAbs(r.LiveComposeFile) && filepath.Clean(r.LiveComposeFile) == r.LiveComposeFile && r.CandidateComposeFile != r.LiveComposeFile &&
		resetEvidenceSHA.MatchString(r.CandidateComposeSHA) && resetEvidenceSHA.MatchString(r.LiveComposeSHA) && filepath.IsAbs(r.CapsReaderFile) && filepath.Clean(r.CapsReaderFile) == r.CapsReaderFile
}

// Actual fixed source producer for the two reviewed Compose originals. The
// installer compares complete native file bytes to these computed originals.
// This returns source bytes only; it never writes files or starts containers.
func produceResetD101CandidateCompose(op string, images map[string]string) (candidate, live []byte, err error) {
	if !lifecycleJobIDRe.MatchString(op) || !validResetFiveImageDigests(images) {
		return nil, nil, errResetExecutionEvidence
	}
	r := resetD101CandidateResourceNames(op)
	services := map[string]any{
		"game-postgres": map[string]any{"image": "postgres@" + images["game-postgres"], "container_name": "spep-game-postgres", "restart": "no",
			"environment": map[string]string{"POSTGRES_DB": "${GAME_POSTGRES_DB:?required}", "POSTGRES_USER": "${GAME_POSTGRES_USER:?required}", "POSTGRES_PASSWORD": "${GAME_POSTGRES_PASSWORD:?required}"},
			"volumes":     []string{"candidate-pgdata:/var/lib/postgresql/data"}, "networks": []string{"candidate"},
			"healthcheck": map[string]any{"test": []string{"CMD-SHELL", "pg_isready -U ${GAME_POSTGRES_USER:?required}"}, "interval": "2s", "timeout": "2s", "retries": 10}},
		"game-redis": map[string]any{"image": "redis@" + images["game-redis"], "container_name": "spep-game-redis", "restart": "no",
			"command": []string{"redis-server", "--appendonly", "yes", "--maxmemory", "256mb", "--maxmemory-policy", "allkeys-lru"},
			"volumes": []string{"candidate-redisdata:/data"}, "networks": []string{"candidate"},
			"healthcheck": map[string]any{"test": []string{"CMD", "redis-cli", "ping"}, "interval": "2s", "timeout": "2s", "retries": 10}},
	}
	candidate, err = json.Marshal(map[string]any{"name": r.Project, "services": services, "volumes": map[string]any{"candidate-pgdata": map[string]string{"name": r.PostgresVolume, "driver": "local"}, "candidate-redisdata": map[string]string{"name": r.RedisVolume, "driver": "local"}}, "networks": map[string]any{"candidate": map[string]any{"name": r.Network, "internal": true, "driver": "bridge"}}})
	if err != nil {
		return nil, nil, errResetExecutionEvidence
	}
	apps := map[string]any{}
	for _, service := range []string{"game-api", "game-engine", "web-game"} {
		apps[service] = map[string]any{"networks": []string{"opensamguk-net", "d101-candidate"}}
	}
	live, err = json.Marshal(map[string]any{"services": apps, "networks": map[string]any{"d101-candidate": map[string]any{"external": true, "name": r.Network}}})
	if err != nil {
		return nil, nil, errResetExecutionEvidence
	}
	return candidate, live, nil
}
func requireResetD101CandidateCompose(r resetD101CandidateResources, op string, images map[string]string) error {
	if !validResetD101CandidateResources(r, op) {
		return errResetExecutionEvidence
	}
	expectedCandidate, expectedLive, err := produceResetD101CandidateCompose(op, images)
	if err != nil {
		return err
	}
	for _, item := range []struct {
		path, sha string
		expected  []byte
	}{{r.CandidateComposeFile, r.CandidateComposeSHA, expectedCandidate}, {r.LiveComposeFile, r.LiveComposeSHA, expectedLive}} {
		native, err := d101custody.ReadPrivate(item.path, 32*1024)
		if err != nil || native.SHA256 != item.sha || !bytes.Equal(native.Bytes, item.expected) {
			return errResetExecutionEvidence
		}
	}
	return nil
}

// The copy intercepts helpers' single physical command without changing the
// original runner/environment. Its closure calls the original config, avoiding
// recursion and preventing one successful guard from covering later commands.
func (c config) withResetD101CandidateCommandGuard(a resetD101CandidateAdmission, guard func(context.Context) error) config {
	guarded := c
	guarded.dockerRunner = nil
	guarded.dockerRunnerContext = func(ctx context.Context, args ...string) (string, error) {
		return runResetD101CandidateCommand(ctx, a, guard, func(ctx context.Context) (string, error) {
			return c.runServerDockerContext(ctx, args...)
		})
	}
	return guarded
}

func (c config) promoteResetD101CandidateApps(ctx context.Context, a resetD101CandidateAdmission, seed resetD101CandidateSeedEvidence, guard func(context.Context) error) error {
	r := a.CandidateResources()
	if ctx == nil || ctx.Err() != nil || guard == nil || requireResetD101CandidateCompose(r, a.OperationID(), a.ImagePins()) != nil {
		return errResetExecutionEvidence
	}
	guarded := c.withResetD101CandidateCommandGuard(a, guard)
	storage := []struct{ service, id string }{{"game-postgres", seed.PostgresContainerID}, {"game-redis", seed.RedisContainerID}}
	// Verify same independently inspected storage immediately before promotion.
	for _, item := range storage {
		value, err := guarded.observeResetRuntimeContainerProject(ctx, item.service, r.Project)
		if err != nil || value.ID != item.id {
			return errResetExecutionEvidence
		}
	}
	if _, err := c.validateServerTarget(a.Server()); err != nil {
		return errResetExecutionEvidence
	}
	_, err := runResetD101CandidateCommand(ctx, a, guard, func(ctx context.Context) (string, error) {
		// Consume the fixed native originals only after fresh authority.
		if requireResetD101CandidateCompose(r, a.OperationID(), a.ImagePins()) != nil {
			return "", errResetExecutionEvidence
		}
		return c.runServerDockerContext(ctx, "compose", "-p", a.Server().Project, "--env-file", a.Server().EnvFile, "-f", c.composeServer, "-f", r.LiveComposeFile, "up", "-d", "--no-deps", "game-api", "game-engine", "web-game")
	})
	if err != nil {
		return errResetExecutionEvidence
	}
	for _, item := range storage {
		value, err := guarded.observeResetRuntimeContainerProject(ctx, item.service, r.Project)
		if err != nil || value.ID != item.id {
			return errResetExecutionEvidence
		}
	}
	return nil
}

// A retained promotion original, not a caller-supplied project flag, selects the
// storage project accepted by runtime/result proof validation.
func (c config) readResetD101CandidatePromotion(op string, uid uint32) (resetD101CandidatePromotionProof, error) {
	var proof resetD101CandidatePromotionProof
	wire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-candidate-promotion"), op, uid)
	if err != nil || requireResetIntentShape(wire, reflect.TypeOf(proof)) != nil || decodeResetPrivateJSON(wire, &proof) != nil || proof.SchemaVersion != 1 || proof.Kind != "D101_CANDIDATE_PROMOTION_V1" || proof.OperationID != op || !validResetD101CandidateResources(proof.Resources, op) || !gitSHA40.MatchString(proof.AppSourceSHA) {
		return proof, errResetExecutionEvidence
	}
	for _, sha := range []string{proof.ApprovalIntentSHA, proof.TargetFingerprint, proof.CommandPlanSHA, proof.SelectedSourceReceiptSHA, proof.SeedReceiptSHA, proof.WorkerContainerID, proof.PostgresContainerID, proof.RedisContainerID, proof.ActualCapsSHA, proof.CapsReaderSHA} {
		if !resetEvidenceSHA.MatchString(sha) {
			return proof, errResetExecutionEvidence
		}
	}
	seed, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-candidate-seed"), op, uid)
	if err != nil || resetD101OriginalSHA(seed) != proof.SeedReceiptSHA {
		return proof, errResetExecutionEvidence
	}
	caps, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-candidate-caps"), op, uid)
	if err != nil || resetD101OriginalSHA(caps) != proof.ActualCapsSHA {
		return proof, errResetExecutionEvidence
	}
	var seedValue resetD101CandidateSeedReceipt
	if requireResetIntentShape(seed, reflect.TypeOf(seedValue)) != nil || decodeResetPrivateJSON(seed, &seedValue) != nil || seedValue.SchemaVersion != 1 || seedValue.Kind != "D101_SEED_ONLY_RESULT_V1" || seedValue.ApprovalIntentSHA != proof.ApprovalIntentSHA || seedValue.OriginalOp != op || seedValue.AppSourceSHA != proof.AppSourceSHA || seedValue.TargetFingerprint != proof.TargetFingerprint || seedValue.SelectedSourceReceiptSHA != proof.SelectedSourceReceiptSHA || seedValue.ObservedGeneration == nil || *seedValue.ObservedGeneration != 0 || seedValue.ConfigMaxGeneral != 50 || seedValue.GameEnvMaxGeneral != 50 || !validResetFiveImageDigests(seedValue.ImagePins) {
		return proof, errResetExecutionEvidence
	}
	var capsValue resetD101CandidateCapsObservation
	observed, err := resetD101RecoveryUTC(proof.ObservedAtUTC)
	if err != nil || requireResetIntentShape(caps, reflect.TypeOf(capsValue)) != nil || decodeResetPrivateJSON(caps, &capsValue) != nil {
		return proof, errResetExecutionEvidence
	}
	if _, err = decodeResetD101CandidateCaps(caps, capsValue.DatabaseName, capsValue.DatabaseUser, capsValue.ServerAddress, proof.ApprovalIntentSHA, observed.Add(-29*time.Second), observed); err != nil {
		return proof, errResetExecutionEvidence
	}
	return proof, nil
}
