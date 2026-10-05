package main

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// The caller supplies exactly one physical Docker command. A command must not
// bundle another Docker operation: each operation needs a fresh core callback.
// Unknown authority and an expired original cutoff execute zero commands.
func runResetD101CandidateCommand(ctx context.Context, admission resetD101CandidateAdmission,
	beforeCommand func(context.Context) error, command func(context.Context) (string, error)) (string, error) {
	if ctx == nil || ctx.Err() != nil || beforeCommand == nil || command == nil ||
		!validResetD101CandidateCommandAdmission(admission, time.Now()) {
		return "", errResetExecutionEvidence
	}
	if err := beforeCommand(ctx); err != nil {
		return "", errResetExecutionEvidence
	}
	if ctx.Err() != nil || !validResetD101CandidateCommandAdmission(admission, time.Now()) {
		return "", errResetExecutionEvidence
	}
	out, err := command(ctx)
	if err != nil || ctx.Err() != nil || !time.Now().Before(admission.Cutoff()) {
		return "", errResetExecutionEvidence
	}
	return out, nil
}

func validResetD101CandidateCommandAdmission(admission resetD101CandidateAdmission, now time.Time) bool {
	target := admission.Target()
	server := admission.Server()
	return lifecycleJobIDRe.MatchString(admission.OperationID()) &&
		resetEvidenceSHA.MatchString(admission.ApprovalIntentSHA()) &&
		resetEvidenceSHA.MatchString(admission.TargetFingerprint()) &&
		resetEvidenceSHA.MatchString(admission.SelectedSourceReceiptSHA()) &&
		gitSHA40.MatchString(admission.AppSourceSHA()) &&
		server.ID == "pep" && server.Project == "opensamguk-spep" &&
		target.ScenarioCode == "scenario_3190" && target.Generation == 0 && target.ScenarioSeedEnabled &&
		resetRequestFingerprint("pep", target) == admission.TargetFingerprint() &&
		validResetFiveImageDigests(admission.ImagePins()) &&
		!admission.Cutoff().IsZero() && now.Before(admission.Cutoff())
}

// This checks only the fixed outer evidence fields. C8 compares the actual CLI
// option/provenance maps with the signed selected original; the unused options
// receipt field is not an authority and may be empty. This does not prove the
// child exit code or authorize live stack promotion.
func requireResetD101CandidateEvidenceEnvelope(admission resetD101CandidateAdmission,
	evidence resetD101CandidateSeedEvidence) error {
	if !validResetD101CandidateCommandAdmission(admission, evidence.StartedAt) ||
		!resetEvidenceSHA.MatchString(evidence.WorkerContainerID) ||
		!resetEvidenceSHA.MatchString(evidence.PostgresContainerID) ||
		!resetEvidenceSHA.MatchString(evidence.RedisContainerID) ||
		evidence.WorkerContainerID == evidence.PostgresContainerID ||
		evidence.WorkerContainerID == evidence.RedisContainerID ||
		evidence.PostgresContainerID == evidence.RedisContainerID ||
		!resetManifestDigest.MatchString(evidence.WorkerImageID) ||
		!resetEvidenceSHA.MatchString(evidence.GenerationProvenanceSHA) ||
		evidence.SelectedSourceReceiptSHA != admission.SelectedSourceReceiptSHA() ||
		evidence.ActualGeneration != "0" ||
		evidence.StartedAt.IsZero() || evidence.CompletedAt.IsZero() ||
		evidence.CompletedAt.Before(evidence.StartedAt) ||
		!evidence.CompletedAt.Before(admission.Cutoff()) ||
		len(evidence.Original) == 0 || len(evidence.Original) > resetEvidenceMaxBytes {
		return errResetExecutionEvidence
	}
	repository, digest, separated := strings.Cut(evidence.WorkerRepoDigest, "@")
	if !separated || !resetRuntimeRepository.MatchString(repository) ||
		digest != admission.ImagePins()["game-engine"] {
		return errResetExecutionEvidence
	}
	return nil
}

// The approved native candidate Compose contains only the two storage
// services. Its operation-scoped project, volumes and private network are
// checked against the immutable command plan before the first Docker command.
func resetD101CandidateStorageUpArgs(admission resetD101CandidateAdmission) []string {
	r := admission.CandidateResources()
	return []string{"compose", "-p", r.Project, "--env-file", admission.Server().EnvFile,
		"-f", r.CandidateComposeFile, "up", "-d", "--wait", "--no-deps", "game-postgres", "game-redis"}
}

func (c config) prepareResetD101CandidateStorage(ctx context.Context, admission resetD101CandidateAdmission,
	beforeCommand func(context.Context) error) (string, string, error) {
	r := admission.CandidateResources()
	if !validResetD101CandidateCommandAdmission(admission, time.Now()) ||
		!validResetD101CandidateResources(r, admission.OperationID()) ||
		requireResetD101CandidateCompose(r, admission.OperationID(), admission.ImagePins()) != nil {
		return "", "", errResetExecutionEvidence
	}
	if _, err := c.validateServerTarget(admission.Server()); err != nil {
		return "", "", errResetExecutionEvidence
	}
	if _, err := runResetD101CandidateCommand(ctx, admission, beforeCommand, func(ctx context.Context) (string, error) {
		// Re-read the fixed native original after fresh authority, immediately
		// before Compose consumes it. The server env still belongs to the core.
		if requireResetD101CandidateCompose(r, admission.OperationID(), admission.ImagePins()) != nil {
			return "", errResetExecutionEvidence
		}
		return c.runServerDockerContext(ctx, resetD101CandidateStorageUpArgs(admission)...)
	}); err != nil {
		return "", "", err
	}
	ids := map[string]string{}
	for _, service := range []string{"game-postgres", "game-redis"} {
		var observed resetRuntimeContainer
		_, err := runResetD101CandidateCommand(ctx, admission, beforeCommand, func(ctx context.Context) (string, error) {
			var err error
			observed, err = c.observeResetRuntimeContainerProject(ctx, service, r.Project)
			return "", err
		})
		if err != nil || !resetEvidenceSHA.MatchString(observed.ID) {
			return "", "", errResetExecutionEvidence
		}
		ids[service] = observed.ID
		var image resetRuntimeImage
		_, err = runResetD101CandidateCommand(ctx, admission, beforeCommand, func(ctx context.Context) (string, error) {
			out, err := c.runServerDockerContext(ctx, "image", "inspect", "--format",
				`{"repoDigests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}`, observed.ImageID)
			if err != nil || len(out) > resetEvidenceMaxBytes || json.Unmarshal([]byte(out), &image) != nil {
				return "", errResetExecutionEvidence
			}
			return "", nil
		})
		if err != nil || image.OS != "linux" || image.Architecture != "amd64" ||
			!resetRuntimePinMatches(image.RepoDigests, service, "", admission.ImagePins()[service]) {
			return "", "", errResetExecutionEvidence
		}
	}
	if ids["game-postgres"] == ids["game-redis"] {
		return "", "", errResetExecutionEvidence
	}
	return ids["game-postgres"], ids["game-redis"], nil
}
