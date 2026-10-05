package main

import (
	"context"
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

// This checks only the fixed outer evidence fields. It does not parse the seed
// child Original, prove exit code zero, or authorize live stack promotion. The
// child command and its raw output codec are still being fixed with C4/C8.
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
		!resetEvidenceSHA.MatchString(evidence.EffectiveOptionsReceiptSHA) ||
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
