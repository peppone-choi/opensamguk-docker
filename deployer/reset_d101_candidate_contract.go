package main

import (
	"context"
	"reflect"
	"time"
)

// Created only by the owned Root worker after current authority/dispatch and
// immutable plan checks. It is not a request codec or an installation switch.
type resetD101CandidateAdmission struct {
	operationID        string
	intentSHA          string
	targetFingerprint  string
	appSourceSHA       string
	selectedReceiptSHA string
	imagePins          map[string]string
	target             resetLifecycleTarget
	server             serverTarget
	cutoff             time.Time
}

func (a resetD101CandidateAdmission) OperationID() string              { return a.operationID }
func (a resetD101CandidateAdmission) ApprovalIntentSHA() string        { return a.intentSHA }
func (a resetD101CandidateAdmission) TargetFingerprint() string        { return a.targetFingerprint }
func (a resetD101CandidateAdmission) AppSourceSHA() string             { return a.appSourceSHA }
func (a resetD101CandidateAdmission) SelectedSourceReceiptSHA() string { return a.selectedReceiptSHA }
func (a resetD101CandidateAdmission) Server() serverTarget             { return a.server }
func (a resetD101CandidateAdmission) Cutoff() time.Time                { return a.cutoff }
func (a resetD101CandidateAdmission) ImagePins() map[string]string {
	return cloneResetD101Strings(a.imagePins)
}
func (a resetD101CandidateAdmission) Target() resetLifecycleTarget {
	t := a.target
	t.Updates = cloneResetD101Strings(t.Updates)
	t.ImageDigests = cloneResetD101Strings(t.ImageDigests)
	t.StorageImageDigests = cloneResetD101Strings(t.StorageImageDigests)
	return t
}
func cloneResetD101Strings(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
func newResetD101CandidateAdmission(intent resetDecodedApprovalIntent, evidence resetExecutionEvidence,
	binding resetExecutionPhaseBinding, server serverTarget) (resetD101CandidateAdmission, error) {
	fresh, err := decodeResetApprovalIntent(intent.originalBytes(), intent.SHA)
	if err != nil {
		return resetD101CandidateAdmission{}, errResetExecutionEvidence
	}
	intent = fresh
	if requireResetIntentPlan(intent, evidence.Plan) != nil || binding.OperationID != intent.Intent.OperationID ||
		!reflect.DeepEqual(binding.Target, intent.Target) || server.ID != "pep" || server.Project != "opensamguk-spep" ||
		!validResetFiveImageDigests(intent.Intent.NewImageDigests) ||
		!resetEvidenceSHA.MatchString(intent.Intent.SelectedSourceReceiptSHA) {
		return resetD101CandidateAdmission{}, errResetExecutionEvidence
	}
	// An observed importer decision must have an explicit approved input. This
	// admission never fills the PHP/default option value into a final card.
	for key, allowed := range map[string]map[string]bool{
		"RESET_EXTEND": {"0": true, "1": true}, "RESET_NPCMODE": {"0": true, "1": true, "2": true},
		"RESET_SHOW_IMG_LEVEL": {"0": true, "1": true, "2": true, "3": true},
	} {
		if !allowed[intent.Target.Updates[key]] {
			return resetD101CandidateAdmission{}, errResetExecutionEvidence
		}
	}
	a := resetD101CandidateAdmission{intent.Intent.OperationID, intent.SHA, intent.Intent.TargetFingerprint,
		intent.Intent.AppSourceSHA, intent.Intent.SelectedSourceReceiptSHA, cloneResetD101Strings(intent.Intent.NewImageDigests),
		intent.Target, server, time.Unix(intent.Intent.DestructiveCutoffUnix, 0)}
	a.target = a.Target()
	return a, nil
}

// C7/C1 NEW worker implementation owns only PG/Redis startup and seed-only
// retained child. The Root core independently observes DB caps and then promotes.
// beforeCommand is the fixed core's fresh same-lease/freeze/dispatch/cutoff guard.
type resetD101CandidateSeeder func(context.Context, resetD101CandidateAdmission, func(context.Context) error) (resetD101CandidateSeedEvidence, error)
type resetD101CandidateSeedEvidence struct {
	WorkerContainerID          string
	PostgresContainerID        string
	RedisContainerID           string
	WorkerImageID              string
	WorkerRepoDigest           string
	SelectedSourceReceiptSHA   string
	EffectiveOptionsReceiptSHA string
	GenerationProvenanceSHA    string
	ActualGeneration           string
	StartedAt                  time.Time
	CompletedAt                time.Time
	Original                   []byte
}
