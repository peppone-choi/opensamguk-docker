package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"unicode/utf8"
)

// This pre-PREPARE original fixes the recovery method. It contains no evidence
// that PREPARE, a backup, or a physical restore has happened. Actual originals
// and their SHA values belong to later immutable receipts.
type resetD101RecoveryPlan struct {
	SchemaVersion         int                      `json:"schemaVersion"`
	Kind                  string                   `json:"kind"`
	ServerID              string                   `json:"serverId"`
	WorldID               int                      `json:"worldId"`
	OperationID           string                   `json:"operationId"`
	ApprovalIntentSHA     string                   `json:"approvalIntentSha256"`
	TargetFingerprint     string                   `json:"targetFingerprint"`
	AppSourceSHA          string                   `json:"appSourceSha"`
	DockerSourceSHA       string                   `json:"dockerSourceSha"`
	OldImageDigests       map[string]string        `json:"oldImageDigests"`
	CommandPlanSHA        string                   `json:"commandPlanSha256"`
	InitialPublicRevision string                   `json:"initialPublicRevision"`
	DestructiveCutoff     int64                    `json:"destructiveCutoffUnix"`
	RecoveryDeadline      int64                    `json:"recoveryDeadlineUnix"`
	SourceStages          []string                 `json:"sourceStages"`
	Backup                resetD101RecoveryBackup  `json:"backup"`
	Restore               resetD101RecoveryRestore `json:"restore"`
	Closure               resetD101RecoveryClosure `json:"closure"`
}

type resetD101RecoveryBackup struct {
	RelativeDirectory    string   `json:"relativeDirectory"`
	RequiredLeaves       []string `json:"requiredLeaves"`
	OptionalLeaf         string   `json:"optionalLeaf"`
	ManifestLeaf         string   `json:"manifestLeaf"`
	MinimumRetainSeconds int64    `json:"minimumRetainSeconds"`
}

type resetD101RecoveryRestore struct {
	ClaimDirectoryRole string `json:"claimDirectoryRole"`
	GateSuffix         string `json:"gateSuffix"`
	MaxAttempts        int    `json:"maxAttempts"`
	RequiredBeginKind  string `json:"requiredBeginKind"`
}

type resetD101RecoveryClosure struct {
	PublicationAtClose         string `json:"publicationAtClose"`
	PreserveOriginalRootResult bool   `json:"preserveOriginalRootResult"`
	SameOperationOnly          bool   `json:"sameOperationOnly"`
	PublicReleaseSeparate      bool   `json:"publicReleaseSeparate"`
}

type resetDecodedD101RecoveryPlan struct {
	Plan     resetD101RecoveryPlan
	SHA      string
	original []byte
}

func (p resetDecodedD101RecoveryPlan) originalBytes() []byte { return bytes.Clone(p.original) }

const resetD101RecoveryPlanKind = "D101_SAME_OP_RECOVERY_PLAN_V1"

var resetD101RecoverySourceStages = []string{
	"gateway-pre-reset-same-tx",
	"query-captured-original",
	"freeze-old-world-runtime-selected",
	"verify-retained-backup",
	"query-committed-recovery-begin",
	"claim-single-old-restore",
	"verify-restored-world-runtime-metadata",
	"close-same-op-verifying",
}

const resetD101RecoveryClaimDirectoryRole = "serversDir/.deployer-reset-restore1-claims"

// A plan may bind the already produced command original. That command and the
// approval intent have no recovery-plan/card reference, so this creates no
// reverse SHA dependency. Physical native file checks remain separate.
func requireResetD101RecoveryCommand(command []byte, intent resetDecodedApprovalIntent) (resetD101CandidateCommandPlan, error) {
	var plan resetD101CandidateCommandPlan
	if len(command) == 0 || len(command) > 32*1024 || !utf8.Valid(command) ||
		requireResetIntentShape(command, reflect.TypeOf(plan)) != nil || decodeResetPrivateJSON(command, &plan) != nil ||
		plan.SchemaVersion != 1 || plan.Kind != "D101_ROOT_CANDIDATE_COMMAND_PLAN_V1" ||
		plan.OperationID != intent.Intent.OperationID || plan.ApprovalIntentSHA != intent.SHA ||
		plan.TargetFingerprint != intent.Intent.TargetFingerprint || plan.AppSourceSHA != intent.Intent.AppSourceSHA ||
		!gitSHA40.MatchString(plan.DockerSourceSHA) || !reflect.DeepEqual(plan.NewImageDigests, intent.Intent.NewImageDigests) ||
		plan.SelectedSourceReceiptSHA != intent.Intent.SelectedSourceReceiptSHA ||
		!resetEvidenceSHA.MatchString(plan.SelectedEnvelopeSHA) || !resetEvidenceSHA.MatchString(plan.CapsReaderSHA) ||
		plan.SeedEntrypoint != resetD101CandidateSeedEntrypoint || !reflect.DeepEqual(plan.Stages, resetD101CandidateStages) ||
		plan.DestructiveCutoffUnix != intent.Intent.DestructiveCutoffUnix ||
		!validResetD101CandidateResources(plan.Resources, intent.Intent.OperationID) {
		return resetD101CandidateCommandPlan{}, errResetExecutionEvidence
	}
	return plan, nil
}

// Pure original producer: no file reads/writes, DB operations, backup issuance,
// approval, or restore. Its returned SHA covers the exact emitted bytes.
func produceResetD101RecoveryPlan(intent resetDecodedApprovalIntent, command []byte) ([]byte, string, error) {
	fresh, err := decodeResetApprovalIntent(intent.originalBytes(), intent.SHA)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	commandPlan, err := requireResetD101RecoveryCommand(command, fresh)
	if err != nil {
		return nil, "", err
	}
	plan := resetD101RecoveryPlan{
		SchemaVersion: 1, Kind: resetD101RecoveryPlanKind, ServerID: "pep", WorldID: 1,
		OperationID: fresh.Intent.OperationID, ApprovalIntentSHA: fresh.SHA,
		TargetFingerprint: fresh.Intent.TargetFingerprint,
		AppSourceSHA:      fresh.Intent.AppSourceSHA, DockerSourceSHA: commandPlan.DockerSourceSHA,
		OldImageDigests:       cloneResetD101Strings(fresh.Intent.OldImageDigests),
		CommandPlanSHA:        resetD101OriginalSHA(command),
		InitialPublicRevision: fresh.Intent.InitialPublicRevision,
		DestructiveCutoff:     fresh.Intent.DestructiveCutoffUnix,
		RecoveryDeadline:      fresh.Intent.RecoveryDeadlineUnix,
		SourceStages:          append([]string(nil), resetD101RecoverySourceStages...),
		Backup: resetD101RecoveryBackup{RelativeDirectory: "backups/pep/<operationId>",
			RequiredLeaves: append([]string(nil), resetRecoveryBackupLeaves...),
			OptionalLeaf:   "old-external-scenario.json", ManifestLeaf: "checksums.sha256", MinimumRetainSeconds: 7 * 24 * 60 * 60},
		Restore: resetD101RecoveryRestore{ClaimDirectoryRole: resetD101RecoveryClaimDirectoryRole,
			GateSuffix: ".d101-restore1", MaxAttempts: 1, RequiredBeginKind: "D101_RECOVERY_BEGIN_V1"},
		Closure: resetD101RecoveryClosure{PublicationAtClose: "VERIFYING", PreserveOriginalRootResult: true,
			SameOperationOnly: true, PublicReleaseSeparate: true},
	}
	wire, err := json.Marshal(plan)
	if err != nil || len(wire) > 32*1024 {
		return nil, "", errResetExecutionEvidence
	}
	sha := resetD101OriginalSHA(wire)
	if _, err = decodeResetD101RecoveryPlan(wire, sha, fresh, command); err != nil {
		return nil, "", err
	}
	return wire, sha, nil
}

// Only the fixed host producer may supply the actual originals to this pure
// decoder. A valid plan shape is not a purpose grant or a recovery receipt.
func decodeResetD101RecoveryPlan(wire []byte, expectedSHA string, intent resetDecodedApprovalIntent, command []byte) (resetDecodedD101RecoveryPlan, error) {
	closed := resetDecodedD101RecoveryPlan{}
	fresh, err := decodeResetApprovalIntent(intent.originalBytes(), intent.SHA)
	if err != nil || len(wire) == 0 || len(wire) > 32*1024 || !utf8.Valid(wire) ||
		!resetEvidenceSHA.MatchString(expectedSHA) || resetD101OriginalSHA(wire) != expectedSHA ||
		requireResetIntentShape(wire, reflect.TypeOf(resetD101RecoveryPlan{})) != nil {
		return closed, errResetExecutionEvidence
	}
	commandPlan, err := requireResetD101RecoveryCommand(command, fresh)
	if err != nil {
		return closed, err
	}
	var plan resetD101RecoveryPlan
	if decodeResetPrivateJSON(wire, &plan) != nil || plan.SchemaVersion != 1 || plan.Kind != resetD101RecoveryPlanKind ||
		plan.ServerID != "pep" || plan.WorldID != 1 || plan.OperationID != fresh.Intent.OperationID ||
		plan.ApprovalIntentSHA != fresh.SHA || plan.TargetFingerprint != fresh.Intent.TargetFingerprint ||
		plan.AppSourceSHA != fresh.Intent.AppSourceSHA || plan.DockerSourceSHA != commandPlan.DockerSourceSHA ||
		!validResetFiveImageDigests(plan.OldImageDigests) || !reflect.DeepEqual(plan.OldImageDigests, fresh.Intent.OldImageDigests) ||
		plan.CommandPlanSHA != resetD101OriginalSHA(command) || plan.InitialPublicRevision != fresh.Intent.InitialPublicRevision ||
		plan.DestructiveCutoff != fresh.Intent.DestructiveCutoffUnix || plan.RecoveryDeadline != fresh.Intent.RecoveryDeadlineUnix ||
		!reflect.DeepEqual(plan.SourceStages, resetD101RecoverySourceStages) ||
		plan.Backup.RelativeDirectory != "backups/pep/<operationId>" || !reflect.DeepEqual(plan.Backup.RequiredLeaves, resetRecoveryBackupLeaves) ||
		plan.Backup.OptionalLeaf != "old-external-scenario.json" || plan.Backup.ManifestLeaf != "checksums.sha256" || plan.Backup.MinimumRetainSeconds != 7*24*60*60 ||
		plan.Restore.ClaimDirectoryRole != resetD101RecoveryClaimDirectoryRole || plan.Restore.GateSuffix != ".d101-restore1" ||
		plan.Restore.MaxAttempts != 1 || plan.Restore.RequiredBeginKind != "D101_RECOVERY_BEGIN_V1" ||
		plan.Closure.PublicationAtClose != "VERIFYING" || !plan.Closure.PreserveOriginalRootResult || !plan.Closure.SameOperationOnly || !plan.Closure.PublicReleaseSeparate {
		return closed, errResetExecutionEvidence
	}
	plan.OldImageDigests = cloneResetD101Strings(plan.OldImageDigests)
	plan.SourceStages = append([]string(nil), plan.SourceStages...)
	plan.Backup.RequiredLeaves = append([]string(nil), plan.Backup.RequiredLeaves...)
	return resetDecodedD101RecoveryPlan{Plan: plan, SHA: expectedSHA, original: bytes.Clone(wire)}, nil
}

// The card is created only after this original. Compare its references without
// putting the card SHA back into the plan or the preceding command original.
func requireResetD101RecoveryPlanCard(wire []byte, card resetDecodedDeploymentCard, intent resetDecodedApprovalIntent, command []byte) (resetDecodedD101RecoveryPlan, error) {
	closed := resetDecodedD101RecoveryPlan{}
	freshCard, err := decodeResetD101DeploymentCard(card.originalBytes(), card.SHA, intent)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	plan, err := decodeResetD101RecoveryPlan(wire, freshCard.Card.RecoveryPlanSHA, intent, command)
	if err != nil || plan.Plan.CommandPlanSHA != freshCard.Card.CommandPlanSHA ||
		plan.Plan.AppSourceSHA != freshCard.Card.AppSourceSHA || plan.Plan.DockerSourceSHA != freshCard.Card.DockerSourceSHA ||
		!reflect.DeepEqual(plan.Plan.OldImageDigests, freshCard.Card.OldImageDigests) {
		return closed, errResetExecutionEvidence
	}
	return plan, nil
}
