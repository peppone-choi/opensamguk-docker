package main

import (
	"encoding/base64"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// Exact pre-reset canonical values, supplied by the fixed private producer.
// Hash labels or a newly reconstructed registry cannot replace this original.
type resetD101OldCanonicalRegistry struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	GameAPIURL    string `json:"gameApiUrl"`
	GameEngineURL string `json:"gameEngineUrl"`
	DeployProject string `json:"deployProject"`
	Generation    int    `json:"generation"`
	ScenarioCode  string `json:"scenarioCode"`
}
type resetD101RestoredOldWorld struct {
	SchemaVersion           int               `json:"schemaVersion"`
	Kind                    string            `json:"kind"`
	OperationID             string            `json:"operationId"`
	ApprovalIntentSHA       string            `json:"approvalIntentSha256"`
	TargetFingerprint       string            `json:"targetFingerprint"`
	VerifyingRevision       string            `json:"verifyingRevision"`
	RecoveryBeginReceiptSHA string            `json:"recoveryBeginReceiptSha256"`
	WorldID                 int               `json:"worldId"`
	Generation              int               `json:"generation"`
	ScenarioCode            string            `json:"scenarioCode"`
	TickSeconds             int               `json:"tickSeconds"`
	OldImageDigests         map[string]string `json:"oldImageDigests"`
	DatabaseReceiptSHA      string            `json:"databaseReceiptSha256"`
	RuntimeReceiptSHA       string            `json:"runtimeReceiptSha256"`
	ObservedAtUTC           string            `json:"observedAtUtc"`
}

func decodeResetD101RecoverySnapshot(encoded, sha string, target any) error {
	if len(encoded) == 0 || len(encoded) > ((16*1024*4+2)/3) || !resetEvidenceSHA.MatchString(sha) {
		return errResetExecutionEvidence
	}
	wire, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(wire) == 0 || len(wire) > 16*1024 || !utf8.Valid(wire) ||
		base64.RawURLEncoding.EncodeToString(wire) != encoded || resetD101OriginalSHA(wire) != sha ||
		requireResetIntentShape(wire, reflect.TypeOf(target).Elem()) != nil || decodeResetPrivateJSON(wire, target) != nil {
		return errResetExecutionEvidence
	}
	return nil
}
func validateResetD101RecoverySnapshots(result resetD101RecoveryResult, started, completed time.Time) error {
	var registry resetD101OldCanonicalRegistry
	var world resetD101RestoredOldWorld
	if decodeResetD101RecoverySnapshot(result.OldCanonicalRegistryBytesBase64url, result.OldRegistryReceiptSHA, &registry) != nil ||
		decodeResetD101RecoverySnapshot(result.RestoredOldWorldBytesBase64url, result.OldWorldReceiptSHA, &world) != nil ||
		registry.ID != "pep" || strings.TrimSpace(registry.Name) == "" ||
		registry.GameAPIURL != "http://spep-game-api:8081" || registry.GameEngineURL != "http://spep-game-engine:8082" ||
		registry.DeployProject != "opensamguk-spep" || registry.Generation != result.OldGeneration ||
		registry.ScenarioCode != result.OldScenarioCode || world.SchemaVersion != 1 || world.Kind != "D101_RESTORED_OLD_WORLD_V1" ||
		world.OperationID != result.OperationID || world.ApprovalIntentSHA != result.ApprovalIntentSHA ||
		world.TargetFingerprint != result.TargetFingerprint || world.VerifyingRevision != result.VerifyingRevision ||
		world.RecoveryBeginReceiptSHA != result.RecoveryBeginReceiptSHA || world.WorldID != 1 ||
		world.Generation != result.OldGeneration || world.ScenarioCode != result.OldScenarioCode || world.TickSeconds <= 0 ||
		world.TickSeconds > 2147483647 || !reflect.DeepEqual(world.OldImageDigests, result.OldImageDigests) ||
		world.DatabaseReceiptSHA != result.RestoredDatabaseReceiptSHA || world.RuntimeReceiptSHA != result.RestoredRuntimeReceiptSHA {
		return errResetExecutionEvidence
	}
	observed, err := resetD101RecoveryUTC(world.ObservedAtUTC)
	if err != nil || observed.Before(started) || observed.After(completed) {
		return errResetExecutionEvidence
	}
	return nil
}
