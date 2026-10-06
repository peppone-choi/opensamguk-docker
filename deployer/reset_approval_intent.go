package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Immutable approval transport. This decoder does not certify human approval,
// selected-source provenance or clock agreement; custody alone supplies none.
type resetApprovalIntent struct {
	SchemaVersion              int               `json:"schemaVersion"`
	ServerID                   string            `json:"serverId"`
	WorldID                    int               `json:"worldId"`
	OperationID                string            `json:"operationId"`
	ServerName                 string            `json:"serverName"`
	TargetFingerprint          string            `json:"targetFingerprint"`
	RootTargetBytesBase64url   string            `json:"rootTargetBytesBase64url"`
	AppSourceSHA               string            `json:"appSourceSha"`
	OldImageDigests            map[string]string `json:"oldImageDigests"`
	NewImageDigests            map[string]string `json:"newImageDigests"`
	InitialPublicRevision      string            `json:"initialPublicRevision"`
	WindowOpensAtUnix          int64             `json:"windowOpensAtUnix"`
	DestructiveCutoffUnix      int64             `json:"destructiveCutoffUnix"`
	RecoveryDeadlineUnix       int64             `json:"recoveryDeadlineUnix"`
	ApprovalReceiptSHA         string            `json:"approvalReceiptSha256"`
	CombinedCIReceiptSHA       string            `json:"combinedCiReceiptSha256"`
	SelectedSourceReceiptSHA   string            `json:"selectedSourceReceiptSha256"`
	IsolatedSeedTickReceiptSHA string            `json:"isolatedSeedTickReceiptSha256"`
	SpaceInventoryReceiptSHA   string            `json:"spaceInventoryReceiptSha256"`
	SpaceBudget                resetSpaceBudget  `json:"spaceBudget"`
}

type resetDecodedApprovalIntent struct {
	Intent         resetApprovalIntent
	Target         resetLifecycleTarget
	SHA            string
	original       []byte
	targetOriginal []byte
}

func (i resetDecodedApprovalIntent) originalBytes() []byte { return bytes.Clone(i.original) }
func (i resetDecodedApprovalIntent) targetBytes() []byte   { return bytes.Clone(i.targetOriginal) }

// Exact keys, including nested maps, reject Go's case-insensitive field aliases
// and null-to-zero coercion. The raw target is kept independently of JSON decode.
func requireResetIntentShape(wire []byte, shape reflect.Type) error {
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
		for n := 0; n < shape.NumField(); n++ {
			field := shape.Field(n)
			key := strings.Split(field.Tag.Get("json"), ",")[0]
			if key == "" {
				key = field.Name
			}
			value, ok := fields[key]
			if !ok || requireResetIntentShape(value, field.Type) != nil {
				return errResetExecutionEvidence
			}
		}
	case reflect.Map:
		var fields map[string]json.RawMessage
		if json.Unmarshal(wire, &fields) != nil {
			return errResetExecutionEvidence
		}
		for _, value := range fields {
			if requireResetIntentShape(value, shape.Elem()) != nil {
				return errResetExecutionEvidence
			}
		}
	}
	return nil
}

func decodeResetApprovalIntent(wire []byte, expectedSHA string) (resetDecodedApprovalIntent, error) {
	empty := resetDecodedApprovalIntent{}
	sum := sha256.Sum256(wire)
	if len(wire) == 0 || len(wire) > 32*1024 || !utf8.Valid(wire) ||
		!resetEvidenceSHA.MatchString(expectedSHA) || hex.EncodeToString(sum[:]) != expectedSHA ||
		requireResetIntentShape(wire, reflect.TypeOf(resetApprovalIntent{})) != nil {
		return empty, errResetExecutionEvidence
	}
	var intent resetApprovalIntent
	if decodeResetPrivateJSON(wire, &intent) != nil || intent.SchemaVersion != 1 || intent.ServerID != "pep" ||
		intent.WorldID != 1 || intent.ServerName != "빼섭" || !lifecycleJobIDRe.MatchString(intent.OperationID) ||
		!gitSHA40.MatchString(intent.AppSourceSHA) || !resetEvidenceSHA.MatchString(intent.TargetFingerprint) ||
		!validResetFiveImageDigests(intent.OldImageDigests) || !validResetFiveImageDigests(intent.NewImageDigests) ||
		intent.WindowOpensAtUnix <= 0 || intent.WindowOpensAtUnix >= intent.DestructiveCutoffUnix ||
		intent.DestructiveCutoffUnix >= intent.RecoveryDeadlineUnix {
		return empty, errResetExecutionEvidence
	}
	revision, err := strconv.ParseInt(intent.InitialPublicRevision, 10, 64)
	if err != nil || revision <= 0 || strconv.FormatInt(revision, 10) != intent.InitialPublicRevision {
		return empty, errResetExecutionEvidence
	}
	for _, sha := range []string{intent.ApprovalReceiptSHA, intent.CombinedCIReceiptSHA, intent.SelectedSourceReceiptSHA,
		intent.IsolatedSeedTickReceiptSHA, intent.SpaceInventoryReceiptSHA} {
		if !resetEvidenceSHA.MatchString(sha) {
			return empty, errResetExecutionEvidence
		}
	}
	if _, err := resetRequiredSpace(intent.SpaceBudget); err != nil {
		return empty, errResetExecutionEvidence
	}
	rawTarget, err := base64.RawURLEncoding.Strict().DecodeString(intent.RootTargetBytesBase64url)
	if err != nil || len(rawTarget) == 0 || len(rawTarget) > 16*1024 ||
		base64.RawURLEncoding.EncodeToString(rawTarget) != intent.RootTargetBytesBase64url || !utf8.Valid(rawTarget) {
		return empty, errResetExecutionEvidence
	}
	targetSum := sha256.Sum256(rawTarget)
	var wrapper struct {
		ID     string               `json:"id"`
		Target resetLifecycleTarget `json:"target"`
	}
	if hex.EncodeToString(targetSum[:]) != intent.TargetFingerprint || requireResetIntentShape(rawTarget, reflect.TypeOf(wrapper)) != nil ||
		decodeResetPrivateJSON(rawTarget, &wrapper) != nil || wrapper.ID != "pep" {
		return empty, errResetExecutionEvidence
	}
	target := wrapper.Target
	// The existing Root logical target fingerprint is typed JSON. Its bytes
	// must be the approved original representation, so both peers bind one hash.
	if resetRequestFingerprint("pep", target) != intent.TargetFingerprint || target.ScenarioCode != "scenario_3190" ||
		target.Generation != 0 || !target.ScenarioSeedEnabled || len(target.ImageDigests) != 3 || len(target.StorageImageDigests) != 2 {
		return empty, errResetExecutionEvidence
	}
	required := map[string]string{
		"SERVER_NAME": "빼섭", "SERVER_GENERATION": "0", "SCENARIO_CODE": "scenario_3190", "SCENARIO_SEED_ENABLED": "true",
		"RESET_MAXGENERAL": "50", "RESET_FIRST_TURN": "immediate", "SCENARIO_LOOKUP_DIR": "", "RESET_BLOCK_GENERAL_CREATE": "1",
		"RESET_TURNTERM": "60", "RESET_EXTEND": "1", "IMAGE_TAG": intent.AppSourceSHA, "WEB_GAME_TAG": intent.AppSourceSHA,
		"GAME_POSTGRES_IMAGE": "postgres:16-alpine@" + target.StorageImageDigests["game-postgres"],
		"GAME_REDIS_IMAGE":    "redis:7-alpine@" + target.StorageImageDigests["game-redis"],
	}
	optional := map[string]bool{"RESET_SYNC": true, "RESET_FICTION": true, "RESET_NPCMODE": true, "RESET_SHOW_IMG_LEVEL": true,
		"RESET_AUTORUN_USER_OPTIONS": true, "RESET_AUTORUN_USER_MINUTES": true, "RESET_JOIN_MODE": true, "RESET_TOURNAMENT_TRIG": true,
		"RESET_RESERVE_OPEN": true, "RESET_PRE_RESERVE_OPEN": true}
	for key, want := range required {
		if actual, ok := target.Updates[key]; !ok || actual != want {
			return empty, errResetExecutionEvidence
		}
	}
	for key, value := range target.Updates {
		if _, fixed := required[key]; !fixed && !optional[key] {
			return empty, errResetExecutionEvidence
		}
		if strings.TrimSpace(value) != value || (value == "" && key != "SCENARIO_LOOKUP_DIR") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return empty, errResetExecutionEvidence
		}
	}
	for _, service := range resetImageServices {
		if target.ImageDigests[service] != intent.NewImageDigests[service] {
			return empty, errResetExecutionEvidence
		}
	}
	for _, service := range resetStorageServices {
		if target.StorageImageDigests[service] != intent.NewImageDigests[service] {
			return empty, errResetExecutionEvidence
		}
	}
	return resetDecodedApprovalIntent{intent, target, expectedSHA, bytes.Clone(wire), bytes.Clone(rawTarget)}, nil
}

func requireResetIntentPlan(intent resetDecodedApprovalIntent, plan resetApprovalPlan) error {
	fresh, err := decodeResetApprovalIntent(intent.originalBytes(), intent.SHA)
	if err != nil {
		return errResetExecutionEvidence
	}
	i := fresh.Intent
	if plan.ApprovalIntentSHA != intent.SHA || plan.Version != 1 || plan.ServerID != i.ServerID || plan.WorldID != i.WorldID ||
		plan.OperationID != i.OperationID || plan.TargetFingerprint != i.TargetFingerprint || plan.AppSourceSHA != i.AppSourceSHA ||
		!reflect.DeepEqual(plan.Target, fresh.Target) || !reflect.DeepEqual(plan.OldImageDigests, i.OldImageDigests) ||
		!reflect.DeepEqual(plan.NewImageDigests, i.NewImageDigests) || !reflect.DeepEqual(plan.SpaceBudget, i.SpaceBudget) ||
		plan.WindowOpensAtUnix != i.WindowOpensAtUnix || plan.DestructiveCutoffUnix != i.DestructiveCutoffUnix ||
		plan.RecoveryDeadlineUnix != i.RecoveryDeadlineUnix || plan.ApprovalReceiptSHA != i.ApprovalReceiptSHA ||
		plan.CombinedCIReceiptSHA != i.CombinedCIReceiptSHA || plan.SelectedSourceReceiptSHA != i.SelectedSourceReceiptSHA ||
		plan.IsolatedSeedTickReceiptSHA != i.IsolatedSeedTickReceiptSHA || plan.SpaceInventoryReceiptSHA != i.SpaceInventoryReceiptSHA {
		return errResetExecutionEvidence
	}
	return nil
}
