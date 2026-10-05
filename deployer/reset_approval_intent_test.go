package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func resetIntentFixture(t *testing.T) ([]byte, string, resetApprovalPlan) {
	t.Helper()
	plan, _, _ := resetEvidenceFixture(t)
	// Root's normalized legacy env leaves the storage image text for plan
	// production; the D101 original carries explicit immutable storage pins.
	plan.Target.Updates["GAME_POSTGRES_IMAGE"] = "postgres:16-alpine@" + plan.Target.StorageImageDigests["game-postgres"]
	plan.Target.Updates["GAME_REDIS_IMAGE"] = "redis:7-alpine@" + plan.Target.StorageImageDigests["game-redis"]
	target, err := json.Marshal(struct {
		ID     string               `json:"id"`
		Target resetLifecycleTarget `json:"target"`
	}{"pep", plan.Target})
	if err != nil {
		t.Fatal(err)
	}
	plan.TargetFingerprint = resetRequestFingerprint("pep", plan.Target)
	intent := resetApprovalIntent{SchemaVersion: 1, ServerID: "pep", WorldID: 1, OperationID: plan.OperationID, ServerName: "빼섭",
		TargetFingerprint: plan.TargetFingerprint, RootTargetBytesBase64url: base64.RawURLEncoding.EncodeToString(target), AppSourceSHA: plan.AppSourceSHA,
		OldImageDigests: plan.OldImageDigests, NewImageDigests: plan.NewImageDigests, InitialPublicRevision: "1",
		WindowOpensAtUnix: plan.WindowOpensAtUnix, DestructiveCutoffUnix: plan.DestructiveCutoffUnix, RecoveryDeadlineUnix: plan.RecoveryDeadlineUnix,
		ApprovalReceiptSHA: plan.ApprovalReceiptSHA, CombinedCIReceiptSHA: plan.CombinedCIReceiptSHA, SelectedSourceReceiptSHA: plan.SelectedSourceReceiptSHA,
		IsolatedSeedTickReceiptSHA: plan.IsolatedSeedTickReceiptSHA, SpaceInventoryReceiptSHA: plan.SpaceInventoryReceiptSHA, SpaceBudget: plan.SpaceBudget}
	wire, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	sha := hex.EncodeToString(sum[:])
	plan.ApprovalIntentSHA = sha
	return wire, sha, plan
}

func TestResetIntentOriginalPlanBindingAndDefensiveBytes(t *testing.T) {
	wire, sha, plan := resetIntentFixture(t)
	decoded, err := decodeResetApprovalIntent(wire, sha)
	if err != nil || requireResetIntentPlan(decoded, plan) != nil {
		t.Fatal("valid original intent refused", err)
	}
	original := bytes.Clone(wire)
	wire[0] = 'x'
	copyOut := decoded.originalBytes()
	copyOut[0] = 'x'
	if !bytes.Equal(decoded.originalBytes(), original) {
		t.Fatal("mutable intent original")
	}
	target := decoded.targetBytes()
	target[0] = 'x'
	if decoded.targetBytes()[0] != '{' {
		t.Fatal("mutable target original")
	}
	changes := map[string]func(*resetApprovalPlan){
		"intent":          func(p *resetApprovalPlan) { p.ApprovalIntentSHA = strings.Repeat("f", 64) },
		"operation":       func(p *resetApprovalPlan) { p.OperationID = strings.Repeat("f", 32) },
		"cutoff":          func(p *resetApprovalPlan) { p.DestructiveCutoffUnix++ },
		"approval":        func(p *resetApprovalPlan) { p.ApprovalReceiptSHA = strings.Repeat("f", 64) },
		"selected-source": func(p *resetApprovalPlan) { p.SelectedSourceReceiptSHA = strings.Repeat("f", 64) },
		"space":           func(p *resetApprovalPlan) { v := uint64(999); p.SpaceBudget.RecoveryBytes = &v },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			bad := plan
			mutate(&bad)
			if requireResetIntentPlan(decoded, bad) == nil {
				t.Fatal("changed plan accepted")
			}
		})
	}
}

func TestResetIntentRejectsRawHashShapeAliasesNullAndTargetChanges(t *testing.T) {
	wire, sha, _ := resetIntentFixture(t)
	if _, err := decodeResetApprovalIntent(wire, strings.Repeat("f", 64)); err == nil {
		t.Fatal("wrong original hash accepted")
	}
	changes := map[string][]byte{
		"case-alias":            bytes.Replace(wire, []byte(`"schemaVersion"`), []byte(`"SchemaVersion"`), 1),
		"duplicate":             bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1),
		"null-revision":         bytes.Replace(wire, []byte(`"initialPublicRevision":"1"`), []byte(`"initialPublicRevision":null`), 1),
		"null-pin":              bytes.Replace(wire, []byte(`"game-api":"sha256:`+strings.Repeat("a", 64)+`"`), []byte(`"game-api":null`), 1),
		"missing-space":         bytes.Replace(wire, []byte(`"CandidateUnpackedBytes":100,`), nil, 1),
		"unknown-root":          bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"unknown":1`), 1),
		"trailing":              append(bytes.Clone(wire), []byte(` {}`)...),
		"revision-leading-zero": bytes.Replace(wire, []byte(`"initialPublicRevision":"1"`), []byte(`"initialPublicRevision":"01"`), 1),
		"future-schema":         bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":2`), 1),
	}
	for name, bad := range changes {
		t.Run(name, func(t *testing.T) {
			sum := sha256.Sum256(bad)
			if _, err := decodeResetApprovalIntent(bad, hex.EncodeToString(sum[:])); err == nil {
				t.Fatal("invalid intent accepted")
			}
		})
	}
	if _, err := decodeResetApprovalIntent(append(bytes.Clone(wire), '\n'), sha); err == nil {
		t.Fatal("rehash of different original accepted")
	}
}
