package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func candidateAdmissionFixture(t *testing.T) (resetDecodedApprovalIntent, resetExecutionEvidence, resetExecutionPhaseBinding, serverTarget) {
	t.Helper()
	wire, _, plan := resetIntentFixture(t)
	var original resetApprovalIntent
	if json.Unmarshal(wire, &original) != nil {
		t.Fatal("synthetic intent")
	}
	plan.Target.Updates["RESET_NPCMODE"] = "0"
	plan.Target.Updates["RESET_SHOW_IMG_LEVEL"] = "3"
	target, _ := json.Marshal(struct {
		ID     string               `json:"id"`
		Target resetLifecycleTarget `json:"target"`
	}{"pep", plan.Target})
	original.RootTargetBytesBase64url = base64.RawURLEncoding.EncodeToString(target)
	original.TargetFingerprint = resetRequestFingerprint("pep", plan.Target)
	plan.TargetFingerprint = original.TargetFingerprint
	wire, _ = json.Marshal(original)
	intent, err := decodeResetApprovalIntent(wire, resetD101OriginalSHA(wire))
	if err != nil {
		t.Fatal(err)
	}
	plan.ApprovalIntentSHA = intent.SHA
	binding := resetExecutionPhaseBinding{OperationID: plan.OperationID, Target: plan.Target, AcceptedAtUnix: plan.WindowOpensAtUnix, Phase: "prepared"}
	return intent, resetExecutionEvidence{Plan: plan}, binding, serverTarget{ID: "pep", Project: "opensamguk-spep", EnvFile: "/fixed/spep.env"}
}
func TestCandidateAdmissionFreezesOriginalScopeAndExplicitImporterInputs(t *testing.T) {
	intent, evidence, binding, server := candidateAdmissionFixture(t)
	a, err := newResetD101CandidateAdmission(intent, evidence, binding, server)
	if err != nil {
		t.Fatal(err)
	}
	if a.OperationID() != intent.Intent.OperationID || a.ApprovalIntentSHA() != intent.SHA || a.Cutoff().Unix() != intent.Intent.DestructiveCutoffUnix {
		t.Fatal("original scope unbound")
	}
	a.ImagePins()["game-api"] = "changed"
	a.Target().Updates["RESET_NPCMODE"] = "2"
	if a.ImagePins()["game-api"] != intent.Intent.NewImageDigests["game-api"] || a.Target().Updates["RESET_NPCMODE"] != "0" {
		t.Fatal("mutable admission")
	}
	intent.Intent.NewImageDigests["game-api"] = "changed"
	if a.ImagePins()["game-api"] == "changed" {
		t.Fatal("input map remained shared")
	}
}
func TestCandidateAdmissionRefusesDifferentOriginalOrUnspecifiedDefaultOptions(t *testing.T) {
	for _, mode := range []string{"missing-npc", "missing-image-level", "changed-plan", "changed-binding", "wrong-project"} {
		intent, evidence, binding, server := candidateAdmissionFixture(t)
		switch mode {
		case "missing-npc", "missing-image-level":
			key := "RESET_NPCMODE"
			if mode == "missing-image-level" {
				key = "RESET_SHOW_IMG_LEVEL"
			}
			// Remove the option from the actual approved target original, then
			// rebuild all scope hashes. Changing a decoded copy is insufficient.
			var original resetApprovalIntent
			if json.Unmarshal(intent.originalBytes(), &original) != nil {
				t.Fatal("synthetic original")
			}
			delete(evidence.Plan.Target.Updates, key)
			target, err := json.Marshal(struct {
				ID     string               `json:"id"`
				Target resetLifecycleTarget `json:"target"`
			}{"pep", evidence.Plan.Target})
			if err != nil {
				t.Fatal(err)
			}
			original.RootTargetBytesBase64url = base64.RawURLEncoding.EncodeToString(target)
			original.TargetFingerprint = resetRequestFingerprint("pep", evidence.Plan.Target)
			wire, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			intent, err = decodeResetApprovalIntent(wire, resetD101OriginalSHA(wire))
			if err != nil {
				t.Fatal(err)
			}
			if _, present := intent.Target.Updates[key]; present {
				t.Fatal("missing option fixture retained approved input")
			}
			evidence.Plan.TargetFingerprint = original.TargetFingerprint
			evidence.Plan.ApprovalIntentSHA = intent.SHA
			binding.Target = intent.Target
		case "changed-plan":
			evidence.Plan.AppSourceSHA = strings.Repeat("f", 40)
		case "changed-binding":
			binding.OperationID = strings.Repeat("f", 32)
		case "wrong-project":
			server.Project = "opensamguk-sother"
		}
		if _, err := newResetD101CandidateAdmission(intent, evidence, binding, server); err == nil {
			t.Fatal("invalid admission " + mode)
		}
	}
}
