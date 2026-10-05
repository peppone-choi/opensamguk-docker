package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func resetDeploymentCardFixture(t *testing.T) (resetDecodedApprovalIntent, []byte) {
	t.Helper()
	wire, sha, _ := resetIntentFixture(t)
	intent, err := decodeResetApprovalIntent(wire, sha)
	if err != nil {
		t.Fatal(err)
	}
	card := resetD101DeploymentCard{SchemaVersion: 1, Kind: "D101_PEP_EXECUTION_CARD", OperationID: intent.Intent.OperationID, ApprovalIntentSHA: intent.SHA,
		AppSourceSHA: intent.Intent.AppSourceSHA, DockerSourceSHA: strings.Repeat("c", 40), OldImageDigests: intent.Intent.OldImageDigests, NewImageDigests: intent.Intent.NewImageDigests,
		ConfigInventorySHA: strings.Repeat("1", 64), CommandPlanSHA: strings.Repeat("2", 64), RecoveryPlanSHA: strings.Repeat("3", 64), ReaderBindingsSHA: strings.Repeat("4", 64), EvidenceCatalogSHA: strings.Repeat("5", 64), ReviewBasisSHA: strings.Repeat("6", 64)}
	cardWire, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	return intent, cardWire
}

func TestResetDeploymentCardKeepsOriginalBytesSeparateFromIntentAndAuthority(t *testing.T) {
	intent, wire := resetDeploymentCardFixture(t)
	original := bytes.Clone(wire)
	card, err := decodeResetD101DeploymentCard(wire, resetD101OriginalSHA(wire), intent)
	if err != nil || card.SHA == intent.SHA || card.Card.ApprovalIntentSHA != intent.SHA {
		t.Fatal("synthetic artifact/intent binding refused")
	}
	wire[0] = 'x'
	copy := card.originalBytes()
	copy[0] = 'x'
	if !bytes.Equal(card.originalBytes(), original) {
		t.Fatal("artifact originals were mutable")
	}
	if _, err := decodeResetApprovalIntent(original, card.SHA); err == nil {
		t.Fatal("deployment card became strict20 approval intent")
	}
	if resetD101DeploymentCardDomain == "OPENSAMGUK-D101-GRANT-V1\n" || resetD101DeploymentCardDomain == "OPENSAMGUK-D101-RESULT-V1\n" || resetD101DeploymentCardDomain == "OPENSAMGUK-D101-PREPARED-V1\n" {
		t.Fatal("card shared a purpose/result/proof domain")
	}
}

func TestResetDeploymentCardRejectsChangedBindingsShapeAndIntermediateCatalog(t *testing.T) {
	intent, wire := resetDeploymentCardFixture(t)
	for _, mode := range []string{"operation", "intent", "app", "docker", "old-pin", "new-pin", "config", "commands", "recovery", "readers", "catalog", "review", "version", "kind", "null", "missing", "duplicate", "alias", "unknown", "trailing", "bad-utf8", "oversized", "intermediate", "intent-wire", "wrong-hash"} {
		t.Run(mode, func(t *testing.T) {
			var tree map[string]any
			_ = json.Unmarshal(wire, &tree)
			switch mode {
			case "operation":
				tree["operationId"] = strings.Repeat("f", 32)
			case "intent":
				tree["approvalIntentSha256"] = strings.Repeat("f", 64)
			case "app":
				tree["appSourceSha"] = strings.Repeat("f", 40)
			case "docker":
				tree["dockerSourceSha"] = "UNKNOWN"
			case "old-pin":
				tree["oldImageDigests"].(map[string]any)["game-api"] = "sha256:" + strings.Repeat("f", 64)
			case "new-pin":
				tree["newImageDigests"].(map[string]any)["game-api"] = "sha256:" + strings.Repeat("f", 64)
			case "config":
				tree["configInventorySha256"] = "UNKNOWN"
			case "commands":
				tree["commandPlanSha256"] = "UNKNOWN"
			case "recovery":
				tree["recoveryPlanSha256"] = "UNKNOWN"
			case "readers":
				tree["readerBindingsSha256"] = "UNKNOWN"
			case "catalog":
				tree["evidenceCatalogSha256"] = "UNKNOWN"
			case "review":
				tree["reviewBasisSha256"] = "UNKNOWN"
			case "version":
				tree["schemaVersion"] = 2
			case "kind":
				tree["kind"] = "INTERMEDIATE_ASSEMBLY_NOT_EXECUTABLE"
			case "null":
				tree["commandPlanSha256"] = nil
			case "missing":
				delete(tree, "commandPlanSha256")
			case "alias":
				delete(tree, "kind")
				tree["Kind"] = "D101_PEP_EXECUTION_CARD"
			case "unknown":
				tree["ready"] = true
			}
			bad, _ := json.Marshal(tree)
			switch mode {
			case "duplicate":
				bad = bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1)
			case "trailing":
				bad = append(bytes.Clone(wire), []byte(` {}`)...)
			case "bad-utf8":
				bad = bytes.Replace(wire, []byte("D101_PEP_EXECUTION_CARD"), []byte{0xff}, 1)
			case "oversized":
				bad = append(bytes.Clone(wire), bytes.Repeat([]byte(" "), 32*1024)...)
			case "intermediate":
				bad = []byte(`{"schemaVersion":1,"ready":false,"status":"INTERMEDIATE_ASSEMBLY_NOT_EXECUTABLE"}`)
			case "intent-wire":
				bad = intent.originalBytes()
			}
			sha := resetD101OriginalSHA(bad)
			if mode == "wrong-hash" {
				sha = strings.Repeat("f", 64)
			}
			if _, err := decodeResetD101DeploymentCard(bad, sha, intent); err == nil {
				t.Fatal("changed or untyped artifact accepted")
			}
		})
	}
}
