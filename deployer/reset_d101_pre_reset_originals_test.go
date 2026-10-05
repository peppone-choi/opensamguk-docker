package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetD101PreResetFixture(t *testing.T, execution resetD101GatewayExecution) []byte {
	t.Helper()
	registry := json.RawMessage(`{ "id":"pep", "name":"old-name", "gameApiUrl":"http://spep-game-api:8081", "gameEngineUrl":"http://spep-game-engine:8082", "deployProject":"opensamguk-spep", "generation":null, "scenarioCode":null }`)
	publication := json.RawMessage(`{ "state":"PUBLIC", "revision":"1", "operationId":null, "expectedGeneration":null, "expectedScenarioCode":null, "targetFingerprint":null }`)
	value := resetD101PreResetOriginal{1, "D101_PRE_RESET_ORIGINALS_V1", execution.OperationID, execution.ApprovalIntentSHA, execution.TargetFingerprint, execution.GatewayPayloadSHA, execution.InitialPublicRevision, registry, publication}
	wire, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestPreResetOriginalPreservesNullableIdentityAndNestedRawBytes(t *testing.T) {
	wire, _, _, _, _ := resetD101GatewayDispatchFixture(t)
	base, capture, err := decodeResetD101GatewayQueryCapture(wire, false)
	if err != nil || capture.registry.Generation != nil || capture.registry.ScenarioCode != nil || capture.publication.OperationID != nil {
		t.Fatal("null identity replaced", err)
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(capture.Original(), &raw) != nil || !bytes.Equal(capture.RegistryOriginal(), raw["oldRegistry"]) || !bytes.Equal(capture.PublicationOriginal(), raw["oldPublication"]) {
		t.Fatal("nested originals reconstructed")
	}
	copy := capture.RegistryOriginal()
	copy[0] = 'X'
	if !bytes.Equal(capture.RegistryOriginal(), raw["oldRegistry"]) {
		t.Fatal("mutable registry original")
	}
	var execution resetD101GatewayExecution
	if decodeResetPrivateJSON(base, &execution) != nil || execution.InitialPublicRevision != capture.value.InitialPublicRevision {
		t.Fatal("execution binding")
	}
	if _, err := decodeResetD101GatewayExecution(wire); err == nil {
		t.Fatal("query fields admitted as mutation15")
	}
	if _, _, err := decodeResetD101GatewayQueryCapture(base, false); err == nil {
		t.Fatal("legacy operation invented capture")
	}
}

func TestPreResetOriginalRejectsMalformedOrPostPrepareCapture(t *testing.T) {
	wire, _, _, _, _ := resetD101GatewayDispatchFixture(t)
	_, valid, err := decodeResetD101GatewayQueryCapture(wire, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"version-null", "unknown", "duplicate", "op", "sha", "revision-number", "revision-leading-zero", "publication-state", "publication-revision", "partial-target", "generation-negative", "generation-decimal", "scenario-blank", "registry-missing", "invalid-utf8"} {
		t.Run(mode, func(t *testing.T) {
			var root map[string]any
			if json.Unmarshal(valid.Original(), &root) != nil {
				t.Fatal("fixture")
			}
			registry := root["oldRegistry"].(map[string]any)
			pub := root["oldPublication"].(map[string]any)
			switch mode {
			case "version-null":
				root["schemaVersion"] = nil
			case "unknown":
				root["extra"] = true
			case "op":
				root["operationId"] = "bad"
			case "sha":
				root["approvalIntentSha256"] = "bad"
			case "revision-number":
				root["initialPublicRevision"] = 1
			case "revision-leading-zero":
				root["initialPublicRevision"] = "01"
			case "publication-state":
				pub["state"] = "VERIFYING"
			case "publication-revision":
				pub["revision"] = "2"
			case "partial-target":
				pub["operationId"] = strings.Repeat("f", 32)
			case "generation-negative":
				registry["generation"] = -1
			case "generation-decimal":
				registry["generation"] = 1.5
			case "scenario-blank":
				registry["scenarioCode"] = " "
			case "registry-missing":
				delete(registry, "generation")
			}
			changed, _ := json.Marshal(root)
			if mode == "duplicate" {
				changed = []byte(strings.Replace(string(changed), `"generation":null`, `"generation":null,"generation":null`, 1))
			}
			if mode == "invalid-utf8" {
				changed = bytes.Replace(changed, []byte("old-name"), []byte{255}, 1)
			}
			if _, err := decodeResetD101PreResetOriginal(changed, resetD101OriginalSHA(changed)); err == nil {
				t.Fatal("invalid capture accepted")
			}
		})
	}
}

func TestPreResetQueryRequiresExactCaptureBindingAndCanonicalEncoding(t *testing.T) {
	wire, _, _, _, _ := resetD101GatewayDispatchFixture(t)
	for _, mode := range []string{"missing", "hash-only", "padded", "wrong-sha", "extra", "intent", "target", "payload", "op", "revision"} {
		t.Run(mode, func(t *testing.T) {
			var fields map[string]any
			if json.Unmarshal(wire, &fields) != nil {
				t.Fatal("fixture")
			}
			switch mode {
			case "missing":
				delete(fields, "preResetOriginalsSha256")
				delete(fields, "preResetOriginalsBytesBase64url")
			case "hash-only":
				delete(fields, "preResetOriginalsBytesBase64url")
			case "padded":
				fields["preResetOriginalsBytesBase64url"] = fields["preResetOriginalsBytesBase64url"].(string) + "="
			case "wrong-sha":
				fields["preResetOriginalsSha256"] = strings.Repeat("f", 64)
			case "extra":
				fields["extra"] = true
			default:
				original, _ := base64.RawURLEncoding.DecodeString(fields["preResetOriginalsBytesBase64url"].(string))
				var capture map[string]any
				if json.Unmarshal(original, &capture) != nil {
					t.Fatal("fixture capture")
				}
				switch mode {
				case "intent":
					capture["approvalIntentSha256"] = strings.Repeat("f", 64)
				case "target":
					capture["targetFingerprint"] = strings.Repeat("f", 64)
				case "payload":
					capture["gatewayPayloadSha256"] = strings.Repeat("f", 64)
				case "op":
					capture["operationId"] = strings.Repeat("f", 32)
				case "revision":
					capture["initialPublicRevision"] = "3"
					capture["oldPublication"].(map[string]any)["revision"] = "3"
				}
				original, _ = json.Marshal(capture)
				fields["preResetOriginalsSha256"] = resetD101OriginalSHA(original)
				fields["preResetOriginalsBytesBase64url"] = base64.RawURLEncoding.EncodeToString(original)
			}
			changed, _ := json.Marshal(fields)
			if _, _, err := decodeResetD101GatewayQueryCapture(changed, false); err == nil {
				t.Fatal("changed capture accepted")
			}
		})
	}
}

func TestPreResetCaptureNativeCustodyKeepsExactReplayAndRejectsReplacement(t *testing.T) {
	wire, _, _, _, _ := resetD101GatewayDispatchFixture(t)
	_, capture, err := decodeResetD101GatewayQueryCapture(wire, false)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := config{serversDir: root}
	uid := uint32(os.Getuid())
	if c.retainResetD101PreResetCaptureWithCustodyUID(capture, uid) == nil {
		t.Fatal("missing installed directory admitted")
	}
	dir := filepath.Join(root, ".deployer-reset-pre-reset-originals")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("fixture directory")
	}
	if c.retainResetD101PreResetCaptureWithCustodyUID(capture, uid) != nil {
		t.Fatal("initial capture refused")
	}
	before, err := os.Stat(filepath.Join(dir, capture.value.OperationID+".json"))
	if err != nil || c.retainResetD101PreResetCaptureWithCustodyUID(capture, uid) != nil {
		t.Fatal("exact replay refused")
	}
	changed := bytes.Replace(capture.Original(), []byte("old-name"), []byte("new-name"), 1)
	replacement, err := decodeResetD101PreResetOriginal(changed, resetD101OriginalSHA(changed))
	if err != nil || c.retainResetD101PreResetCaptureWithCustodyUID(replacement, uid) == nil {
		t.Fatal("different original overwrote capture")
	}
	after, err := os.Stat(filepath.Join(dir, capture.value.OperationID+".json"))
	actual, readErr := readResetPrivateCustody(dir, capture.value.OperationID, uid)
	if err != nil || readErr != nil || !os.SameFile(before, after) || !bytes.Equal(actual, capture.Original()) {
		t.Fatal("native original changed")
	}
}
