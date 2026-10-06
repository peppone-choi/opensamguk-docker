package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func resetD101RecoveryPlanFixture(t *testing.T) (resetDecodedApprovalIntent, []byte, []byte, string) {
	t.Helper()
	intent, _ := resetDeploymentCardFixture(t)
	r := resetD101CandidateResourceNames(intent.Intent.OperationID)
	r.CandidateComposeFile, r.LiveComposeFile, r.CapsReaderFile = "/fixed/candidate.json", "/fixed/live.json", "/fixed/caps.json"
	r.CandidateComposeSHA, r.LiveComposeSHA = strings.Repeat("1", 64), strings.Repeat("2", 64)
	command := resetD101CandidateCommandPlan{SchemaVersion: 1, Kind: "D101_ROOT_CANDIDATE_COMMAND_PLAN_V1",
		OperationID: intent.Intent.OperationID, ApprovalIntentSHA: intent.SHA,
		TargetFingerprint: intent.Intent.TargetFingerprint, AppSourceSHA: intent.Intent.AppSourceSHA,
		DockerSourceSHA: strings.Repeat("c", 40), NewImageDigests: cloneResetD101Strings(intent.Intent.NewImageDigests),
		SelectedSourceReceiptSHA: intent.Intent.SelectedSourceReceiptSHA,
		SelectedEnvelopeSHA:      strings.Repeat("3", 64), CapsReaderSHA: strings.Repeat("4", 64),
		SeedEntrypoint: resetD101CandidateSeedEntrypoint, Stages: append([]string(nil), resetD101CandidateStages...),
		DestructiveCutoffUnix: intent.Intent.DestructiveCutoffUnix, Resources: r}
	commandWire, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	wire, sha, err := produceResetD101RecoveryPlan(intent, commandWire)
	if err != nil {
		t.Fatal(err)
	}
	return intent, commandWire, wire, sha
}

func TestResetD101RecoveryPlanPureProducerAndExact18(t *testing.T) {
	intent, command, wire, sha := resetD101RecoveryPlanFixture(t)
	decoded, err := decodeResetD101RecoveryPlan(wire, sha, intent, command)
	if err != nil || decoded.SHA != sha || !bytes.Equal(decoded.originalBytes(), wire) {
		t.Fatal("pure plan original or binding rejected", err)
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(wire, &root) != nil || len(root) != 18 ||
		decoded.Plan.Backup.MinimumRetainSeconds != 604800 || decoded.Plan.Restore.MaxAttempts != 1 ||
		decoded.Plan.Closure.PublicationAtClose != "VERIFYING" || len(decoded.Plan.SourceStages) != 8 ||
		!reflect.DeepEqual(decoded.Plan.Backup.RequiredLeaves, resetRecoveryBackupLeaves) {
		t.Fatal("exact 18-key plan shape drift")
	}
	for _, forbidden := range []string{"deploymentCardSha256", "evidenceCatalogSha256", "backupManifestSha256", "preResetOriginalsSha256", "restoreSucceeded", "approved"} {
		if _, found := root[forbidden]; found {
			t.Fatal("future/card evidence entered pre-intent plan:", forbidden)
		}
	}
	wire[0] = 'x'
	decoded.Plan.OldImageDigests["game-api"] = "changed"
	decoded.Plan.Backup.RequiredLeaves[0] = "changed"
	if bytes.Equal(decoded.originalBytes(), wire) || decoded.Plan.OldImageDigests["game-api"] == intent.Intent.OldImageDigests["game-api"] {
		t.Fatal("decoded copy unexpectedly shares mutable input")
	}
}

func TestResetD101RecoveryPlanRejectsMeaningAndWireForgery(t *testing.T) {
	intent, command, wire, sha := resetD101RecoveryPlanFixture(t)
	for _, mode := range []string{"op", "intent", "target", "app", "docker", "old-image", "command", "revision", "cutoff", "deadline", "stage", "backup-path", "backup-leaf", "backup-retention", "restore-path", "restore-attempt", "begin-kind", "closure", "future-sha", "old-16", "alias", "missing", "null", "duplicate", "trailing", "wrong-sha", "oversized", "invalid-utf8"} {
		t.Run(mode, func(t *testing.T) {
			var tree map[string]any
			if json.Unmarshal(wire, &tree) != nil {
				t.Fatal("fixture")
			}
			switch mode {
			case "op":
				tree["operationId"] = strings.Repeat("f", 32)
			case "intent":
				tree["approvalIntentSha256"] = strings.Repeat("f", 64)
			case "target":
				tree["targetFingerprint"] = strings.Repeat("f", 64)
			case "app":
				tree["appSourceSha"] = strings.Repeat("f", 40)
			case "docker":
				tree["dockerSourceSha"] = strings.Repeat("f", 40)
			case "old-image":
				tree["oldImageDigests"].(map[string]any)["game-api"] = "sha256:" + strings.Repeat("f", 64)
			case "command":
				tree["commandPlanSha256"] = strings.Repeat("f", 64)
			case "revision":
				tree["initialPublicRevision"] = "999"
			case "cutoff":
				tree["destructiveCutoffUnix"] = float64(1)
			case "deadline":
				tree["recoveryDeadlineUnix"] = float64(1)
			case "stage":
				tree["sourceStages"].([]any)[3] = "skip-backup"
			case "backup-path":
				tree["backup"].(map[string]any)["relativeDirectory"] = "/caller/path"
			case "backup-leaf":
				tree["backup"].(map[string]any)["requiredLeaves"].([]any)[0] = "fake"
			case "backup-retention":
				tree["backup"].(map[string]any)["minimumRetainSeconds"] = float64(1)
			case "restore-path":
				tree["restore"].(map[string]any)["claimDirectoryRole"] = "/caller/path"
			case "restore-attempt":
				tree["restore"].(map[string]any)["maxAttempts"] = float64(2)
			case "begin-kind":
				tree["restore"].(map[string]any)["requiredBeginKind"] = "synthetic"
			case "closure":
				tree["closure"].(map[string]any)["publicReleaseSeparate"] = false
			case "future-sha":
				tree["backupManifestSha256"] = strings.Repeat("f", 64)
			case "old-16":
				delete(tree, "backup")
				tree["sourceContracts"] = []string{}
			case "alias":
				delete(tree, "kind")
				tree["Kind"] = resetD101RecoveryPlanKind
			case "missing":
				delete(tree, "sourceStages")
			case "null":
				tree["restore"] = nil
			}
			bad, _ := json.Marshal(tree)
			switch mode {
			case "duplicate":
				bad = bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1)
			case "trailing":
				bad = append(bytes.Clone(wire), []byte(` {}`)...)
			case "wrong-sha":
				bad = bytes.Clone(wire)
			case "oversized":
				bad = append(bytes.Clone(wire), bytes.Repeat([]byte(" "), 32*1024)...)
			case "invalid-utf8":
				bad = bytes.Replace(wire, []byte(resetD101RecoveryPlanKind), []byte{0xff}, 1)
			}
			badSHA := resetD101OriginalSHA(bad)
			if mode == "wrong-sha" {
				badSHA = strings.Repeat("f", 64)
			}
			if _, err := decodeResetD101RecoveryPlan(bad, badSHA, intent, command); err == nil {
				t.Fatal("accepted forged plan")
			}
		})
	}
	if _, err := decodeResetD101RecoveryPlan(wire, sha, intent, append(bytes.Clone(command), ' ')); err == nil {
		t.Fatal("different command original reused plan")
	}
}

func TestResetD101RecoveryPlanRejectsForgedCommandBeforeProduction(t *testing.T) {
	intent, command, _, _ := resetD101RecoveryPlanFixture(t)
	for _, mode := range []string{"op", "target", "source", "old-stage", "cutoff", "reverse-plan", "duplicate", "null"} {
		t.Run(mode, func(t *testing.T) {
			var tree map[string]any
			if json.Unmarshal(command, &tree) != nil {
				t.Fatal("fixture")
			}
			switch mode {
			case "op":
				tree["operationId"] = strings.Repeat("f", 32)
			case "target":
				tree["targetFingerprint"] = strings.Repeat("f", 64)
			case "source":
				tree["dockerSourceSha"] = "UNKNOWN"
			case "old-stage":
				tree["stages"].([]any)[0] = "skip-freeze"
			case "cutoff":
				tree["destructiveCutoffUnix"] = float64(1)
			case "reverse-plan":
				tree["recoveryPlanSha256"] = strings.Repeat("f", 64)
			case "null":
				tree["resources"] = nil
			}
			bad, _ := json.Marshal(tree)
			if mode == "duplicate" {
				bad = bytes.Replace(command, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1)
			}
			if _, _, err := produceResetD101RecoveryPlan(intent, bad); err == nil {
				t.Fatal("forged command accepted")
			}
		})
	}
}

func TestResetD101RecoveryPlanCardBindsBothOriginalsWithoutCycle(t *testing.T) {
	intent, command, wire, sha := resetD101RecoveryPlanFixture(t)
	_, cardWire := resetDeploymentCardFixture(t)
	var card resetD101DeploymentCard
	if json.Unmarshal(cardWire, &card) != nil {
		t.Fatal("card fixture")
	}
	card.CommandPlanSHA = resetD101OriginalSHA(command)
	card.RecoveryPlanSHA = sha
	buildCard := func(v resetD101DeploymentCard) resetDecodedDeploymentCard {
		original, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeResetD101DeploymentCard(original, resetD101OriginalSHA(original), intent)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	valid := buildCard(card)
	if _, err := requireResetD101RecoveryPlanCard(wire, valid, intent, command); err != nil {
		t.Fatal("card failed to bind preceding originals", err)
	}
	for _, mode := range []string{"command", "plan", "docker"} {
		changed := card
		switch mode {
		case "command":
			changed.CommandPlanSHA = strings.Repeat("f", 64)
		case "plan":
			changed.RecoveryPlanSHA = strings.Repeat("f", 64)
		case "docker":
			changed.DockerSourceSHA = strings.Repeat("f", 40)
		}
		if _, err := requireResetD101RecoveryPlanCard(wire, buildCard(changed), intent, command); err == nil {
			t.Fatal("card accepted different", mode)
		}
	}
}
