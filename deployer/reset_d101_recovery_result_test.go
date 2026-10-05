package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func recoveryFixture(t *testing.T) (resetDecodedApprovalIntent, resetD101RecoveryResult, time.Time) {
	t.Helper()
	wire, sha, plan := resetIntentFixture(t)
	intent, err := decodeResetApprovalIntent(wire, sha)
	if err != nil {
		t.Fatal(err)
	}
	// Recovery originals require literal UTC Z; time.Unix carries time.Local,
	// so formatting the fixture must not depend on the test host's timezone.
	now := time.Unix(plan.WindowOpensAtUnix+10, 0).UTC()
	pin := strings.Repeat("c", 64)
	result := resetD101RecoveryResult{SchemaVersion: 1, Kind: "D101_RECOVERY_RESULT_V1", Status: "RECOVERED", ServerID: "pep", WorldID: 1,
		OperationID: intent.Intent.OperationID, ApprovalIntentSHA: intent.SHA, TargetFingerprint: intent.Intent.TargetFingerprint,
		GatewayPayloadSHA: pin, VerifyingRevision: "2", RecoveryBeginReceiptSHA: pin, OriginalRootResultSHA: pin, BackupManifestSHA: pin,
		RecoveryClaimSHA: pin, RestoredDatabaseReceiptSHA: pin, RestoredRuntimeReceiptSHA: pin, RestoredSelectedMetadataReceiptSHA: pin,
		OldImageDigests: intent.Intent.OldImageDigests, RestoreAttempt: 1, StartedAtUTC: now.Add(-time.Second).Format(time.RFC3339Nano),
		CompletedAtUTC: now.Format(time.RFC3339Nano), RecoveryDeadlineUnix: intent.Intent.RecoveryDeadlineUnix, OldGeneration: 9,
		OldScenarioCode: "scenario_990002", OldPublicationReceiptSHA: pin}
	registry, _ := json.Marshal(resetD101OldCanonicalRegistry{"pep", "synthetic old name", "http://spep-game-api:8081", "http://spep-game-engine:8082", "opensamguk-spep", 9, "scenario_990002"})
	world, _ := json.Marshal(resetD101RestoredOldWorld{1, "D101_RESTORED_OLD_WORLD_V1", result.OperationID, result.ApprovalIntentSHA,
		result.TargetFingerprint, "2", pin, 1, 9, "scenario_990002", 300, result.OldImageDigests, pin, pin, result.CompletedAtUTC})
	result.OldRegistryReceiptSHA = resetD101OriginalSHA(registry)
	result.OldCanonicalRegistryBytesBase64url = base64.RawURLEncoding.EncodeToString(registry)
	result.OldWorldReceiptSHA = resetD101OriginalSHA(world)
	result.RestoredOldWorldBytesBase64url = base64.RawURLEncoding.EncodeToString(world)
	return intent, result, now
}
func TestRecoveryResultRejectsUnboundOrMissingActualSnapshots(t *testing.T) {
	intent, original, now := recoveryFixture(t)
	wire, _ := json.Marshal(original)
	if _, err := validateResetD101RecoveryResult(wire, intent, original.RecoveryBeginReceiptSHA, now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*resetD101RecoveryResult){func(r *resetD101RecoveryResult) { r.RestoreAttempt = 2 }, func(r *resetD101RecoveryResult) { r.OldGeneration = 0 }, func(r *resetD101RecoveryResult) { r.OldCanonicalRegistryBytesBase64url = "" }, func(r *resetD101RecoveryResult) { r.OldWorldReceiptSHA = strings.Repeat("f", 64) }, func(r *resetD101RecoveryResult) { r.VerifyingRevision = "02" }, func(r *resetD101RecoveryResult) { r.CompletedAtUTC = now.Add(time.Second).Format(time.RFC3339Nano) }} {
		changed := original
		change(&changed)
		wire, _ := json.Marshal(changed)
		if _, err := validateResetD101RecoveryResult(wire, intent, original.RecoveryBeginReceiptSHA, now); err == nil {
			t.Fatal("invalid recovery evidence accepted")
		}
	}
	for _, bad := range [][]byte{append(append([]byte{}, wire...), []byte(`{}`)...), []byte(`{"schemaVersion":1,"schemaVersion":1}`), {0xff}} {
		if _, err := validateResetD101RecoveryResult(bad, intent, original.RecoveryBeginReceiptSHA, now); err == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
	if _, err := validateResetD101RecoveryResult(wire, intent, original.RecoveryBeginReceiptSHA, time.Unix(intent.Intent.RecoveryDeadlineUnix, 0)); err == nil {
		t.Fatal("deadline renewed")
	}
}
func TestRecoveryResultSeparateDomainAndMissingActualProducerClosed(t *testing.T) {
	intent, result, now := recoveryFixture(t)
	pins, public := resetD101KeyFixture(t)
	authority := resetD101VerifiedPurposeAuthority{intent, pins, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), now}
	source := func(context.Context, string, string) (resetD101VerifiedPurposeAuthority, error) {
		return authority, nil
	}
	actual := func(context.Context, string, string) (resetD101RecoveryResult, error) { return result, nil }
	key := func(p resetD101SigningKeyPins) (resetD101SigningKey, error) {
		return readResetD101SigningKeyWithUID(p, uint32(os.Getuid()))
	}
	clock := func() time.Time { return now }
	if _, _, err := issueResetD101RecoveryResultWithKeyReader(context.Background(), source, nil, result.OperationID, intent.SHA, result.RecoveryBeginReceiptSHA, clock, key); err == nil {
		t.Fatal("missing observer became authority")
	}
	wire, proof, err := issueResetD101RecoveryResultWithKeyReader(context.Background(), source, actual, result.OperationID, intent.SHA, result.RecoveryBeginReceiptSHA, clock, key)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 2 {
		t.Fatal("invalid proof")
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if !ed25519.Verify(public, append([]byte(resetD101RecoveryResultDomain), wire...), sig) || ed25519.Verify(public, append([]byte("OPENSAMGUK-D101-RESULT-V1\n"), wire...), sig) {
		t.Fatal("domain mismatch")
	}
	for _, action := range []string{"RECOVERY_BEGIN", "RECOVERY_CLOSE"} {
		method, path, err := resetD101PurposeRoute(action, result.OperationID)
		if err != nil || method != "POST" || !strings.HasSuffix(path, map[string]string{"RECOVERY_BEGIN": "/recovery-begin", "RECOVERY_CLOSE": "/recovery-close"}[action]) {
			t.Fatal("wrong recovery route")
		}
	}
}

func TestRecoveryOriginalIssuerPreservesBytesAndFreezesSourceSlice(t *testing.T) {
	intent, result, now := recoveryFixture(t)
	pins, public := resetD101KeyFixture(t)
	authority := resetD101VerifiedPurposeAuthority{intent, pins, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), now}
	source := func(context.Context, string, string) (resetD101VerifiedPurposeAuthority, error) {
		return authority, nil
	}
	original, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	original = append(original, '\n')
	retained := append([]byte(nil), original...)
	actual := func(context.Context, string, string) ([]byte, error) { return original, nil }
	key := func(p resetD101SigningKeyPins) (resetD101SigningKey, error) {
		original[0] = 'X'
		return readResetD101SigningKeyWithUID(p, uint32(os.Getuid()))
	}
	wire, proof, err := issueResetD101RecoveryResultOriginalWithKeyReader(context.Background(), source, actual, result.OperationID, intent.SHA, result.RecoveryBeginReceiptSHA, func() time.Time { return now }, key)
	if err != nil || !bytes.Equal(wire, retained) {
		t.Fatal("retained original was changed", err)
	}
	parts := strings.Split(proof, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !ed25519.Verify(public, append([]byte(resetD101RecoveryResultDomain), retained...), signature) {
		t.Fatal("signature does not bind actual original")
	}
}
