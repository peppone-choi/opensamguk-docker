package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This fixture uses public synthetic keys, real private fixture files and the
// persisted preparation binding. It supplies no operating issuer or native9.
func preparedTypedSigningFixture(t *testing.T) (config, *resetD101PreparedSigningInput, resetD101SigningKey, ed25519.PublicKey, []byte) {
	t.Helper()
	cfg, uid, _, evidence, chain, record := resetD101PreparedFixture(t)
	pins, public := resetD101KeyFixture(t)
	prior := cfg.d101PurposeAuthority
	cfg.d101PurposeAuthority = func(ctx context.Context, op, sha string) (resetD101VerifiedPurposeAuthority, error) {
		authority, err := prior(ctx, op, sha)
		authority.KeyPins = pins
		return authority, err
	}
	if _, err := cfg.persistResetD101PreparedPhase(context.Background(), record, evidence, chain, uid); err != nil {
		t.Fatal("fixture persisted preparation", err)
	}
	binding := resetExecutionPhaseBinding{OperationID: record.OperationID, Target: evidence.Plan.Target, Evidence: chain.Evidence, AcceptedAtUnix: record.CreatedAt.Unix(), Phase: "prepared"}
	wire, retained, err := cfg.readResetD101PreparedPhase(binding, record, evidence, uid)
	if err != nil {
		t.Fatal("fixture actual private original binding", err)
	}
	proof, err := decodeResetD101PreparedProof(wire)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := cfg.d101PurposeAuthority(context.Background(), record.OperationID, record.D101IntentSHA)
	request := resetD101PurposeGrantRequest{OperationID: record.OperationID, ApprovalIntentSHA: record.D101IntentSHA, Action: "DISPATCH_INTENT"}
	intent, authorityErr := requireResetD101Authority(authority, request, time.Now())
	if err != nil || authorityErr != nil || cfg.requireResetD101Preparation(record) != nil || requireResetD101PreparedBinding(proof, retained, intent, evidence, record, time.Now()) != nil {
		t.Fatal("synthetic bound preparation rejected", err, authorityErr)
	}
	key, err := readResetD101SigningKeyWithUID(pins, uid)
	if err != nil {
		t.Fatal("real fixture key custody", err)
	}
	t.Cleanup(func() { key.close() })
	input := &resetD101PreparedSigningInput{original: append([]byte(nil), wire...), originalSHA: resetD101OriginalSHA(wire), proof: proof, authority: authority, request: request, chain: retained, evidence: evidence, record: record, validatedAt: time.Now()}
	return cfg, input, key, public, wire
}

func TestPreparedTypedSignerPreservesExactBoundOriginal(t *testing.T) {
	_, input, key, public, wire := preparedTypedSigningFixture(t)
	original := append([]byte(nil), wire...)
	wire[0] = '!'
	signature, err := key.signPrepared(context.Background(), input)
	if err != nil || !bytes.Equal(input.original, original) || !ed25519.Verify(public, append([]byte("OPENSAMGUK-D101-PREPARED-V1\n"), original...), signature) {
		t.Fatal("typed PREPARED failed exact original", err)
	}
	if ed25519.Verify(public, append([]byte("OPENSAMGUK-D101-RESULT-V1\n"), original...), signature) || ed25519.Verify(public, append([]byte("OPENSAMGUK-D101-PREPARED-V1\n"), wire...), signature) {
		t.Fatal("changed bytes or domain accepted")
	}
}

func TestPreparedTypedSignerRejectsInvalidTransferAndKeepsGenericClosed(t *testing.T) {
	modes := []string{"nil-input", "zero-input", "nil-context", "cancelled", "empty-original", "changed-original", "malformed-original", "decoded-mismatch", "wrong-identity", "key-id", "key-spki", "private-key", "closed-key", "future-validation", "stale-validation", "future-prepared", "stale-prepared", "expired-cutoff", "authority-clock", "wrong-purpose", "receipt-binding", "record-binding", "consumed-preparation"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			cfg, input, key, _, _ := preparedTypedSigningFixture(t)
			ctx := context.Background()
			rewriteProof := func() {
				b, err := json.Marshal(input.proof)
				if err != nil {
					t.Fatal(err)
				}
				input.original = b
				input.originalSHA = resetD101OriginalSHA(b)
			}
			switch mode {
			case "nil-input":
				input = nil
			case "zero-input":
				input = &resetD101PreparedSigningInput{}
			case "nil-context":
				ctx = nil
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "empty-original":
				input.original = nil
			case "changed-original":
				input.original = append(input.original, '\n')
			case "malformed-original":
				input.original = []byte(`{"schemaVersion":1}`)
				input.originalSHA = resetD101OriginalSHA(input.original)
			case "decoded-mismatch":
				input.proof.AppSourceSHA = strings.Repeat("f", 40)
			case "wrong-identity":
				input.proof.OperationID = strings.Repeat("f", 32)
				rewriteProof()
			case "key-id":
				key.keyID = "different-key"
			case "key-spki":
				key.publicKeySpkiSHA = strings.Repeat("f", 64)
			case "private-key":
				key.private = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
				t.Cleanup(func() { clear(key.private) })
			case "closed-key":
				key.close()
			case "future-validation":
				input.validatedAt = time.Now().Add(time.Hour)
			case "stale-validation":
				input.validatedAt = time.Now().Add(-resetPreflightMaxAge - time.Second)
			case "future-prepared":
				input.proof.PreparedAtUTC = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
				rewriteProof()
			case "stale-prepared":
				input.proof.PreparedAtUTC = time.Now().Add(-resetPreflightMaxAge - time.Second).UTC().Format(time.RFC3339Nano)
				rewriteProof()
			case "expired-cutoff":
				input.proof.DestructiveCutoffUnix = time.Now().Unix()
				rewriteProof()
			case "authority-clock":
				input.authority.ClockObservedAt = time.Now().Add(-resetPreflightMaxAge - time.Second)
			case "wrong-purpose":
				input.request.Action = "QUERY"
			case "receipt-binding":
				input.evidence.Preflight.ApprovalPlanSHA = strings.Repeat("f", 64)
			case "record-binding":
				input.record.RequestFingerprint = strings.Repeat("f", 64)
			case "consumed-preparation":
				cfg.operations.mu.Lock()
				cfg.operations.maintenanceLease.consumed = true
				cfg.operations.mu.Unlock()
				// The production caller owns this live check; the transfer is not an
				// authority lease and cannot replace it.
				if cfg.requireResetD101Preparation(input.record) == nil {
					t.Fatal("consumed preparation remained live")
				}
				return
			}
			signature, err := key.signPrepared(ctx, input)
			if err == nil || len(signature) != 0 {
				t.Fatal("invalid typed input returned signature")
			}
		})
	}
	_, input, key, _, _ := preparedTypedSigningFixture(t)
	var absent *resetD101SigningKey
	if signature, err := absent.signPrepared(context.Background(), input); err == nil || len(signature) != 0 {
		t.Fatal("absent key returned signature")
	}
	signature, err := key.sign("OPENSAMGUK-D101-PREPARED-V1\n", input.original)
	if err == nil || len(signature) != 0 {
		t.Fatal("generic PREPARED route opened")
	}
	signature, err = key.sign("OPENSAMGUK_D101_NATIVE_AUTHORITY_V1\n", input.original)
	if err == nil || len(signature) != 0 {
		t.Fatal("unapproved native domain opened")
	}
}

// This is the actual production caller oracle for the generic-call mutation.
// Mac/ordinary non-root QA must record it NOT_RUN, not native positive PASS.
func TestPreparedProductionCallerExactOriginalAndGenericMutation(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("actual full producer requires Linux/root native custody; no UID or native-reader bypass")
	}
	cfg, input, _, public, original := preparedTypedSigningFixture(t)
	returned, header, err := cfg.readResetD101PreparedProof(context.Background(), input.record.OperationID, input.proof.ApprovalPlanSHA, input.proof.ExecutionReceiptSHA)
	parts := strings.Split(header, ".")
	if err != nil || len(parts) != 2 || parts[0] != input.authority.KeyPins.KeyID || !bytes.Equal(returned, original) {
		t.Fatal("actual producer failed exact typed route", err)
	}
	signature, decodeErr := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if decodeErr != nil || !ed25519.Verify(public, append([]byte("OPENSAMGUK-D101-PREPARED-V1\n"), original...), signature) {
		t.Fatal("actual producer signature mismatch", decodeErr)
	}
	for _, mode := range []string{"cancelled", "consumed-lease", "record-drift", "wrong-plan", "missing-original", "wrong-key-pin", "stale-authority"} {
		t.Run(mode, func(t *testing.T) {
			cfg, input, _, _, _ := preparedTypedSigningFixture(t)
			ctx := context.Background()
			plan := input.proof.ApprovalPlanSHA
			switch mode {
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "consumed-lease":
				cfg.operations.mu.Lock()
				cfg.operations.maintenanceLease.consumed = true
				cfg.operations.mu.Unlock()
			case "record-drift":
				cfg.lifecycleOperationStore.mu.Lock()
				changed := input.record
				changed.RequestFingerprint = strings.Repeat("f", 64)
				cfg.lifecycleOperationStore.operations[changed.OperationID] = changed
				cfg.lifecycleOperationStore.mu.Unlock()
			case "wrong-plan":
				plan = strings.Repeat("f", 64)
			case "missing-original":
				if os.Remove(filepath.Join(cfg.serversDir, ".deployer-reset-prepared-proofs", input.record.OperationID+".json")) != nil {
					t.Fatal("fixture removal failed")
				}
			case "wrong-key-pin", "stale-authority":
				prior := cfg.d101PurposeAuthority
				cfg.d101PurposeAuthority = func(ctx context.Context, op, sha string) (resetD101VerifiedPurposeAuthority, error) {
					a, err := prior(ctx, op, sha)
					if mode == "wrong-key-pin" {
						a.KeyPins.KeyID = "different-key"
					} else {
						a.ClockObservedAt = time.Now().Add(-resetPreflightMaxAge - time.Second)
					}
					return a, err
				}
			}
			wire, proof, err := cfg.readResetD101PreparedProof(ctx, input.record.OperationID, plan, input.proof.ExecutionReceiptSHA)
			if err == nil || len(wire) != 0 || proof != "" {
				t.Fatal("invalid production input returned wire/header")
			}
		})
	}
}
