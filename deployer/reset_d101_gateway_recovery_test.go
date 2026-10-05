package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCommittedRecoveryBeginRequiresActualOriginalAndSameRootResult(t *testing.T) {
	dispatch, intent, evidence, binding, payloadSHA := resetD101GatewayDispatchFixture(t)
	rootSHA := strings.Repeat("f", 64)
	now := time.Unix(intent.Intent.WindowOpensAtUnix+65, 0)
	var outer map[string]any
	if json.Unmarshal(dispatch, &outer) != nil {
		t.Fatal("fixture")
	}
	begin := resetD101RecoveryBeginOriginal{1, "D101_RECOVERY_BEGIN_V1", binding.OperationID, evidence.Preflight.PublicationRevision, "DISPATCH_INTENT", rootSHA, "RECOVERY_REQUIRED", strings.Repeat("c", 64)}
	original, err := json.MarshalIndent(begin, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	outer["state"] = "RECOVERY_REQUIRED"
	outer["recoveryBeginReceiptSha256"] = resetD101OriginalSHA(original)
	outer["recoveryBeginReceiptBytesBase64url"] = base64.RawURLEncoding.EncodeToString(original)
	wire, _ := json.Marshal(outer)
	observed, err := decodeResetD101GatewayRecoveryBegin(wire, intent, evidence, binding, payloadSHA, rootSHA, now)
	if err != nil || !bytes.Equal(observed.Original(), original) {
		t.Fatal("committed original rejected", err)
	}
	copy := observed.Original()
	copy[0] = 'X'
	if !bytes.Equal(observed.Original(), original) {
		t.Fatal("mutable committed original")
	}
	if decodeResetD101GatewayDispatch(wire, intent, evidence, binding, payloadSHA, time.Now()) == nil {
		t.Fatal("recovery enabled dispatch")
	}
	for _, mode := range []string{"hash-only", "wrong-state", "wrong-op", "wrong-target", "wrong-payload", "wrong-revision", "padded", "wrong-original-sha", "different-root", "duplicate-begin", "different-begin-op", "null-stored-after-success", "published"} {
		var changed map[string]any
		if json.Unmarshal(wire, &changed) != nil {
			t.Fatal("fixture")
		}
		newBegin := begin
		switch mode {
		case "hash-only":
			delete(changed, "recoveryBeginReceiptBytesBase64url")
		case "wrong-state":
			changed["state"] = "DISPATCH_INTENT"
		case "wrong-op":
			changed["operationId"] = strings.Repeat("b", 32)
		case "wrong-target":
			changed["targetFingerprint"] = strings.Repeat("b", 64)
		case "wrong-payload":
			changed["gatewayPayloadSha256"] = strings.Repeat("b", 64)
		case "wrong-revision":
			changed["verifyingRevision"] = "3"
		case "padded":
			changed["recoveryBeginReceiptBytesBase64url"] = base64.RawURLEncoding.EncodeToString(original) + "="
		case "wrong-original-sha":
			changed["recoveryBeginReceiptSha256"] = strings.Repeat("b", 64)
		case "different-root":
			newBegin.RootResultReceiptSHA = strings.Repeat("b", 64)
		case "different-begin-op":
			newBegin.OperationID = strings.Repeat("b", 32)
		case "null-stored-after-success":
			newBegin.LastSafeState = "REMOTE_SUCCEEDED"
		case "published":
			changed["publishedRevision"] = "3"
		}
		if mode == "different-root" || mode == "different-begin-op" || mode == "null-stored-after-success" || mode == "duplicate-begin" {
			raw, _ := json.Marshal(newBegin)
			if mode == "duplicate-begin" {
				raw = []byte(strings.Replace(string(raw), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1))
			}
			changed["recoveryBeginReceiptSha256"] = resetD101OriginalSHA(raw)
			changed["recoveryBeginReceiptBytesBase64url"] = base64.RawURLEncoding.EncodeToString(raw)
		}
		bad, _ := json.Marshal(changed)
		if _, err := decodeResetD101GatewayRecoveryBegin(bad, intent, evidence, binding, payloadSHA, rootSHA, now); err == nil {
			t.Fatal("invalid committed BEGIN accepted", mode)
		}
	}
	// A post-success failure keeps the original SUCCEEDED Root receipt in both
	// the execution row and the separate BEGIN. This does not rewrite Root state.
	begin.LastSafeState = "REMOTE_SUCCEEDED"
	original, _ = json.Marshal(begin)
	outer["rootResultReceiptSha256"] = rootSHA
	outer["recoveryBeginReceiptSha256"] = resetD101OriginalSHA(original)
	outer["recoveryBeginReceiptBytesBase64url"] = base64.RawURLEncoding.EncodeToString(original)
	wire, _ = json.Marshal(outer)
	if _, err := decodeResetD101GatewayRecoveryBegin(wire, intent, evidence, binding, payloadSHA, rootSHA, now); err != nil {
		t.Fatal("post-success committed BEGIN refused", err)
	}
}
func TestActualRecoveryBeginReaderWithoutAuthorityCallsNoDocker(t *testing.T) {
	calls := 0
	c := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	if value, err := c.readResetD101GatewayRecoveryBegin(context.Background(), strings.Repeat("a", 32), strings.Repeat("b", 64)); err == nil || value.SHA() != "" || len(value.Original()) != 0 || calls != 0 {
		t.Fatal("missing installed source became committed BEGIN")
	}
}
