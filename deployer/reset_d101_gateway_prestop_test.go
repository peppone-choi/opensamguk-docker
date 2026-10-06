package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func resetD101GatewayPreStopFixture(t *testing.T) ([]byte, resetDecodedApprovalIntent, string, time.Time) {
	t.Helper()
	wire, intent, _, _, prepareSHA := resetD101GatewayDispatchFixture(t)
	var fields map[string]any
	if json.Unmarshal(wire, &fields) != nil {
		t.Fatal("Gateway fixture")
	}
	fields["state"] = "PREPARED"
	fields["rootRequestFingerprint"] = nil
	prepared, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(intent.Intent.WindowOpensAtUnix+61, 0)
	return prepared, intent, prepareSHA, now
}

func TestResetD101GatewayPreStopAcceptsOnlyActualPreparedQueryAndDefendsOriginal(t *testing.T) {
	wire, intent, prepareSHA, now := resetD101GatewayPreStopFixture(t)
	observed, err := decodeResetD101GatewayPreStop(wire, intent, prepareSHA, now)
	if err != nil || observed.execution.State != "PREPARED" || observed.execution.RootRequestFingerprint != nil ||
		observed.preReset.value.OperationID != intent.Intent.OperationID || !bytes.Equal(observed.Original(), wire) {
		t.Fatal("valid PREPARED Gateway QUERY original refused", err)
	}
	copyOut := observed.Original()
	copyOut[0] ^= 1
	if !bytes.Equal(observed.Original(), wire) {
		t.Fatal("Gateway original is mutable through accessor")
	}
}

func TestResetD101GatewayPreStopRejectsWrongStateIdentityNullableAndTime(t *testing.T) {
	wire, intent, prepareSHA, now := resetD101GatewayPreStopFixture(t)
	for _, mode := range []string{
		"dispatch", "remote", "settled", "recovery", "public", "root-request", "root-result", "published", "validation",
		"operation", "intent", "target", "prepare", "initial-revision", "verifying-equal", "verifying-leading-zero",
		"created-before-window", "updated-before-created", "updated-in-future", "extra-current-publication", "no-capture", "duplicate",
	} {
		t.Run(mode, func(t *testing.T) {
			var fields map[string]any
			if json.Unmarshal(wire, &fields) != nil {
				t.Fatal("fixture")
			}
			switch mode {
			case "dispatch":
				fields["state"] = "DISPATCH_INTENT"
			case "remote":
				fields["state"] = "REMOTE_SUCCEEDED"
			case "settled":
				fields["state"] = "REGISTRY_SETTLED"
			case "recovery":
				fields["state"] = "RECOVERY_REQUIRED"
			case "public":
				fields["state"] = "PUBLISHED"
			case "root-request":
				fields["rootRequestFingerprint"] = strings.Repeat("a", 64)
			case "root-result":
				fields["rootResultReceiptSha256"] = strings.Repeat("a", 64)
			case "published":
				fields["publishedRevision"] = "3"
			case "validation":
				fields["validationReceiptSha256"] = strings.Repeat("a", 64)
			case "operation":
				fields["operationId"] = strings.Repeat("f", 32)
			case "intent":
				fields["approvalIntentSha256"] = strings.Repeat("f", 64)
			case "target":
				fields["targetFingerprint"] = strings.Repeat("f", 64)
			case "prepare":
				fields["gatewayPayloadSha256"] = strings.Repeat("f", 64)
			case "initial-revision":
				fields["initialPublicRevision"] = "2"
			case "verifying-equal":
				fields["verifyingRevision"] = "1"
			case "verifying-leading-zero":
				fields["verifyingRevision"] = "02"
			case "created-before-window":
				fields["createdAtUtc"] = time.Unix(intent.Intent.WindowOpensAtUnix-1, 0).UTC().Format(time.RFC3339Nano)
			case "updated-before-created":
				fields["updatedAtUtc"] = time.Unix(intent.Intent.WindowOpensAtUnix, 0).UTC().Format(time.RFC3339Nano)
			case "updated-in-future":
				fields["updatedAtUtc"] = now.Add(time.Second).UTC().Format(time.RFC3339Nano)
			case "extra-current-publication":
				fields["publicationState"] = "VERIFYING"
			case "no-capture":
				delete(fields, "preResetOriginalsBytesBase64url")
				delete(fields, "preResetOriginalsSha256")
			}
			changed, _ := json.Marshal(fields)
			if mode == "duplicate" {
				changed = []byte(strings.Replace(string(changed), `"state":"PREPARED"`, `"state":"PREPARED","state":"PREPARED"`, 1))
			}
			if _, err := decodeResetD101GatewayPreStop(changed, intent, prepareSHA, now); err == nil {
				t.Fatal("changed Gateway QUERY accepted")
			}
		})
	}
	if _, err := decodeResetD101GatewayPreStop(wire, intent, strings.Repeat("f", 64), now); err == nil {
		t.Fatal("wrong installed prepare SHA accepted")
	}
	if _, err := decodeResetD101GatewayPreStop(wire, intent, prepareSHA, time.Unix(intent.Intent.WindowOpensAtUnix-1, 0)); err == nil {
		t.Fatal("before approval window accepted")
	}
	if _, err := decodeResetD101GatewayPreStop(wire, intent, prepareSHA, time.Unix(intent.Intent.DestructiveCutoffUnix, 0)); err == nil {
		t.Fatal("after original cutoff accepted")
	}
}
