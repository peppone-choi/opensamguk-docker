package main

import (
	"bytes"
	"encoding/json"
	et "opensamguk-deployer/internal/d101evidencetransport"
	"strings"
	"testing"
	"time"
)

func nativeHumanFixture(t *testing.T) ([][]byte, resetD101NativeHumanEventPins, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)
	ids := []string{"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003", "00000000-0000-0000-0000-000000000004"}
	session := "00000000-0000-0000-0000-000000000005"
	event := map[string]any{"parentUuid": ids[1], "isSidechain": false, "promptId": "synthetic", "type": "user", "message": map[string]any{"role": "user", "content": "synthetic fixture"}, "uuid": ids[0], "timestamp": now.Add(-time.Second).Format(time.RFC3339Nano), "permissionMode": "synthetic", "origin": map[string]any{"kind": "human"}, "promptSource": "synthetic", "turnOrigin": "human", "turnPosition": 1, "userType": "external", "entrypoint": "claude-desktop", "cwd": "/synthetic", "sessionId": session, "version": "2.1.286", "gitBranch": "synthetic", "slug": "synthetic"}
	parent := map[string]any{"parentUuid": ids[2], "isSidechain": false, "type": "system", "uuid": ids[1], "timestamp": now.Add(-2 * time.Second).Format(time.RFC3339Nano), "sessionId": session, "version": "2.1.286", "entrypoint": "claude-desktop", "userType": "external", "cwd": "/synthetic", "gitBranch": "synthetic", "slug": "synthetic", "hasOutput": false, "hookAdditionalContext": "", "hookCount": 0, "hookErrors": []string{}, "hookInfos": []string{}, "level": "synthetic", "preventedContinuation": false, "stopReason": "synthetic", "subtype": "synthetic", "toolUseID": nil}
	context := map[string]any{"parentUuid": ids[3], "isSidechain": false, "type": "assistant", "message": map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "text", "text": "synthetic context"}}}, "uuid": ids[2], "timestamp": now.Add(-3 * time.Second).Format(time.RFC3339Nano), "sessionId": session, "version": "2.1.286", "entrypoint": "claude-desktop", "userType": "external", "cwd": "/synthetic", "gitBranch": "synthetic", "slug": "synthetic", "advisorModel": nil, "apiBlockIndex": 0, "effort": "synthetic", "perTurnEffort": "synthetic", "requestId": "synthetic", "serverClassifierRequest": nil}
	wires := make([][]byte, 3)
	refs := make([]et.RawReference, 3)
	for n, v := range []map[string]any{event, parent, context} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		wires[n] = append(b, '\n')
		refs[n] = et.RawReference{LogicalID: "raw:native-" + ids[n], SHA256: et.HashOriginal(wires[n]), ByteLength: uint64(len(wires[n])), MediaType: "application/json"}
	}
	return wires, resetD101NativeHumanEventPins{refs[0], refs[1], refs[2], session, ids[0], ids[1], ids[2], event["timestamp"].(string)}, now
}
func TestNativeHumanEventPreservesOriginalParentChainWithoutActorAuthority(t *testing.T) {
	wires, pins, now := nativeHumanFixture(t)
	value, err := decodeResetD101NativeHumanEvent(wires[0], wires[1], wires[2], pins, now)
	if err != nil {
		t.Fatal(err)
	}
	event, parent, context := value.originals()
	if !bytes.Equal(event, wires[0]) || !bytes.Equal(parent, wires[1]) || !bytes.Equal(context, wires[2]) {
		t.Fatal("originals changed")
	}
	event[0] = '!'
	wires[1][0] = '!'
	againEvent, againParent, _ := value.originals()
	if againEvent[0] != '{' || againParent[0] != '{' {
		t.Fatal("originals alias caller")
	}
}
func TestNativeHumanEventRejectsBrokenProvenanceOrNativeChain(t *testing.T) {
	for _, mode := range []string{"pin-sha", "missing-parent", "wrong-parent", "mixed-session", "sidechain", "null-sidechain", "non-human", "tool-role", "future-time", "reversed-time", "wrong-issued", "unknown-version", "extra-key", "duplicate-key", "array", "multiple-events", "duplicate-ref", "context-cycle", "context-primitive", "context-empty", "context-block-type", "context-block-unknown"} {
		t.Run(mode, func(t *testing.T) {
			wires, pins, now := nativeHumanFixture(t)
			var event, parent, context map[string]any
			for n, out := range []*map[string]any{&event, &parent, &context} {
				if json.Unmarshal(wires[n], out) != nil {
					t.Fatal("fixture")
				}
			}
			switch mode {
			case "pin-sha":
				pins.Event.SHA256 = strings.Repeat("a", 64)
			case "missing-parent":
				wires[1] = nil
			case "wrong-parent":
				event["parentUuid"] = pins.ContextID
			case "mixed-session":
				parent["sessionId"] = "00000000-0000-0000-0000-000000000099"
			case "sidechain":
				event["isSidechain"] = true
			case "null-sidechain":
				event["isSidechain"] = nil
			case "non-human":
				event["origin"] = map[string]any{"kind": "agent"}
			case "tool-role":
				event["message"].(map[string]any)["role"] = "tool"
			case "future-time":
				event["timestamp"] = now.Add(time.Second).Format(time.RFC3339Nano)
				pins.OriginalIssuedAtUTC = event["timestamp"].(string)
			case "reversed-time":
				parent["timestamp"] = now.Format(time.RFC3339Nano)
			case "wrong-issued":
				pins.OriginalIssuedAtUTC = now.Add(-4 * time.Second).Format(time.RFC3339Nano)
			case "unknown-version":
				event["version"] = "new-unreviewed"
			case "extra-key":
				event["actorIdentity"] = "generated"
			case "duplicate-ref":
				pins.Parent.LogicalID = pins.Event.LogicalID
			case "context-cycle":
				context["parentUuid"] = pins.EventID
			case "context-primitive":
				context["message"].(map[string]any)["content"] = 1
			case "context-empty":
				context["message"].(map[string]any)["content"] = []any{}
			case "context-block-type":
				context["message"].(map[string]any)["content"] = []any{map[string]any{"type": "tool_result", "text": "synthetic"}}
			case "context-block-unknown":
				context["message"].(map[string]any)["content"] = []any{map[string]any{"type": "text", "text": "synthetic", "extra": true}}
			}
			if mode != "pin-sha" && mode != "missing-parent" && mode != "duplicate-ref" {
				for n, obj := range []map[string]any{event, parent, context} {
					b, _ := json.Marshal(obj)
					wires[n] = append(b, '\n')
				}
				if mode == "duplicate-key" {
					wires[0] = bytes.Replace(wires[0], []byte(`"isSidechain":false`), []byte(`"isSidechain":false,"isSidechain":false`), 1)
				}
				if mode == "array" {
					wires[0] = append(append([]byte{'['}, bytes.TrimSpace(wires[0])...), ']')
				}
				if mode == "multiple-events" {
					wires[0] = append(wires[0], wires[0]...)
				}
				refs := []*et.RawReference{&pins.Event, &pins.Parent, &pins.Context}
				for n, ref := range refs {
					ref.SHA256 = et.HashOriginal(wires[n])
					ref.ByteLength = uint64(len(wires[n]))
				}
			}
			if _, err := decodeResetD101NativeHumanEvent(wires[0], wires[1], wires[2], pins, now); err == nil {
				t.Fatal("invalid native source accepted")
			}
		})
	}
}
