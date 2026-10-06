package main

import (
	"bytes"
	"encoding/json"
	et "opensamguk-deployer/internal/d101evidencetransport"
	"regexp"
	"time"
	"unicode/utf8"
)

// Independently reviewed originals of one native human event and its actual
// two-edge parent chain. These pins do not authenticate the file owner/actor.
type resetD101NativeHumanEventPins struct {
	Event, Parent, Context                  et.RawReference
	SessionID, EventID, ParentID, ContextID string
	OriginalIssuedAtUTC                     string
}
type resetD101NativeHumanEvent struct {
	event, parent, context []byte
	pins                   resetD101NativeHumanEventPins
}

func (v resetD101NativeHumanEvent) originals() (event, parent, context []byte) {
	return bytes.Clone(v.event), bytes.Clone(v.parent), bytes.Clone(v.context)
}

// Claude native log version 2.1.286 as actually retained. This binds provenance,
// source time and parent edges only. Human intent/scope and historical native
// authenticated-session->principal remain separate mandatory evidence.
func decodeResetD101NativeHumanEvent(event, parent, context []byte, pins resetD101NativeHumanEventPins, now time.Time) (resetD101NativeHumanEvent, error) {
	deny := func() (resetD101NativeHumanEvent, error) {
		return resetD101NativeHumanEvent{}, errResetExecutionEvidence
	}
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	for _, id := range []string{pins.SessionID, pins.EventID, pins.ParentID, pins.ContextID} {
		if !uuid.MatchString(id) {
			return deny()
		}
	}
	if pins.EventID == pins.ParentID || pins.EventID == pins.ContextID || pins.ParentID == pins.ContextID || now.Unix() <= 0 {
		return deny()
	}
	wires := [][]byte{event, parent, context}
	refs := []et.RawReference{pins.Event, pins.Parent, pins.Context}
	for n, ref := range refs {
		if et.ValidateRawReference(ref) != nil || ref.MediaType != "application/json" || ref.ByteLength > et.MetadataMaxBytes || !utf8.Valid(wires[n]) || uint64(len(wires[n])) != ref.ByteLength || et.HashOriginal(wires[n]) != ref.SHA256 {
			return deny()
		}
		for prior := 0; prior < n; prior++ {
			if refs[prior].LogicalID == ref.LogicalID {
				return deny()
			}
		}
	}
	keys := [][]string{
		{"parentUuid", "isSidechain", "promptId", "type", "message", "uuid", "timestamp", "permissionMode", "origin", "promptSource", "turnOrigin", "turnPosition", "userType", "entrypoint", "cwd", "sessionId", "version", "gitBranch", "slug"},
		{"parentUuid", "isSidechain", "type", "uuid", "timestamp", "sessionId", "version", "entrypoint", "userType", "cwd", "gitBranch", "slug", "hasOutput", "hookAdditionalContext", "hookCount", "hookErrors", "hookInfos", "level", "preventedContinuation", "stopReason", "subtype", "toolUseID"},
		{"parentUuid", "isSidechain", "type", "message", "uuid", "timestamp", "sessionId", "version", "entrypoint", "userType", "cwd", "gitBranch", "slug", "advisorModel", "apiBlockIndex", "effort", "perTurnEffort", "requestId", "serverClassifierRequest"},
	}
	objects := make([]map[string]json.RawMessage, 3)
	text := func(fields map[string]json.RawMessage, key string) string {
		var s string
		if json.Unmarshal(fields[key], &s) != nil {
			return ""
		}
		return s
	}
	ids := []string{pins.EventID, pins.ParentID, pins.ContextID}
	kinds := []string{"user", "system", "assistant"}
	times := make([]time.Time, 3)
	for n, wire := range wires {
		var fields map[string]json.RawMessage
		if decodeResetPrivateJSON(wire, &fields) != nil || fields == nil || len(fields) != len(keys[n]) {
			return deny()
		}
		for _, key := range keys[n] {
			if _, ok := fields[key]; !ok {
				return deny()
			}
		}
		var sidechain bool
		if !bytes.Equal(bytes.TrimSpace(fields["isSidechain"]), []byte("false")) || json.Unmarshal(fields["isSidechain"], &sidechain) != nil || sidechain || text(fields, "uuid") != ids[n] || text(fields, "sessionId") != pins.SessionID || text(fields, "type") != kinds[n] || text(fields, "version") != "2.1.286" || text(fields, "entrypoint") != "claude-desktop" || text(fields, "userType") != "external" {
			return deny()
		}
		at, err := resetD101RecoveryUTC(text(fields, "timestamp"))
		if err != nil || at.Unix() <= 0 || at.After(now) {
			return deny()
		}
		times[n] = at
		objects[n] = fields
	}
	if text(objects[0], "parentUuid") != pins.ParentID || text(objects[1], "parentUuid") != pins.ContextID || !uuid.MatchString(text(objects[2], "parentUuid")) || text(objects[2], "parentUuid") == pins.EventID || text(objects[2], "parentUuid") == pins.ParentID || text(objects[2], "parentUuid") == pins.ContextID || text(objects[0], "timestamp") != pins.OriginalIssuedAtUTC || times[2].After(times[1]) || times[1].After(times[0]) {
		return deny()
	}
	var origin map[string]json.RawMessage
	var message map[string]json.RawMessage
	var content string
	if decodeResetPrivateJSON(objects[0]["origin"], &origin) != nil || len(origin) != 1 || text(origin, "kind") != "human" || text(objects[0], "turnOrigin") != "human" || decodeResetPrivateJSON(objects[0]["message"], &message) != nil || len(message) != 2 || text(message, "role") != "user" || json.Unmarshal(message["content"], &content) != nil || len(content) == 0 {
		return deny()
	}
	var assistant map[string]json.RawMessage
	if decodeResetPrivateJSON(objects[2]["message"], &assistant) != nil || text(assistant, "role") != "assistant" || len(assistant["content"]) == 0 || bytes.Equal(bytes.TrimSpace(assistant["content"]), []byte("null")) {
		return deny()
	}
	return resetD101NativeHumanEvent{bytes.Clone(event), bytes.Clone(parent), bytes.Clone(context), pins}, nil
}
