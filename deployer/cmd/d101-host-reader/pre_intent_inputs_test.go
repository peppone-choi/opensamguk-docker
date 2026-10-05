package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101preinput"
)

func preInputFixture(t *testing.T) (map[string]d101custody.Original, privateReader) {
	t.Helper()
	files, read := fixture(t)
	// Prove pre-input does not need any approved readerBindings/final14 files.
	for path := range files {
		delete(files, path)
	}
	op := strings.Repeat("a", 32)
	config := selectedWire([]byte(`{"SYNTHETIC_ONLY":"configuration"}`))
	target := selectedWire([]byte(`{"SYNTHETIC_ONLY":"typed-target"}`))
	b := d101preinput.Bindings{SchemaVersion: 1, Kind: d101preinput.Kind, OriginalOp: op, TargetFingerprint: target.SHA256, AppSourceSHA: strings.Repeat("b", 40), ImagePins: map[string]string{}, Configuration: d101preinput.Reference{RawSHA: config.SHA256, ByteLength: uint64(len(config.Bytes))}, TypedTarget: d101preinput.Reference{RawSHA: target.SHA256, ByteLength: uint64(len(target.Bytes))}, ArtifactsRoot: "/reviewed/release"}
	for _, id := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		b.ImagePins[id] = "sha256:" + strings.Repeat("c", 64)
	}
	wire, _ := json.Marshal(b)
	files[d101preinput.BindingsPath] = selectedWire(wire)
	path, _ := d101preinput.InputPath(op, "configuration")
	files[path] = config
	path, _ = d101preinput.InputPath(op, "typed-target")
	files[path] = target
	return files, read
}
func TestPreIntentInputHelperReadsOnlyIndependentFixedOriginals(t *testing.T) {
	files, read := preInputFixture(t)
	wire, err := readFixed(d101preinput.Action, installationPath, read)
	var response map[string]json.RawMessage
	if err != nil || json.Unmarshal(wire, &response) != nil || len(response) != 5 || len(wire) > 144<<10 {
		t.Fatal("fixed pre-input unavailable", err)
	}
	var encoded string
	json.Unmarshal(response["preIntentInstallationBytesBase64url"], &encoded)
	actual, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || string(actual) != string(files[d101preinput.BindingsPath].Bytes) {
		t.Fatal("changed original")
	}
}
func TestPreIntentInputHelperRejectsMissingChangedAndReboundInputs(t *testing.T) {
	for _, mode := range []string{"missing", "config", "target", "bindings", "drift"} {
		t.Run(mode, func(t *testing.T) {
			files, read := preInputFixture(t)
			path, _ := d101preinput.InputPath(strings.Repeat("a", 32), "configuration")
			switch mode {
			case "missing":
				delete(files, path)
			case "config":
				files[path] = selectedWire([]byte("changed"))
			case "target":
				path, _ = d101preinput.InputPath(strings.Repeat("a", 32), "typed-target")
				files[path] = selectedWire([]byte("changed"))
			case "bindings":
				delete(files, d101preinput.BindingsPath)
			case "drift":
				original := read
				calls := 0
				read = func(p string, limit int64) (d101custody.Original, error) {
					value, err := original(p, limit)
					if p == path {
						calls++
						if calls > 1 {
							value = selectedWire(append(append([]byte{}, value.Bytes...), ' '))
						}
					}
					return value, err
				}
			}
			if _, err := readPreIntentInputs(read); err == nil {
				t.Fatal("mixed pre-input original")
			}
		})
	}
}
func TestPreIntentInputHelperRejectsCallerActionsAndMissingReader(t *testing.T) {
	_, read := preInputFixture(t)
	for _, action := range []string{"read-pre-intent-inputs:/caller", "read-pre-intent-inputs:0", "read-pre-intent-inputs?path=/caller"} {
		if _, err := readFixed(action, installationPath, read); err == nil {
			t.Fatal("caller path allowed")
		}
	}
	if _, err := readPreIntentInputs(nil); err == nil {
		t.Fatal("missing native custody replaced")
	}
}
