package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"opensamguk-deployer/internal/d101custody"
	"testing"
)

func fixture(t *testing.T) (map[string]d101custody.Original, privateReader) {
	t.Helper()
	raw := func(wire []byte) d101custody.Original {
		sum := sha256.Sum256(wire)
		return d101custody.Original{Bytes: wire, SHA256: hex.EncodeToString(sum[:])}
	}
	config := installation{1, "D101_NATIVE_READER_BINDINGS_V1", "/fixed/manifest", "/fixed/clock", map[string]string{}, "/fixed/token", "/fixed/selected"}
	files := map[string]d101custody.Original{}
	for _, id := range originalIDs {
		config.OriginalFiles[id] = "/fixed/" + id
		files[config.OriginalFiles[id]] = raw([]byte("SYNTHETIC_ONLY " + id))
	}
	config.OriginalFiles["readerBindings"] = installationPath
	wire, _ := json.Marshal(config)
	files[installationPath] = raw(wire)
	for _, path := range []string{config.ManifestFile, config.ClockFile, config.SelectedEnvelopeFile} {
		files[path] = raw([]byte("SYNTHETIC_ONLY envelope"))
	}
	files[config.RootTokenFile] = raw([]byte(`{"schemaVersion":1,"rootToken":"synthetic-token"}`))
	return files, func(path string, limit int64) (d101custody.Original, error) {
		value, ok := files[path]
		if !ok || int64(len(value.Bytes)) > limit {
			return d101custody.Original{}, d101custody.ErrUnavailable
		}
		return value, nil
	}
}
func TestFixedReaderActionsBindExactInstallationOriginal(t *testing.T) {
	files, read := fixture(t)
	for _, action := range []string{"read-originals", "read-token", "read-selected"} {
		wire, err := readFixed(action, installationPath, read)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(wire, &fields) != nil {
			t.Fatal("invalid envelope")
		}
		var pin string
		json.Unmarshal(fields["installationSha256"], &pin)
		if pin != files[installationPath].SHA256 {
			t.Fatal("installation unbound")
		}
		if action == "read-originals" {
			var originals map[string]string
			json.Unmarshal(fields["originals"], &originals)
			raw, _ := base64.RawURLEncoding.DecodeString(originals["readerBindings"])
			if string(raw) != string(files[installationPath].Bytes) || len(originals) != 14 {
				t.Fatal("original missing")
			}
		}
	}
}
func TestMissingChangedOrCallerSelectedInputsStayClosed(t *testing.T) {
	for _, mode := range []string{"missing", "changed", "token", "unknown"} {
		files, read := fixture(t)
		action := "read-originals"
		switch mode {
		case "missing":
			delete(files, "/fixed/approvalReceipt")
		case "changed":
			calls := 0
			originalRead := read
			read = func(path string, limit int64) (d101custody.Original, error) {
				calls++
				v, e := originalRead(path, limit)
				if calls > 1 && path == installationPath {
					v.SHA256 = "changed"
				}
				return v, e
			}
		case "token":
			files["/fixed/token"] = d101custody.Original{Bytes: []byte(`{"schemaVersion":1,"rootToken":"bad\nvalue"}`)}
			action = "read-token"
		case "unknown":
			action = "/caller/path"
		}
		if _, err := readFixed(action, installationPath, read); err == nil {
			t.Fatal("accepted " + mode)
		}
	}
}
func TestExactJSONRejectsDuplicateNestedNullAliasTrailingAndInvalidUTF8(t *testing.T) {
	for _, wire := range [][]byte{[]byte(`{"schemaVersion":1,"schemaVersion":1,"rootToken":"x"}`), []byte(`{"schemaVersion":1,"rootToken":null}`), []byte(`{"SchemaVersion":1,"rootToken":"x"}`), []byte(`{"schemaVersion":1,"rootToken":"x"}{}`), {0xff}} {
		var token tokenEnvelope
		if exactJSON(wire, []string{"schemaVersion", "rootToken"}, &token) == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
}
