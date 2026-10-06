// Fixed root-only native custody bridge for Gateway. Private output belongs to
// its bounded child pipe; errors never contain paths, originals or credentials.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101preinput"
	"os"
	"regexp"
	"time"
	"unicode/utf8"
)

const installationPath = "/etc/opensamguk/d101/reader-installation.json"

var originalIDs = []string{"approvalIntent", "deploymentCard", "approvalReceipt", "combinedCiReceipt",
	"selectedSourceReceipt", "isolatedSeedTickReceipt", "spaceInventoryReceipt", "configInventory",
	"commandPlan", "recoveryPlan", "readerBindings", "evidenceCatalog", "reviewBasis", "approvedReceiptProvenance"}

type installation struct {
	SchemaVersion        int               `json:"schemaVersion"`
	Kind                 string            `json:"kind"`
	ManifestFile         string            `json:"manifestFile"`
	ClockFile            string            `json:"clockFile"`
	OriginalFiles        map[string]string `json:"originalFiles"`
	RootTokenFile        string            `json:"rootTokenFile"`
	SelectedEnvelopeFile string            `json:"selectedEnvelopeFile"`
}
type bundle struct {
	SchemaVersion    int               `json:"schemaVersion"`
	InstallationSHA  string            `json:"installationSha256"`
	ManifestEnvelope string            `json:"manifestEnvelopeBase64url"`
	ClockEnvelope    string            `json:"clockEnvelopeBase64url"`
	Originals        map[string]string `json:"originals"`
}
type tokenEnvelope struct {
	SchemaVersion int    `json:"schemaVersion"`
	RootToken     string `json:"rootToken"`
}
type tokenResponse struct {
	SchemaVersion   int    `json:"schemaVersion"`
	InstallationSHA string `json:"installationSha256"`
	RootToken       string `json:"rootToken"`
}
type privateReader func(string, int64) (d101custody.Original, error)

func exactJSON(wire []byte, keys []string, target any) error {
	if !utf8.Valid(wire) {
		return d101custody.ErrUnavailable
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(wire, &fields) != nil || len(fields) != len(keys) {
		return d101custody.ErrUnavailable
	}
	for _, key := range keys {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return d101custody.ErrUnavailable
		}
	}
	// Decoder token walk rejects duplicates at every nested object.
	decoder := json.NewDecoder(bytes.NewReader(wire))
	var value func() error
	value = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			if delim == '{' {
				seen := map[string]bool{}
				for decoder.More() {
					name, err := decoder.Token()
					if err != nil {
						return err
					}
					key, ok := name.(string)
					if !ok || seen[key] {
						return d101custody.ErrUnavailable
					}
					seen[key] = true
					if err := value(); err != nil {
						return err
					}
				}
			} else if delim == '[' {
				for decoder.More() {
					if err := value(); err != nil {
						return err
					}
				}
			} else {
				return d101custody.ErrUnavailable
			}
			_, err = decoder.Token()
			return err
		}
		return nil
	}
	if value() != nil {
		return d101custody.ErrUnavailable
	}
	if _, err := decoder.Token(); err != io.EOF {
		return d101custody.ErrUnavailable
	}
	typed := json.NewDecoder(bytes.NewReader(wire))
	typed.DisallowUnknownFields()
	if typed.Decode(target) != nil {
		return d101custody.ErrUnavailable
	}
	return nil
}

func readFixed(action, path string, read privateReader) ([]byte, error) {
	if action == currentFreezeAction {
		if path != installationPath {
			return nil, d101custody.ErrUnavailable
		}
		return readCurrentFreeze(read)
	}
	if action == d101preinput.Action {
		return readPreIntentInputs(read)
	}
	if read == nil || action != "read-originals" && action != "read-token" && action != "read-selected" && action != "read-command-originals" && !selectedTransportAction(action) && !evidenceTransportAction(action) {
		return nil, d101custody.ErrUnavailable
	}
	original, err := read(path, 64<<10)
	if err != nil {
		return nil, err
	}
	var config installation
	if exactJSON(original.Bytes, []string{"schemaVersion", "kind", "manifestFile", "clockFile", "originalFiles", "rootTokenFile", "selectedEnvelopeFile"}, &config) != nil ||
		config.SchemaVersion != 1 || config.Kind != "D101_NATIVE_READER_BINDINGS_V1" ||
		len(config.OriginalFiles) != len(originalIDs) {
		return nil, d101custody.ErrUnavailable
	}
	for _, id := range originalIDs {
		if config.OriginalFiles[id] == "" {
			return nil, d101custody.ErrUnavailable
		}
	}
	if evidenceTransportAction(action) {
		return readEvidenceSources(action, path, original, read, d101custody.CapturePrivateOriginal, d101custody.InspectPrivateSnapshot, d101custody.ReadPrivatePart)
	}
	if selectedTransportAction(action) {
		return readSelectedSources(action, path, original, read, d101custody.InspectPrivateSnapshot, d101custody.ReadPrivatePart, time.Now())
	}
	if action == "read-command-originals" {
		return readCommandOriginals(config, original, path, read)
	}
	if action == "read-selected" {
		selected, err := read(config.SelectedEnvelopeFile, 96<<10)
		if err != nil {
			return nil, err
		}
		after, err := read(path, 64<<10)
		if err != nil || after.SHA256 != original.SHA256 || !bytes.Equal(after.Bytes, original.Bytes) {
			return nil, d101custody.ErrUnavailable
		}
		return json.Marshal(struct {
			SchemaVersion    int    `json:"schemaVersion"`
			InstallationSHA  string `json:"installationSha256"`
			SelectedEnvelope string `json:"selectedEnvelopeBase64url"`
		}{1, original.SHA256, base64.RawURLEncoding.EncodeToString(selected.Bytes)})
	}
	if action == "read-token" {
		raw, err := read(config.RootTokenFile, 16<<10)
		if err != nil {
			return nil, err
		}
		var token tokenEnvelope
		if exactJSON(raw.Bytes, []string{"schemaVersion", "rootToken"}, &token) != nil || token.SchemaVersion != 1 ||
			len(token.RootToken) == 0 || len(token.RootToken) > 4096 {
			return nil, d101custody.ErrUnavailable
		}
		for _, b := range []byte(token.RootToken) {
			if b < 33 || b > 126 {
				return nil, d101custody.ErrUnavailable
			}
		}
		after, err := read(path, 64<<10)
		if err != nil || after.SHA256 != original.SHA256 || !bytes.Equal(after.Bytes, original.Bytes) {
			return nil, d101custody.ErrUnavailable
		}
		return json.Marshal(tokenResponse{1, original.SHA256, token.RootToken})
	}
	manifest, err := read(config.ManifestFile, 64<<10)
	if err != nil {
		return nil, err
	}
	clock, err := read(config.ClockFile, 64<<10)
	if err != nil {
		return nil, err
	}
	result := bundle{1, original.SHA256, base64.RawURLEncoding.EncodeToString(manifest.Bytes),
		base64.RawURLEncoding.EncodeToString(clock.Bytes), make(map[string]string, len(originalIDs))}
	for _, id := range originalIDs {
		raw, err := read(config.OriginalFiles[id], 64<<10)
		if err != nil {
			return nil, err
		}
		if id == "readerBindings" && !bytes.Equal(raw.Bytes, original.Bytes) {
			return nil, d101custody.ErrUnavailable
		}
		result.Originals[id] = base64.RawURLEncoding.EncodeToString(raw.Bytes)
	}
	after, err := read(path, 64<<10)
	if err != nil || after.SHA256 != original.SHA256 || !bytes.Equal(after.Bytes, original.Bytes) {
		return nil, d101custody.ErrUnavailable
	}
	return json.Marshal(result)
}

func main() {
	if len(os.Args) != 2 {
		fail()
		return
	}
	wire, err := readFixed(os.Args[1], installationPath, d101custody.ReadPrivate)
	if err != nil || len(wire) > 2<<20 {
		fail()
		return
	}
	defer clear(wire)
	if _, err = os.Stdout.Write(wire); err != nil {
		fail()
	}
}
func fail() { _, _ = io.WriteString(os.Stderr, "D101 private source unavailable\n"); os.Exit(1) }

// Read only the four fixed native originals required by the pinned commandPlan.
// Their paths are selected by that original, not by a request or shell argument.
func readCommandOriginals(config installation, installationOriginal d101custody.Original, path string, read privateReader) ([]byte, error) {
	command, err := read(config.OriginalFiles["commandPlan"], 32<<10)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	keys := []string{"schemaVersion", "kind", "operationId", "approvalIntentSha256", "targetFingerprint", "appSourceSha", "dockerSourceSha", "newImageDigests", "selectedSourceReceiptSha256", "selectedEnvelopeSha256", "capsReaderSha256", "seedEntrypoint", "stages", "destructiveCutoffUnix", "resources"}
	if exactJSON(command.Bytes, keys, &fields) != nil {
		return nil, d101custody.ErrUnavailable
	}
	var scope struct {
		SchemaVersion       int    `json:"schemaVersion"`
		Kind                string `json:"kind"`
		OperationID         string `json:"operationId"`
		CapsReaderSHA       string `json:"capsReaderSha256"`
		SelectedEnvelopeSHA string `json:"selectedEnvelopeSha256"`
	}
	// Select exact fields without silently coercing null/string/unknown values.
	if json.Unmarshal(fields["schemaVersion"], &scope.SchemaVersion) != nil || json.Unmarshal(fields["kind"], &scope.Kind) != nil || json.Unmarshal(fields["operationId"], &scope.OperationID) != nil || json.Unmarshal(fields["capsReaderSha256"], &scope.CapsReaderSHA) != nil || json.Unmarshal(fields["selectedEnvelopeSha256"], &scope.SelectedEnvelopeSHA) != nil || scope.SchemaVersion != 1 || scope.Kind != "D101_ROOT_CANDIDATE_COMMAND_PLAN_V1" || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(scope.OperationID) {
		return nil, d101custody.ErrUnavailable
	}
	var resources struct {
		Project              string `json:"project"`
		Network              string `json:"network"`
		PostgresVolume       string `json:"postgresVolume"`
		RedisVolume          string `json:"redisVolume"`
		CandidateComposeFile string `json:"candidateComposeFile"`
		CandidateComposeSHA  string `json:"candidateComposeSha256"`
		LiveComposeFile      string `json:"liveComposeFile"`
		LiveComposeSHA       string `json:"liveComposeSha256"`
		CapsReaderFile       string `json:"capsReaderFile"`
	}
	if exactJSON(fields["resources"], []string{"project", "network", "postgresVolume", "redisVolume", "candidateComposeFile", "candidateComposeSha256", "liveComposeFile", "liveComposeSha256", "capsReaderFile"}, &resources) != nil {
		return nil, d101custody.ErrUnavailable
	}
	originals := map[string]string{}
	captured := map[string]d101custody.Original{}
	locations := map[string]struct {
		path, sha string
		limit     int64
	}{"capsReaderOriginal": {resources.CapsReaderFile, scope.CapsReaderSHA, 16 << 10}, "selectedEnvelope": {config.SelectedEnvelopeFile, scope.SelectedEnvelopeSHA, 96 << 10}, "candidateCompose": {resources.CandidateComposeFile, resources.CandidateComposeSHA, 32 << 10}, "liveCompose": {resources.LiveComposeFile, resources.LiveComposeSHA, 32 << 10}}
	for id, location := range locations {
		raw, err := read(location.path, location.limit)
		if err != nil || raw.SHA256 != location.sha {
			return nil, d101custody.ErrUnavailable
		}
		captured[id] = raw
		originals[id] = base64.RawURLEncoding.EncodeToString(raw.Bytes)
	}
	for id, location := range locations {
		after, err := read(location.path, location.limit)
		if err != nil || after.SHA256 != captured[id].SHA256 || !bytes.Equal(after.Bytes, captured[id].Bytes) {
			return nil, d101custody.ErrUnavailable
		}
	}
	afterCommand, err := read(config.OriginalFiles["commandPlan"], 32<<10)
	if err != nil || afterCommand.SHA256 != command.SHA256 || !bytes.Equal(afterCommand.Bytes, command.Bytes) {
		return nil, d101custody.ErrUnavailable
	}
	after, err := read(path, 64<<10)
	if err != nil || after.SHA256 != installationOriginal.SHA256 || !bytes.Equal(after.Bytes, installationOriginal.Bytes) {
		return nil, d101custody.ErrUnavailable
	}
	return json.Marshal(struct {
		SchemaVersion   int               `json:"schemaVersion"`
		InstallationSHA string            `json:"installationSha256"`
		CommandPlanSHA  string            `json:"commandPlanSha256"`
		Originals       map[string]string `json:"originals"`
	}{1, installationOriginal.SHA256, command.SHA256, originals})
}
