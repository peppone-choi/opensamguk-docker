// Package d101preinput describes inputs before selection and signing. It is
// separate from the completed capture index and contains no future receipt.
package d101preinput

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
)

const BindingsPath = "/etc/opensamguk/d101/pre-intent-inputs.json"
const InputDirectory = "/etc/opensamguk/d101/pre-intent-inputs"
const Action = "read-pre-intent-inputs"
const Kind = "D101_PRE_INTENT_INPUT_BINDINGS_V1"

type Reference struct {
	RawSHA     string `json:"rawSha256"`
	ByteLength uint64 `json:"byteLength"`
}
type Bindings struct {
	SchemaVersion     int               `json:"schemaVersion"`
	Kind              string            `json:"kind"`
	OriginalOp        string            `json:"originalOp"`
	TargetFingerprint string            `json:"typedTargetFingerprint"`
	AppSourceSHA      string            `json:"appSourceSha"`
	ImagePins         map[string]string `json:"imagePins"`
	Configuration     Reference         `json:"configurationOriginal"`
	TypedTarget       Reference         `json:"typedTargetOriginal"`
	ArtifactsRoot     string            `json:"artifactsRoot"`
}

func InputPath(op, role string) (string, error) {
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(op) || role != "configuration" && role != "typed-target" {
		return "", d101custody.ErrUnavailable
	}
	return filepath.Join(InputDirectory, op, role+".json"), nil
}

func exact(wire []byte, keys []string) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(wire, &fields) != nil || len(fields) != len(keys) {
		return d101custody.ErrUnavailable
	}
	for _, key := range keys {
		if raw, ok := fields[key]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return d101custody.ErrUnavailable
		}
	}
	return nil
}
func rejectDuplicateKeys(wire []byte) error {
	d := json.NewDecoder(bytes.NewReader(wire))
	var walk func() error
	walk = func() error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			if delim == '{' {
				seen := map[string]bool{}
				for d.More() {
					name, err := d.Token()
					key, ok := name.(string)
					if err != nil || !ok || seen[key] {
						return d101custody.ErrUnavailable
					}
					seen[key] = true
					if err := walk(); err != nil {
						return err
					}
				}
			} else if delim == '[' {
				for d.More() {
					if err := walk(); err != nil {
						return err
					}
				}
			} else {
				return d101custody.ErrUnavailable
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if walk() != nil {
		return d101custody.ErrUnavailable
	}
	if _, err := d.Token(); err != io.EOF {
		return d101custody.ErrUnavailable
	}
	return nil
}
func Decode(wire []byte) (Bindings, error) {
	var value Bindings
	keys := []string{"schemaVersion", "kind", "originalOp", "typedTargetFingerprint", "appSourceSha", "imagePins", "configurationOriginal", "typedTargetOriginal", "artifactsRoot"}
	if len(wire) == 0 || len(wire) > 16<<10 || !utf8.Valid(wire) || exact(wire, keys) != nil || rejectDuplicateKeys(wire) != nil {
		return Bindings{}, d101custody.ErrUnavailable
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(wire, &fields)
	for _, key := range []string{"configurationOriginal", "typedTargetOriginal"} {
		if exact(fields[key], []string{"rawSha256", "byteLength"}) != nil {
			return Bindings{}, d101custody.ErrUnavailable
		}
	}
	d := json.NewDecoder(bytes.NewReader(wire))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil {
		return Bindings{}, d101custody.ErrUnavailable
	}
	sha := regexp.MustCompile(`^[a-f0-9]{64}$`)
	if value.SchemaVersion != 1 || value.Kind != Kind || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(value.OriginalOp) || !sha.MatchString(value.TargetFingerprint) || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(value.AppSourceSHA) ||
		!sha.MatchString(value.Configuration.RawSHA) || value.Configuration.ByteLength == 0 || value.Configuration.ByteLength > 64<<10 || value.TypedTarget.RawSHA != value.TargetFingerprint || value.TypedTarget.ByteLength == 0 || value.TypedTarget.ByteLength > 16<<10 ||
		!filepath.IsAbs(value.ArtifactsRoot) || filepath.Clean(value.ArtifactsRoot) != value.ArtifactsRoot || value.ArtifactsRoot == "/" || len(value.ImagePins) != 5 {
		return Bindings{}, d101custody.ErrUnavailable
	}
	for _, id := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		if !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(value.ImagePins[id]) {
			return Bindings{}, d101custody.ErrUnavailable
		}
	}
	return value, nil
}
