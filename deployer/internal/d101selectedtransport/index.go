// Package d101selectedtransport defines the fixed pre-intent byte transport.
// Its native index is not an approval, semantic PASS or installed authority.
package d101selectedtransport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
)

const IndexPath = "/etc/opensamguk/d101/selected-capture-index.json"
const OriginalDirectory = "/etc/opensamguk/d101/selected-capture-originals"
const IndexKind = "D101_SELECTED_CAPTURE_INDEX_V1"
const IndexAction = "read-selected-source-index"
const PartActionPrefix = "read-selected-source-part:"

var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var opPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var sourcePattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var producerPattern = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
var topologyPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,256}$`)

var RequiredOriginalIDs = []string{"selectedEnvelope", "selectedReceipt", "typedTarget", "configuration", "parserClass", "resolverDecision", "topologyRootClass", "topologyCanonical", "selectedWorld", "parsedOptions", "tiles.json", "world.json", "roads.json", "selected-scenario.json", "classpath-scenario.json"}

type SourceReference struct {
	FilePath   string                      `json:"filePath"`
	RawSHA     string                      `json:"rawSha256"`
	ByteLength uint64                      `json:"byteLength"`
	Snapshot   d101custody.PrivateSnapshot `json:"snapshot"`
	MediaType  string                      `json:"mediaType"`
}
type Index struct {
	SchemaVersion       int                        `json:"schemaVersion"`
	Kind                string                     `json:"kind"`
	OriginalOp          string                     `json:"originalOp"`
	TargetFingerprint   string                     `json:"typedTargetFingerprint"`
	AppSourceSHA        string                     `json:"appSourceSha"`
	ImagePins           map[string]string          `json:"imagePins"`
	ProducerIdentity    string                     `json:"trustedProducerIdentity"`
	ProducerContainerID string                     `json:"producerContainerId"`
	ProducerImageID     string                     `json:"producerImageId"`
	SelectedEnvelopeSHA string                     `json:"selectedEnvelopeSha256"`
	SelectedReceiptSHA  string                     `json:"selectedReceiptSha256"`
	PartBytes           uint64                     `json:"partBytes"`
	CapturedAtUTC       string                     `json:"capturedAtUtc"`
	Originals           map[string]SourceReference `json:"originals"`
}

func ValidSourceID(id string) bool {
	for _, required := range RequiredOriginalIDs {
		if id == required {
			return true
		}
	}
	path := strings.TrimPrefix(id, "topology-input:")
	return path != id && topologyPattern.MatchString(path) && !filepath.IsAbs(path) && path != "." && path != ".." && filepath.Clean(path) == path && !strings.HasPrefix(path, "../") && !strings.Contains(path, "/../")
}

// Data-only immutable capture namespace. An index cannot select a key/token/
// password path. Source ID hashes are filenames, not source-content SHA labels.
func OriginalPath(op, id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(OriginalDirectory, op, hex.EncodeToString(sum[:])+".bin")
}

func exactShape(wire []byte, shape reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(wire), []byte("null")) {
		return d101custody.ErrUnavailable
	}
	switch shape.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(wire, &fields) != nil || len(fields) != shape.NumField() {
			return d101custody.ErrUnavailable
		}
		for i := 0; i < shape.NumField(); i++ {
			field := shape.Field(i)
			raw, ok := fields[field.Tag.Get("json")]
			if !ok || exactShape(raw, field.Type) != nil {
				return d101custody.ErrUnavailable
			}
		}
	case reflect.Map:
		var fields map[string]json.RawMessage
		if json.Unmarshal(wire, &fields) != nil {
			return d101custody.ErrUnavailable
		}
		for _, raw := range fields {
			if exactShape(raw, shape.Elem()) != nil {
				return d101custody.ErrUnavailable
			}
		}
	}
	return nil
}
func rejectDuplicates(wire []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	var walk func() error
	walk = func() error {
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
					if err := walk(); err != nil {
						return err
					}
				}
			} else if delim == '[' {
				for decoder.More() {
					if err := walk(); err != nil {
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
	if walk() != nil {
		return d101custody.ErrUnavailable
	}
	if _, err := decoder.Token(); err != io.EOF {
		return d101custody.ErrUnavailable
	}
	return nil
}
func Decode(wire []byte, now time.Time) (Index, error) {
	closed := Index{}
	var value Index
	if len(wire) == 0 || len(wire) > 64<<10 || !utf8.Valid(wire) || rejectDuplicates(wire) != nil || exactShape(wire, reflect.TypeOf(value)) != nil {
		return closed, d101custody.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		return closed, d101custody.ErrUnavailable
	}
	if value.SchemaVersion != 1 || value.Kind != IndexKind || !opPattern.MatchString(value.OriginalOp) || !shaPattern.MatchString(value.TargetFingerprint) || !sourcePattern.MatchString(value.AppSourceSHA) || !producerPattern.MatchString(value.ProducerIdentity) || !shaPattern.MatchString(value.ProducerContainerID) || !strings.HasPrefix(value.ProducerImageID, "sha256:") || !shaPattern.MatchString(strings.TrimPrefix(value.ProducerImageID, "sha256:")) || !shaPattern.MatchString(value.SelectedEnvelopeSHA) || !shaPattern.MatchString(value.SelectedReceiptSHA) || value.PartBytes != d101custody.PrivateOriginalPartBytes || len(value.ImagePins) != 5 || len(value.Originals) < len(RequiredOriginalIDs) || len(value.Originals) > len(RequiredOriginalIDs)+32 {
		return closed, d101custody.ErrUnavailable
	}
	for _, id := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		pin, ok := value.ImagePins[id]
		if !ok || !strings.HasPrefix(pin, "sha256:") || !shaPattern.MatchString(strings.TrimPrefix(pin, "sha256:")) {
			return closed, d101custody.ErrUnavailable
		}
	}
	for _, id := range RequiredOriginalIDs {
		if _, ok := value.Originals[id]; !ok {
			return closed, d101custody.ErrUnavailable
		}
	}
	at, err := time.Parse(time.RFC3339Nano, value.CapturedAtUTC)
	if err != nil || !strings.HasSuffix(value.CapturedAtUTC, "Z") || at.Unix() <= 0 || now.Unix() <= 0 || at.After(now) {
		return closed, d101custody.ErrUnavailable
	}
	for id, ref := range value.Originals {
		if !ValidSourceID(id) || ref.FilePath != OriginalPath(value.OriginalOp, id) || !shaPattern.MatchString(ref.RawSHA) || ref.ByteLength == 0 || ref.ByteLength > d101custody.PrivateOriginalMaxBytes || ref.Snapshot.ByteLength != ref.ByteLength || ref.Snapshot.Device == 0 || ref.Snapshot.Inode == 0 || ref.Snapshot.ModifiedAtUnixNano <= 0 {
			return closed, d101custody.ErrUnavailable
		}
		class := id == "parserClass" || id == "topologyRootClass"
		binary := class || id == "topologyCanonical"
		input := strings.HasPrefix(id, "topology-input:")
		if (binary && ref.MediaType != "application/octet-stream") || (class && ref.ByteLength > 2<<20) ||
			(input && ref.MediaType != "application/json" && ref.MediaType != "application/octet-stream") ||
			(!binary && !input && ref.MediaType != "application/json") {
			return closed, d101custody.ErrUnavailable
		}
		limit := uint64(64 << 20)
		switch id {
		case "selectedEnvelope":
			limit = 96 << 10
		case "selectedReceipt", "configuration", "resolverDecision", "parsedOptions":
			limit = 64 << 10
		case "typedTarget":
			limit = 16 << 10
		case "selected-scenario.json", "classpath-scenario.json":
			limit = 16 << 20
		}
		if ref.ByteLength > limit {
			return closed, d101custody.ErrUnavailable
		}
	}
	if value.Originals["selectedEnvelope"].RawSHA != value.SelectedEnvelopeSHA || value.Originals["selectedReceipt"].RawSHA != value.SelectedReceiptSHA || value.Originals["typedTarget"].RawSHA != value.TargetFingerprint {
		return closed, d101custody.ErrUnavailable
	}
	return value, nil
}
