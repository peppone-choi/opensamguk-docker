package d101preinput

import (
	"encoding/json"
	"strings"
	"testing"
)

func bindingFixture() Bindings {
	sha := strings.Repeat("a", 64)
	b := Bindings{1, Kind, strings.Repeat("b", 32), sha, strings.Repeat("c", 40), map[string]string{}, Reference{sha, 8}, Reference{sha, 8}, "/reviewed/release"}
	for _, id := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		b.ImagePins[id] = "sha256:" + sha
	}
	return b
}
func TestPreIntentInputBindingsAreIndependentOfFutureCapture(t *testing.T) {
	b := bindingFixture()
	wire, _ := json.Marshal(b)
	got, err := Decode(wire)
	if err != nil || got.OriginalOp != b.OriginalOp {
		t.Fatal(err)
	}
	path, err := InputPath(b.OriginalOp, "configuration")
	if err != nil || path != InputDirectory+"/"+b.OriginalOp+"/configuration.json" {
		t.Fatal("caller path chosen")
	}
	if _, err = InputPath(b.OriginalOp, "rootToken"); err == nil {
		t.Fatal("non-input role allowed")
	}
}
func TestPreIntentInputBindingsRejectFutureFieldsDuplicateAndInvalidShape(t *testing.T) {
	wire, _ := json.Marshal(bindingFixture())
	for _, bad := range [][]byte{
		[]byte(strings.Replace(string(wire), `"schemaVersion":1`, `"schemaVersion":1,"captureIndexSha256":"future"`, 1)),
		[]byte(strings.Replace(string(wire), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1)),
		[]byte(strings.Replace(string(wire), `"byteLength":8`, `"byteLength":null`, 1)),
		[]byte(strings.Replace(string(wire), `"byteLength":8`, `"byteLength":8,"filePath":"/caller"`, 1)),
		append(append([]byte{}, wire...), []byte(" {}")...), {0xff},
	} {
		if _, err := Decode(bad); err == nil {
			t.Fatal("invalid pre-input binding")
		}
	}
}
func TestPreIntentInputBindingsRejectMissingPinsCapsAndUnreviewedPath(t *testing.T) {
	for _, mode := range []string{"root", "relative", "alias", "target-pin", "config-cap", "target-cap", "image-missing"} {
		t.Run(mode, func(t *testing.T) {
			b := bindingFixture()
			switch mode {
			case "root":
				b.ArtifactsRoot = "/"
			case "relative":
				b.ArtifactsRoot = "release"
			case "alias":
				b.ArtifactsRoot = "/reviewed/../release"
			case "target-pin":
				b.TypedTarget.RawSHA = strings.Repeat("d", 64)
			case "config-cap":
				b.Configuration.ByteLength = 64<<10 + 1
			case "target-cap":
				b.TypedTarget.ByteLength = 16<<10 + 1
			case "image-missing":
				delete(b.ImagePins, "game-api")
			}
			wire, _ := json.Marshal(b)
			if _, err := Decode(wire); err == nil {
				t.Fatal("invalid fixed source accepted")
			}
		})
	}
}
