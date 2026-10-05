package d101selectedtransport

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101custody"
)

func indexFixture() Index {
	op, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	value := Index{1, IndexKind, op, sha, strings.Repeat("c", 40), map[string]string{}, "fixture-producer", sha, "sha256:" + sha, sha, sha, d101custody.PrivateOriginalPartBytes, "2026-10-06T00:00:00Z", map[string]SourceReference{}}
	for _, id := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		value.ImagePins[id] = "sha256:" + sha
	}
	for _, id := range RequiredOriginalIDs {
		media := "application/json"
		if id == "parserClass" || id == "topologyRootClass" || id == "topologyCanonical" {
			media = "application/octet-stream"
		}
		value.Originals[id] = SourceReference{OriginalPath(op, id), sha, 8, d101custody.PrivateSnapshot{1, 2, 8, 3}, media}
	}
	return value
}
func TestSelectedIndexExactPreIntentShape(t *testing.T) {
	value := indexFixture()
	id := "topology-input:dryLandProjectionPolicy"
	value.Originals[id] = SourceReference{OriginalPath(value.OriginalOp, id), strings.Repeat("d", 64), 64 << 20, d101custody.PrivateSnapshot{1, 4, 64 << 20, 5}, "application/octet-stream"}
	canonical := value.Originals["topologyCanonical"]
	canonical.ByteLength, canonical.Snapshot.ByteLength = 64<<20, 64<<20
	value.Originals["topologyCanonical"] = canonical
	wire, _ := json.Marshal(value)
	got, err := Decode(wire, time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC))
	if err != nil || len(got.Originals) != 16 || got.Originals[id].FilePath != OriginalPath(value.OriginalOp, id) {
		t.Fatal("bounded data-only pre-intent index refused", err)
	}
}
func TestSelectedIndexRejectsUnknownDuplicateMissingAndFutureFields(t *testing.T) {
	wire, _ := json.Marshal(indexFixture())
	for _, changed := range [][]byte{
		append(append([]byte{}, wire...), []byte(" {}")...),
		[]byte(strings.Replace(string(wire), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1)),
		[]byte(strings.Replace(string(wire), `"schemaVersion":1`, `"schemaVersion":1,"approvalIntentSha256":"future"`, 1)),
		[]byte(strings.Replace(string(wire), `"partBytes":1048576`, `"partBytes":null`, 1)),
		[]byte(strings.Replace(string(wire), `"capturedAtUtc":"2026-10-06T00:00:00Z"`, `"capturedAtUtc":"2027-10-06T00:00:00Z"`, 1)),
	} {
		if _, err := Decode(changed, time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)); err == nil {
			t.Fatal("invalid original accepted")
		}
	}
}
func TestSelectedIndexRejectsPathSnapshotCapsAndRebinding(t *testing.T) {
	for _, mode := range []string{"path", "missing", "snapshot", "scenario-cap", "class-cap", "target-rebind", "extra-id", "media"} {
		t.Run(mode, func(t *testing.T) {
			value := indexFixture()
			id := "selected-scenario.json"
			ref := value.Originals[id]
			switch mode {
			case "path":
				ref.FilePath = "/etc/opensamguk/d101/signing-key.json"
			case "missing":
				delete(value.Originals, "configuration")
			case "snapshot":
				ref.Snapshot.Inode = 0
			case "scenario-cap":
				ref.ByteLength = 16<<20 + 1
				ref.Snapshot.ByteLength = ref.ByteLength
			case "class-cap":
				id = "parserClass"
				ref = value.Originals[id]
				ref.ByteLength = 2<<20 + 1
				ref.Snapshot.ByteLength = ref.ByteLength
			case "target-rebind":
				value.TargetFingerprint = strings.Repeat("e", 64)
			case "extra-id":
				value.Originals["topology-input:../key"] = ref
			case "media":
				ref.MediaType = "text/plain"
			}
			value.Originals[id] = ref
			wire, _ := json.Marshal(value)
			if _, err := Decode(wire, time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)); err == nil {
				t.Fatal("unsafe capture index accepted")
			}
		})
	}
	for _, id := range []string{"rootToken", "topology-input:..", "topology-input:/absolute", "topology-input:a/../b", "topology-input:a//b"} {
		if ValidSourceID(id) {
			t.Fatal("unsafe logical ID", id)
		}
	}
}
