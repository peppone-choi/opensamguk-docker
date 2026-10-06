package d101evidencetransport

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func evidenceScopeFixture() Scope {
	pins := func() map[string]string {
		values := map[string]string{}
		for _, id := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
			values[id] = "sha256:" + strings.Repeat("a", 64)
		}
		return values
	}
	return Scope{
		OperationID: strings.Repeat("1", 32), ServerID: "pep", WorldID: 1,
		TargetFingerprint: strings.Repeat("b", 64),
		TypedTargetRef:    RawReference{"raw:typed-target", strings.Repeat("b", 64), 123, "application/json"},
		AppSourceSHA:      strings.Repeat("c", 40), DockerSourceSHA: strings.Repeat("d", 40),
		OldImageDigests: pins(), NewImageDigests: pins(), InitialPublicRevision: "1",
		Window: Window{1, 2, 3}, SpaceBudget: SpaceBudget{},
	}
}

func TestEvidenceRawReferenceUsesExistingFourFieldWire(t *testing.T) {
	for _, media := range []string{"application/json", "application/xml", "application/zip", "text/plain", "application/octet-stream"} {
		t.Run(media, func(t *testing.T) {
			ref := RawReference{"raw:" + strings.Repeat("a", 123), strings.Repeat("b", 64), OriginalMaxBytes, media}
			wire, _ := json.Marshal(ref)
			got, err := DecodeRawReference(wire)
			if err != nil || got != ref {
				t.Fatal("existing RawRef maximum length/media refused")
			}
		})
	}
}

func TestEvidenceRawReferenceRejectsMalformedAndUnregisteredReferences(t *testing.T) {
	base := RawReference{"raw:ci:attempt-3", strings.Repeat("a", 64), 1, "application/zip"}
	for _, mode := range []string{"path", "url", "secret-id", "unknown-id", "id-long", "sha-upper", "zero", "too-large", "media", "null", "string-length", "fractional-length", "duplicate", "unknown-key", "trailing", "invalid-utf8"} {
		t.Run(mode, func(t *testing.T) {
			ref := base
			switch mode {
			case "path":
				ref.LogicalID = "raw:../root-key"
			case "url":
				ref.LogicalID = "raw:https://example.test"
			case "secret-id":
				ref.LogicalID = "rootToken"
			case "unknown-id":
				ref.LogicalID = "arbitrary"
			case "id-long":
				ref.LogicalID = "raw:" + strings.Repeat("a", 124)
			case "sha-upper":
				ref.SHA256 = strings.Repeat("A", 64)
			case "zero":
				ref.ByteLength = 0
			case "too-large":
				ref.ByteLength = OriginalMaxBytes + 1
			case "media":
				ref.MediaType = "image/png"
			}
			wire, _ := json.Marshal(ref)
			s := string(wire)
			switch mode {
			case "null":
				s = strings.Replace(s, `"byteLength":1`, `"byteLength":null`, 1)
			case "string-length":
				s = strings.Replace(s, `"byteLength":1`, `"byteLength":"1"`, 1)
			case "fractional-length":
				s = strings.Replace(s, `"byteLength":1`, `"byteLength":1.5`, 1)
			case "duplicate":
				s = s[:len(s)-1] + `,"logicalId":"raw:other"}`
			case "unknown-key":
				s = s[:len(s)-1] + `,"filePath":"/etc/key"}`
			case "trailing":
				s += `{}`
			case "invalid-utf8":
				s = string(append([]byte(s), 0xff))
			}
			if _, err := DecodeRawReference([]byte(s)); err == nil {
				t.Fatal("malformed original accepted")
			}
		})
	}
}

func TestEvidenceScopeRejectsDriftNullTypeAndOverflow(t *testing.T) {
	for _, mode := range []string{"op", "server", "world", "target-sha", "target-id", "target-media", "target-cap", "app-sha", "image-extra", "image-missing", "image-digest", "revision-zero", "revision-overflow", "window-order", "bytes-overflow", "inode-overflow", "null-budget", "null-pin", "missing-target", "wrong-world-type", "duplicate-nested", "escaped-duplicate", "unknown-key", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			scope := evidenceScopeFixture()
			switch mode {
			case "op":
				scope.OperationID = strings.Repeat("f", 31)
			case "server":
				scope.ServerID = "other"
			case "world":
				scope.WorldID = 2
			case "target-sha":
				scope.TypedTargetRef.SHA256 = strings.Repeat("f", 64)
			case "target-id":
				scope.TypedTargetRef.LogicalID = "deploymentCard"
			case "target-media":
				scope.TypedTargetRef.MediaType = "application/octet-stream"
			case "target-cap":
				scope.TypedTargetRef.ByteLength = 16<<10 + 1
			case "app-sha":
				scope.AppSourceSHA = strings.Repeat("f", 39)
			case "image-extra":
				scope.NewImageDigests["other"] = "sha256:" + strings.Repeat("f", 64)
			case "image-missing":
				delete(scope.OldImageDigests, "game-redis")
			case "image-digest":
				scope.OldImageDigests["game-redis"] = "latest"
			case "revision-zero":
				scope.InitialPublicRevision = "0"
			case "revision-overflow":
				scope.InitialPublicRevision = "9223372036854775808"
			case "window-order":
				scope.Window.RecoveryDeadlineUnix = 2
			case "bytes-overflow":
				scope.SpaceBudget.BackupBytes = math.MaxUint64 - existingDiskReserveBytes + 1
			case "inode-overflow":
				scope.SpaceBudget.NewFileCount = math.MaxUint64
				scope.SpaceBudget.InodeReserve = 1
			}
			wire, _ := json.Marshal(scope)
			s := string(wire)
			switch mode {
			case "null-budget":
				s = strings.Replace(s, `"BackupBytes":0`, `"BackupBytes":null`, 1)
			case "null-pin":
				s = strings.Replace(s, `"game-redis":"sha256:`+strings.Repeat("a", 64)+`"`, `"game-redis":null`, 1)
			case "missing-target":
				s = strings.Replace(s, `"mediaType":"application/json"`, `"unknown":"application/json"`, 1)
			case "wrong-world-type":
				s = strings.Replace(s, `"worldId":1`, `"worldId":"1"`, 1)
			case "duplicate-nested":
				s = strings.Replace(s, `"BackupBytes":0`, `"BackupBytes":0,"BackupBytes":1`, 1)
			case "escaped-duplicate":
				s = s[:len(s)-1] + `,"op\u0065rationId":"` + scope.OperationID + `"}`
			case "unknown-key":
				s = s[:len(s)-1] + `,"approved":true}`
			case "oversize":
				s += strings.Repeat(" ", MetadataMaxBytes)
			}
			if _, err := DecodeScope([]byte(s)); err == nil {
				t.Fatal("scope drift/type/overflow accepted")
			}
		})
	}
}

func TestEvidenceScopeKeepsExistingBoundaryBudgetAndOriginalMaps(t *testing.T) {
	scope := evidenceScopeFixture()
	scope.SpaceBudget.BackupBytes = math.MaxUint64 - existingDiskReserveBytes
	scope.SpaceBudget.NewFileCount = math.MaxUint64
	scope.InitialPublicRevision = "9223372036854775807"
	scope.Window = Window{math.MaxInt64 - 2, math.MaxInt64 - 1, math.MaxInt64}
	wire, _ := json.Marshal(scope)
	got, err := DecodeScope(wire)
	if err != nil || got.SpaceBudget != scope.SpaceBudget || got.InitialPublicRevision != scope.InitialPublicRevision {
		t.Fatal("existing unsigned budget/signed window boundary changed")
	}
	for i := range wire {
		wire[i] = 0
	}
	scope.OldImageDigests["game-redis"] = "mutated"
	if got.OldImageDigests["game-redis"] != "sha256:"+strings.Repeat("a", 64) {
		t.Fatal("decoded scope retained caller data")
	}
}
