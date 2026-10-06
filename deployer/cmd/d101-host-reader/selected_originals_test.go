package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101custody"
	transport "opensamguk-deployer/internal/d101selectedtransport"
)

func selectedWire(wire []byte) d101custody.Original {
	sum := sha256.Sum256(wire)
	return d101custody.Original{Bytes: wire, SHA256: hex.EncodeToString(sum[:])}
}
func selectedFixture(t *testing.T) (map[string]d101custody.Original, privateReader, snapshotInspector, partReader) {
	t.Helper()
	files, read := fixture(t)
	op, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	index := transport.Index{SchemaVersion: 1, Kind: transport.IndexKind, OriginalOp: op, AppSourceSHA: strings.Repeat("c", 40), ImagePins: map[string]string{}, ProducerIdentity: "fixture-producer", ProducerContainerID: sha, ProducerImageID: "sha256:" + sha, PartBytes: 1 << 20, CapturedAtUTC: "2026-10-06T00:00:00Z", Originals: map[string]transport.SourceReference{}}
	for _, id := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		index.ImagePins[id] = "sha256:" + sha
	}
	for _, id := range transport.RequiredOriginalIDs {
		wire := []byte(`{"synthetic":"` + id + `"}`)
		if id == "world.json" {
			wire = bytes.Repeat([]byte("actual mock transport bytes"), 100000)
		}
		if id == "selectedEnvelope" {
			wire, _ = json.Marshal(map[string]any{"schemaVersion": 1, "originalBytesBase64url": base64.RawURLEncoding.EncodeToString([]byte(`{"synthetic":"selectedReceipt"}`)), "signatureBase64url": base64.RawURLEncoding.EncodeToString(make([]byte, 64))})
		}
		path := transport.OriginalPath(op, id)
		files[path] = selectedWire(wire)
		media := "application/json"
		if id == "parserClass" || id == "topologyRootClass" || id == "topologyCanonical" {
			media = "application/octet-stream"
		}
		index.Originals[id] = transport.SourceReference{FilePath: path, RawSHA: files[path].SHA256, ByteLength: uint64(len(wire)), Snapshot: d101custody.PrivateSnapshot{Device: 1, Inode: uint64(len(index.Originals) + 1), ByteLength: uint64(len(wire)), ModifiedAtUnixNano: 3}, MediaType: media}
	}
	index.TargetFingerprint = index.Originals["typedTarget"].RawSHA
	index.SelectedEnvelopeSHA = index.Originals["selectedEnvelope"].RawSHA
	index.SelectedReceiptSHA = index.Originals["selectedReceipt"].RawSHA
	wire, _ := json.Marshal(index)
	files[transport.IndexPath] = selectedWire(wire)
	inspect := func(path string, snapshot d101custody.PrivateSnapshot) error {
		for _, ref := range index.Originals {
			if path == ref.FilePath && snapshot == ref.Snapshot {
				return nil
			}
		}
		return d101custody.ErrUnavailable
	}
	part := func(path string, snapshot d101custody.PrivateSnapshot, ordinal uint64) (d101custody.PrivatePart, error) {
		if inspect(path, snapshot) != nil || ordinal > (snapshot.ByteLength-1)/(1<<20) {
			return d101custody.PrivatePart{}, d101custody.ErrUnavailable
		}
		offset := ordinal * (1 << 20)
		end := offset + (1 << 20)
		if end > snapshot.ByteLength {
			end = snapshot.ByteLength
		}
		piece := selectedWire(files[path].Bytes[offset:end])
		return d101custody.PrivatePart{Bytes: piece.Bytes, PartSHA256: piece.SHA256, Snapshot: snapshot, PartIndex: ordinal, Offset: offset}, nil
	}
	return files, read, inspect, part
}
func selectedNow() time.Time { return time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC) }
func TestSelectedTransportIndexAndPartsKeepFixedBounds(t *testing.T) {
	files, read, inspect, part := selectedFixture(t)
	bindings := files[installationPath]
	wire, err := readSelectedSources(transport.IndexAction, installationPath, bindings, read, inspect, part, selectedNow())
	var response map[string]json.RawMessage
	if err != nil || json.Unmarshal(wire, &response) != nil || len(response) != 4 {
		t.Fatal("index unavailable", err)
	}
	combined := []byte{}
	for _, action := range []string{transport.PartActionPrefix + "world.json:0", transport.PartActionPrefix + "world.json:1", transport.PartActionPrefix + "world.json:2"} {
		response = nil
		wire, err = readSelectedSources(action, installationPath, bindings, read, inspect, part, selectedNow())
		if err != nil || len(wire) > 2<<20 || json.Unmarshal(wire, &response) != nil || len(response) != 11 {
			t.Fatal("part unavailable", err)
		}
		var encoded string
		json.Unmarshal(response["partBytesBase64url"], &encoded)
		piece, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(piece) > 1<<20 {
			t.Fatal("unbounded part")
		}
		combined = append(combined, piece...)
	}
	if !bytes.Equal(combined, files[transport.OriginalPath(strings.Repeat("a", 32), "world.json")].Bytes) {
		t.Fatal("partial original")
	}
}
func TestSelectedTransportRejectsInvalidActionsAndParts(t *testing.T) {
	for _, action := range []string{transport.PartActionPrefix + "world.json:03", transport.PartActionPrefix + "world.json:-1", transport.PartActionPrefix + "world.json:64", transport.PartActionPrefix + "world.json:3", transport.PartActionPrefix + "rootToken:0", transport.PartActionPrefix + "topology-input:../key:0", "caller-path"} {
		files, read, inspect, part := selectedFixture(t)
		if _, err := readSelectedSources(action, installationPath, files[installationPath], read, inspect, part, selectedNow()); err == nil {
			t.Fatal("caller selection accepted", action)
		}
	}
	if !selectedTransportAction(transport.PartActionPrefix + "topology-input:actual/callback.bin:0") {
		t.Fatal("actual logical input ID refused")
	}
}
func TestSelectedTransportRejectsSnapshotIndexBindingsEnvelopeAndPartDrift(t *testing.T) {
	for _, mode := range []string{"snapshot", "index", "bindings", "envelope", "receipt", "part-offset", "part-snapshot", "part-length"} {
		t.Run(mode, func(t *testing.T) {
			files, read, inspect, part := selectedFixture(t)
			bindings := files[installationPath]
			action := transport.IndexAction
			if strings.HasPrefix(mode, "part-") {
				action = transport.PartActionPrefix + "world.json:0"
				original := part
				part = func(path string, snapshot d101custody.PrivateSnapshot, n uint64) (d101custody.PrivatePart, error) {
					v, e := original(path, snapshot, n)
					switch mode {
					case "part-offset":
						v.Offset++
					case "part-snapshot":
						v.Snapshot.Inode++
					case "part-length":
						v.Bytes = v.Bytes[:len(v.Bytes)-1]
					}
					return v, e
				}
			}
			if mode == "snapshot" {
				inspect = func(string, d101custody.PrivateSnapshot) error { return d101custody.ErrUnavailable }
			}
			if mode == "envelope" || mode == "receipt" {
				id := "selectedEnvelope"
				if mode == "receipt" {
					id = "selectedReceipt"
				}
				path := transport.OriginalPath(strings.Repeat("a", 32), id)
				files[path] = selectedWire([]byte(`{"changed":true}`))
			}
			if mode == "index" || mode == "bindings" {
				original := read
				calls := 0
				read = func(path string, limit int64) (d101custody.Original, error) {
					v, e := original(path, limit)
					if path == transport.IndexPath {
						calls++
					}
					if mode == "index" && path == transport.IndexPath && calls > 1 || mode == "bindings" && path == installationPath {
						v = selectedWire(append(append([]byte{}, v.Bytes...), ' '))
					}
					return v, e
				}
			}
			if _, err := readSelectedSources(action, installationPath, bindings, read, inspect, part, selectedNow()); err == nil {
				t.Fatal("mixed capture emitted")
			}
		})
	}
}
