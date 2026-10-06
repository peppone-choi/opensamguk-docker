package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"opensamguk-deployer/internal/d101custody"
	et "opensamguk-deployer/internal/d101evidencetransport"
)

type evidenceHelperFixture struct {
	files     map[string]d101custody.Original
	snapshots map[string]d101custody.PrivateSnapshot
	bindings  d101custody.Original
	id, path  string
	payload   []byte
}

func newEvidenceHelperFixture(t *testing.T) *evidenceHelperFixture {
	t.Helper()
	f := &evidenceHelperFixture{files: map[string]d101custody.Original{}, snapshots: map[string]d101custody.PrivateSnapshot{}, id: "raw:payload", payload: bytes.Repeat([]byte("x"), int(d101custody.PrivateOriginalPartBytes)+7)}
	put := func(path string, wire []byte) d101custody.PrivateSnapshot {
		f.files[path] = d101custody.Original{Bytes: append([]byte(nil), wire...), SHA256: et.HashOriginal(wire)}
		snapshot := d101custody.PrivateSnapshot{Device: 1, Inode: uint64(len(f.files) + 1), ByteLength: uint64(len(wire)), ModifiedAtUnixNano: 3}
		f.snapshots[path] = snapshot
		return snapshot
	}
	put(installationPath, []byte("synthetic fixed reader bindings"))
	f.bindings = f.files[installationPath]
	images := map[string]string{}
	for _, id := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		images[id] = "sha256:" + strings.Repeat("a", 64)
	}
	scope := et.Scope{OperationID: strings.Repeat("a", 32), ServerID: "pep", WorldID: 1, TargetFingerprint: strings.Repeat("b", 64), TypedTargetRef: et.RawReference{LogicalID: "raw:typed-target", SHA256: strings.Repeat("b", 64), ByteLength: 2, MediaType: "application/json"}, AppSourceSHA: strings.Repeat("c", 40), DockerSourceSHA: strings.Repeat("d", 40), OldImageDigests: images, NewImageDigests: images, InitialPublicRevision: "1", Window: et.Window{WindowOpensAtUnix: 1, DestructiveCutoffUnix: 2, RecoveryDeadlineUnix: 3}}
	f.path, _ = et.OriginalPath(scope.OperationID, f.id)
	originalSnapshot := put(f.path, f.payload)
	digest, _ := et.ScopeDigest(scope)
	leaf := et.LeafPage{SchemaVersion: 1, Kind: et.LeafKind, OperationID: scope.OperationID, ScopeSHA256: digest, Prefix: "", Entries: []et.Entry{{Reference: et.RawReference{LogicalID: f.id, SHA256: et.HashOriginal(f.payload), ByteLength: uint64(len(f.payload)), MediaType: "application/octet-stream"}, LogicalIDHash: et.LogicalIDDigest(f.id), Snapshot: originalSnapshot}}}
	pageWire, _ := json.Marshal(leaf)
	ref := et.PageReference{Prefix: "", SHA256: et.HashOriginal(pageWire), ByteLength: uint64(len(pageWire)), Snapshot: d101custody.PrivateSnapshot{Device: 1, Inode: 4, ByteLength: uint64(len(pageWire)), ModifiedAtUnixNano: 3}}
	pagePath, _ := et.PagePath(scope.OperationID, ref)
	put(pagePath, pageWire)
	f.snapshots[pagePath] = ref.Snapshot
	sourceRef := et.RawReference{LogicalID: "raw:collector-source", SHA256: strings.Repeat("e", 64), ByteLength: 1, MediaType: "application/octet-stream"}
	index := et.Index{SchemaVersion: 1, Kind: et.IndexKind, Scope: scope, PartBytes: d101custody.PrivateOriginalPartBytes, CollectorIdentity: "fixture-collector", CollectorSource: sourceRef, CollectorImageDigest: "sha256:" + strings.Repeat("f", 64), RootPage: ref, OriginProofs: []et.RawReference{}, CapturedAtUnix: 1}
	indexWire, _ := json.Marshal(index)
	indexSnapshot := put(et.IndexPath, indexWire)
	pin := et.SourcePin{SchemaVersion: 1, Kind: et.SourcePinKind, Scope: scope, ReaderBindingsSHA256: f.bindings.SHA256, EvidenceIndexSHA256: et.HashOriginal(indexWire), EvidenceIndexSnapshot: indexSnapshot, HelperSHA256: strings.Repeat("a", 64), CollectorSource: sourceRef, CollectorImageDigest: index.CollectorImageDigest, CollectorIdentity: index.CollectorIdentity, InstallerSource: et.RawReference{LogicalID: "raw:installer", SHA256: strings.Repeat("b", 64), ByteLength: 1, MediaType: "application/octet-stream"}, OriginPins: []et.PublicPin{}, Namespace: et.SourceNamespace}
	pinWire, _ := json.Marshal(pin)
	put(et.SourcePinPath, pinWire)
	return f
}
func (f *evidenceHelperFixture) read(path string, limit int64) (d101custody.Original, error) {
	value, ok := f.files[path]
	if !ok || int64(len(value.Bytes)) > limit {
		return d101custody.Original{}, d101custody.ErrUnavailable
	}
	return d101custody.Original{Bytes: append([]byte(nil), value.Bytes...), SHA256: value.SHA256}, nil
}
func (f *evidenceHelperFixture) capture(path string, limit int64) (d101custody.Original, d101custody.PrivateSnapshot, error) {
	original, err := f.read(path, limit)
	return original, f.snapshots[path], err
}
func (f *evidenceHelperFixture) inspect(path string, snapshot d101custody.PrivateSnapshot) error {
	if f.snapshots[path] != snapshot {
		return d101custody.ErrUnavailable
	}
	return nil
}
func (f *evidenceHelperFixture) part(path string, snapshot d101custody.PrivateSnapshot, ordinal uint64) (d101custody.PrivatePart, error) {
	if path != f.path || snapshot != f.snapshots[path] || ordinal > 1 {
		return d101custody.PrivatePart{}, d101custody.ErrUnavailable
	}
	offset := ordinal * d101custody.PrivateOriginalPartBytes
	end := offset + d101custody.PrivateOriginalPartBytes
	if end > uint64(len(f.payload)) {
		end = uint64(len(f.payload))
	}
	wire := append([]byte(nil), f.payload[offset:end]...)
	return d101custody.PrivatePart{Bytes: wire, PartSHA256: et.HashOriginal(wire), Snapshot: snapshot, PartIndex: ordinal, Offset: offset}, nil
}
func TestEvidenceNativeHelperIndexAndOrderedPartsPreserveWholeOriginal(t *testing.T) {
	f := newEvidenceHelperFixture(t)
	wire, err := readEvidenceSources(et.IndexAction, installationPath, f.bindings, f.read, f.capture, f.inspect, f.part)
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]json.RawMessage
	json.Unmarshal(wire, &response)
	if len(response) != 4 {
		t.Fatal("index response fields")
	}
	var installationSHA string
	json.Unmarshal(response["installationSha256"], &installationSHA)
	if installationSHA != f.bindings.SHA256 || installationSHA == f.files[et.SourcePinPath].SHA256 {
		t.Fatal("source pin substituted installation original SHA")
	}
	var whole []byte
	for ordinal := uint64(0); ordinal < 2; ordinal++ {
		wire, err = readEvidenceSources(et.PartActionPrefix+f.id+":"+[]string{"0", "1"}[ordinal], installationPath, f.bindings, f.read, f.capture, f.inspect, f.part)
		if err != nil {
			t.Fatal(err)
		}
		response = nil
		if err := json.Unmarshal(wire, &response); err != nil {
			t.Fatal(err)
		}
		if len(response) != 11 {
			t.Fatal("part response fields")
		}
		var encoded string
		json.Unmarshal(response["partBytesBase64url"], &encoded)
		piece, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		whole = append(whole, piece...)
	}
	if !bytes.Equal(whole, f.payload) || et.HashOriginal(whole) != et.HashOriginal(f.payload) {
		t.Fatal("whole original changed")
	}
}
func TestEvidenceNativeHelperRejectsFixedSourceSnapshotAndPartDrift(t *testing.T) {
	for _, mode := range []string{"pin-bytes", "pin-snapshot", "index-bytes", "index-snapshot", "bindings-snapshot", "page-snapshot", "original-snapshot", "part-sha", "part-offset", "unregistered-id"} {
		t.Run(mode, func(t *testing.T) {
			f := newEvidenceHelperFixture(t)
			calls := map[string]int{}
			capture := func(path string, limit int64) (d101custody.Original, d101custody.PrivateSnapshot, error) {
				calls[path]++
				original, snapshot, err := f.capture(path, limit)
				if mode == "pin-bytes" && path == et.SourcePinPath && calls[path] > 1 {
					original.Bytes = append(original.Bytes, ' ')
					original.SHA256 = et.HashOriginal(original.Bytes)
				}
				if mode == "pin-snapshot" && path == et.SourcePinPath && calls[path] > 1 {
					snapshot.Inode++
				}
				if mode == "index-bytes" && path == et.IndexPath && calls[path] > 1 {
					original.Bytes = append(original.Bytes, ' ')
					original.SHA256 = et.HashOriginal(original.Bytes)
				}
				if mode == "index-snapshot" && path == et.IndexPath && calls[path] > 1 {
					snapshot.Inode++
				}
				if mode == "bindings-snapshot" && path == installationPath && calls[path] > 1 {
					snapshot.Inode++
				}
				if mode == "page-snapshot" && strings.HasPrefix(path, et.PageDirectory+"/") {
					snapshot.Inode++
				}
				return original, snapshot, err
			}
			part := func(path string, snapshot d101custody.PrivateSnapshot, ordinal uint64) (d101custody.PrivatePart, error) {
				piece, err := f.part(path, snapshot, ordinal)
				if mode == "part-sha" {
					piece.PartSHA256 = strings.Repeat("a", 64)
				}
				if mode == "part-offset" {
					piece.Offset++
				}
				return piece, err
			}
			inspect := func(path string, snapshot d101custody.PrivateSnapshot) error {
				if mode == "original-snapshot" && path == f.path {
					return d101custody.ErrUnavailable
				}
				return f.inspect(path, snapshot)
			}
			id := f.id
			if mode == "unregistered-id" {
				id = "raw:unregistered"
			}
			if _, err := readEvidenceSources(et.PartActionPrefix+id+":0", installationPath, f.bindings, f.read, capture, inspect, part); err == nil {
				t.Fatal("rebound or unregistered source accepted")
			}
		})
	}
}
func TestEvidenceNativeHelperRejectsCallerActionsAndMissingOriginalAudit(t *testing.T) {
	f := newEvidenceHelperFixture(t)
	for _, action := range []string{et.IndexAction + ":/caller", et.PartActionPrefix + f.id + ":00", et.PartActionPrefix + f.id + ":64", et.PartActionPrefix + "/key:0", et.PartActionPrefix + f.id + ":0?offset=1"} {
		if evidenceTransportAction(action) {
			t.Fatal("caller path/offset/action accepted")
		}
	}
	inspect := func(path string, snapshot d101custody.PrivateSnapshot) error {
		if path == f.path {
			return d101custody.ErrUnavailable
		}
		return f.inspect(path, snapshot)
	}
	if _, err := readEvidenceSources(et.IndexAction, installationPath, f.bindings, f.read, f.capture, inspect, f.part); err == nil {
		t.Fatal("index skipped actual originals native audit")
	}
	if _, err := readEvidenceSources(et.IndexAction, installationPath, f.bindings, f.read, nil, f.inspect, f.part); err == nil {
		t.Fatal("missing native capture accepted")
	}
}
