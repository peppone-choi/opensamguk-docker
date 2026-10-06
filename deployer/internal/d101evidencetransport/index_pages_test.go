package d101evidencetransport

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"opensamguk-deployer/internal/d101custody"
)

func transportTestRef(prefix string, wire []byte) PageReference {
	return PageReference{prefix, HashOriginal(wire), uint64(len(wire)), d101custody.PrivateSnapshot{Device: 1, Inode: 2, ByteLength: uint64(len(wire)), ModifiedAtUnixNano: 3}}
}
func transportTestEntry(id string) Entry {
	return Entry{RawReference{id, HashOriginal([]byte("{}")), 2, "application/json"}, LogicalIDDigest(id), d101custody.PrivateSnapshot{Device: 1, Inode: 4, ByteLength: 2, ModifiedAtUnixNano: 3}}
}
func transportTestIndex(root PageReference) Index {
	return Index{1, IndexKind, evidenceScopeFixture(), d101custody.PrivateOriginalPartBytes, "fixture-collector", RawReference{"raw:collector-source", strings.Repeat("b", 64), 1, "application/octet-stream"}, "sha256:" + strings.Repeat("c", 64), root, []RawReference{}, 1}
}
func TestEvidenceIndexSourcePinUseExactR4AndDataOnlyEmptyOrigins(t *testing.T) {
	entry := transportTestEntry("raw:ci")
	scope := evidenceScopeFixture()
	digest, _ := ScopeDigest(scope)
	leaf := LeafPage{1, LeafKind, scope.OperationID, digest, "", []Entry{entry}}
	pageWire, _ := json.Marshal(leaf)
	index := transportTestIndex(transportTestRef("", pageWire))
	wire, _ := json.Marshal(index)
	got, err := DecodeIndex(wire)
	if err != nil || !reflect.DeepEqual(got, index) {
		t.Fatal("exact10 index or empty proof transport refused")
	}
	pin := SourcePin{1, SourcePinKind, scope, strings.Repeat("a", 64), HashOriginal(wire), d101custody.PrivateSnapshot{Device: 1, Inode: 2, ByteLength: uint64(len(wire)), ModifiedAtUnixNano: 3}, strings.Repeat("e", 64), index.CollectorSource, index.CollectorImageDigest, index.CollectorIdentity, RawReference{"raw:installer-source", strings.Repeat("f", 64), 1, "application/octet-stream"}, []PublicPin{}, SourceNamespace}
	pinWire, _ := json.Marshal(pin)
	parsed, err := DecodeSourcePin(pinWire)
	if err != nil || !reflect.DeepEqual(pin, parsed) {
		t.Fatal("exact13 source pin refused")
	}
	if _, err = RequireSourcePinIndexBinding(pin, wire); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"installation-sha-alias", "pin-index-sha", "collector", "scope", "snapshot-length", "origin-profile-extra", "origin-profile-null", "origin-role-duplicate", "pin-unknown-key", "index-null-proofs"} {
		t.Run(mode, func(t *testing.T) {
			changed := pin
			changed.OriginPins = []PublicPin{}
			bindingWire := wire
			if mode == "installation-sha-alias" {
				changed.ReaderBindingsSHA256 = ""
			}
			if mode == "pin-index-sha" {
				changed.EvidenceIndexSHA256 = strings.Repeat("a", 64)
			}
			if mode == "collector" {
				changed.CollectorIdentity = "other-collector"
			}
			if mode == "scope" {
				changed.Scope.InitialPublicRevision = "2"
			}
			if mode == "snapshot-length" {
				changed.EvidenceIndexSnapshot.ByteLength++
			}
			if mode == "index-null-proofs" {
				bindingWire = []byte(strings.Replace(string(wire), `"originProofRefs":[]`, `"originProofRefs":null`, 1))
				changed.EvidenceIndexSHA256 = HashOriginal(bindingWire)
				changed.EvidenceIndexSnapshot.ByteLength = uint64(len(bindingWire))
			}
			if strings.HasPrefix(mode, "origin-") {
				ref := RawReference{"raw:profile", strings.Repeat("a", 64), 1, "application/json"}
				changed.OriginPins = []PublicPin{{ApprovalRole, ref, ref, ref}}
				if mode == "origin-role-duplicate" {
					changed.OriginPins = append(changed.OriginPins, changed.OriginPins[0])
				}
			}
			bytes, _ := json.Marshal(changed)
			if mode == "pin-unknown-key" {
				bytes = []byte(strings.TrimSuffix(string(bytes), "}") + `,"expected":true}`)
			}
			if mode == "origin-profile-extra" {
				bytes = []byte(strings.Replace(string(bytes), `"role":"APPROVAL_ISSUER"`, `"role":"APPROVAL_ISSUER","expected":true`, 1))
			}
			if mode == "origin-profile-null" {
				bytes = []byte(strings.Replace(string(bytes), `"role":"APPROVAL_ISSUER"`, `"role":null`, 1))
			}
			decoded, err := DecodeSourcePin(bytes)
			if err == nil {
				_, err = RequireSourcePinIndexBinding(decoded, bindingWire)
			}
			if err == nil {
				t.Fatal("ambiguous or rebound transport accepted")
			}
		})
	}
}

func TestEvidencePageExactArraysAndNativeReferenceBounds(t *testing.T) {
	scope := evidenceScopeFixture()
	digest, _ := ScopeDigest(scope)
	entry := transportTestEntry("raw:ci")
	leaf := LeafPage{1, LeafKind, scope.OperationID, digest, "", []Entry{entry}}
	wire, _ := json.Marshal(leaf)
	ref := transportTestRef("", wire)
	if _, err := DecodeLeafPage(wire, ref, scope.OperationID, digest); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"entry-unknown", "entry-missing", "entry-null", "duplicate-id", "entry-hash", "entry-snapshot", "unknown-page-field", "wrong-scope", "trailing", "uppercase-prefix"} {
		t.Run(mode, func(t *testing.T) {
			value := leaf
			value.Entries = append([]Entry(nil), leaf.Entries...)
			if mode == "duplicate-id" {
				value.Entries = append(value.Entries, value.Entries[0])
			}
			if mode == "entry-hash" {
				value.Entries[0].LogicalIDHash = strings.Repeat("f", 64)
			}
			if mode == "entry-snapshot" {
				value.Entries[0].Snapshot.ByteLength++
			}
			if mode == "wrong-scope" {
				value.ScopeSHA256 = strings.Repeat("a", 64)
			}
			if mode == "uppercase-prefix" {
				value.Prefix = "A"
			}
			changed, _ := json.Marshal(value)
			text := string(changed)
			if mode == "entry-unknown" {
				text = strings.Replace(text, `"entries":[{`, `"entries":[{"unknown":1,`, 1)
			}
			if mode == "entry-missing" {
				text = strings.Replace(text, `"logicalIdSha256":"`+entry.LogicalIDHash+`",`, "", 1)
			}
			if mode == "entry-null" {
				text = strings.Replace(text, `"entries":[{`, `"entries":[null,{`, 1)
			}
			if mode == "unknown-page-field" {
				text = strings.TrimSuffix(text, "}") + `,"unknown":1}`
			}
			if mode == "trailing" {
				text += "{}"
			}
			changed = []byte(text)
			changedRef := transportTestRef(value.Prefix, changed)
			if _, err := DecodeLeafPage(changed, changedRef, scope.OperationID, digest); err == nil {
				t.Fatal("malformed nested entry/page accepted")
			}
		})
	}
	bad := ref
	bad.Snapshot.ByteLength++
	if _, err := DecodeLeafPage(wire, bad, scope.OperationID, digest); err == nil {
		t.Fatal("page snapshot length drift")
	}
	if _, err := OriginalPath(scope.OperationID, "/caller/key"); err == nil {
		t.Fatal("caller pathname accepted")
	}
}

func transportTreeFixture(t *testing.T, corruptHidden bool) (Index, ReadPage, string) {
	t.Helper()
	scope := evidenceScopeFixture()
	digest, _ := ScopeDigest(scope)
	first := transportTestEntry("raw:lookup")
	secondID := "raw:hidden"
	for LogicalIDDigest(secondID)[:1] == first.LogicalIDHash[:1] {
		secondID += "x"
	}
	second := transportTestEntry(secondID)
	if corruptHidden {
		second.Snapshot.Inode = 0
	}
	files := map[string][]byte{}
	children := map[string]PageReference{}
	for _, entry := range []Entry{first, second} {
		prefix := entry.LogicalIDHash[:1]
		leaf := LeafPage{1, LeafKind, scope.OperationID, digest, prefix, []Entry{entry}}
		wire, _ := json.Marshal(leaf)
		ref := transportTestRef(prefix, wire)
		files[ref.SHA256] = wire
		children[prefix] = ref
	}
	branch := BranchPage{1, BranchKind, scope.OperationID, digest, "", children}
	wire, _ := json.Marshal(branch)
	root := transportTestRef("", wire)
	files[root.SHA256] = wire
	return transportTestIndex(root), func(ref PageReference) ([]byte, error) { return append([]byte(nil), files[ref.SHA256]...), nil }, first.Reference.LogicalID
}
func TestEvidencePageLookupDoesNotReplaceFullReachableAudit(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		index, read, id := transportTreeFixture(t, corrupt)
		if got, err := LookupEntry(context.Background(), index, id, read); err != nil || got.Reference.LogicalID != id {
			t.Fatal("one-path lookup failed")
		}
		entries, err := AuditReachablePages(context.Background(), index, read)
		if corrupt && err == nil {
			t.Fatal("unread hidden descendant supplied final page audit")
		}
		if !corrupt && (err != nil || len(entries) != 2) {
			t.Fatal("reachable originals were lost")
		}
	}
	index, read, id := transportTreeFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LookupEntry(ctx, index, id, read); err == nil {
		t.Fatal("cancelled lookup accepted")
	}
	if _, err := AuditReachablePages(ctx, index, read); err == nil {
		t.Fatal("cancelled full audit accepted")
	}
}
