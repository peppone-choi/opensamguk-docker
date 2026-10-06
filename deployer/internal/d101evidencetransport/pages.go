package d101evidencetransport

import (
	"context"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
)

type Entry struct {
	Reference     RawReference                `json:"ref"`
	LogicalIDHash string                      `json:"logicalIdSha256"`
	Snapshot      d101custody.PrivateSnapshot `json:"nativeSnapshot"`
}
type BranchPage struct {
	SchemaVersion int                      `json:"schemaVersion"`
	Kind          string                   `json:"kind"`
	OperationID   string                   `json:"operationId"`
	ScopeSHA256   string                   `json:"scopeSha256"`
	Prefix        string                   `json:"prefix"`
	Children      map[string]PageReference `json:"children"`
}
type LeafPage struct {
	SchemaVersion int     `json:"schemaVersion"`
	Kind          string  `json:"kind"`
	OperationID   string  `json:"operationId"`
	ScopeSHA256   string  `json:"scopeSha256"`
	Prefix        string  `json:"prefix"`
	Entries       []Entry `json:"entries"`
}

func validateEntry(value Entry, prefix string) error {
	if ValidateRawReference(value.Reference) != nil || value.LogicalIDHash != LogicalIDDigest(value.Reference.LogicalID) || !strings.HasPrefix(value.LogicalIDHash, prefix) ||
		ValidateSnapshot(value.Snapshot) != nil || value.Snapshot.ByteLength != value.Reference.ByteLength {
		return d101custody.ErrUnavailable
	}
	return nil
}
func pageOriginalBound(wire []byte, ref PageReference) error {
	if ValidatePageReference(ref) != nil || len(wire) == 0 || len(wire) > MetadataMaxBytes || uint64(len(wire)) != ref.ByteLength || HashOriginal(wire) != ref.SHA256 {
		return d101custody.ErrUnavailable
	}
	return nil
}
func DecodeBranchPage(wire []byte, ref PageReference, operationID, scopeDigest string) (BranchPage, error) {
	var value BranchPage
	if pageOriginalBound(wire, ref) != nil || decodeExact(wire, &value, MetadataMaxBytes) != nil || value.SchemaVersion != 1 || value.Kind != BranchKind ||
		!opPattern.MatchString(operationID) || !shaPattern.MatchString(scopeDigest) || value.OperationID != operationID || value.ScopeSHA256 != scopeDigest ||
		value.Prefix != ref.Prefix || len(value.Prefix) > 63 || len(value.Children) == 0 {
		return BranchPage{}, d101custody.ErrUnavailable
	}
	for suffix, child := range value.Children {
		if len(suffix) != 1 || !strings.Contains("0123456789abcdef", suffix) || ValidatePageReference(child) != nil || child.Prefix != value.Prefix+suffix {
			return BranchPage{}, d101custody.ErrUnavailable
		}
	}
	return value, nil
}
func DecodeLeafPage(wire []byte, ref PageReference, operationID, scopeDigest string) (LeafPage, error) {
	var value LeafPage
	if pageOriginalBound(wire, ref) != nil || decodeExact(wire, &value, MetadataMaxBytes) != nil || value.SchemaVersion != 1 || value.Kind != LeafKind ||
		!opPattern.MatchString(operationID) || !shaPattern.MatchString(scopeDigest) || value.OperationID != operationID || value.ScopeSHA256 != scopeDigest ||
		value.Prefix != ref.Prefix || len(value.Entries) == 0 {
		return LeafPage{}, d101custody.ErrUnavailable
	}
	ids := map[string]bool{}
	hashes := map[string]bool{}
	for _, entry := range value.Entries {
		if validateEntry(entry, value.Prefix) != nil || ids[entry.Reference.LogicalID] || hashes[entry.LogicalIDHash] {
			return LeafPage{}, d101custody.ErrUnavailable
		}
		ids[entry.Reference.LogicalID] = true
		hashes[entry.LogicalIDHash] = true
	}
	return value, nil
}

// ReadPage supplies bytes only; the fixed native helper must independently
// match the ref's actual FD snapshot before/after. This callback cannot confer
// collector/issuer/approval authority on a decoded page.
type ReadPage func(PageReference) ([]byte, error)

func pageKind(wire []byte) (string, error) {
	if len(wire) == 0 || len(wire) > MetadataMaxBytes || !utf8.Valid(wire) {
		return "", d101custody.ErrUnavailable
	}
	var header struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(wire, &header) != nil || header.Kind != BranchKind && header.Kind != LeafKind {
		return "", d101custody.ErrUnavailable
	}
	return header.Kind, nil
}

// One-path lookup is intentionally separate from the full reachable-page
// audit required before final semantic material. It supplies no hidden-page,
// raw DAG, native snapshot or origin attestation.
func LookupEntry(ctx context.Context, index Index, id string, read ReadPage) (Entry, error) {
	if ctx == nil || ctx.Err() != nil || read == nil || ValidateIndex(index) != nil || !rawIDPattern.MatchString(id) || len(id) > 128 {
		return Entry{}, d101custody.ErrUnavailable
	}
	scopeDigest, err := ScopeDigest(index.Scope)
	if err != nil {
		return Entry{}, err
	}
	idHash := LogicalIDDigest(id)
	ref := index.RootPage
	for depth := 0; depth <= 64; depth++ {
		if ctx.Err() != nil {
			return Entry{}, d101custody.ErrUnavailable
		}
		wire, err := read(ref)
		if err != nil {
			return Entry{}, d101custody.ErrUnavailable
		}
		kind, err := pageKind(wire)
		if err != nil {
			return Entry{}, err
		}
		if kind == LeafKind {
			leaf, err := DecodeLeafPage(wire, ref, index.Scope.OperationID, scopeDigest)
			if err != nil {
				return Entry{}, err
			}
			for _, entry := range leaf.Entries {
				if entry.Reference.LogicalID == id && entry.LogicalIDHash == idHash && ctx.Err() == nil {
					return entry, nil
				}
			}
			return Entry{}, d101custody.ErrUnavailable
		}
		branch, err := DecodeBranchPage(wire, ref, index.Scope.OperationID, scopeDigest)
		if err != nil {
			return Entry{}, err
		}
		child, ok := branch.Children[idHash[len(branch.Prefix):len(branch.Prefix)+1]]
		if !ok {
			return Entry{}, d101custody.ErrUnavailable
		}
		ref = child
	}
	return Entry{}, d101custody.ErrUnavailable
}

// Every reachable page is checked, including non-lookup descendants. No global
// raw count or aggregate-byte cap is introduced. The installed caller's fixed
// deadline and per-page 64KiB/native reader budget remain required. A complete
// raw-reference DAG and role-specific origin audit still follows this result.
func AuditReachablePages(ctx context.Context, index Index, read ReadPage) (map[string]Entry, error) {
	if ctx == nil || ctx.Err() != nil || read == nil || ValidateIndex(index) != nil {
		return nil, d101custody.ErrUnavailable
	}
	scopeDigest, err := ScopeDigest(index.Scope)
	if err != nil {
		return nil, err
	}
	entries := map[string]Entry{}
	idHashes := map[string]string{}
	pages := map[string]bool{}
	prefixes := map[string]bool{}
	var visit func(PageReference) error
	visit = func(ref PageReference) error {
		if ctx.Err() != nil || pages[ref.SHA256] || prefixes[ref.Prefix] {
			return d101custody.ErrUnavailable
		}
		pages[ref.SHA256] = true
		prefixes[ref.Prefix] = true
		wire, err := read(ref)
		if err != nil {
			return d101custody.ErrUnavailable
		}
		kind, err := pageKind(wire)
		if err != nil {
			return err
		}
		if kind == BranchKind {
			branch, err := DecodeBranchPage(wire, ref, index.Scope.OperationID, scopeDigest)
			if err != nil {
				return err
			}
			for _, child := range branch.Children {
				if err := visit(child); err != nil {
					return err
				}
			}
			return nil
		}
		leaf, err := DecodeLeafPage(wire, ref, index.Scope.OperationID, scopeDigest)
		if err != nil {
			return err
		}
		for _, entry := range leaf.Entries {
			if _, ok := entries[entry.Reference.LogicalID]; ok {
				return d101custody.ErrUnavailable
			}
			if _, ok := idHashes[entry.LogicalIDHash]; ok {
				return d101custody.ErrUnavailable
			}
			entries[entry.Reference.LogicalID] = entry
			idHashes[entry.LogicalIDHash] = entry.Reference.LogicalID
		}
		return nil
	}
	if err := visit(index.RootPage); err != nil || ctx.Err() != nil {
		return nil, d101custody.ErrUnavailable
	}
	return entries, nil
}
