package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101evidencetransport"
)

type privateCaptureReader func(string, int64) (d101custody.Original, d101custody.PrivateSnapshot, error)

func evidencePartAction(action string) (string, uint64, error) {
	if !strings.HasPrefix(action, d101evidencetransport.PartActionPrefix) {
		return "", 0, d101custody.ErrUnavailable
	}
	value := strings.TrimPrefix(action, d101evidencetransport.PartActionPrefix)
	at := strings.LastIndex(value, ":")
	if at < 1 {
		return "", 0, d101custody.ErrUnavailable
	}
	id, ordinal := value[:at], value[at+1:]
	n, err := strconv.ParseUint(ordinal, 10, 64)
	if err != nil || n >= 64 || strconv.FormatUint(n, 10) != ordinal {
		return "", 0, d101custody.ErrUnavailable
	}
	if _, err := d101evidencetransport.OriginalPath(strings.Repeat("a", 32), id); err != nil {
		return "", 0, d101custody.ErrUnavailable
	}
	return id, n, nil
}
func evidenceTransportAction(action string) bool {
	if action == d101evidencetransport.IndexAction {
		return true
	}
	_, _, err := evidencePartAction(action)
	return err == nil
}

// Fixed data-only namespace: no caller profile/index/page/path/offset/env/key.
// Independent constructor pins and origin/installer verification remain the
// consumer's responsibility. Native reads and snapshots are production seams,
// not an authenticated issuer callback or an authority result.
func readEvidenceSources(action, bindingsPath string, bindings d101custody.Original, read privateReader,
	capture privateCaptureReader, inspect snapshotInspector, part partReader) ([]byte, error) {
	if read == nil || capture == nil || inspect == nil || part == nil || !evidenceTransportAction(action) {
		return nil, d101custody.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	bindingsOriginal, bindingsSnapshot, err := capture(bindingsPath, 64<<10)
	if err != nil || bindingsOriginal.SHA256 != bindings.SHA256 || !bytes.Equal(bindingsOriginal.Bytes, bindings.Bytes) {
		return nil, d101custody.ErrUnavailable
	}
	pinOriginal, pinSnapshot, err := capture(d101evidencetransport.SourcePinPath, 64<<10)
	if err != nil {
		return nil, d101custody.ErrUnavailable
	}
	pin, err := d101evidencetransport.DecodeSourcePin(pinOriginal.Bytes)
	if err != nil || pin.ReaderBindingsSHA256 != bindings.SHA256 {
		return nil, d101custody.ErrUnavailable
	}
	indexOriginal, indexSnapshot, err := capture(d101evidencetransport.IndexPath, 64<<10)
	if err != nil || indexSnapshot != pin.EvidenceIndexSnapshot || indexOriginal.SHA256 != pin.EvidenceIndexSHA256 {
		return nil, d101custody.ErrUnavailable
	}
	index, err := d101evidencetransport.RequireSourcePinIndexBinding(pin, indexOriginal.Bytes)
	if err != nil {
		return nil, err
	}
	pageSnapshots := map[string]d101custody.PrivateSnapshot{}
	readPage := func(ref d101evidencetransport.PageReference) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, d101custody.ErrUnavailable
		}
		path, err := d101evidencetransport.PagePath(index.Scope.OperationID, ref)
		if err != nil {
			return nil, err
		}
		original, snapshot, err := capture(path, 64<<10)
		if err != nil || snapshot != ref.Snapshot || original.SHA256 != ref.SHA256 || uint64(len(original.Bytes)) != ref.ByteLength {
			return nil, d101custody.ErrUnavailable
		}
		pageSnapshots[path] = snapshot
		return append([]byte(nil), original.Bytes...), nil
	}
	var response any
	originalSnapshots := map[string]d101custody.PrivateSnapshot{}
	if action == d101evidencetransport.IndexAction {
		entries, err := d101evidencetransport.AuditReachablePages(ctx, index, readPage)
		if err != nil {
			return nil, err
		}
		for id, entry := range entries {
			path, err := d101evidencetransport.OriginalPath(index.Scope.OperationID, id)
			if err != nil || inspect(path, entry.Snapshot) != nil || ctx.Err() != nil {
				return nil, d101custody.ErrUnavailable
			}
			originalSnapshots[path] = entry.Snapshot
		}
		response = struct {
			SchemaVersion       int    `json:"schemaVersion"`
			InstallationSHA256  string `json:"installationSha256"`
			EvidenceIndexSHA256 string `json:"evidenceIndexSha256"`
			EvidenceIndexBytes  string `json:"evidenceIndexBytesBase64url"`
		}{1, bindings.SHA256, indexOriginal.SHA256, base64.RawURLEncoding.EncodeToString(indexOriginal.Bytes)}
	} else {
		id, ordinal, err := evidencePartAction(action)
		if err != nil {
			return nil, err
		}
		entry, err := d101evidencetransport.LookupEntry(ctx, index, id, readPage)
		if err != nil || ordinal > (entry.Reference.ByteLength-1)/d101custody.PrivateOriginalPartBytes {
			return nil, d101custody.ErrUnavailable
		}
		path, err := d101evidencetransport.OriginalPath(index.Scope.OperationID, id)
		if err != nil {
			return nil, err
		}
		piece, err := part(path, entry.Snapshot, ordinal)
		length := entry.Reference.ByteLength - ordinal*d101custody.PrivateOriginalPartBytes
		if length > d101custody.PrivateOriginalPartBytes {
			length = d101custody.PrivateOriginalPartBytes
		}
		if err != nil || piece.Snapshot != entry.Snapshot || piece.PartIndex != ordinal || piece.Offset != ordinal*d101custody.PrivateOriginalPartBytes || uint64(len(piece.Bytes)) != length ||
			piece.PartSHA256 != d101evidencetransport.HashOriginal(piece.Bytes) {
			return nil, d101custody.ErrUnavailable
		}
		originalSnapshots[path] = entry.Snapshot
		response = struct {
			SchemaVersion       int                         `json:"schemaVersion"`
			InstallationSHA256  string                      `json:"installationSha256"`
			EvidenceIndexSHA256 string                      `json:"evidenceIndexSha256"`
			LogicalID           string                      `json:"logicalArtifactId"`
			OriginalSHA256      string                      `json:"pinnedOriginalSha256"`
			OriginalByteLength  uint64                      `json:"originalByteLength"`
			PartIndex           uint64                      `json:"partIndex"`
			PartOffset          uint64                      `json:"partOffset"`
			PartSHA256          string                      `json:"partSha256"`
			PartBytes           string                      `json:"partBytesBase64url"`
			Snapshot            d101custody.PrivateSnapshot `json:"nativeSnapshot"`
		}{1, bindings.SHA256, indexOriginal.SHA256, id, entry.Reference.SHA256, entry.Reference.ByteLength, ordinal, piece.Offset, piece.PartSHA256, base64.RawURLEncoding.EncodeToString(piece.Bytes), piece.Snapshot}
	}
	for path, snapshot := range pageSnapshots {
		if inspect(path, snapshot) != nil || ctx.Err() != nil {
			return nil, d101custody.ErrUnavailable
		}
	}
	for path, snapshot := range originalSnapshots {
		if inspect(path, snapshot) != nil || ctx.Err() != nil {
			return nil, d101custody.ErrUnavailable
		}
	}
	afterIndex, afterIndexSnapshot, err := capture(d101evidencetransport.IndexPath, 64<<10)
	if err != nil || afterIndexSnapshot != indexSnapshot || afterIndex.SHA256 != indexOriginal.SHA256 || !bytes.Equal(afterIndex.Bytes, indexOriginal.Bytes) {
		return nil, d101custody.ErrUnavailable
	}
	afterPin, afterPinSnapshot, err := capture(d101evidencetransport.SourcePinPath, 64<<10)
	if err != nil || afterPinSnapshot != pinSnapshot || afterPin.SHA256 != pinOriginal.SHA256 || !bytes.Equal(afterPin.Bytes, pinOriginal.Bytes) {
		return nil, d101custody.ErrUnavailable
	}
	afterBindings, afterBindingsSnapshot, err := capture(bindingsPath, 64<<10)
	if err != nil || afterBindingsSnapshot != bindingsSnapshot || afterBindings.SHA256 != bindings.SHA256 || !bytes.Equal(afterBindings.Bytes, bindings.Bytes) || ctx.Err() != nil {
		return nil, d101custody.ErrUnavailable
	}
	wire, err := json.Marshal(response)
	if err != nil || len(wire) > 2<<20 {
		return nil, d101custody.ErrUnavailable
	}
	return wire, nil
}
