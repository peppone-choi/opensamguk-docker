package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101selectedtransport"
)

type snapshotInspector func(string, d101custody.PrivateSnapshot) error
type partReader func(string, d101custody.PrivateSnapshot, uint64) (d101custody.PrivatePart, error)

func selectedTransportAction(action string) bool {
	if action == d101selectedtransport.IndexAction {
		return true
	}
	_, _, err := selectedPartAction(action)
	return err == nil
}
func selectedPartAction(action string) (string, uint64, error) {
	if !strings.HasPrefix(action, d101selectedtransport.PartActionPrefix) {
		return "", 0, d101custody.ErrUnavailable
	}
	value := strings.TrimPrefix(action, d101selectedtransport.PartActionPrefix)
	colon := strings.LastIndex(value, ":")
	if colon < 1 {
		return "", 0, d101custody.ErrUnavailable
	}
	id, ordinal := value[:colon], value[colon+1:]
	n, err := strconv.ParseUint(ordinal, 10, 64)
	if err != nil || n >= 64 || strconv.FormatUint(n, 10) != ordinal || !d101selectedtransport.ValidSourceID(id) {
		return "", 0, d101custody.ErrUnavailable
	}
	return id, n, nil
}

// Caller arguments contain only a bounded logical ID and canonical ordinal.
// Neither index path nor native payload path is selectable by the caller.
func readSelectedSources(action, bindingsPath string, bindings d101custody.Original, read privateReader, inspect snapshotInspector, part partReader, now time.Time) ([]byte, error) {
	if read == nil || inspect == nil || part == nil {
		return nil, d101custody.ErrUnavailable
	}
	raw, err := read(d101selectedtransport.IndexPath, 64<<10)
	if err != nil {
		return nil, d101custody.ErrUnavailable
	}
	index, err := d101selectedtransport.Decode(raw.Bytes, now)
	if err != nil {
		return nil, d101custody.ErrUnavailable
	}
	audit := func() error {
		for _, ref := range index.Originals {
			if inspect(ref.FilePath, ref.Snapshot) != nil {
				return d101custody.ErrUnavailable
			}
		}
		return nil
	}
	if audit() != nil {
		return nil, d101custody.ErrUnavailable
	}
	var response any
	if action == d101selectedtransport.IndexAction {
		// Check the small envelope actually contains the indexed receipt bytes.
		envelope, err := read(index.Originals["selectedEnvelope"].FilePath, 96<<10)
		if err != nil || envelope.SHA256 != index.SelectedEnvelopeSHA || uint64(len(envelope.Bytes)) != index.Originals["selectedEnvelope"].ByteLength {
			return nil, d101custody.ErrUnavailable
		}
		receipt, err := read(index.Originals["selectedReceipt"].FilePath, 64<<10)
		if err != nil || receipt.SHA256 != index.SelectedReceiptSHA || uint64(len(receipt.Bytes)) != index.Originals["selectedReceipt"].ByteLength {
			return nil, d101custody.ErrUnavailable
		}
		var signed struct {
			SchemaVersion int    `json:"schemaVersion"`
			Original      string `json:"originalBytesBase64url"`
			Signature     string `json:"signatureBase64url"`
		}
		if exactJSON(envelope.Bytes, []string{"schemaVersion", "originalBytesBase64url", "signatureBase64url"}, &signed) != nil || signed.SchemaVersion != 1 {
			return nil, d101custody.ErrUnavailable
		}
		inner, err := base64.RawURLEncoding.Strict().DecodeString(signed.Original)
		signature, sigErr := base64.RawURLEncoding.Strict().DecodeString(signed.Signature)
		if err != nil || sigErr != nil || len(signature) != 64 || base64.RawURLEncoding.EncodeToString(inner) != signed.Original || base64.RawURLEncoding.EncodeToString(signature) != signed.Signature || !bytes.Equal(inner, receipt.Bytes) {
			return nil, d101custody.ErrUnavailable
		}
		// Signature authority and selected semantics remain independent consumers.
		response = struct {
			SchemaVersion   int    `json:"schemaVersion"`
			InstallationSHA string `json:"installationSha256"`
			IndexSHA        string `json:"captureIndexSha256"`
			IndexBytes      string `json:"captureIndexBytesBase64url"`
		}{1, bindings.SHA256, raw.SHA256, base64.RawURLEncoding.EncodeToString(raw.Bytes)}
	} else {
		id, ordinal, err := selectedPartAction(action)
		ref, ok := index.Originals[id]
		if err != nil || !ok || ordinal > (ref.ByteLength-1)/d101custody.PrivateOriginalPartBytes {
			return nil, d101custody.ErrUnavailable
		}
		piece, err := part(ref.FilePath, ref.Snapshot, ordinal)
		count := ref.ByteLength - ordinal*d101custody.PrivateOriginalPartBytes
		if count > d101custody.PrivateOriginalPartBytes {
			count = d101custody.PrivateOriginalPartBytes
		}
		if err != nil || piece.Snapshot != ref.Snapshot || piece.PartIndex != ordinal || piece.Offset != ordinal*d101custody.PrivateOriginalPartBytes || uint64(len(piece.Bytes)) != count {
			return nil, d101custody.ErrUnavailable
		}
		response = struct {
			SchemaVersion   int                         `json:"schemaVersion"`
			InstallationSHA string                      `json:"installationSha256"`
			IndexSHA        string                      `json:"captureIndexSha256"`
			ID              string                      `json:"logicalArtifactId"`
			OriginalSHA     string                      `json:"pinnedOriginalSha256"`
			ByteLength      uint64                      `json:"originalByteLength"`
			PartIndex       uint64                      `json:"partIndex"`
			PartOffset      uint64                      `json:"partOffset"`
			PartSHA         string                      `json:"partSha256"`
			PartBytes       string                      `json:"partBytesBase64url"`
			Snapshot        d101custody.PrivateSnapshot `json:"nativeSnapshot"`
		}{1, bindings.SHA256, raw.SHA256, id, ref.RawSHA, ref.ByteLength, ordinal, piece.Offset, piece.PartSHA256, base64.RawURLEncoding.EncodeToString(piece.Bytes), piece.Snapshot}
	}
	if audit() != nil {
		return nil, d101custody.ErrUnavailable
	}
	afterIndex, err := read(d101selectedtransport.IndexPath, 64<<10)
	if err != nil || afterIndex.SHA256 != raw.SHA256 || !bytes.Equal(afterIndex.Bytes, raw.Bytes) {
		return nil, d101custody.ErrUnavailable
	}
	afterBindings, err := read(bindingsPath, 64<<10)
	if err != nil || afterBindings.SHA256 != bindings.SHA256 || !bytes.Equal(afterBindings.Bytes, bindings.Bytes) {
		return nil, d101custody.ErrUnavailable
	}
	wire, err := json.Marshal(response)
	if err != nil || len(wire) > 2<<20 {
		return nil, d101custody.ErrUnavailable
	}
	return wire, nil
}
