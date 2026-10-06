package main

import (
	"bytes"
	"context"
	"encoding/json"
	"opensamguk-deployer/internal/d101custody"
	et "opensamguk-deployer/internal/d101evidencetransport"
	"opensamguk-deployer/internal/d101origin"
	"path/filepath"
	"time"
)

// Installation values are independently fixed before reception. The key's
// native location uses the existing reviewed private custody convention; it
// cannot be selected by the record body, HTTP request or environment.
type resetD101NativeRecordInstallation struct {
	Evidence  resetD101EvidenceOriginInstallation
	Expected  d101origin.ExpectedRecordInstallation
	OriginKey resetD101SigningKeyPins
}
type resetD101NativeUnverifiedRecords struct {
	reception *resetD101NativeUnverifiedOrigin
	records   d101origin.UnverifiedRecords
}

// Actual native FD10/whole-original reception. It authenticates neither the
// provider nor issuer installation and cannot make an authority or semantic PASS.
// No private key bytes are retained, returned or added to evidence transport.
func captureResetD101NativeUnverifiedRecords(ctx context.Context, installed resetD101NativeRecordInstallation) (*resetD101NativeUnverifiedRecords, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errResetExecutionEvidence
	}
	expected := installed.Expected
	selected, ok := installed.Evidence.Roles[expected.Role]
	keyPins := installed.OriginKey
	if !ok || expected.ScopeOriginal != installed.Evidence.ScopeOriginal || expected.Profile != selected.PublicPin.PublicProfile || expected.Verifier != selected.PublicPin.VerifierSource || expected.Envelope != selected.Envelope || expected.ReaderBindingsSHA != installed.Evidence.ReaderBindingsSHA || expected.HelperSHA != installed.Evidence.HelperSHA || expected.KeyEnvelopeSHA != keyPins.EnvelopeSHA || !filepath.IsAbs(keyPins.Directory) || filepath.Clean(keyPins.Directory) != keyPins.Directory || !lifecycleJobIDRe.MatchString(keyPins.CustodyID) || !resetD101KeyID.MatchString(keyPins.KeyID) || !resetEvidenceSHA.MatchString(keyPins.PublicKeySpkiSHA) {
		return nil, errResetExecutionEvidence
	}
	bounded, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
	defer cancel()
	start := time.Now()
	current := func() bool { return bounded.Err() == nil && time.Since(start) < resetPreflightMaxAge }
	captured, err := captureResetD101NativeUnverifiedOrigin(bounded, installed.Evidence, expected.Role, expected.Subject)
	if err != nil || captured.operationID != expected.OperationID {
		return nil, errResetExecutionEvidence
	}
	origin, err := captured.Original(captured.binding.OriginRecordReference().LogicalID)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	custody, err := captured.Original(captured.binding.NativeCustodyReference().LogicalID)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	records, err := d101origin.ParseUnverifiedRecords(captured.binding, origin, custody, expected, time.Now())
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	// Every role binding dependency is consumed as registered whole bytes, with
	// its actual native snapshot. Parser references never select filesystem paths.
	consume := func(ref et.RawReference) ([]byte, error) {
		entry, ok := captured.entries[ref.LogicalID]
		if !current() || !ok || entry.Reference != ref {
			return nil, errResetExecutionEvidence
		}
		path, err := et.OriginalPath(expected.OperationID, ref.LogicalID)
		if err != nil {
			return nil, errResetExecutionEvidence
		}
		native, snapshot, err := d101custody.CapturePrivateOriginal(path, int64(ref.ByteLength))
		if err != nil || snapshot != entry.Snapshot || native.SHA256 != ref.SHA256 || uint64(len(native.Bytes)) != ref.ByteLength {
			return nil, errResetExecutionEvidence
		}
		if prior, ok := captured.originals[ref.LogicalID]; ok && !bytes.Equal(prior, native.Bytes) {
			return nil, errResetExecutionEvidence
		}
		captured.originals[ref.LogicalID] = bytes.Clone(native.Bytes)
		captured.observed[path] = resetD101NativeOriginOriginal{path: path, original: native, snapshot: snapshot}
		return native.Bytes, nil
	}
	for _, ref := range records.Dependencies() {
		if _, err := consume(ref); err != nil {
			return nil, err
		}
	}
	actual := make(map[string]d101custody.NativeFilePin, 10)
	type nativeRead struct {
		path       string
		limit      int64
		executable bool
	}
	pinReads := make(map[string]nativeRead, 10)
	refs := map[string]et.RawReference{"subject": expected.Subject, "originRecord": captured.binding.OriginRecordReference(), "scope": expected.ScopeOriginal, "verifierSource": expected.Verifier, "providerRecord": records.Origin().ProviderRecord, "processIdentity": expected.ProcessIdentity}
	for slot, ref := range refs {
		if _, err := consume(ref); err != nil {
			return nil, err
		}
		path, _ := et.OriginalPath(expected.OperationID, ref.LogicalID)
		native, pin, err := d101custody.CapturePrivateOriginalPin(path, int64(ref.ByteLength))
		if err != nil || !current() || pin.Snapshot != captured.entries[ref.LogicalID].Snapshot || native.SHA256 != ref.SHA256 || !bytes.Equal(native.Bytes, captured.originals[ref.LogicalID]) {
			return nil, errResetExecutionEvidence
		}
		actual[slot] = pin
		pinReads[slot] = nativeRead{path, int64(ref.ByteLength), false}
	}
	profilePath, _ := et.PublicProfilePath(string(expected.Role))
	for _, item := range []struct {
		slot, path, sha string
		limit           int64
		executable      bool
	}{
		{"publicProfile", profilePath, expected.Profile.SHA256, int64(expected.Profile.ByteLength), false},
		{"readerBindings", resetD101NativeReaderBindingsPath, expected.ReaderBindingsSHA, et.MetadataMaxBytes, false},
		{"helper", resetD101EvidenceHelperPath, expected.HelperSHA, 32 << 20, true},
		{"signingKeyEnvelope", filepath.Join(keyPins.Directory, keyPins.CustodyID+".json"), expected.KeyEnvelopeSHA, et.MetadataMaxBytes, false},
	} {
		read := d101custody.CapturePrivateOriginalPin
		if item.executable {
			read = d101custody.CapturePrivateExecutablePin
		}
		native, pin, err := read(item.path, item.limit)
		if item.slot == "signingKeyEnvelope" {
			defer clear(native.Bytes)
		}
		if err != nil || !current() || native.SHA256 != item.sha {
			return nil, errResetExecutionEvidence
		}
		if item.slot != "signingKeyEnvelope" {
			prior, ok := captured.observed[item.path]
			if !ok || prior.snapshot != pin.Snapshot || !bytes.Equal(prior.original.Bytes, native.Bytes) {
				return nil, errResetExecutionEvidence
			}
		}
		actual[item.slot] = pin
		pinReads[item.slot] = nativeRead{item.path, item.limit, item.executable}
	}
	if records.RequireNativePins(actual) != nil {
		return nil, errResetExecutionEvidence
	}
	// Derive the public SPKI from the actual private envelope and compare the
	// independently pinned public profile. This does not use the purpose signer.
	profile, err := captured.Original(expected.Profile.LogicalID)
	var public struct {
		PublicKeySpkiSHA string `json:"publicKeySpkiSha256"`
	}
	if err != nil || json.Unmarshal(profile, &public) != nil || public.PublicKeySpkiSHA != keyPins.PublicKeySpkiSHA {
		return nil, errResetExecutionEvidence
	}
	key, err := readResetD101SigningKey(keyPins)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	defer key.close()
	// Recheck all consumed originals and the native key pin after key decoding.
	for _, prior := range captured.observed {
		read := d101custody.CapturePrivateOriginal
		if prior.executable {
			read = d101custody.CapturePrivateExecutable
		}
		native, snapshot, err := read(prior.path, int64(prior.snapshot.ByteLength))
		if err != nil || !current() || snapshot != prior.snapshot || native.SHA256 != prior.original.SHA256 || !bytes.Equal(native.Bytes, prior.original.Bytes) {
			return nil, errResetExecutionEvidence
		}
	}
	// Parent FD snapshots must also remain identical after all later reads.
	for slot, source := range pinReads {
		read := d101custody.CapturePrivateOriginalPin
		if source.executable {
			read = d101custody.CapturePrivateExecutablePin
		}
		native, pin, err := read(source.path, source.limit)
		if slot == "signingKeyEnvelope" {
			clear(native.Bytes)
		}
		if err != nil || !current() || pin != actual[slot] {
			return nil, errResetExecutionEvidence
		}
	}
	if records.RequireNativePins(actual) != nil {
		return nil, errResetExecutionEvidence
	}
	for id, entry := range captured.entries {
		path, err := et.OriginalPath(expected.OperationID, id)
		if err != nil || !current() || d101custody.InspectPrivateSnapshot(path, entry.Snapshot) != nil {
			return nil, errResetExecutionEvidence
		}
	}
	if !current() || time.Since(captured.binding.ObservedAt()) < 0 || time.Since(captured.binding.ObservedAt()) >= resetPreflightMaxAge {
		return nil, errResetExecutionEvidence
	}
	return &resetD101NativeUnverifiedRecords{captured, records}, nil
}
