package main

import (
	"bytes"
	"context"
	"reflect"
	"time"

	"opensamguk-deployer/internal/d101custody"
	et "opensamguk-deployer/internal/d101evidencetransport"
	"opensamguk-deployer/internal/d101origin"
)

const resetD101NativeReaderBindingsPath = "/etc/opensamguk/d101/reader-installation.json"
const resetD101EvidenceHelperPath = "/etc/opensamguk/d101/native-helper/d101-host-reader"

// Values must be supplied by the independently reviewed fixed installation.
// No field is an HTTP/env path, and no expected value is learned from a response.
// This is a data reception contract; it does not approve installing an issuer.
type resetD101EvidenceOriginInstallation struct {
	SourcePinSHA      string
	SourcePinSnapshot d101custody.PrivateSnapshot
	ReaderBindingsSHA string
	BindingsSnapshot  d101custody.PrivateSnapshot
	HelperSHA         string
	HelperSnapshot    d101custody.PrivateSnapshot
	ScopeOriginal     et.RawReference
	Roles             map[d101origin.Role]resetD101ReviewedOriginRole
}

type resetD101ReviewedOriginRole struct {
	PublicPin       et.PublicPin
	ProfileSnapshot d101custody.PrivateSnapshot
	Envelope        et.RawReference
}

type resetD101NativeOriginOriginal struct {
	path       string
	original   d101custody.Original
	snapshot   d101custody.PrivateSnapshot
	executable bool
}

// Native reception plus pure signature binding only. The private fields never
// produce a VerifiedPurposeAuthority, approval Boolean, installer or row PASS.
// Actual role-specific origin/custody parsers must consume these whole originals
// before the production main installer may register any authority.
type resetD101NativeUnverifiedOrigin struct {
	binding   d101origin.UnverifiedOriginBinding
	originals map[string][]byte
}

func (value *resetD101NativeUnverifiedOrigin) Original(id string) ([]byte, error) {
	if value == nil {
		return nil, errResetExecutionEvidence
	}
	wire, ok := value.originals[id]
	if !ok {
		return nil, errResetExecutionEvidence
	}
	return append([]byte(nil), wire...), nil
}

// This production call reads only fixed native paths. It issues no key or
// signature, writes no file, runs no child and does not change config authority.
func captureResetD101NativeUnverifiedOrigin(ctx context.Context, pins resetD101EvidenceOriginInstallation,
	role d101origin.Role, expectedSubject et.RawReference) (*resetD101NativeUnverifiedOrigin, error) {
	return captureResetD101NativeUnverifiedOriginWithReaders(ctx, pins, role, expectedSubject,
		d101custody.CapturePrivateOriginal, d101custody.CapturePrivateExecutable,
		d101custody.InspectPrivateSnapshot, time.Now)
}

// Data reader injection is isolated from the production entry point. It is not
// an authentication callback and cannot return installed or verified authority.
func captureResetD101NativeUnverifiedOriginWithReaders(ctx context.Context, pins resetD101EvidenceOriginInstallation,
	role d101origin.Role, expectedSubject et.RawReference,
	capture, executable func(string, int64) (d101custody.Original, d101custody.PrivateSnapshot, error),
	inspect func(string, d101custody.PrivateSnapshot) error, clock func() time.Time) (*resetD101NativeUnverifiedOrigin, error) {
	if ctx == nil || ctx.Err() != nil || capture == nil || executable == nil || inspect == nil || clock == nil ||
		!resetEvidenceSHA.MatchString(pins.SourcePinSHA) || !resetEvidenceSHA.MatchString(pins.ReaderBindingsSHA) || !resetEvidenceSHA.MatchString(pins.HelperSHA) ||
		et.ValidateSnapshot(pins.SourcePinSnapshot) != nil || pins.SourcePinSnapshot.ByteLength > et.MetadataMaxBytes ||
		et.ValidateSnapshot(pins.BindingsSnapshot) != nil || pins.BindingsSnapshot.ByteLength > et.MetadataMaxBytes ||
		pins.HelperSnapshot.Device == 0 || pins.HelperSnapshot.Inode == 0 || pins.HelperSnapshot.ByteLength == 0 || pins.HelperSnapshot.ByteLength > 32<<20 || pins.HelperSnapshot.ModifiedAtUnixNano <= 0 ||
		et.ValidateRawReference(pins.ScopeOriginal) != nil || pins.ScopeOriginal.MediaType != "application/json" || pins.ScopeOriginal.ByteLength > et.MetadataMaxBytes ||
		et.ValidateRawReference(expectedSubject) != nil || len(pins.Roles) != 3 {
		return nil, errResetExecutionEvidence
	}
	roles := make(map[d101origin.Role]resetD101ReviewedOriginRole, 3)
	for _, fixedRole := range []d101origin.Role{d101origin.ApprovalIssuer, d101origin.OfficialGitHubCollector, d101origin.IndependentReviewCollector} {
		value, ok := pins.Roles[fixedRole]
		if !ok || value.PublicPin.Role != string(fixedRole) || et.ValidateRawReference(value.PublicPin.PublicProfile) != nil ||
			value.PublicPin.PublicProfile.ByteLength > et.MetadataMaxBytes || value.PublicPin.PublicProfile.MediaType != "application/json" ||
			et.ValidateRawReference(value.PublicPin.VerifierSource) != nil || et.ValidateRawReference(value.PublicPin.NativeCustody) != nil ||
			value.PublicPin.NativeCustody.ByteLength > et.MetadataMaxBytes || value.PublicPin.NativeCustody.MediaType != "application/json" ||
			et.ValidateRawReference(value.Envelope) != nil || value.Envelope.ByteLength > et.MetadataMaxBytes || value.Envelope.MediaType != "application/json" ||
			et.ValidateSnapshot(value.ProfileSnapshot) != nil || value.ProfileSnapshot.ByteLength != value.PublicPin.PublicProfile.ByteLength {
			return nil, errResetExecutionEvidence
		}
		roles[fixedRole] = value
	}
	selected, ok := roles[role]
	if !ok {
		return nil, errResetExecutionEvidence
	}
	ctx, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
	defer cancel()
	started := time.Now()
	current := func() bool { return ctx.Err() == nil && time.Since(started) < resetPreflightMaxAge }
	observed := map[string]resetD101NativeOriginOriginal{}
	readFixed := func(path string, sha string, snapshot d101custody.PrivateSnapshot, isExecutable bool) ([]byte, error) {
		if !current() {
			return nil, errResetExecutionEvidence
		}
		reader := capture
		if isExecutable {
			reader = executable
		}
		original, actual, err := reader(path, int64(snapshot.ByteLength))
		if err != nil || actual != snapshot || uint64(len(original.Bytes)) != snapshot.ByteLength || original.SHA256 != sha || et.HashOriginal(original.Bytes) != sha || !current() {
			return nil, errResetExecutionEvidence
		}
		if prior, ok := observed[path]; ok && (prior.snapshot != actual || prior.original.SHA256 != sha || !bytes.Equal(prior.original.Bytes, original.Bytes) || prior.executable != isExecutable) {
			return nil, errResetExecutionEvidence
		}
		observed[path] = resetD101NativeOriginOriginal{path, original, actual, isExecutable}
		return append([]byte(nil), original.Bytes...), nil
	}
	pinWire, err := readFixed(et.SourcePinPath, pins.SourcePinSHA, pins.SourcePinSnapshot, false)
	if err != nil {
		return nil, err
	}
	pin, err := et.DecodeSourcePin(pinWire)
	if err != nil || pin.ReaderBindingsSHA256 != pins.ReaderBindingsSHA || pin.HelperSHA256 != pins.HelperSHA || len(pin.OriginPins) != 3 {
		return nil, errResetExecutionEvidence
	}
	for _, publicPin := range pin.OriginPins {
		fixed, ok := roles[d101origin.Role(publicPin.Role)]
		if !ok || fixed.PublicPin != publicPin {
			return nil, errResetExecutionEvidence
		}
	}
	if _, err := readFixed(resetD101NativeReaderBindingsPath, pins.ReaderBindingsSHA, pins.BindingsSnapshot, false); err != nil {
		return nil, err
	}
	if _, err := readFixed(resetD101EvidenceHelperPath, pins.HelperSHA, pins.HelperSnapshot, true); err != nil {
		return nil, err
	}
	indexWire, err := readFixed(et.IndexPath, pin.EvidenceIndexSHA256, pin.EvidenceIndexSnapshot, false)
	if err != nil {
		return nil, err
	}
	index, err := et.RequireSourcePinIndexBinding(pin, indexWire)
	if err != nil || index.CapturedAtUnix > clock().Unix() || clock().Unix() <= 0 {
		return nil, errResetExecutionEvidence
	}
	entries, err := et.AuditReachablePages(ctx, index, func(ref et.PageReference) ([]byte, error) {
		path, err := et.PagePath(index.Scope.OperationID, ref)
		if err != nil {
			return nil, err
		}
		return readFixed(path, ref.SHA256, ref.Snapshot, false)
	})
	if err != nil || !current() {
		return nil, errResetExecutionEvidence
	}
	for id, entry := range entries {
		path, err := et.OriginalPath(index.Scope.OperationID, id)
		if err != nil || !current() || inspect(path, entry.Snapshot) != nil {
			return nil, errResetExecutionEvidence
		}
	}
	readRegistered := func(ref et.RawReference) ([]byte, error) {
		entry, ok := entries[ref.LogicalID]
		if !ok || et.ValidateRawReference(ref) != nil || entry.Reference != ref {
			return nil, errResetExecutionEvidence
		}
		path, err := et.OriginalPath(index.Scope.OperationID, ref.LogicalID)
		if err != nil {
			return nil, err
		}
		return readFixed(path, ref.SHA256, entry.Snapshot, false)
	}
	scopeWire, err := readRegistered(pins.ScopeOriginal)
	if err != nil {
		return nil, err
	}
	scope, err := et.DecodeScope(scopeWire)
	if err != nil || !reflect.DeepEqual(scope, pin.Scope) {
		return nil, errResetExecutionEvidence
	}
	envelopePresent := false
	for _, ref := range index.OriginProofs {
		if ref == selected.Envelope {
			envelopePresent = true
		}
	}
	if !envelopePresent {
		return nil, errResetExecutionEvidence
	}
	profilePath, err := et.PublicProfilePath(string(role))
	if err != nil {
		return nil, err
	}
	profile, err := readFixed(profilePath, selected.PublicPin.PublicProfile.SHA256, selected.ProfileSnapshot, false)
	if err != nil {
		return nil, err
	}
	envelope, err := readRegistered(selected.Envelope)
	if err != nil {
		return nil, err
	}
	binding, err := d101origin.VerifyCryptographicBinding(envelope, profile, d101origin.ExpectedBinding{
		Role: role, OperationID: scope.OperationID, ProfileSHA256: selected.PublicPin.PublicProfile.SHA256, ScopeOriginal: pins.ScopeOriginal,
	}, clock())
	if err != nil || binding.SubjectReference() != expectedSubject || binding.NativeCustodyReference() != selected.PublicPin.NativeCustody ||
		binding.OriginRecordReference().ByteLength > et.MetadataMaxBytes || binding.OriginRecordReference().MediaType != "application/json" {
		return nil, errResetExecutionEvidence
	}
	result := &resetD101NativeUnverifiedOrigin{binding: binding, originals: map[string][]byte{}}
	for _, ref := range []et.RawReference{pins.ScopeOriginal, selected.Envelope, expectedSubject, binding.OriginRecordReference(), binding.NativeCustodyReference(), selected.PublicPin.VerifierSource, pin.CollectorSource, pin.InstallerSource} {
		wire, err := readRegistered(ref)
		if err != nil {
			return nil, err
		}
		result.originals[ref.LogicalID] = append([]byte(nil), wire...)
	}
	if prior, ok := result.originals[selected.PublicPin.PublicProfile.LogicalID]; ok && !bytes.Equal(prior, profile) {
		return nil, errResetExecutionEvidence
	}
	result.originals[selected.PublicPin.PublicProfile.LogicalID] = append([]byte(nil), profile...)
	// All reachable original snapshots and every consumed whole original are
	// rechecked. Unconsumed raw-DAG semantics are still the final verifier's job.
	for id, entry := range entries {
		path, err := et.OriginalPath(scope.OperationID, id)
		if err != nil || !current() || inspect(path, entry.Snapshot) != nil {
			return nil, errResetExecutionEvidence
		}
	}
	for _, prior := range observed {
		if _, err := readFixed(prior.path, prior.original.SHA256, prior.snapshot, prior.executable); err != nil {
			return nil, err
		}
	}
	if !current() {
		return nil, errResetExecutionEvidence
	}
	return result, nil
}
