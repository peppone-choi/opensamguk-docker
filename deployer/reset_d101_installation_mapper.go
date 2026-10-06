package main

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"time"

	"opensamguk-deployer/internal/d101custody"
)

// Private Go installation input from the independently reviewed fixed installer.
// The exact7 reader JSON still maps only existing originals. It cannot select
// the independent anchor, semantic verifier, launcher or restored SQL producer.
// No public schema, role, purpose, key, path or enable switch is introduced.
// Populated only by reviewed private Go source after the exact actual input
// card exists. No file owner/body, HTTP caller or env can replace this anchor.
var resetD101ReviewedFixedInstallation *resetD101FixedInstallation

type resetD101FixedInstallation struct {
	readerSHA  string
	readerPin  d101custody.NativeFilePin
	authority  resetD101HostAuthorityPins
	provenance resetD101ApprovedReceiptPins
	current    resetD101CurrentFreezePins
	preStop    resetD101PreStopNativeInstallation
	seed       resetD101SeedMaterialInputs
	candidate  resetD101CandidateInstallation
	upstream   resetD101ProvenanceUpstreamVerifier
	evidence   resetD101HostEvidenceVerifier
	recovery   resetD101FixedRecoveryProducer
}

// Actual restore1/native producer, not a record claiming RECOVERED. The
// existing consumers separately require the same BEGIN/claim, backup, old SQL,
// actual restored observation and RESULT before signing the closure.
type resetD101FixedRecoveryProducer interface {
	ReadClosure(context.Context, string, string) ([]byte, error)
	VerifyRecovery(context.Context, resetD101RecoveryBinding) error
	ReadDatabase(context.Context, string, string) (resetD101RestoredDatabaseObservation, error)
}

func mapResetD101FixedInstallation(ctx context.Context, c config, original d101custody.Original, pin d101custody.NativeFilePin, input *resetD101FixedInstallation) (resetD101InstalledSources, error) {
	return mapResetD101FixedInstallationWithSources(ctx, c, original, pin, input,
		d101custody.CapturePrivateOriginalPin, time.Now, 0)
}

// Data reader/clock/UID injection is confined to isolated native fixtures.
// Production always enters above with fixed path/root custody. Verifiers and
// suppliers remain mandatory; the mapper never substitutes successful callbacks.
func mapResetD101FixedInstallationWithSources(ctx context.Context, c config, original d101custody.Original, pin d101custody.NativeFilePin, input *resetD101FixedInstallation,
	read resetD101CurrentFreezeReader, clock func() time.Time, uid uint32) (resetD101InstalledSources, error) {
	empty := resetD101InstalledSources{}
	if ctx == nil || ctx.Err() != nil || input == nil {
		return empty, errResetD101InstallationNotSupplied
	}
	p := *input
	if read == nil || clock == nil || p.upstream == nil || p.evidence == nil || p.preStop.verify == nil || p.current.supplier == nil || p.recovery == nil ||
		(reflect.ValueOf(p.recovery).Kind() == reflect.Pointer && reflect.ValueOf(p.recovery).IsNil()) {
		return empty, errResetD101InstallationNotSupplied
	}
	// Freeze every mutable independent map/key before any producer can run.
	p.authority.OriginalDirectories = cloneResetD101Strings(p.authority.OriginalDirectories)
	p.authority.ApprovalAnchorSpki = bytes.Clone(p.authority.ApprovalAnchorSpki)
	p.provenance.OriginalDirectories = cloneResetD101Strings(p.provenance.OriginalDirectories)
	p.provenance.AuxiliaryDirectories = cloneResetD101Strings(p.provenance.AuxiliaryDirectories)
	p.provenance.IssuerSPKI = bytes.Clone(p.provenance.IssuerSPKI)
	p.provenance.AllowedPurposes = append([]string(nil), p.provenance.AllowedPurposes...)
	original.Bytes = bytes.Clone(original.Bytes)
	if requireResetD101FixedReaderMapping(original, pin, p) != nil {
		return empty, errResetExecutionEvidence
	}
	checkRecord := func(ctx context.Context) error {
		if ctx == nil || ctx.Err() != nil {
			return errResetExecutionEvidence
		}
		after, afterPin, err := read(resetD101NativeReaderInstallationPath, 64<<10)
		if err != nil || afterPin != pin || after.SHA256 != original.SHA256 || !bytes.Equal(after.Bytes, original.Bytes) || ctx.Err() != nil {
			return errResetExecutionEvidence
		}
		return nil
	}
	if checkRecord(ctx) != nil {
		return empty, errResetExecutionEvidence
	}
	// Construct the actual authority from existing typed signature/custody/
	// scope/issuer parsers. Authentication is rerun on every later purpose query.
	verifyEvidence := func(ctx context.Context, evidence *resetD101HostEvidence) error {
		if evidence == nil || checkRecord(ctx) != nil {
			return errResetExecutionEvidence
		}
		wire, err := verifyResetD101ApprovedReceiptProvenanceWithSources(ctx, p.provenance, p.upstream, clock, uid, func() ([]byte, error) {
			if checkRecord(ctx) != nil {
				return nil, errResetExecutionEvidence
			}
			return bytes.Clone(original.Bytes), nil
		})
		expected, e := evidence.Original("approvedReceiptProvenance")
		if err != nil || e != nil || !bytes.Equal(wire, expected) || p.evidence(ctx, evidence) != nil || checkRecord(ctx) != nil {
			return errResetExecutionEvidence
		}
		return nil
	}
	authority, err := newResetD101HostAuthorityWithUID(p.authority, verifyEvidence, clock, uid)
	if err != nil {
		return empty, err
	}
	phase, err := newResetD101CurrentFreezeSource(p.current)
	if err != nil {
		return empty, err
	}
	// Wrap all late supplier seams in the unchanged installation custody. A
	// replaced native record cannot inherit registered authority or seed paths.
	purpose := func(ctx context.Context, op, sha string) (resetD101VerifiedPurposeAuthority, error) {
		if checkRecord(ctx) != nil {
			return resetD101VerifiedPurposeAuthority{}, errResetExecutionEvidence
		}
		value, err := authority(ctx, op, sha)
		if err != nil || checkRecord(ctx) != nil {
			return resetD101VerifiedPurposeAuthority{}, errResetExecutionEvidence
		}
		return value, nil
	}
	current := func(ctx context.Context, binding resetExecutionPhaseBinding) (resetExecutionPhaseSnapshot, error) {
		if checkRecord(ctx) != nil {
			return resetExecutionPhaseSnapshot{}, errResetExecutionEvidence
		}
		value, err := phase(ctx, binding)
		if err != nil || checkRecord(ctx) != nil {
			return resetExecutionPhaseSnapshot{}, errResetExecutionEvidence
		}
		return value, nil
	}
	preStop := p.preStop
	preStop.verify = func(ctx context.Context, binding resetD101PreStopNativeBinding) error {
		if checkRecord(ctx) != nil || p.preStop.verify(ctx, binding) != nil || checkRecord(ctx) != nil {
			return errResetExecutionEvidence
		}
		return nil
	}
	closure := func(ctx context.Context, op, sha string) ([]byte, error) {
		if op != p.authority.OperationID || !resetEvidenceSHA.MatchString(sha) || checkRecord(ctx) != nil {
			return nil, errResetExecutionEvidence
		}
		wire, err := p.recovery.ReadClosure(ctx, op, sha)
		wire = bytes.Clone(wire)
		if err != nil || len(wire) == 0 || len(wire) > 16<<10 || resetD101OriginalSHA(wire) != sha || checkRecord(ctx) != nil {
			return nil, errResetExecutionEvidence
		}
		return wire, nil
	}
	verifier := func(ctx context.Context, binding resetD101RecoveryBinding) error {
		if binding.operation.OperationID != p.authority.OperationID || binding.intent.SHA != p.authority.ApprovalIntentSHA ||
			checkRecord(ctx) != nil || p.recovery.VerifyRecovery(ctx, binding) != nil || checkRecord(ctx) != nil {
			return errResetExecutionEvidence
		}
		return nil
	}
	database := func(ctx context.Context, op, sha string) (resetD101RestoredDatabaseObservation, error) {
		if op != p.authority.OperationID || !resetEvidenceSHA.MatchString(sha) || checkRecord(ctx) != nil {
			return resetD101RestoredDatabaseObservation{}, errResetExecutionEvidence
		}
		value, err := p.recovery.ReadDatabase(ctx, op, sha)
		value.original = bytes.Clone(value.original)
		if err != nil || value.sha != sha || resetD101OriginalSHA(value.original) != sha || checkRecord(ctx) != nil {
			return resetD101RestoredDatabaseObservation{}, errResetExecutionEvidence
		}
		return value, nil
	}
	if checkRecord(ctx) != nil {
		return empty, errResetExecutionEvidence
	}
	// Candidate installation consumes a real QUERY, command/card/caps/selected
	// originals and the installed purpose envelope; no Docker/seeder command runs.
	candidateConfig := closeResetD101InstalledSources(c)
	candidateConfig.d101PurposeAuthority = purpose
	candidateConfig.d101PhaseSource = current
	candidateConfig.d101PreStopNativeInstallation = &preStop
	candidateConfig.d101RecoveryClosureReader = closure
	candidateConfig.d101RecoveryVerifier = verifier
	candidateConfig.d101RecoveryDatabaseSource = database
	candidateConfig.d101SeedMaterialInputs = &p.seed
	installed, err := candidateConfig.installResetD101CandidatePipeline(ctx, p.candidate)
	if err != nil || installed.d101CandidatePipeline == nil || checkRecord(ctx) != nil {
		return empty, errResetExecutionEvidence
	}
	return resetD101InstalledSources{purpose, current, &preStop, closure, verifier, database, &p.seed, installed.d101CandidatePipeline}, nil
}

// Pure structural/native binding only: this never supplies actor authority.
func requireResetD101FixedReaderMapping(original d101custody.Original, pin d101custody.NativeFilePin, p resetD101FixedInstallation) error {
	if !resetEvidenceSHA.MatchString(p.readerSHA) || original.SHA256 != p.readerSHA || resetD101OriginalSHA(original.Bytes) != p.readerSHA ||
		pin != p.readerPin || p.readerSHA != p.provenance.ReaderInstallationSHA ||
		p.authority.OperationID != p.provenance.OperationID || p.authority.ApprovalIntentSHA != p.provenance.ApprovalIntentSHA ||
		p.authority.SigningKey != p.provenance.RootKey || !reflect.DeepEqual(p.authority.OriginalDirectories, p.provenance.OriginalDirectories) ||
		!gitSHA40.MatchString(p.preStop.sourceSHA) || p.preStop.parentDevice == 0 || p.preStop.parentInode == 0 ||
		p.candidate.OperationID != p.authority.OperationID || p.candidate.IntentSHA != p.authority.ApprovalIntentSHA ||
		p.current.operationID != p.authority.OperationID || p.candidate.ProducerIdentity != p.authority.SigningKey.KeyID {
		return errResetExecutionEvidence
	}
	var record resetD101ProvenanceReaderInstallation
	if requireResetIntentShape(original.Bytes, reflect.TypeOf(record)) != nil || decodeResetPrivateJSON(original.Bytes, &record) != nil ||
		record.SchemaVersion != 1 || record.Kind != "D101_NATIVE_READER_BINDINGS_V1" || len(record.OriginalFiles) != 14 ||
		record.ManifestFile != filepath.Join(p.authority.ManifestDirectory, p.authority.OperationID+".json") ||
		record.ClockFile != filepath.Join(p.authority.ClockDirectory, p.authority.OperationID+".json") ||
		record.SelectedEnvelopeFile != filepath.Join(p.candidate.SelectedEnvelopeDirectory, p.authority.OperationID+".json") {
		return errResetExecutionEvidence
	}
	seen := map[string]bool{}
	for _, id := range resetD101HostOriginalIDs {
		path := record.OriginalFiles[id]
		if path != filepath.Join(p.authority.OriginalDirectories[id], p.authority.OperationID+".json") || !filepath.IsAbs(path) || filepath.Clean(path) != path || seen[path] {
			return errResetExecutionEvidence
		}
		seen[path] = true
	}
	// Root token is checked as a fixed native original; its body never becomes a
	// purpose key or authenticator. The existing actual semantic verifier must
	// bind it to the approved transport/installer, rather than adopt its contents.
	if !filepath.IsAbs(record.RootTokenFile) || filepath.Clean(record.RootTokenFile) != record.RootTokenFile ||
		seen[record.RootTokenFile] || seen[record.ManifestFile] || seen[record.ClockFile] || seen[record.SelectedEnvelopeFile] {
		return errResetExecutionEvidence
	}
	if pin.SHA256 != original.SHA256 || pin.Snapshot.ByteLength != uint64(len(original.Bytes)) || pin.Snapshot.Device == 0 || pin.Snapshot.Inode == 0 || pin.Snapshot.ModifiedAtUnixNano <= 0 || pin.OwnerUID != 0 || pin.FileMode != 0400 || pin.LinkCount != 1 || pin.ParentSnapshot.Device == 0 || pin.ParentSnapshot.Inode == 0 || pin.ParentOwnerUID != 0 || pin.ParentMode != 0700 {
		return errResetExecutionEvidence
	}
	return nil
}
