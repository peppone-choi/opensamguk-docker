package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"time"

	et "opensamguk-deployer/internal/d101evidencetransport"
	"opensamguk-deployer/internal/d101operatorauth"
	"opensamguk-deployer/internal/d101origin"
)

// Only an independently installed native supplier may implement this seam.
// Its authentication must cover approved historical originals, all upstream
// semantics, actual installation/key custody and before/after native snapshots.
// Shape, current JWT authentication and JSON hashes do not supply that authority.
type resetD101IssuerSemanticSource interface {
	CaptureAuthenticatedUnsigned(context.Context, d101operatorauth.TechnicalIssuance) (resetD101IssuerSemanticSnapshot, error)
	RecheckAuthenticatedUnsigned(context.Context, d101operatorauth.TechnicalIssuance, resetD101IssuerSemanticSnapshot) error
}

type resetD101IssuerSemanticSnapshot struct {
	FinalCard, ScopeOriginal, DecisionSlices               []byte
	DecisionParents                                        [5][]byte
	HistoricalApproval                                     d101origin.UnverifiedRecords
	OriginOriginal, OriginCustodyOriginal, ApprovalPayload []byte
	OriginNativeCustodyRef                                 et.RawReference
	OriginInstallation                                     d101origin.ExpectedRecordInstallation
	OriginDependencies                                     map[string][]byte
	Original13                                             map[string][]byte
	Receipt                                                resetD101ApprovedReceiptAttestation
	NativeCustody, InstallerIdentity                       []byte
	ReceiptPins                                            resetD101ApprovedReceiptPins
	InstalledApprovalIssuer, InstalledReceiptIssuer        d101operatorauth.IssuerPins
}

// A private projection is obtained only from opaque TechnicalIssuance in the
// production entrypoint. Tests can exercise pure mapping without forging it.
type resetD101IssuerSemanticFacts struct {
	scope             d101operatorauth.TechnicalScope
	event             d101operatorauth.IssuanceEvent
	approval, receipt d101operatorauth.IssuerPins
	issued            time.Time
}

// No signer or filesystem writer is exposed. Both unsigned roles are returned
// together only after semantic and native rechecks. This is not an execution grant.
type resetD101IssuerUnsignedBatch struct {
	approvalPayload, receiptAttestation []byte
	receipt                             resetD101ApprovedReceiptAttestation
	receiptPins                         d101operatorauth.IssuerPins
}

func (b resetD101IssuerUnsignedBatch) ApprovalPayload() []byte { return bytes.Clone(b.approvalPayload) }
func (b resetD101IssuerUnsignedBatch) ReceiptAttestation() []byte {
	return bytes.Clone(b.receiptAttestation)
}

func newResetD101IssuerUnsignedBatch(ctx context.Context, issuance d101operatorauth.TechnicalIssuance, source resetD101IssuerSemanticSource) (resetD101IssuerUnsignedBatch, error) {
	empty := resetD101IssuerUnsignedBatch{}
	if ctx == nil || ctx.Err() != nil || source == nil || (reflect.ValueOf(source).Kind() == reflect.Pointer && reflect.ValueOf(source).IsNil()) {
		return empty, errResetExecutionEvidence
	}
	scope, e1 := issuance.Scope()
	event, e2 := issuance.Event()
	approval, e3 := issuance.Issuer(d101operatorauth.ApprovalIssuerRole)
	receipt, e4 := issuance.Issuer(d101operatorauth.ApprovedReceiptIssuerRole)
	issued, e5 := issuance.IssuedAtUTC()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return empty, errResetExecutionEvidence
	}
	facts := resetD101IssuerSemanticFacts{scope, event, approval, receipt, issued}
	snapshot, err := source.CaptureAuthenticatedUnsigned(ctx, issuance)
	if err != nil || ctx.Err() != nil {
		return empty, errResetExecutionEvidence
	}
	frozen, err := freezeResetD101IssuerSemanticSnapshot(snapshot)
	if err != nil {
		return empty, errResetExecutionEvidence
	}
	beforeRecheck, err := json.Marshal(frozen)
	if err != nil {
		return empty, errResetExecutionEvidence
	}
	batch, err := mapResetD101IssuerSemanticUnsigned(ctx, facts, frozen)
	if err != nil || source.RecheckAuthenticatedUnsigned(ctx, issuance, frozen) != nil || ctx.Err() != nil {
		return empty, errResetExecutionEvidence
	}
	afterRecheck, marshalErr := json.Marshal(frozen)
	if marshalErr != nil || !bytes.Equal(beforeRecheck, afterRecheck) {
		return empty, errResetExecutionEvidence
	}
	// A supplier callback cannot mutate the frozen fields and thereby change the
	// unsigned bytes after validation. Compare the whole private projection again.
	after, err := mapResetD101IssuerSemanticUnsigned(ctx, facts, frozen)
	if err != nil || !bytes.Equal(batch.approvalPayload, after.approvalPayload) || !bytes.Equal(batch.receiptAttestation, after.receiptAttestation) {
		return empty, errResetExecutionEvidence
	}
	return batch, nil
}

func freezeResetD101IssuerSemanticSnapshot(s resetD101IssuerSemanticSnapshot) (resetD101IssuerSemanticSnapshot, error) {
	history := s.HistoricalApproval
	// Deep copying all mutable exported inputs prevents caller-owned maps/slices
	// from silently changing scope, originals, purposes or installation pins.
	wire, err := json.Marshal(s)
	if err != nil {
		return resetD101IssuerSemanticSnapshot{}, errResetExecutionEvidence
	}
	var result resetD101IssuerSemanticSnapshot
	if json.Unmarshal(wire, &result) != nil {
		return result, errResetExecutionEvidence
	}
	result.HistoricalApproval = history
	return result, nil
}

func resetD101SemanticRefMatches(ref d101operatorauth.Reference, original []byte) bool {
	return et.ValidateRawReference(et.RawReference{LogicalID: ref.LogicalID, SHA256: ref.SHA256, ByteLength: ref.ByteLength, MediaType: ref.MediaType}) == nil &&
		len(original) > 0 && len(original) <= et.MetadataMaxBytes && uint64(len(original)) == ref.ByteLength && resetD101OriginalSHA(original) == ref.SHA256
}
func resetD101SemanticRawMatches(ref et.RawReference, original []byte) bool {
	return et.ValidateRawReference(ref) == nil && len(original) > 0 && uint64(len(original)) == ref.ByteLength && resetD101OriginalSHA(original) == ref.SHA256
}
func resetD101SemanticDecode(original []byte, value any) error {
	if len(original) == 0 || len(original) > et.MetadataMaxBytes || requireResetIntentShape(original, reflect.TypeOf(value)) != nil || decodeResetPrivateJSON(original, value) != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func mapResetD101IssuerSemanticUnsigned(ctx context.Context, f resetD101IssuerSemanticFacts, s resetD101IssuerSemanticSnapshot) (resetD101IssuerUnsignedBatch, error) {
	empty := resetD101IssuerUnsignedBatch{}
	if ctx == nil || ctx.Err() != nil || f.issued.IsZero() || f.issued.After(time.Now()) ||
		!reflect.DeepEqual(f.approval, s.InstalledApprovalIssuer) || !reflect.DeepEqual(f.receipt, s.InstalledReceiptIssuer) ||
		f.approval.Role != d101operatorauth.ApprovalIssuerRole || f.receipt.Role != d101operatorauth.ApprovedReceiptIssuerRole || f.approval.PublicKeySPKISHA256 == f.receipt.PublicKeySPKISHA256 ||
		f.event.RunAttempt != 1 || f.event.JTI == "" || f.event.ScopeDecisionOriginal != f.scope.FinalCard ||
		!resetD101SemanticRefMatches(f.scope.FinalCard, s.FinalCard) || !resetD101SemanticRefMatches(f.scope.ScopeOriginal, s.ScopeOriginal) ||
		!resetEvidenceSHA.MatchString(f.scope.DecisionSlicesSHA256) || resetD101OriginalSHA(s.DecisionSlices) != f.scope.DecisionSlicesSHA256 || len(s.DecisionSlices) == 0 || len(s.DecisionSlices) > et.MetadataMaxBytes {
		return empty, errResetExecutionEvidence
	}
	for i, ref := range f.scope.DecisionParents {
		if !resetD101SemanticRefMatches(ref, s.DecisionParents[i]) {
			return empty, errResetExecutionEvidence
		}
	}
	if err := validateResetD101ApprovalUnsigned(f, s); err != nil {
		return empty, err
	}
	if err := validateResetD101ReceiptUnsigned(f, s); err != nil {
		return empty, err
	}
	receipt, err := json.Marshal(s.Receipt)
	if err != nil || len(receipt) > 32<<10 {
		return empty, errResetExecutionEvidence
	}
	var privateReceipt resetD101ApprovedReceiptAttestation
	if json.Unmarshal(receipt, &privateReceipt) != nil {
		return empty, errResetExecutionEvidence
	}
	privatePins := f.receipt
	privatePins.PublicKeySPKI = bytes.Clone(f.receipt.PublicKeySPKI)
	return resetD101IssuerUnsignedBatch{bytes.Clone(s.ApprovalPayload), receipt, privateReceipt, privatePins}, nil
}

func validateResetD101ApprovalUnsigned(f resetD101IssuerSemanticFacts, s resetD101IssuerSemanticSnapshot) error {
	history := s.HistoricalApproval.Origin()
	var origin d101origin.OriginRecord
	var custody d101origin.NativeCustodyRecord
	if history.Role != d101origin.ApprovalIssuer || len(history.RoleBindings) == 0 ||
		resetD101SemanticDecode(s.OriginOriginal, &origin) != nil || resetD101SemanticDecode(s.OriginCustodyOriginal, &custody) != nil {
		return errResetExecutionEvidence
	}
	// Preserve the historical seven fields byte-for-byte, including the old human
	// authentication ref and original approval time. Current event/JTI never replace them.
	if !bytes.Equal(origin.RoleBindings, history.RoleBindings) || origin.ProviderRecord != history.ProviderRecord || origin.Subject != history.Subject || origin.ScopeOriginal != history.ScopeOriginal || history.OperationID != f.scope.OperationID ||
		origin.SchemaVersion != 1 || origin.Kind != "D101_EVIDENCE_ORIGIN_RECORD_V1" || origin.Role != d101origin.ApprovalIssuer || origin.OperationID != f.scope.OperationID ||
		origin.IssuerIdentity != f.approval.Identity || origin.IssuerSourceSHA != f.approval.SourceSHA || origin.IssuerImageDigest != f.approval.ImageDigest || origin.IssuedAtUTC != f.issued.UTC().Format(time.RFC3339Nano) {
		return errResetExecutionEvidence
	}
	installed := s.OriginInstallation
	if installed.Role != origin.Role || installed.OperationID != origin.OperationID || installed.IssuerIdentity != origin.IssuerIdentity || installed.IssuerSourceSHA != origin.IssuerSourceSHA || installed.IssuerImageDigest != origin.IssuerImageDigest ||
		installed.ScopeOriginal != origin.ScopeOriginal || installed.Subject != origin.Subject || origin.ScopeOriginal != (et.RawReference{LogicalID: f.scope.ScopeOriginal.LogicalID, SHA256: f.scope.ScopeOriginal.SHA256, ByteLength: f.scope.ScopeOriginal.ByteLength, MediaType: f.scope.ScopeOriginal.MediaType}) ||
		!resetD101SemanticRawMatches(origin.ScopeOriginal, s.ScopeOriginal) || !resetD101SemanticRawMatches(origin.Subject, s.OriginDependencies[origin.Subject.LogicalID]) || !resetD101SemanticRawMatches(origin.ProviderRecord, s.OriginDependencies[origin.ProviderRecord.LogicalID]) {
		return errResetExecutionEvidence
	}
	originRef := custody.OriginRecord
	if custody.SchemaVersion != 1 || custody.Kind != "D101_EVIDENCE_ORIGIN_NATIVE_CUSTODY_V1" || custody.Role != origin.Role || custody.OperationID != origin.OperationID || custody.IssuerIdentity != origin.IssuerIdentity || custody.IssuerSourceSHA != origin.IssuerSourceSHA || custody.IssuerImageDigest != origin.IssuerImageDigest ||
		custody.ScopeOriginal != origin.ScopeOriginal || custody.Subject != origin.Subject || custody.ProviderRecord != origin.ProviderRecord || !resetD101SemanticRawMatches(originRef, s.OriginOriginal) ||
		custody.PublicProfile != installed.Profile || custody.VerifierSource != installed.Verifier || custody.ProcessIdentity != installed.ProcessIdentity || custody.ReaderBindingsSHA != installed.ReaderBindingsSHA || custody.HelperSHA != installed.HelperSHA || custody.SigningKeyEnvelopeSHA != installed.KeyEnvelopeSHA {
		return errResetExecutionEvidence
	}
	observed, e1 := time.Parse(time.RFC3339Nano, origin.ObservedAtUTC)
	nativeObserved, e2 := time.Parse(time.RFC3339Nano, custody.ObservedAtUTC)
	nativeIssued, e3 := time.Parse(time.RFC3339Nano, custody.IssuedAtUTC)
	if e1 != nil || e2 != nil || e3 != nil || origin.ObservedAtUTC != observed.UTC().Format(time.RFC3339Nano) || custody.ObservedAtUTC != nativeObserved.UTC().Format(time.RFC3339Nano) || custody.IssuedAtUTC != nativeIssued.UTC().Format(time.RFC3339Nano) ||
		observed.After(f.issued) || f.issued.After(nativeObserved) || nativeObserved.After(nativeIssued) || nativeIssued.After(time.Now()) {
		return errResetExecutionEvidence
	}
	for id, pin := range custody.FDPins {
		mode := uint32(0400)
		if id == "helper" {
			mode = 0500
		}
		if et.ValidateSnapshot(pin.Snapshot) != nil || et.ValidateSnapshot(pin.ParentSnapshot) != nil || pin.OwnerUID != 0 || pin.ParentOwnerUID != 0 || pin.FileMode != mode || pin.ParentMode != 0700 || pin.LinkCount != 1 {
			return errResetExecutionEvidence
		}
	}
	refs := map[string]et.RawReference{"subject": origin.Subject, "originRecord": originRef, "scope": origin.ScopeOriginal, "publicProfile": installed.Profile, "verifierSource": installed.Verifier, "providerRecord": origin.ProviderRecord, "processIdentity": installed.ProcessIdentity}
	if len(custody.FDPins) != 10 {
		return errResetExecutionEvidence
	}
	for id, ref := range refs {
		pin, ok := custody.FDPins[id]
		if !ok || et.ValidateRawReference(ref) != nil || pin.SHA256 != ref.SHA256 || pin.Snapshot.ByteLength != ref.ByteLength {
			return errResetExecutionEvidence
		}
	}
	for id, sha := range map[string]string{"readerBindings": installed.ReaderBindingsSHA, "helper": installed.HelperSHA, "signingKeyEnvelope": installed.KeyEnvelopeSHA} {
		if !resetEvidenceSHA.MatchString(sha) || custody.FDPins[id].SHA256 != sha {
			return errResetExecutionEvidence
		}
	}
	if !resetD101SemanticRawMatches(s.OriginNativeCustodyRef, s.OriginCustodyOriginal) || s.OriginNativeCustodyRef.MediaType != "application/json" {
		return errResetExecutionEvidence
	}
	for _, id := range []string{origin.Subject.LogicalID, origin.ScopeOriginal.LogicalID, originRef.LogicalID, installed.Envelope.LogicalID} {
		if id == s.OriginNativeCustodyRef.LogicalID {
			return errResetExecutionEvidence
		}
	}
	for _, ref := range []et.RawReference{origin.Subject, origin.ProviderRecord, installed.Profile, installed.Verifier, installed.ProcessIdentity} {
		if !resetD101SemanticRawMatches(ref, s.OriginDependencies[ref.LogicalID]) {
			return errResetExecutionEvidence
		}
	}
	var profile map[string]json.RawMessage
	if decodeResetPrivateJSON(s.OriginDependencies[installed.Profile.LogicalID], &profile) != nil || len(profile) != 8 {
		return errResetExecutionEvidence
	}
	profileExpected := map[string]any{"schemaVersion": 1, "kind": "D101_EVIDENCE_ORIGIN_PUBLIC_PINS_V1", "role": origin.Role, "issuerIdentity": f.approval.Identity, "issuerSourceSha": f.approval.SourceSHA, "issuerImageDigest": f.approval.ImageDigest, "publicKeySpkiBase64url": base64.RawURLEncoding.EncodeToString(f.approval.PublicKeySPKI), "publicKeySpkiSha256": f.approval.PublicKeySPKISHA256}
	// The existing profile has eight fields, not a new installation flag.
	if len(profile) != len(profileExpected) {
		return errResetExecutionEvidence
	}
	for key, value := range profileExpected {
		encoded, err := json.Marshal(value)
		if err != nil || !bytes.Equal(bytes.TrimSpace(profile[key]), encoded) {
			return errResetExecutionEvidence
		}
	}
	// The existing origin payload codec is private in d101origin. Preserve its
	// exact twelve fields here as raw JSON; no alternative body/profile is introduced.
	var fields map[string]json.RawMessage
	if decodeResetPrivateJSON(s.ApprovalPayload, &fields) != nil || len(fields) != 12 || len(s.ApprovalPayload) > 32<<10 {
		return errResetExecutionEvidence
	}
	expected := map[string]any{"schemaVersion": 1, "kind": "D101_EVIDENCE_ORIGIN_PROOF_V1", "role": origin.Role, "issuerIdentity": origin.IssuerIdentity, "issuerSourceSha": origin.IssuerSourceSHA, "issuerImageDigest": origin.IssuerImageDigest, "operationId": origin.OperationID, "scopeOriginalRef": origin.ScopeOriginal, "subjectRef": origin.Subject, "originRecordRef": originRef, "nativeCustodyRef": s.OriginNativeCustodyRef, "observedAtUtc": custody.ObservedAtUTC}
	for key, value := range expected {
		raw, ok := fields[key]
		if !ok {
			return errResetExecutionEvidence
		}
		if ref, isRef := value.(et.RawReference); isRef {
			got, err := et.DecodeRawReference(raw)
			if err != nil || got != ref {
				return errResetExecutionEvidence
			}
		} else {
			encoded, err := json.Marshal(value)
			if err != nil || !bytes.Equal(bytes.TrimSpace(raw), encoded) {
				return errResetExecutionEvidence
			}
		}
	}
	return nil
}

func validateResetD101ReceiptUnsigned(f resetD101IssuerSemanticFacts, s resetD101IssuerSemanticSnapshot) error {
	if len(s.Original13) != 13 || requireResetD101ProvenancePurposes(s.ReceiptPins.AllowedPurposes) != nil {
		return errResetExecutionEvidence
	}
	intent, err := decodeResetApprovalIntent(s.Original13["approvalIntent"], s.ReceiptPins.ApprovalIntentSHA)
	if err != nil {
		return errResetExecutionEvidence
	}
	card, err := decodeResetD101DeploymentCard(s.Original13["deploymentCard"], s.ReceiptPins.DeploymentCardSHA, intent)
	if err != nil {
		return errResetExecutionEvidence
	}
	a := s.Receipt
	pins := s.ReceiptPins
	if a.SchemaVersion != 1 || a.Kind != "D101_APPROVED_RECEIPT_SCOPE_ATTESTATION_V1" || a.IssuerID != f.receipt.Identity || a.IssuerSourceSHA != f.receipt.SourceSHA ||
		pins.OperationID != f.scope.OperationID || pins.IssuerID != f.receipt.Identity || pins.IssuerSourceSHA != f.receipt.SourceSHA || pins.IssuerSPKISHA != f.receipt.PublicKeySPKISHA256 || !bytes.Equal(pins.IssuerSPKI, f.receipt.PublicKeySPKI) ||
		f.approval.PublicKeySPKISHA256 == f.receipt.PublicKeySPKISHA256 || f.approval.PublicKeySPKISHA256 == pins.RootKey.PublicKeySpkiSHA || f.receipt.PublicKeySPKISHA256 == pins.RootKey.PublicKeySpkiSHA ||
		a.Scope.OperationID != f.scope.OperationID || a.Scope.AppSourceSHA != f.scope.AppSourceSHA || a.Scope.DockerSourceSHA != f.scope.DockerSourceSHA || requireResetD101FinalScope(a.Scope, intent, card) != nil ||
		a.IssuedAtUnix != f.issued.Unix() || a.IssuedAtUnix <= 0 || a.IssuedAtUnix >= intent.Intent.DestructiveCutoffUnix || !reflect.DeepEqual(a.AllowedPurposes, pins.AllowedPurposes) ||
		a.InstallerSourceSHA != pins.InstallerSourceSHA || len(a.OriginalBindings) != 13 {
		return errResetExecutionEvidence
	}
	expected := map[string]string{"approvalIntent": intent.SHA, "deploymentCard": card.SHA, "approvalReceipt": intent.Intent.ApprovalReceiptSHA, "combinedCiReceipt": intent.Intent.CombinedCIReceiptSHA, "selectedSourceReceipt": intent.Intent.SelectedSourceReceiptSHA, "isolatedSeedTickReceipt": intent.Intent.IsolatedSeedTickReceiptSHA, "spaceInventoryReceipt": intent.Intent.SpaceInventoryReceiptSHA, "configInventory": card.Card.ConfigInventorySHA, "commandPlan": card.Card.CommandPlanSHA, "recoveryPlan": card.Card.RecoveryPlanSHA, "readerBindings": card.Card.ReaderBindingsSHA, "evidenceCatalog": card.Card.EvidenceCatalogSHA, "reviewBasis": card.Card.ReviewBasisSHA}
	for id, sha := range expected {
		ref, ok := a.OriginalBindings[id]
		if !ok || ref.SHA != sha || requireResetD101FinalReference(ref, id, s.Original13[id]) != nil || len(s.Original13[id]) > et.MetadataMaxBytes {
			return errResetExecutionEvidence
		}
	}
	if requireResetD101FinalReference(a.NativeCustodyRef, "raw:approved-receipt-native-custody", s.NativeCustody) != nil || requireResetD101FinalReference(a.InstallerIdentityRef, "raw:approved-receipt-installer-identity", s.InstallerIdentity) != nil {
		return errResetExecutionEvidence
	}
	var native resetD101ApprovedReceiptNativeCustody
	var installer resetD101ApprovedReceiptInstallerIdentity
	if resetD101SemanticDecode(s.NativeCustody, &native) != nil || resetD101SemanticDecode(s.InstallerIdentity, &installer) != nil ||
		native.SchemaVersion != 1 || native.Kind != "D101_APPROVED_RECEIPT_NATIVE_CUSTODY_V1" || native.OperationID != f.scope.OperationID || native.RootKeyID != pins.RootKey.KeyID || native.SigningKeyEnvelopeSHA != pins.RootKey.EnvelopeSHA || native.RootPublicKeySpkiSHA != pins.RootKey.PublicKeySpkiSHA || native.ReaderInstallationSHA != pins.ReaderInstallationSHA || native.OwnerUID != 0 || native.FileMode != "0400" || native.LinkCount != 1 ||
		installer.SchemaVersion != 1 || installer.Kind != "D101_APPROVED_RECEIPT_INSTALLER_IDENTITY_V1" || installer.OperationID != f.scope.OperationID || installer.InstallerID != pins.InstallerID || installer.InstallerSourceSHA != pins.InstallerSourceSHA || installer.AppSourceSHA != f.scope.AppSourceSHA || installer.DockerSourceSHA != f.scope.DockerSourceSHA || installer.ReaderInstallationFile != resetD101NativeReaderInstallationPath || installer.ReaderInstallationSHA != pins.ReaderInstallationSHA || installer.RootKeyID != pins.RootKey.KeyID || installer.RootPublicKeySpkiSHA != pins.RootKey.PublicKeySpkiSHA ||
		resetD101OriginalSHA(s.Original13["readerBindings"]) != pins.ReaderInstallationSHA {
		return errResetExecutionEvidence
	}
	return nil
}

// Called only after C8 actually signs and immutably retains/readbacks the exact
// attestation envelope. This preserves the existing anti-cycle ordering; its
// signed-envelope RawRef cannot be invented before signing. Native recheck is
// still the supplier's responsibility. No signer, root key or receipt issue here.
func (b resetD101IssuerUnsignedBatch) ProvenanceAfterRetainedAttestation(ctx context.Context, signed []byte) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || time.Now().Unix() >= b.receipt.Scope.Window.DestructiveCutoffUnix || len(b.approvalPayload) == 0 || len(b.receiptAttestation) == 0 {
		return nil, errResetExecutionEvidence
	}
	var envelope resetD101SignedHostOriginal
	if resetD101SemanticDecode(signed, &envelope) != nil || envelope.SchemaVersion != 1 {
		return nil, errResetExecutionEvidence
	}
	original, e1 := base64.RawURLEncoding.Strict().DecodeString(envelope.OriginalBytesBase64url)
	sig, e2 := base64.RawURLEncoding.Strict().DecodeString(envelope.SignatureBase64url)
	key, e3 := resetD101PinnedPublicKey(b.receiptPins.PublicKeySPKI, b.receiptPins.PublicKeySPKISHA256)
	if e1 != nil || e2 != nil || e3 != nil || len(sig) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(original) != envelope.OriginalBytesBase64url || base64.RawURLEncoding.EncodeToString(sig) != envelope.SignatureBase64url || !bytes.Equal(original, b.receiptAttestation) || !ed25519.Verify(key, append([]byte(resetD101ApprovedReceiptAttestationDomain), original...), sig) {
		return nil, errResetExecutionEvidence
	}
	a := b.receipt
	value := resetD101ApprovedReceiptProvenance{1, "D101_APPROVED_RECEIPT_PROVENANCE_V1", a.Scope, "FIXED_APPROVED_RECEIPT_ISSUER", resetD101FinalIssuer{d101operatorauth.ApprovedReceiptIssuerRole, "FIXED_INSTALLED_ISSUER", b.receiptPins.Identity, b.receiptPins.SourceSHA, b.receiptPins.PublicKeySPKISHA256, resetD101FinalRawReference{"raw:approved-receipt-scope-attestation", resetD101OriginalSHA(signed), uint64(len(signed)), "application/json"}, a.NativeCustodyRef}, a.IssuedAtUnix, a.AllowedPurposes, a.InstallerSourceSHA, a.InstallerIdentityRef, a.OriginalBindings}
	return json.Marshal(value)
}
