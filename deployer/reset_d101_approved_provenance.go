package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"reflect"
	"regexp"
	"time"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
)

const resetD101ApprovedReceiptAttestationDomain = "OPENSAMGUK-D101-APPROVED-RECEIPT-ATTESTATION-V1\n"
const resetD101NativeReaderInstallationPath = "/etc/opensamguk/d101/reader-installation.json"

var resetD101IssuerIdentity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var resetD101RawLogicalIdentity = regexp.MustCompile(`^raw:[A-Za-z0-9._:-]{1,123}$`)

// C9 original6-v1 RawRef4/scope12/issuer7/final provenance10. These codecs
// do not issue approval, sign an attestation, or install an issuer.
type resetD101FinalRawReference struct {
	LogicalID  string `json:"logicalId"`
	SHA        string `json:"sha256"`
	ByteLength uint64 `json:"byteLength"`
	MediaType  string `json:"mediaType"`
}
type resetD101FinalScopeWindow struct {
	WindowOpensAtUnix     int64 `json:"windowOpensAtUnix"`
	DestructiveCutoffUnix int64 `json:"destructiveCutoffUnix"`
	RecoveryDeadlineUnix  int64 `json:"recoveryDeadlineUnix"`
}
type resetD101FinalOriginalScope struct {
	OperationID           string                     `json:"operationId"`
	ServerID              string                     `json:"serverId"`
	WorldID               int                        `json:"worldId"`
	TargetFingerprint     string                     `json:"targetFingerprint"`
	TypedTargetRef        resetD101FinalRawReference `json:"typedTargetRef"`
	AppSourceSHA          string                     `json:"appSourceSha"`
	DockerSourceSHA       string                     `json:"dockerSourceSha"`
	OldImageDigests       map[string]string          `json:"oldImageDigests"`
	NewImageDigests       map[string]string          `json:"newImageDigests"`
	InitialPublicRevision string                     `json:"initialPublicRevision"`
	Window                resetD101FinalScopeWindow  `json:"window"`
	SpaceBudget           resetSpaceBudget           `json:"spaceBudget"`
}
type resetD101FinalIssuer struct {
	Role                string                     `json:"role"`
	IdentitySource      string                     `json:"identitySource"`
	IssuerID            string                     `json:"issuerId"`
	IssuerSourceSHA     string                     `json:"issuerSourceSha"`
	PublicKeySpkiSHA    string                     `json:"publicKeySpkiSha256"`
	ScopeAttestationRef resetD101FinalRawReference `json:"scopeAttestationRef"`
	NativeCustodyRef    resetD101FinalRawReference `json:"nativeCustodyRef"`
}
type resetD101ApprovedReceiptProvenance struct {
	SchemaVersion        int                                   `json:"schemaVersion"`
	Kind                 string                                `json:"kind"`
	Scope                resetD101FinalOriginalScope           `json:"scope"`
	SourceAuthority      string                                `json:"sourceAuthority"`
	Issuer               resetD101FinalIssuer                  `json:"issuer"`
	IssuedAtUnix         int64                                 `json:"issuedAtUnix"`
	AllowedPurposes      []string                              `json:"allowedPurposes"`
	InstallerSourceSHA   string                                `json:"installerSourceSha"`
	InstallerIdentityRef resetD101FinalRawReference            `json:"installerIdentityRef"`
	OriginalBindings     map[string]resetD101FinalRawReference `json:"originalBindings"`
}

// Independent issuer signs upstream13 and these fixed installation/custody
// originals; neither itself, provenance nor the later outer manifest is hashed.
type resetD101ApprovedReceiptAttestation struct {
	SchemaVersion        int                                   `json:"schemaVersion"`
	Kind                 string                                `json:"kind"`
	IssuerID             string                                `json:"issuerId"`
	IssuerSourceSHA      string                                `json:"issuerSourceSha"`
	Scope                resetD101FinalOriginalScope           `json:"scope"`
	IssuedAtUnix         int64                                 `json:"issuedAtUnix"`
	AllowedPurposes      []string                              `json:"allowedPurposes"`
	InstallerSourceSHA   string                                `json:"installerSourceSha"`
	InstallerIdentityRef resetD101FinalRawReference            `json:"installerIdentityRef"`
	NativeCustodyRef     resetD101FinalRawReference            `json:"nativeCustodyRef"`
	OriginalBindings     map[string]resetD101FinalRawReference `json:"originalBindings"`
}
type resetD101ApprovedReceiptNativeCustody struct {
	SchemaVersion         int    `json:"schemaVersion"`
	Kind                  string `json:"kind"`
	OperationID           string `json:"operationId"`
	RootKeyID             string `json:"rootKeyId"`
	SigningKeyEnvelopeSHA string `json:"signingKeyEnvelopeSha256"`
	RootPublicKeySpkiSHA  string `json:"rootPublicKeySpkiSha256"`
	ReaderInstallationSHA string `json:"readerInstallationSha256"`
	OwnerUID              uint32 `json:"ownerUid"`
	FileMode              string `json:"fileMode"`
	LinkCount             uint64 `json:"linkCount"`
}
type resetD101ApprovedReceiptInstallerIdentity struct {
	SchemaVersion          int    `json:"schemaVersion"`
	Kind                   string `json:"kind"`
	OperationID            string `json:"operationId"`
	InstallerID            string `json:"installerId"`
	InstallerSourceSHA     string `json:"installerSourceSha"`
	AppSourceSHA           string `json:"appSourceSha"`
	DockerSourceSHA        string `json:"dockerSourceSha"`
	ReaderInstallationFile string `json:"readerInstallationFile"`
	ReaderInstallationSHA  string `json:"readerInstallationSha256"`
	RootKeyID              string `json:"rootKeyId"`
	RootPublicKeySpkiSHA   string `json:"rootPublicKeySpkiSha256"`
}
type resetD101ProvenanceReaderInstallation struct {
	SchemaVersion        int               `json:"schemaVersion"`
	Kind                 string            `json:"kind"`
	ManifestFile         string            `json:"manifestFile"`
	ClockFile            string            `json:"clockFile"`
	OriginalFiles        map[string]string `json:"originalFiles"`
	RootTokenFile        string            `json:"rootTokenFile"`
	SelectedEnvelopeFile string            `json:"selectedEnvelopeFile"`
}

type resetD101ApprovedReceiptPins struct {
	OperationID           string
	ApprovalIntentSHA     string
	DeploymentCardSHA     string
	ProvenanceSHA         string
	IssuerID              string
	IssuerSourceSHA       string
	IssuerSPKI            []byte
	IssuerSPKISHA         string
	InstallerID           string
	InstallerSourceSHA    string
	ReaderInstallationSHA string
	AllowedPurposes       []string
	OriginalDirectories   map[string]string
	AuxiliaryDirectories  map[string]string
	RootKey               resetD101SigningKeyPins
}
type resetD101ProvenanceUpstreamVerifier func(context.Context, *resetD101HostEvidence) error

func requireResetD101FinalReference(ref resetD101FinalRawReference, id string, wire []byte) error {
	validID := resetD101RawLogicalIdentity.MatchString(id)
	for _, originalID := range resetD101HostOriginalIDs {
		if originalID == id {
			validID = true
		}
	}
	if !validID || ref.LogicalID != id || ref.MediaType != "application/json" || ref.ByteLength == 0 || ref.ByteLength > 64<<20 || uint64(len(wire)) != ref.ByteLength || !resetEvidenceSHA.MatchString(ref.SHA) || resetD101OriginalSHA(wire) != ref.SHA {
		return errResetExecutionEvidence
	}
	return nil
}
func requireResetD101ProvenancePurposes(actions []string) error {
	if len(actions) < 1 || len(actions) > 6 {
		return errResetExecutionEvidence
	}
	seen := map[string]bool{}
	for _, action := range actions {
		switch action {
		case "PREPARE", "QUERY", "DISPATCH_INTENT", "SETTLE_REGISTRY", "RECOVERY_BEGIN", "RECOVERY_CLOSE":
		default:
			return errResetExecutionEvidence
		}
		if seen[action] {
			return errResetExecutionEvidence
		}
		seen[action] = true
	}
	return nil
}
func requireResetD101FinalScope(scope resetD101FinalOriginalScope, intent resetDecodedApprovalIntent, card resetDecodedDeploymentCard) error {
	i := intent.Intent
	if scope.OperationID != i.OperationID || scope.ServerID != "pep" || scope.WorldID != 1 || scope.TargetFingerprint != i.TargetFingerprint || scope.AppSourceSHA != i.AppSourceSHA || scope.DockerSourceSHA != card.Card.DockerSourceSHA ||
		!reflect.DeepEqual(scope.OldImageDigests, i.OldImageDigests) || !reflect.DeepEqual(scope.NewImageDigests, i.NewImageDigests) || scope.InitialPublicRevision != i.InitialPublicRevision ||
		scope.Window != (resetD101FinalScopeWindow{i.WindowOpensAtUnix, i.DestructiveCutoffUnix, i.RecoveryDeadlineUnix}) || !reflect.DeepEqual(scope.SpaceBudget, i.SpaceBudget) ||
		len(scope.TypedTargetRef.LogicalID) < 5 || scope.TypedTargetRef.LogicalID[:4] != "raw:" || requireResetD101FinalReference(scope.TypedTargetRef, scope.TypedTargetRef.LogicalID, intent.targetBytes()) != nil {
		return errResetExecutionEvidence
	}
	return nil
}

// Fixed native source only. Missing issuer/auxiliary originals/upstream semantic
// verifier closes the row. Existing purpose-key signing cannot sign this domain.
func verifyResetD101ApprovedReceiptProvenance(ctx context.Context, pins resetD101ApprovedReceiptPins, verify resetD101ProvenanceUpstreamVerifier, clock func() time.Time) ([]byte, error) {
	readInstallation := func() ([]byte, error) {
		v, err := d101custody.ReadPrivate(resetD101NativeReaderInstallationPath, 64<<10)
		return v.Bytes, err
	}
	return verifyResetD101ApprovedReceiptProvenanceWithSources(ctx, pins, verify, clock, 0, readInstallation)
}

// UID/installation reader seams are confined to isolated fixtures.
func verifyResetD101ApprovedReceiptProvenanceWithSources(ctx context.Context, pins resetD101ApprovedReceiptPins, verify resetD101ProvenanceUpstreamVerifier, clock func() time.Time, uid uint32, readInstallation func() ([]byte, error)) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || verify == nil || clock == nil || readInstallation == nil || len(pins.OriginalDirectories) != 14 || len(pins.AuxiliaryDirectories) != 3 || !resetD101IssuerIdentity.MatchString(pins.IssuerID) || !gitSHA40.MatchString(pins.IssuerSourceSHA) || !resetD101IssuerIdentity.MatchString(pins.InstallerID) || !gitSHA40.MatchString(pins.InstallerSourceSHA) || requireResetD101ProvenancePurposes(pins.AllowedPurposes) != nil {
		return nil, errResetExecutionEvidence
	}
	anchor, err := resetD101PinnedPublicKey(pins.IssuerSPKI, pins.IssuerSPKISHA)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	bounded, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
	defer cancel()
	started := clock()
	monotonic := time.Now()
	// Freeze mutable installation maps/slices before any external verifier call.
	clone := func(input map[string]string) map[string]string {
		output := map[string]string{}
		for id, value := range input {
			output[id] = value
		}
		return output
	}
	pins.OriginalDirectories = clone(pins.OriginalDirectories)
	pins.AuxiliaryDirectories = clone(pins.AuxiliaryDirectories)
	pins.AllowedPurposes = append([]string(nil), pins.AllowedPurposes...)
	originals := map[string][]byte{}
	paths := map[string]bool{}
	for _, id := range resetD101HostOriginalIDs {
		dir := pins.OriginalDirectories[id]
		path := filepath.Join(dir, pins.OperationID+".json")
		wire, err := readResetPrivateCustody(dir, pins.OperationID, uid)
		if err != nil || paths[path] {
			return nil, errResetExecutionEvidence
		}
		paths[path] = true
		originals[id] = wire
	}
	intent, err := decodeResetApprovalIntent(originals["approvalIntent"], pins.ApprovalIntentSHA)
	card, cardErr := decodeResetD101DeploymentCard(originals["deploymentCard"], pins.DeploymentCardSHA, intent)
	if err != nil || cardErr != nil || intent.Intent.OperationID != pins.OperationID {
		return nil, errResetExecutionEvidence
	}
	wire := originals["approvedReceiptProvenance"]
	var value resetD101ApprovedReceiptProvenance
	if !utf8.Valid(wire) || resetD101OriginalSHA(wire) != pins.ProvenanceSHA || requireResetIntentShape(wire, reflect.TypeOf(value)) != nil || decodeResetPrivateJSON(wire, &value) != nil || value.SchemaVersion != 1 || value.Kind != "D101_APPROVED_RECEIPT_PROVENANCE_V1" || value.SourceAuthority != "FIXED_APPROVED_RECEIPT_ISSUER" || value.Issuer.Role != "APPROVED_RECEIPT_ISSUER" || value.Issuer.IdentitySource != "FIXED_INSTALLED_ISSUER" || value.Issuer.IssuerID != pins.IssuerID || value.Issuer.IssuerSourceSHA != pins.IssuerSourceSHA || value.Issuer.PublicKeySpkiSHA != pins.IssuerSPKISHA || value.InstallerSourceSHA != pins.InstallerSourceSHA || !reflect.DeepEqual(value.AllowedPurposes, pins.AllowedPurposes) || len(value.OriginalBindings) != 13 || value.IssuedAtUnix <= 0 || value.IssuedAtUnix > started.Unix() || value.IssuedAtUnix >= intent.Intent.DestructiveCutoffUnix || requireResetD101FinalScope(value.Scope, intent, card) != nil {
		return nil, errResetExecutionEvidence
	}
	expected := map[string]string{"approvalIntent": intent.SHA, "deploymentCard": card.SHA, "approvalReceipt": intent.Intent.ApprovalReceiptSHA, "combinedCiReceipt": intent.Intent.CombinedCIReceiptSHA, "selectedSourceReceipt": intent.Intent.SelectedSourceReceiptSHA, "isolatedSeedTickReceipt": intent.Intent.IsolatedSeedTickReceiptSHA, "spaceInventoryReceipt": intent.Intent.SpaceInventoryReceiptSHA, "configInventory": card.Card.ConfigInventorySHA, "commandPlan": card.Card.CommandPlanSHA, "recoveryPlan": card.Card.RecoveryPlanSHA, "readerBindings": card.Card.ReaderBindingsSHA, "evidenceCatalog": card.Card.EvidenceCatalogSHA, "reviewBasis": card.Card.ReviewBasisSHA}
	for id, sha := range expected {
		ref, ok := value.OriginalBindings[id]
		if !ok || ref.SHA != sha || requireResetD101FinalReference(ref, id, originals[id]) != nil || len(originals[id]) > 64<<10 {
			return nil, errResetExecutionEvidence
		}
	}
	auxiliary := map[string][]byte{}
	for _, id := range []string{"scopeAttestation", "nativeCustody", "installerIdentity"} {
		dir := pins.AuxiliaryDirectories[id]
		path := filepath.Join(dir, pins.OperationID+".json")
		raw, err := readResetPrivateCustody(dir, pins.OperationID, uid)
		if err != nil || paths[path] {
			return nil, errResetExecutionEvidence
		}
		paths[path] = true
		auxiliary[id] = raw
	}
	if requireResetD101FinalReference(value.Issuer.ScopeAttestationRef, "raw:approved-receipt-scope-attestation", auxiliary["scopeAttestation"]) != nil || requireResetD101FinalReference(value.Issuer.NativeCustodyRef, "raw:approved-receipt-native-custody", auxiliary["nativeCustody"]) != nil || requireResetD101FinalReference(value.InstallerIdentityRef, "raw:approved-receipt-installer-identity", auxiliary["installerIdentity"]) != nil {
		return nil, errResetExecutionEvidence
	}
	var envelope resetD101SignedHostOriginal
	if requireResetIntentShape(auxiliary["scopeAttestation"], reflect.TypeOf(envelope)) != nil || decodeResetPrivateJSON(auxiliary["scopeAttestation"], &envelope) != nil || envelope.SchemaVersion != 1 {
		return nil, errResetExecutionEvidence
	}
	attested, decodeErr := base64.RawURLEncoding.Strict().DecodeString(envelope.OriginalBytesBase64url)
	signature, sigErr := base64.RawURLEncoding.Strict().DecodeString(envelope.SignatureBase64url)
	var attest resetD101ApprovedReceiptAttestation
	if decodeErr != nil || sigErr != nil || len(attested) == 0 || len(attested) > 32<<10 || !utf8.Valid(attested) || base64.RawURLEncoding.EncodeToString(attested) != envelope.OriginalBytesBase64url || base64.RawURLEncoding.EncodeToString(signature) != envelope.SignatureBase64url || len(signature) != ed25519.SignatureSize || !ed25519.Verify(anchor, append([]byte(resetD101ApprovedReceiptAttestationDomain), attested...), signature) || requireResetIntentShape(attested, reflect.TypeOf(attest)) != nil || decodeResetPrivateJSON(attested, &attest) != nil ||
		attest.SchemaVersion != 1 || attest.Kind != "D101_APPROVED_RECEIPT_SCOPE_ATTESTATION_V1" || attest.IssuerID != value.Issuer.IssuerID || attest.IssuerSourceSHA != value.Issuer.IssuerSourceSHA || !reflect.DeepEqual(attest.Scope, value.Scope) || attest.IssuedAtUnix != value.IssuedAtUnix || !reflect.DeepEqual(attest.AllowedPurposes, value.AllowedPurposes) || attest.InstallerSourceSHA != value.InstallerSourceSHA || attest.InstallerIdentityRef != value.InstallerIdentityRef || attest.NativeCustodyRef != value.Issuer.NativeCustodyRef || !reflect.DeepEqual(attest.OriginalBindings, value.OriginalBindings) {
		return nil, errResetExecutionEvidence
	}
	installation, err := readInstallation()
	if err != nil || resetD101OriginalSHA(installation) != pins.ReaderInstallationSHA || !bytes.Equal(installation, originals["readerBindings"]) {
		return nil, errResetExecutionEvidence
	}
	var nativeInstallation resetD101ProvenanceReaderInstallation
	if requireResetIntentShape(installation, reflect.TypeOf(nativeInstallation)) != nil || decodeResetPrivateJSON(installation, &nativeInstallation) != nil || nativeInstallation.SchemaVersion != 1 || nativeInstallation.Kind != "D101_NATIVE_READER_BINDINGS_V1" || len(nativeInstallation.OriginalFiles) != 14 {
		return nil, errResetExecutionEvidence
	}
	for _, id := range resetD101HostOriginalIDs {
		if nativeInstallation.OriginalFiles[id] != filepath.Join(pins.OriginalDirectories[id], pins.OperationID+".json") {
			return nil, errResetExecutionEvidence
		}
	}
	for _, path := range []string{nativeInstallation.ManifestFile, nativeInstallation.ClockFile, nativeInstallation.RootTokenFile, nativeInstallation.SelectedEnvelopeFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errResetExecutionEvidence
		}
	}
	var custody resetD101ApprovedReceiptNativeCustody
	var installer resetD101ApprovedReceiptInstallerIdentity
	if requireResetIntentShape(auxiliary["nativeCustody"], reflect.TypeOf(custody)) != nil || decodeResetPrivateJSON(auxiliary["nativeCustody"], &custody) != nil || custody.SchemaVersion != 1 || custody.Kind != "D101_APPROVED_RECEIPT_NATIVE_CUSTODY_V1" || custody.OperationID != pins.OperationID || custody.RootKeyID != pins.RootKey.KeyID || custody.SigningKeyEnvelopeSHA != pins.RootKey.EnvelopeSHA || custody.RootPublicKeySpkiSHA != pins.RootKey.PublicKeySpkiSHA || custody.ReaderInstallationSHA != pins.ReaderInstallationSHA || custody.OwnerUID != 0 || custody.FileMode != "0400" || custody.LinkCount != 1 ||
		requireResetIntentShape(auxiliary["installerIdentity"], reflect.TypeOf(installer)) != nil || decodeResetPrivateJSON(auxiliary["installerIdentity"], &installer) != nil || installer.SchemaVersion != 1 || installer.Kind != "D101_APPROVED_RECEIPT_INSTALLER_IDENTITY_V1" || installer.OperationID != pins.OperationID || installer.InstallerID != pins.InstallerID || installer.InstallerSourceSHA != pins.InstallerSourceSHA || installer.AppSourceSHA != intent.Intent.AppSourceSHA || installer.DockerSourceSHA != card.Card.DockerSourceSHA || installer.ReaderInstallationFile != resetD101NativeReaderInstallationPath || installer.ReaderInstallationSHA != pins.ReaderInstallationSHA || installer.RootKeyID != pins.RootKey.KeyID || installer.RootPublicKeySpkiSHA != pins.RootKey.PublicKeySpkiSHA {
		return nil, errResetExecutionEvidence
	}
	key, keyErr := readResetD101SigningKeyWithUID(pins.RootKey, uid)
	if keyErr != nil {
		return nil, errResetExecutionEvidence
	}
	key.close()
	input := &resetD101HostEvidence{originals: map[string][]byte{}}
	for id, original := range originals {
		if id != "approvedReceiptProvenance" {
			input.originals[id] = append([]byte(nil), original...)
		}
	}
	if verify(bounded, input) != nil || bounded.Err() != nil {
		return nil, errResetExecutionEvidence
	}
	// A signed claim does not replace current native reads. Recheck all payloads,
	// auxiliary proofs, fixed installation and root key before returning raw10.
	for id, before := range originals {
		after, err := readResetPrivateCustody(pins.OriginalDirectories[id], pins.OperationID, uid)
		if err != nil || !bytes.Equal(before, after) {
			return nil, errResetExecutionEvidence
		}
	}
	for id, before := range auxiliary {
		after, err := readResetPrivateCustody(pins.AuxiliaryDirectories[id], pins.OperationID, uid)
		if err != nil || !bytes.Equal(before, after) {
			return nil, errResetExecutionEvidence
		}
	}
	after, err := readInstallation()
	if err != nil || !bytes.Equal(installation, after) {
		return nil, errResetExecutionEvidence
	}
	key, keyErr = readResetD101SigningKeyWithUID(pins.RootKey, uid)
	if keyErr != nil {
		return nil, errResetExecutionEvidence
	}
	key.close()
	completed := clock()
	if completed.Before(started) || completed.Sub(started) >= resetPreflightMaxAge || time.Since(monotonic) >= resetPreflightMaxAge || bounded.Err() != nil {
		return nil, errResetExecutionEvidence
	}
	return append([]byte(nil), wire...), nil
}
