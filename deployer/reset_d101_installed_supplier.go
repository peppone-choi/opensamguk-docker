package main

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101operatorauth"
)

// Independent reviewed bootstrap policy only: no operation/card/source hash
// literal is compiled into the artifact whose source the card will approve.
// Actual approved anchor/paths and C1's typed operator adapter remain required.
type resetD101InstalledBootstrap struct {
	anchorDER   []byte
	anchorSHA   string
	manifestDir string
	producer    resetD101AuthenticatedInstallationProducer
}

// The adapter must consume C1's actual typed technical issuance plus installer,
// key/native custody and all remaining semantic producers. JWT/signature alone
// cannot produce this input. Missing provider keeps factory/mapper unavailable.
type resetD101AuthenticatedInstallationProducer interface {
	BuildVerified(context.Context, resetD101BootstrapNativeOriginals) (*resetD101FixedInstallation, error)
}

// The outer signature is checked before handing these bytes to the producer,
// but actor/installer/writer semantics are NOT authenticated by this carrier.
type resetD101BootstrapNativeOriginals struct {
	reader       d101custody.Original
	readerPin    d101custody.NativeFilePin
	manifest     []byte
	manifestPin  d101custody.NativeFilePin
	manifestBody []byte
	operationID  string
}

// Actual technical authentication is separate from the remaining installer,
// historical approval, custody and semantic producers. Neither seam has a
// success default. Policy authentication must bind retained JWT/event metadata,
// current approved workflow/issuer sources and every scope original, not merely
// accept NewVerifier's structural checks.
type resetD101TechnicalPolicyAuthenticator func(context.Context, d101operatorauth.ReviewedPolicy, d101operatorauth.IssuanceEvent, resetD101BootstrapNativeOriginals) error
type resetD101TechnicalInstallationProducer interface {
	BuildFromTechnicalIssuance(context.Context, d101operatorauth.TechnicalIssuance, resetD101BootstrapNativeOriginals) (*resetD101FixedInstallation, error)
}
type resetD101TechnicalBootstrapProducer struct {
	mu           sync.Mutex
	attempted    bool
	policy       d101operatorauth.ReviewedPolicy
	event        d101operatorauth.IssuanceEvent
	jwtPath      string
	jwtPin       d101custody.NativeFilePin
	authenticate resetD101TechnicalPolicyAuthenticator
	installation resetD101TechnicalInstallationProducer
}

func cloneResetD101BootstrapNative(v resetD101BootstrapNativeOriginals) resetD101BootstrapNativeOriginals {
	v.reader.Bytes = bytes.Clone(v.reader.Bytes)
	v.manifest = bytes.Clone(v.manifest)
	v.manifestBody = bytes.Clone(v.manifestBody)
	return v
}
func cloneResetD101TechnicalPolicy(v d101operatorauth.ReviewedPolicy) d101operatorauth.ReviewedPolicy {
	v.ApprovalIssuer.PublicKeySPKI = bytes.Clone(v.ApprovalIssuer.PublicKeySPKI)
	v.ReceiptIssuer.PublicKeySPKI = bytes.Clone(v.ReceiptIssuer.PublicKeySPKI)
	return v
}

// Production uses the actual C1 verifier's fixed official JWKS transport and
// the retained root-private JWT. No mock operator/key or JSON PASS can enter.
func (p *resetD101TechnicalBootstrapProducer) BuildVerified(ctx context.Context, native resetD101BootstrapNativeOriginals) (*resetD101FixedInstallation, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || p.authenticate == nil || p.installation == nil ||
		(reflect.ValueOf(p.installation).Kind() == reflect.Pointer && reflect.ValueOf(p.installation).IsNil()) ||
		!filepath.IsAbs(p.jwtPath) || filepath.Clean(p.jwtPath) != p.jwtPath {
		return nil, errResetD101InstallationNotSupplied
	}
	if !p.mu.TryLock() {
		return nil, errResetD101InstallationNotSupplied
	}
	defer p.mu.Unlock()
	if p.attempted {
		return nil, errResetD101InstallationNotSupplied
	}
	input := resetD101TechnicalBootstrapProducer{policy: p.policy, event: p.event, jwtPath: p.jwtPath,
		jwtPin: p.jwtPin, authenticate: p.authenticate, installation: p.installation}
	policy := cloneResetD101TechnicalPolicy(input.policy)
	native = cloneResetD101BootstrapNative(native)
	// The operation's existing bound and approved cutoff both apply. No renewed
	// deadline or unbounded provider request is granted by this bootstrap.
	deadline := time.Now().Add(resetPreflightMaxAge)
	if cutoff := time.Unix(policy.CutoffUnix, 0); cutoff.Before(deadline) {
		deadline = cutoff
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if bounded.Err() != nil || requireResetD101TechnicalBootstrapScope(native, policy, input.event) != nil ||
		input.authenticate(bounded, cloneResetD101TechnicalPolicy(policy), input.event, cloneResetD101BootstrapNative(native)) != nil || bounded.Err() != nil {
		return nil, errResetExecutionEvidence
	}
	verifier, err := d101operatorauth.NewVerifier(policy)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	// Preserve failed/unknown authentication as a consumed invocation. Creating
	// a fresh C1 Verifier on retry must not reset its JTI replay protection.
	p.attempted = true
	jwt, jwtPin, err := d101custody.CapturePrivateOriginalPin(input.jwtPath, 64<<10)
	ref := input.event.AuthenticationOriginal
	if err != nil || jwtPin != input.jwtPin || jwt.SHA256 != ref.SHA256 || ref.MediaType != "text/plain" ||
		uint64(len(jwt.Bytes)) != ref.ByteLength || bounded.Err() != nil {
		return nil, errResetExecutionEvidence
	}
	operator, err := verifier.Verify(bounded, jwt.Bytes, ref)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	issuance, err := d101operatorauth.NewTechnicalIssuance(operator, input.event, policy.Scope)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	// C1 opaque proof is consumed once. The downstream native producer receives
	// the real type but must still authenticate every other installation leaf.
	installed, err := input.installation.BuildFromTechnicalIssuance(bounded, issuance, cloneResetD101BootstrapNative(native))
	if err != nil || installed == nil || requireResetD101TechnicalInstalledBinding(issuance, policy, installed) != nil ||
		bounded.Err() != nil || time.Now().Unix() >= policy.CutoffUnix ||
		input.authenticate(bounded, cloneResetD101TechnicalPolicy(policy), input.event, cloneResetD101BootstrapNative(native)) != nil {
		return nil, errResetD101InstallationNotSupplied
	}
	after, afterPin, err := d101custody.CapturePrivateOriginalPin(input.jwtPath, 64<<10)
	if err != nil || afterPin != jwtPin || !bytes.Equal(after.Bytes, jwt.Bytes) || bounded.Err() != nil {
		return nil, errResetExecutionEvidence
	}
	return installed, nil
}

// This comparison is only a data binding; the authenticator above and the
// existing all8 mapper below separately establish semantics and custody.
func requireResetD101TechnicalBootstrapScope(native resetD101BootstrapNativeOriginals, policy d101operatorauth.ReviewedPolicy, event d101operatorauth.IssuanceEvent) error {
	var manifest resetD101HostTrustManifest
	s := policy.Scope
	if requireResetIntentShape(native.manifestBody, reflect.TypeOf(manifest)) != nil || decodeResetPrivateJSON(native.manifestBody, &manifest) != nil ||
		manifest.SchemaVersion != 1 || manifest.Kind != "D101_HOST_TRUST_V1" || !lifecycleJobIDRe.MatchString(native.operationID) ||
		manifest.OperationID != native.operationID || s.OperationID != native.operationID ||
		s.AppSourceSHA != manifest.AppSourceSHA || s.DockerSourceSHA != manifest.DockerSourceSHA ||
		s.FinalCard.SHA256 != manifest.DeploymentCardSHA || s.FinalCard.MediaType != "application/json" ||
		event.ScopeDecisionOriginal != s.FinalCard || policy.RootPurposeSPKISHA256 != manifest.PublicKeySpkiSHA {
		return errResetExecutionEvidence
	}
	return nil
}

func requireResetD101TechnicalInstalledBinding(issuance d101operatorauth.TechnicalIssuance, policy d101operatorauth.ReviewedPolicy, installed *resetD101FixedInstallation) error {
	scope, e1 := issuance.Scope()
	issuer, e2 := issuance.Issuer(d101operatorauth.ApprovedReceiptIssuerRole)
	event, e3 := issuance.Event()
	issuedAt, e4 := issuance.IssuedAtUTC()
	if installed == nil || e1 != nil || e2 != nil || e3 != nil || e4 != nil || issuedAt.IsZero() ||
		scope != policy.Scope || event.ScopeDecisionOriginal != scope.FinalCard ||
		installed.authority.OperationID != scope.OperationID || installed.provenance.DeploymentCardSHA != scope.FinalCard.SHA256 ||
		installed.authority.SigningKey.PublicKeySpkiSHA != policy.RootPurposeSPKISHA256 ||
		installed.provenance.IssuerID != issuer.Identity || installed.provenance.IssuerSourceSHA != issuer.SourceSHA ||
		installed.provenance.IssuerSPKISHA != issuer.PublicKeySPKISHA256 || !bytes.Equal(installed.provenance.IssuerSPKI, issuer.PublicKeySPKI) {
		return errResetExecutionEvidence
	}
	return nil
}

func loadResetD101ReviewedInstallation(ctx context.Context, c config, bootstrap *resetD101InstalledBootstrap) (config, error) {
	closed := closeResetD101InstalledSources(c)
	closed.d101FixedInstallation = nil
	if ctx == nil || ctx.Err() != nil || bootstrap == nil || bootstrap.producer == nil ||
		(reflect.ValueOf(bootstrap.producer).Kind() == reflect.Pointer && reflect.ValueOf(bootstrap.producer).IsNil()) ||
		!filepath.IsAbs(bootstrap.manifestDir) || filepath.Clean(bootstrap.manifestDir) != bootstrap.manifestDir {
		return closed, errResetD101InstallationNotSupplied
	}
	policy := *bootstrap
	anchorDER := bytes.Clone(policy.anchorDER)
	anchor, err := resetD101PinnedPublicKey(anchorDER, policy.anchorSHA)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	reader, readerPin, err := d101custody.CapturePrivateOriginalPin(resetD101NativeReaderInstallationPath, 64<<10)
	var record resetD101ProvenanceReaderInstallation
	if err != nil || requireResetIntentShape(reader.Bytes, reflect.TypeOf(record)) != nil || decodeResetPrivateJSON(reader.Bytes, &record) != nil ||
		record.SchemaVersion != 1 || record.Kind != "D101_NATIVE_READER_BINDINGS_V1" || len(record.OriginalFiles) != 14 {
		return closed, errResetExecutionEvidence
	}
	// The untrusted filename only selects a bounded candidate under the
	// independently installed directory. Signature and exact scope authenticate
	// the operation; this filename never establishes actor or key authority.
	leaf := filepath.Base(record.ManifestFile)
	op := strings.TrimSuffix(leaf, ".json")
	if !lifecycleJobIDRe.MatchString(op) || leaf != op+".json" || record.ManifestFile != filepath.Join(policy.manifestDir, leaf) {
		return closed, errResetExecutionEvidence
	}
	manifest, manifestPin, err := d101custody.CapturePrivateOriginalPin(record.ManifestFile, 64<<10)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	body, err := decodeResetD101SignedHostOriginal(manifest.Bytes, resetD101HostTrustDomain, anchor)
	var scope resetD101HostTrustManifest
	if err != nil || requireResetIntentShape(body, reflect.TypeOf(scope)) != nil || decodeResetPrivateJSON(body, &scope) != nil ||
		scope.SchemaVersion != 1 || scope.Kind != "D101_HOST_TRUST_V1" || scope.OperationID != op ||
		!resetEvidenceSHA.MatchString(scope.ApprovalIntentSHA) || !resetEvidenceSHA.MatchString(scope.DeploymentCardSHA) ||
		!resetEvidenceSHA.MatchString(scope.ApprovedReceiptProvenanceSHA) || ctx.Err() != nil {
		return closed, errResetExecutionEvidence
	}
	native := resetD101BootstrapNativeOriginals{d101custody.Original{Bytes: bytes.Clone(reader.Bytes), SHA256: reader.SHA256}, readerPin,
		bytes.Clone(manifest.Bytes), manifestPin, bytes.Clone(body), op}
	inputs, err := policy.producer.BuildVerified(ctx, native)
	if err != nil || inputs == nil || ctx.Err() != nil {
		return closed, errResetD101InstallationNotSupplied
	}
	// Dynamic values must be the signed existing originals, not independent
	// producer self-claims or hashes baked into this source. The mapper below
	// still invokes mandatory upstream/semantic authentication and all8 checks.
	p := *inputs
	if p.readerSHA != reader.SHA256 || p.readerPin != readerPin ||
		p.authority.OperationID != op || p.authority.ApprovalIntentSHA != scope.ApprovalIntentSHA ||
		p.authority.ManifestSHA != resetD101OriginalSHA(body) || p.authority.ManifestDirectory != policy.manifestDir ||
		!bytes.Equal(p.authority.ApprovalAnchorSpki, anchorDER) || p.authority.ApprovalAnchorSpkiSHA != policy.anchorSHA ||
		p.provenance.DeploymentCardSHA != scope.DeploymentCardSHA || p.provenance.ProvenanceSHA != scope.ApprovedReceiptProvenanceSHA ||
		p.authority.RootPrivateOrigin != scope.RootPrivateOrigin || p.authority.SigningKey.KeyID != scope.KeyID ||
		p.authority.SigningKey.PublicKeySpkiSHA != scope.PublicKeySpkiSHA || p.authority.SigningKey.EnvelopeSHA != scope.SigningKeyEnvelopeSHA {
		return closed, errResetExecutionEvidence
	}
	readerAfter, readerAfterPin, e1 := d101custody.CapturePrivateOriginalPin(resetD101NativeReaderInstallationPath, 64<<10)
	manifestAfter, manifestAfterPin, e2 := d101custody.CapturePrivateOriginalPin(record.ManifestFile, 64<<10)
	if e1 != nil || e2 != nil || readerAfterPin != readerPin || manifestAfterPin != manifestPin ||
		!bytes.Equal(readerAfter.Bytes, reader.Bytes) || !bytes.Equal(manifestAfter.Bytes, manifest.Bytes) || ctx.Err() != nil {
		return closed, errResetExecutionEvidence
	}
	// Registration is all-or-nothing; the concrete mapper and candidate
	// constructors must succeed before the host session receives usable sources.
	closed.d101FixedInstallation = &p
	installed, err := assembleResetD101InstalledSources(ctx, closed)
	if err != nil {
		closed.d101FixedInstallation = nil
		closed.d101InstallationError = err
		return closed, err
	}
	return installed, nil
}
