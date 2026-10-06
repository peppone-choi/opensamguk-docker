package d101operatorauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const ApprovalIssuerRole = "APPROVAL_ISSUER"
const ApprovedReceiptIssuerRole = "APPROVED_RECEIPT_ISSUER"
const ApprovalOriginDomain = "OPENSAMGUK_D101_APPROVAL_ORIGIN_V1\n"
const ReceiptAttestationDomain = "OPENSAMGUK-D101-APPROVED-RECEIPT-ATTESTATION-V1\n"

var hash64 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var source40 = regexp.MustCompile(`^[a-f0-9]{40}$`)
var operation32 = regexp.MustCompile(`^[a-f0-9]{32}$`)
var identity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var positiveNumber = regexp.MustCompile(`^[1-9][0-9]*$`)
var repositoryName = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// These private host inputs retain the existing RawRef shape. No wire decoder,
// installation profile, filesystem path selection or enable switch is added.
type Reference struct {
	LogicalID, SHA256 string
	ByteLength        uint64
	MediaType         string
}
type IssuerPins struct {
	Role, Identity, SourceSHA, ImageDigest, PublicKeySPKISHA256 string
	PublicKeySPKI                                               []byte
}
type TechnicalScope struct {
	OperationID, AppSourceSHA, DockerSourceSHA string
	FinalCard, ScopeOriginal                   Reference
	DecisionParents                            [5]Reference
	DecisionSlicesSHA256                       string
}

// ReviewedPolicy must come from the independently authenticated host bootstrap.
// Validating its shape here does not certify its review, installation or custody.
type ReviewedPolicy struct {
	SourceSHA                                                     string
	ReviewOriginal                                                Reference
	Audience, Subject, Repository, RepositoryID, OwnerID, ActorID string
	WorkflowRef, WorkflowSHA, RunID                               string
	OpensAtUnix, CutoffUnix                                       int64
	ApprovalIssuer, ReceiptIssuer                                 IssuerPins
	RootPurposeSPKISHA256                                         string
	Scope                                                         TechnicalScope
}

type IssuanceEvent struct {
	ActorID, RunID, JTI, WorkflowSHA              string
	RunAttempt                                    uint64
	AuthenticationOriginal, ScopeDecisionOriginal Reference
}

// TechnicalIssuance is current issuer evidence only. It carries no historical
// actor authority, native installation proof, execution grant or all-leaf PASS.
type TechnicalIssuance struct{ proof *technicalProof }
type technicalProof struct {
	scope    TechnicalScope
	event    IssuanceEvent
	policy   ReviewedPolicy
	issuedAt time.Time
}

func NewTechnicalIssuance(operator CurrentOperator, event IssuanceEvent, scope TechnicalScope) (TechnicalIssuance, error) {
	if operator.proof == nil {
		return TechnicalIssuance{}, ErrUnavailable
	}
	p := operator.proof
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().UTC()
	if p.consumed || validatePolicy(p.policy) != nil || validateScope(scope) != nil || scope != p.policy.Scope ||
		event.ActorID != p.claims.actor || event.RunID != p.claims.run || event.RunAttempt != p.claims.attempt ||
		event.JTI != p.claims.jti || event.WorkflowSHA != p.claims.workflow ||
		event.AuthenticationOriginal != p.auth || event.ScopeDecisionOriginal != scope.FinalCard ||
		now.Before(p.verifiedAt) || now.Unix() >= p.claims.exp || now.Unix() >= p.policy.CutoffUnix {
		return TechnicalIssuance{}, ErrUnavailable
	}
	p.consumed = true
	return TechnicalIssuance{&technicalProof{scope, event, clonePolicy(p.policy), now}}, nil
}

func (v TechnicalIssuance) Scope() (TechnicalScope, error) {
	if v.proof == nil {
		return TechnicalScope{}, ErrUnavailable
	}
	return v.proof.scope, nil
}
func (v TechnicalIssuance) Event() (IssuanceEvent, error) {
	if v.proof == nil {
		return IssuanceEvent{}, ErrUnavailable
	}
	return v.proof.event, nil
}
func (v TechnicalIssuance) Issuer(role string) (IssuerPins, error) {
	if v.proof == nil {
		return IssuerPins{}, ErrUnavailable
	}
	var pins IssuerPins
	switch role {
	case ApprovalIssuerRole:
		pins = v.proof.policy.ApprovalIssuer
	case ApprovedReceiptIssuerRole:
		pins = v.proof.policy.ReceiptIssuer
	default:
		return IssuerPins{}, ErrUnavailable
	}
	pins.PublicKeySPKI = bytes.Clone(pins.PublicKeySPKI)
	return pins, nil
}
func (v TechnicalIssuance) IssuedAtUTC() (time.Time, error) {
	if v.proof == nil {
		return time.Time{}, ErrUnavailable
	}
	return v.proof.issuedAt, nil
}

func validatePolicy(p ReviewedPolicy) error {
	if !source40.MatchString(p.SourceSHA) || !validRef(p.ReviewOriginal) || p.Audience == "" || p.Subject == "" ||
		strings.TrimSpace(p.Audience) != p.Audience || strings.TrimSpace(p.Subject) != p.Subject ||
		len(p.Audience) > metadataBytes || len(p.Subject) > metadataBytes ||
		!numericIdentity(p.RepositoryID) || !numericIdentity(p.OwnerID) ||
		!numericIdentity(p.ActorID) || !numericIdentity(p.RunID) ||
		!repositoryName.MatchString(p.Repository) ||
		!strings.HasPrefix(p.WorkflowRef, p.Repository+"/.github/workflows/") || !strings.Contains(p.WorkflowRef, "@refs/") ||
		!source40.MatchString(p.WorkflowSHA) || p.OpensAtUnix <= 0 || p.CutoffUnix <= p.OpensAtUnix ||
		validateIssuer(p.ApprovalIssuer, ApprovalIssuerRole) != nil || validateIssuer(p.ReceiptIssuer, ApprovedReceiptIssuerRole) != nil ||
		!hash64.MatchString(p.RootPurposeSPKISHA256) ||
		p.ApprovalIssuer.PublicKeySPKISHA256 == p.ReceiptIssuer.PublicKeySPKISHA256 ||
		p.ApprovalIssuer.PublicKeySPKISHA256 == p.RootPurposeSPKISHA256 || p.ReceiptIssuer.PublicKeySPKISHA256 == p.RootPurposeSPKISHA256 ||
		validateScope(p.Scope) != nil {
		return ErrUnavailable
	}
	return nil
}

func validateIssuer(p IssuerPins, role string) error {
	if p.Role != role || !identity.MatchString(p.Identity) || !source40.MatchString(p.SourceSHA) ||
		!strings.HasPrefix(p.ImageDigest, "sha256:") || !hash64.MatchString(strings.TrimPrefix(p.ImageDigest, "sha256:")) ||
		!hash64.MatchString(p.PublicKeySPKISHA256) || hash(p.PublicKeySPKI) != p.PublicKeySPKISHA256 {
		return ErrUnavailable
	}
	key, err := x509.ParsePKIXPublicKey(p.PublicKeySPKI)
	public, ok := key.(ed25519.PublicKey)
	if err != nil || !ok || len(public) != ed25519.PublicKeySize {
		return ErrUnavailable
	}
	wire, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || !bytes.Equal(wire, p.PublicKeySPKI) {
		return ErrUnavailable
	}
	return nil
}

func validateScope(s TechnicalScope) error {
	if !operation32.MatchString(s.OperationID) || !source40.MatchString(s.AppSourceSHA) || !source40.MatchString(s.DockerSourceSHA) ||
		!validRef(s.FinalCard) || !validRef(s.ScopeOriginal) || !hash64.MatchString(s.DecisionSlicesSHA256) ||
		s.FinalCard.LogicalID == s.ScopeOriginal.LogicalID {
		return ErrUnavailable
	}
	seen := map[string]struct{}{s.FinalCard.LogicalID: {}, s.ScopeOriginal.LogicalID: {}}
	for _, ref := range s.DecisionParents {
		if !validRef(ref) {
			return ErrUnavailable
		}
		if _, duplicate := seen[ref.LogicalID]; duplicate {
			return ErrUnavailable
		}
		seen[ref.LogicalID] = struct{}{}
	}
	return nil
}

func clonePolicy(p ReviewedPolicy) ReviewedPolicy {
	p.ApprovalIssuer.PublicKeySPKI = bytes.Clone(p.ApprovalIssuer.PublicKeySPKI)
	p.ReceiptIssuer.PublicKeySPKI = bytes.Clone(p.ReceiptIssuer.PublicKeySPKI)
	return p
}
func validRef(r Reference) bool {
	return strings.HasPrefix(r.LogicalID, "raw:") && identity.MatchString(r.LogicalID) && hash64.MatchString(r.SHA256) &&
		r.ByteLength > 0 && r.MediaType != "" && (r.MediaType == "application/json" || r.MediaType == "text/plain")
}
func matchesOriginal(r Reference, original []byte, media string) bool {
	return validRef(r) && r.MediaType == media && r.ByteLength == uint64(len(original)) && hash(original) == r.SHA256
}
func hash(wire []byte) string { sum := sha256.Sum256(wire); return hex.EncodeToString(sum[:]) }

func numericIdentity(text string) bool {
	if !positiveNumber.MatchString(text) {
		return false
	}
	value, err := strconv.ParseUint(text, 10, 64)
	return err == nil && value > 0
}
