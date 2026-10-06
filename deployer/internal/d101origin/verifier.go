// Package d101origin verifies only the cryptographic binding of an origin proof.
// The returned value does not establish that its claimed origin or custody exists.
package d101origin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101evidencetransport"
)

type Role string

const (
	ApprovalIssuer             Role = "APPROVAL_ISSUER"
	OfficialGitHubCollector    Role = "OFFICIAL_GITHUB_COLLECTOR"
	IndependentReviewCollector Role = "INDEPENDENT_REVIEW_COLLECTOR"
)

var (
	sha256Pattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	sha40Pattern    = regexp.MustCompile(`^[a-f0-9]{40}$`)
	opPattern       = regexp.MustCompile(`^[a-f0-9]{32}$`)
	identityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
)

type ExpectedBinding struct {
	Role          Role
	OperationID   string
	ProfileSHA256 string
	ScopeOriginal d101evidencetransport.RawReference
}

// UnverifiedOriginBinding carries a verified signature and fixed references,
// without granting approval, CI, review, installation, or source authority.
type UnverifiedOriginBinding struct {
	payloadOriginal []byte
	subject         d101evidencetransport.RawReference
	originRecord    d101evidencetransport.RawReference
	nativeCustody   d101evidencetransport.RawReference
	observedAt      time.Time
	role            Role
	profileSHA256   string
}

func (b UnverifiedOriginBinding) PayloadOriginal() []byte {
	return bytes.Clone(b.payloadOriginal)
}

func (b UnverifiedOriginBinding) SubjectReference() d101evidencetransport.RawReference {
	return b.subject
}

func (b UnverifiedOriginBinding) OriginRecordReference() d101evidencetransport.RawReference {
	return b.originRecord
}

func (b UnverifiedOriginBinding) NativeCustodyReference() d101evidencetransport.RawReference {
	return b.nativeCustody
}

func (b UnverifiedOriginBinding) ObservedAt() time.Time { return b.observedAt }
func (b UnverifiedOriginBinding) Role() Role            { return b.role }
func (b UnverifiedOriginBinding) ProfileSHA256() string { return b.profileSHA256 }

type envelope struct {
	SchemaVersion          int    `json:"schemaVersion"`
	OriginalBytesBase64URL string `json:"originalBytesBase64url"`
	SignatureBase64URL     string `json:"signatureBase64url"`
}

type publicProfile struct {
	SchemaVersion       int    `json:"schemaVersion"`
	Kind                string `json:"kind"`
	Role                Role   `json:"role"`
	IssuerIdentity      string `json:"issuerIdentity"`
	IssuerSourceSHA     string `json:"issuerSourceSha"`
	IssuerImageDigest   string `json:"issuerImageDigest"`
	PublicKeySPKIBase64 string `json:"publicKeySpkiBase64url"`
	PublicKeySPKISHA256 string `json:"publicKeySpkiSha256"`
}

type payload struct {
	SchemaVersion     int                                `json:"schemaVersion"`
	Kind              string                             `json:"kind"`
	Role              Role                               `json:"role"`
	IssuerIdentity    string                             `json:"issuerIdentity"`
	IssuerSourceSHA   string                             `json:"issuerSourceSha"`
	IssuerImageDigest string                             `json:"issuerImageDigest"`
	OperationID       string                             `json:"operationId"`
	ScopeOriginalRef  d101evidencetransport.RawReference `json:"scopeOriginalRef"`
	SubjectRef        d101evidencetransport.RawReference `json:"subjectRef"`
	OriginRecordRef   d101evidencetransport.RawReference `json:"originRecordRef"`
	NativeCustodyRef  d101evidencetransport.RawReference `json:"nativeCustodyRef"`
	ObservedAtUTC     string                             `json:"observedAtUtc"`
}

func VerifyCryptographicBinding(envelopeOriginal, publicProfileOriginal []byte, expected ExpectedBinding, now time.Time) (UnverifiedOriginBinding, error) {
	deny := func() (UnverifiedOriginBinding, error) { return UnverifiedOriginBinding{}, d101custody.ErrUnavailable }
	domain, ok := roleDomain(expected.Role)
	if !ok || !opPattern.MatchString(expected.OperationID) || !sha256Pattern.MatchString(expected.ProfileSHA256) ||
		d101evidencetransport.ValidateRawReference(expected.ScopeOriginal) != nil || now.Unix() <= 0 {
		return deny()
	}
	profileDigest := sha256.Sum256(publicProfileOriginal)
	if hex.EncodeToString(profileDigest[:]) != expected.ProfileSHA256 {
		return deny()
	}
	if _, err := exactObject(publicProfileOriginal, "schemaVersion", "kind", "role", "issuerIdentity", "issuerSourceSha", "issuerImageDigest", "publicKeySpkiBase64url", "publicKeySpkiSha256"); err != nil {
		return deny()
	}
	var profile publicProfile
	if json.Unmarshal(publicProfileOriginal, &profile) != nil || profile.SchemaVersion != 1 || profile.Kind != "D101_EVIDENCE_ORIGIN_PUBLIC_PINS_V1" ||
		profile.Role != expected.Role || !identityPattern.MatchString(profile.IssuerIdentity) || !sha40Pattern.MatchString(profile.IssuerSourceSHA) ||
		!validImageDigest(profile.IssuerImageDigest) || !sha256Pattern.MatchString(profile.PublicKeySPKISHA256) {
		return deny()
	}
	spki, ok := canonicalBase64URL(profile.PublicKeySPKIBase64, 44)
	if !ok {
		return deny()
	}
	spkiDigest := sha256.Sum256(spki)
	parsedKey, err := x509.ParsePKIXPublicKey(spki)
	key, keyOK := parsedKey.(ed25519.PublicKey)
	if err != nil || !keyOK || len(key) != ed25519.PublicKeySize || hex.EncodeToString(spkiDigest[:]) != profile.PublicKeySPKISHA256 {
		return deny()
	}
	reencoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(reencoded, spki) {
		return deny()
	}

	if _, err := exactObject(envelopeOriginal, "schemaVersion", "originalBytesBase64url", "signatureBase64url"); err != nil {
		return deny()
	}
	var proof envelope
	if json.Unmarshal(envelopeOriginal, &proof) != nil || proof.SchemaVersion != 1 {
		return deny()
	}
	original, ok := canonicalBase64URL(proof.OriginalBytesBase64URL, 0)
	if !ok || len(original) == 0 || len(original) > d101evidencetransport.MetadataMaxBytes {
		return deny()
	}
	signature, ok := canonicalBase64URL(proof.SignatureBase64URL, ed25519.SignatureSize)
	if !ok {
		return deny()
	}
	fields, err := exactObject(original, "schemaVersion", "kind", "role", "issuerIdentity", "issuerSourceSha", "issuerImageDigest", "operationId", "scopeOriginalRef", "subjectRef", "originRecordRef", "nativeCustodyRef", "observedAtUtc")
	if err != nil {
		return deny()
	}
	var body payload
	if json.Unmarshal(original, &body) != nil || body.SchemaVersion != 1 || body.Kind != "D101_EVIDENCE_ORIGIN_PROOF_V1" ||
		body.Role != expected.Role || body.IssuerIdentity != profile.IssuerIdentity || body.IssuerSourceSHA != profile.IssuerSourceSHA ||
		body.IssuerImageDigest != profile.IssuerImageDigest || body.OperationID != expected.OperationID {
		return deny()
	}
	for _, binding := range []struct {
		name string
		out  *d101evidencetransport.RawReference
	}{
		{"scopeOriginalRef", &body.ScopeOriginalRef},
		{"subjectRef", &body.SubjectRef},
		{"originRecordRef", &body.OriginRecordRef},
		{"nativeCustodyRef", &body.NativeCustodyRef},
	} {
		ref, err := d101evidencetransport.DecodeRawReference(fields[binding.name])
		if err != nil {
			return deny()
		}
		*binding.out = ref
	}
	if body.ScopeOriginalRef != expected.ScopeOriginal {
		return deny()
	}
	if !strings.HasSuffix(body.ObservedAtUTC, "Z") {
		return deny()
	}
	observedAt, err := time.Parse(time.RFC3339Nano, body.ObservedAtUTC)
	if err != nil || observedAt.Unix() <= 0 || observedAt.After(now) {
		return deny()
	}
	signed := make([]byte, 0, len(domain)+len(original))
	signed = append(signed, domain...)
	signed = append(signed, original...)
	if !ed25519.Verify(key, signed, signature) {
		return deny()
	}
	return UnverifiedOriginBinding{
		payloadOriginal: bytes.Clone(original),
		subject:         body.SubjectRef, originRecord: body.OriginRecordRef, nativeCustody: body.NativeCustodyRef,
		observedAt: observedAt, role: expected.Role, profileSHA256: expected.ProfileSHA256,
	}, nil
}

func roleDomain(role Role) (string, bool) {
	switch role {
	case ApprovalIssuer:
		return "OPENSAMGUK_D101_APPROVAL_ORIGIN_V1\n", true
	case OfficialGitHubCollector:
		return "OPENSAMGUK_D101_GITHUB_ORIGIN_V1\n", true
	case IndependentReviewCollector:
		return "OPENSAMGUK_D101_REVIEW_ORIGIN_V1\n", true
	default:
		return "", false
	}
}

func validImageDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && sha256Pattern.MatchString(strings.TrimPrefix(value, "sha256:"))
}

func canonicalBase64URL(value string, exactLength int) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return decoded, err == nil && len(decoded) > 0 && (exactLength == 0 || len(decoded) == exactLength) && base64.RawURLEncoding.EncodeToString(decoded) == value
}

// exactObject rejects ambiguous JSON before typed decoding. Nested RawReference
// values are checked by the shared transport decoder, preserving its one wire.
func exactObject(original []byte, names ...string) (map[string]json.RawMessage, error) {
	if len(original) == 0 || len(original) > d101evidencetransport.MetadataMaxBytes || !utf8.Valid(original) {
		return nil, d101custody.ErrUnavailable
	}
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	decoder := json.NewDecoder(bytes.NewReader(original))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, d101custody.ErrUnavailable
	}
	fields := make(map[string]json.RawMessage, len(names))
	for decoder.More() {
		token, err := decoder.Token()
		name, valid := token.(string)
		if err != nil || !valid || !allowed[name] {
			return nil, d101custody.ErrUnavailable
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, d101custody.ErrUnavailable
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, d101custody.ErrUnavailable
		}
		fields[name] = raw
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(fields) != len(names) {
		return nil, d101custody.ErrUnavailable
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, d101custody.ErrUnavailable
	}
	return fields, nil
}
