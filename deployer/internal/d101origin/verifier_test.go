package d101origin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101evidencetransport"
)

type originFixture struct {
	private  ed25519.PrivateKey
	profile  publicProfile
	body     payload
	expected ExpectedBinding
	now      time.Time
}

func newOriginFixture(t *testing.T, role Role) originFixture {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize))
	spki, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	spkiSHA := sha256.Sum256(spki)
	ref := func(id string) d101evidencetransport.RawReference {
		return d101evidencetransport.RawReference{LogicalID: "raw:" + id, SHA256: strings.Repeat("a", 64), ByteLength: 12, MediaType: "application/json"}
	}
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	profile := publicProfile{
		SchemaVersion: 1, Kind: "D101_EVIDENCE_ORIGIN_PUBLIC_PINS_V1", Role: role,
		IssuerIdentity: "fixed.issuer", IssuerSourceSHA: strings.Repeat("b", 40), IssuerImageDigest: "sha256:" + strings.Repeat("c", 64),
		PublicKeySPKIBase64: base64.RawURLEncoding.EncodeToString(spki), PublicKeySPKISHA256: hex.EncodeToString(spkiSHA[:]),
	}
	body := payload{
		SchemaVersion: 1, Kind: "D101_EVIDENCE_ORIGIN_PROOF_V1", Role: role,
		IssuerIdentity: profile.IssuerIdentity, IssuerSourceSHA: profile.IssuerSourceSHA, IssuerImageDigest: profile.IssuerImageDigest,
		OperationID: strings.Repeat("d", 32), ScopeOriginalRef: ref("scope"), SubjectRef: ref("subject"),
		OriginRecordRef: ref("origin"), NativeCustodyRef: ref("custody"), ObservedAtUTC: now.Add(-time.Second).Format(time.RFC3339Nano),
	}
	return originFixture{private: private, profile: profile, body: body, now: now,
		expected: ExpectedBinding{Role: role, OperationID: body.OperationID, ScopeOriginal: body.ScopeOriginalRef}}
}

func fixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (f originFixture) originals(t *testing.T, signingRole Role) ([]byte, []byte, ExpectedBinding) {
	t.Helper()
	profileOriginal := fixtureJSON(t, f.profile)
	profileSHA := sha256.Sum256(profileOriginal)
	expected := f.expected
	expected.ProfileSHA256 = hex.EncodeToString(profileSHA[:])
	payloadOriginal := fixtureJSON(t, f.body)
	domain, ok := roleDomain(signingRole)
	if !ok {
		t.Fatal("fixture role has no domain")
	}
	signature := ed25519.Sign(f.private, append([]byte(domain), payloadOriginal...))
	envelopeOriginal := fixtureJSON(t, envelope{
		SchemaVersion:          1,
		OriginalBytesBase64URL: base64.RawURLEncoding.EncodeToString(payloadOriginal),
		SignatureBase64URL:     base64.RawURLEncoding.EncodeToString(signature),
	})
	return envelopeOriginal, profileOriginal, expected
}

func TestOriginPureBindingAcceptedRolesAndDefensiveCopy(t *testing.T) {
	for _, role := range []Role{ApprovalIssuer, OfficialGitHubCollector, IndependentReviewCollector} {
		t.Run(string(role), func(t *testing.T) {
			f := newOriginFixture(t, role)
			env, profile, expected := f.originals(t, role)
			binding, err := VerifyCryptographicBinding(env, profile, expected, f.now)
			if err != nil {
				t.Fatal(err)
			}
			original := fixtureJSON(t, f.body)
			if !bytes.Equal(binding.PayloadOriginal(), original) || binding.SubjectReference() != f.body.SubjectRef ||
				binding.OriginRecordReference() != f.body.OriginRecordRef || binding.NativeCustodyReference() != f.body.NativeCustodyRef ||
				!binding.ObservedAt().Equal(f.now.Add(-time.Second)) || binding.Role() != role || binding.ProfileSHA256() != expected.ProfileSHA256 {
				t.Fatal("cryptographic binding lost original references")
			}
			original[0] = '!'
			copyOut := binding.PayloadOriginal()
			copyOut[0] = '!'
			if binding.PayloadOriginal()[0] == '!' {
				t.Fatal("payload accessor exposed mutable original")
			}
			env[0], profile[0] = '!', '!'
			if binding.PayloadOriginal()[0] == '!' {
				t.Fatal("binding retained caller buffer")
			}
		})
	}
}

func TestOriginPureBindingRejectsIndependentPinAndDomainMismatch(t *testing.T) {
	base := newOriginFixture(t, OfficialGitHubCollector)
	for _, tc := range []struct {
		name   string
		mutate func(*originFixture, *ExpectedBinding)
	}{
		{"wrong expected role", func(_ *originFixture, e *ExpectedBinding) { e.Role = ApprovalIssuer }},
		{"wrong operation", func(_ *originFixture, e *ExpectedBinding) { e.OperationID = strings.Repeat("e", 32) }},
		{"wrong scope", func(_ *originFixture, e *ExpectedBinding) { e.ScopeOriginal.SHA256 = strings.Repeat("e", 64) }},
		{"wrong whole profile pin", func(_ *originFixture, e *ExpectedBinding) { e.ProfileSHA256 = strings.Repeat("e", 64) }},
		{"body source does not match profile", func(f *originFixture, _ *ExpectedBinding) { f.body.IssuerSourceSHA = strings.Repeat("e", 40) }},
		{"body identity does not match profile", func(f *originFixture, _ *ExpectedBinding) { f.body.IssuerIdentity = "other.issuer" }},
		{"body image does not match profile", func(f *originFixture, _ *ExpectedBinding) {
			f.body.IssuerImageDigest = "sha256:" + strings.Repeat("e", 64)
		}},
		{"future observation", func(f *originFixture, _ *ExpectedBinding) {
			f.body.ObservedAtUTC = f.now.Add(time.Second).Format(time.RFC3339Nano)
		}},
		{"non UTC observation", func(f *originFixture, _ *ExpectedBinding) { f.body.ObservedAtUTC = "2026-10-06T08:59:59+09:00" }},
		{"invalid subject", func(f *originFixture, _ *ExpectedBinding) { f.body.SubjectRef.ByteLength = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			env, profile, expected := f.originals(t, f.body.Role)
			_ = env
			tc.mutate(&f, &expected)
			// Re-sign changes to the claimed body, so rejection must come from
			// fixed pins and references rather than a stale signature.
			env, profile, pinned := f.originals(t, f.body.Role)
			if expected.ProfileSHA256 != pinned.ProfileSHA256 {
				pinned.ProfileSHA256 = expected.ProfileSHA256
			}
			pinned.Role, pinned.OperationID, pinned.ScopeOriginal = expected.Role, expected.OperationID, expected.ScopeOriginal
			if _, err := VerifyCryptographicBinding(env, profile, pinned, f.now); err == nil {
				t.Fatal("accepted mismatched independent binding")
			}
		})
	}
	t.Run("wrong fixed domain", func(t *testing.T) {
		env, profile, expected := base.originals(t, ApprovalIssuer)
		if _, err := VerifyCryptographicBinding(env, profile, expected, base.now); err == nil {
			t.Fatal("accepted another role's signature domain")
		}
	})
}

func TestOriginPureBindingRejectsMalformedAndUntrustedOriginals(t *testing.T) {
	f := newOriginFixture(t, ApprovalIssuer)
	env, profile, expected := f.originals(t, f.body.Role)
	for _, tc := range []struct {
		name    string
		env     []byte
		profile []byte
	}{
		{"duplicate envelope field", []byte(`{"schemaVersion":1,"schemaVersion":1,"originalBytesBase64url":"x","signatureBase64url":"x"}`), profile},
		{"null envelope field", []byte(`{"schemaVersion":1,"originalBytesBase64url":null,"signatureBase64url":"x"}`), profile},
		{"trailing envelope bytes", append(bytes.Clone(env), []byte(` {}`)...), profile},
		{"unknown envelope field", append(bytes.TrimSuffix(bytes.Clone(env), []byte("}")), []byte(`,"keyId":"self"}`)...), profile},
		{"changed profile original", env, append(bytes.Clone(profile), ' ')},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyCryptographicBinding(tc.env, tc.profile, expected, f.now); err == nil {
				t.Fatal("accepted malformed proof or unpinned profile")
			}
		})
	}
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"unknown payload field", append(bytes.TrimSuffix(fixtureJSON(t, f.body), []byte("}")), []byte(`,"authority":true}`)...)},
		{"duplicate payload field", append(bytes.TrimSuffix(fixtureJSON(t, f.body), []byte("}")), []byte(`,"role":"APPROVAL_ISSUER"}`)...)},
		{"null nested reference", bytes.Replace(fixtureJSON(t, f.body), fixtureJSON(t, f.body.SubjectRef), []byte("null"), 1)},
		{"duplicate nested reference", bytes.Replace(fixtureJSON(t, f.body), fixtureJSON(t, f.body.SubjectRef), []byte(`{"logicalId":"raw:subject","logicalId":"raw:subject","sha256":"`+strings.Repeat("a", 64)+`","byteLength":12,"mediaType":"application/json"}`), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			domain, _ := roleDomain(f.body.Role)
			sig := ed25519.Sign(f.private, append([]byte(domain), tc.body...))
			proof := fixtureJSON(t, envelope{1, base64.RawURLEncoding.EncodeToString(tc.body), base64.RawURLEncoding.EncodeToString(sig)})
			if _, err := VerifyCryptographicBinding(proof, profile, expected, f.now); err == nil {
				t.Fatal("accepted malformed signed payload")
			}
		})
	}
}
