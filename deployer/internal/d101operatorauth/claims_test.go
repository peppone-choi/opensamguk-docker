package d101operatorauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

var fixtureKey *rsa.PrivateKey
var fixtureKeyError error
var fixtureKeyOnce sync.Once

type operatorFixture struct {
	policy ReviewedPolicy
	claims map[string]any
	key    *rsa.PrivateKey
	jwks   []byte
	now    time.Time
}

func jsonFixture(t *testing.T, value any) []byte {
	t.Helper()
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal("synthetic JSON fixture failed")
	}
	return wire
}
func rawFixture(id string, wire []byte, media string) Reference {
	return Reference{id, hash(wire), uint64(len(wire)), media}
}
func issuerFixture(t *testing.T, role string, seed byte) IssuerPins {
	t.Helper()
	// These deterministic keys are test-only and never leave the fixture.
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal("synthetic issuer fixture failed")
	}
	return IssuerPins{role, "synthetic-" + role, strings.Repeat("a", 40), "sha256:" + strings.Repeat("b", 64), hash(spki), spki}
}
func newOperatorFixture(t *testing.T) operatorFixture {
	t.Helper()
	fixtureKeyOnce.Do(func() { fixtureKey, fixtureKeyError = rsa.GenerateKey(rand.Reader, 2048) })
	if fixtureKeyError != nil {
		t.Fatal("synthetic RSA fixture failed")
	}
	now := time.Now().UTC().Truncate(time.Second)
	scope := TechnicalScope{OperationID: strings.Repeat("1", 32), AppSourceSHA: strings.Repeat("a", 40), DockerSourceSHA: strings.Repeat("b", 40),
		FinalCard:            rawFixture("raw:synthetic-final-card", []byte("synthetic final card"), "text/plain"),
		ScopeOriginal:        rawFixture("raw:synthetic-scope", []byte("synthetic fixed scope"), "text/plain"),
		DecisionSlicesSHA256: hash([]byte("synthetic original twenty decision slices"))}
	for n := range scope.DecisionParents {
		scope.DecisionParents[n] = rawFixture("raw:synthetic-parent-"+string(rune('a'+n)), []byte{byte(n + 1)}, "text/plain")
	}
	p := ReviewedPolicy{SourceSHA: strings.Repeat("c", 40), ReviewOriginal: rawFixture("raw:synthetic-review", []byte("synthetic policy review"), "text/plain"),
		Audience: "synthetic-approved-audience", Subject: "synthetic-reviewed-subject", Repository: "synthetic/issuer", RepositoryID: "101", OwnerID: "102", ActorID: "103",
		WorkflowRef: "synthetic/issuer/.github/workflows/issuance.yml@refs/heads/main", WorkflowSHA: strings.Repeat("d", 40), RunID: "104",
		OpensAtUnix: now.Add(-time.Minute).Unix(), CutoffUnix: now.Add(10 * time.Minute).Unix(),
		ApprovalIssuer: issuerFixture(t, ApprovalIssuerRole, 0x21), ReceiptIssuer: issuerFixture(t, ApprovedReceiptIssuerRole, 0x22), RootPurposeSPKISHA256: strings.Repeat("e", 64), Scope: scope}
	c := map[string]any{"iss": OfficialIssuer, "aud": p.Audience, "sub": p.Subject, "repository": p.Repository, "repository_id": p.RepositoryID, "repository_owner_id": p.OwnerID,
		"actor_id": p.ActorID, "workflow_ref": p.WorkflowRef, "workflow_sha": p.WorkflowSHA, "event_name": "workflow_dispatch", "run_id": p.RunID, "run_attempt": "1",
		"iat": now.Add(-time.Second).Unix(), "nbf": now.Add(-time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": "synthetic-current-event"}
	f := operatorFixture{p, c, fixtureKey, nil, now}
	f.jwks = jsonFixture(t, map[string]any{"keys": []any{f.jwk()}})
	return f
}
func (f operatorFixture) jwk() map[string]any {
	return map[string]any{"kid": "synthetic-key", "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes())}
}
func (f operatorFixture) signed(t *testing.T, header, payload []byte) []byte {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal("synthetic signature fixture failed")
	}
	return []byte(input + "." + base64.RawURLEncoding.EncodeToString(signature))
}
func (f operatorFixture) token(t *testing.T) []byte {
	return f.signed(t, jsonFixture(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "synthetic-key"}), jsonFixture(t, f.claims))
}
func (f operatorFixture) operator(t *testing.T) CurrentOperator {
	t.Helper()
	v, err := NewVerifier(f.policy)
	if err != nil {
		t.Fatal("synthetic constructor denied")
	}
	token := f.token(t)
	op, err := v.verifyWithKeys(token, rawFixture("raw:synthetic-authentication", token, "text/plain"), f.jwks, f.now)
	if err != nil {
		t.Fatal("valid synthetic signature/current binding denied")
	}
	return op
}

func TestCurrentOperatorVerifiesSignedPinnedCurrentEvent(t *testing.T) {
	f := newOperatorFixture(t)
	op := f.operator(t)
	if op.proof == nil || op.proof.claims.actor != f.policy.ActorID || op.proof.claims.run != f.policy.RunID ||
		op.proof.claims.attempt != 1 || op.proof.claims.jti != f.claims["jti"] {
		t.Fatal("wrong current event")
	}
	if op.proof.policy.Scope != f.policy.Scope {
		t.Fatal("scope binding changed")
	}
}

func TestCurrentOperatorRejectsSignedClaimDrift(t *testing.T) {
	f := newOperatorFixture(t)
	mutants := map[string]any{"iss": "https://untrusted.invalid", "aud": "other", "sub": "other", "repository": "other/issuer", "repository_id": "105", "repository_owner_id": "105",
		"actor_id": "105", "workflow_ref": "other/issuer/.github/workflows/issuance.yml@refs/heads/main", "workflow_sha": strings.Repeat("e", 40), "event_name": "push",
		"run_id": "105", "run_attempt": "2", "iat": f.now.Add(time.Second).Unix(), "nbf": f.now.Add(time.Second).Unix(), "exp": f.now.Unix(), "jti": ""}
	for field, value := range mutants {
		t.Run(field, func(t *testing.T) {
			c := make(map[string]any)
			for k, v := range f.claims {
				c[k] = v
			}
			c[field] = value
			v, err := NewVerifier(f.policy)
			if err != nil {
				t.Fatal("fixture constructor")
			}
			token := f.signed(t, jsonFixture(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "synthetic-key"}), jsonFixture(t, c))
			if _, err := v.verifyWithKeys(token, rawFixture("raw:synthetic-authentication", token, "text/plain"), f.jwks, f.now); !errors.Is(err, ErrUnavailable) {
				t.Fatal("signed current claim drift accepted")
			}
		})
	}
	for _, field := range []string{"iat", "nbf", "exp", "actor_id", "run_attempt"} {
		for _, value := range []any{nil, 1.5, "1e3", json.Number("1e3")} {
			t.Run(field+"-wrong-type", func(t *testing.T) {
				c := make(map[string]any)
				for k, v := range f.claims {
					c[k] = v
				}
				c[field] = value
				v, _ := NewVerifier(f.policy)
				token := f.signed(t, []byte(`{"alg":"RS256","typ":"JWT","kid":"synthetic-key"}`), jsonFixture(t, c))
				if _, err := v.verifyWithKeys(token, rawFixture("raw:synthetic-authentication", token, "text/plain"), f.jwks, f.now); err == nil {
					t.Fatal("wrong claim type accepted")
				}
			})
		}
	}
}

func TestCurrentOperatorRejectsMalformedJwsAndKeySubstitution(t *testing.T) {
	f := newOperatorFixture(t)
	payload := jsonFixture(t, f.claims)
	headers := []string{`{"alg":"RS256","typ":"JWT","kid":"synthetic-key","kid":"synthetic-key"}`,
		`{"alg":"RS256","typ":"JWT","kid":null}`, `{"alg":"none","typ":"JWT","kid":"synthetic-key"}`,
		`{"alg":"RS256","typ":"JWT","kid":"synthetic-key","jku":"https://untrusted.invalid"}`,
		`{"alg":"RS256","typ":"JWT","kid":"synthetic-key","x5u":"https://untrusted.invalid"}`}
	for _, header := range headers {
		v, _ := NewVerifier(f.policy)
		token := f.signed(t, []byte(header), payload)
		if _, err := v.verifyWithKeys(token, rawFixture("raw:synthetic-authentication", token, "text/plain"), f.jwks, f.now); err == nil {
			t.Fatal("unverified header accepted")
		}
	}
	for _, malformed := range []string{strings.TrimSuffix(string(payload), "}") + `,"actor_id":"103"}`, string(payload) + " {}", `[]`, `null`} {
		v, _ := NewVerifier(f.policy)
		token := f.signed(t, []byte(`{"alg":"RS256","typ":"JWT","kid":"synthetic-key"}`), []byte(malformed))
		if _, err := v.verifyWithKeys(token, rawFixture("raw:synthetic-authentication", token, "text/plain"), f.jwks, f.now); err == nil {
			t.Fatal("malformed payload accepted")
		}
	}
	token := f.token(t)
	parts := strings.Split(string(token), ".")
	signature, _ := canonicalURLBytes(parts[2])
	signature[0] ^= 1
	bad := []byte(parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature))
	v, _ := NewVerifier(f.policy)
	if _, err := v.verifyWithKeys(bad, rawFixture("raw:synthetic-authentication", bad, "text/plain"), f.jwks, f.now); err == nil {
		t.Fatal("bad signature accepted")
	}
	for _, mode := range []string{"duplicate-kid", "weak-key", "wrong-use", "wrong-algorithm", "noncanonical-number"} {
		key := f.jwk()
		keys := []any{key}
		switch mode {
		case "duplicate-kid":
			keys = append(keys, f.jwk())
		case "weak-key":
			key["n"] = "AQ"
		case "wrong-use":
			key["use"] = "enc"
		case "wrong-algorithm":
			key["alg"] = "HS256"
		case "noncanonical-number":
			key["e"] = "AAEAAQ"
		}
		v, _ := NewVerifier(f.policy)
		if _, err := v.verifyWithKeys(token, rawFixture("raw:synthetic-authentication", token, "text/plain"), jsonFixture(t, map[string]any{"keys": keys}), f.now); err == nil {
			t.Fatal("unverified RSA key accepted")
		}
	}
}

func TestCurrentOperatorRequiresPolicyAndRetainedBindings(t *testing.T) {
	f := newOperatorFixture(t)
	mutants := []func(*ReviewedPolicy){func(p *ReviewedPolicy) { p.Audience = "" }, func(p *ReviewedPolicy) { p.Subject = "" }, func(p *ReviewedPolicy) { p.ActorID = "0" },
		func(p *ReviewedPolicy) { p.ActorID = "18446744073709551616" }, func(p *ReviewedPolicy) { p.RunID = "" }, func(p *ReviewedPolicy) { p.ReviewOriginal = Reference{} },
		func(p *ReviewedPolicy) { p.SourceSHA = "" }, func(p *ReviewedPolicy) { p.WorkflowSHA = "" }, func(p *ReviewedPolicy) { p.Repository = "/" },
		func(p *ReviewedPolicy) { p.OpensAtUnix = 0 }, func(p *ReviewedPolicy) { p.CutoffUnix = p.OpensAtUnix }, func(p *ReviewedPolicy) { p.ApprovalIssuer = IssuerPins{} },
		func(p *ReviewedPolicy) { p.ReceiptIssuer.Role = ApprovalIssuerRole }, func(p *ReviewedPolicy) {
			p.ReceiptIssuer.PublicKeySPKI = bytes.Clone(p.ApprovalIssuer.PublicKeySPKI)
			p.ReceiptIssuer.PublicKeySPKISHA256 = p.ApprovalIssuer.PublicKeySPKISHA256
		},
		func(p *ReviewedPolicy) { p.RootPurposeSPKISHA256 = p.ApprovalIssuer.PublicKeySPKISHA256 }, func(p *ReviewedPolicy) { p.RootPurposeSPKISHA256 = "" }}
	for _, mutate := range mutants {
		p := clonePolicy(f.policy)
		mutate(&p)
		if _, err := NewVerifier(p); err == nil {
			t.Fatal("missing independent policy accepted")
		}
	}
	v, _ := NewVerifier(f.policy)
	token := f.token(t)
	ref := rawFixture("raw:synthetic-authentication", token, "text/plain")
	ref.SHA256 = strings.Repeat("f", 64)
	if _, err := v.verifyWithKeys(token, ref, f.jwks, f.now); err == nil {
		t.Fatal("retained original mismatch accepted")
	}
	if _, err := v.Verify(context.Background(), token, rawFixture("raw:synthetic-authentication", token, "text/plain")); err == nil {
		t.Fatal("unbounded production context accepted")
	}
	if _, err := v.Verify(nil, token, rawFixture("raw:synthetic-authentication", token, "text/plain")); err == nil {
		t.Fatal("nil production context accepted")
	}
}

func TestCurrentOperatorRejectsReplayAndOwnsPolicyBytes(t *testing.T) {
	f := newOperatorFixture(t)
	v, err := NewVerifier(f.policy)
	if err != nil {
		t.Fatal("fixture constructor")
	}
	f.policy.ApprovalIssuer.PublicKeySPKI[0] ^= 1
	token := f.token(t)
	ref := rawFixture("raw:synthetic-authentication", token, "text/plain")
	if _, err := v.verifyWithKeys(token, ref, f.jwks, f.now); err != nil {
		t.Fatal("caller policy alias changed verifier")
	}
	if _, err := v.verifyWithKeys(token, ref, f.jwks, f.now); err == nil {
		t.Fatal("same JWT event replay accepted")
	}
}
