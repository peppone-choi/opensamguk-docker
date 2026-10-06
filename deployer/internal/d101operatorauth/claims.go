// Package d101operatorauth authenticates current technical issuance only.
// It never authenticates a historical conversation or authorizes execution.
package d101operatorauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const OfficialIssuer = "https://token.actions.githubusercontent.com"
const officialJWKS = OfficialIssuer + "/.well-known/jwks"

// Match the existing D101 evidence metadata bound, not a new operating budget.
const metadataBytes = 64 << 10

var ErrUnavailable = errors.New("current technical issuance authentication unavailable")

// Verifier owns an immutable copy of independently reviewed host policy.
// The host installer must authenticate that policy before constructing it.
type Verifier struct {
	policy ReviewedPolicy
	mu     sync.Mutex
	seen   map[string]struct{}
}

type currentClaims struct {
	actor, run, jti, workflow string
	attempt                   uint64
	iat, nbf, exp             int64
}

type operatorProof struct {
	policy     ReviewedPolicy
	claims     currentClaims
	auth       Reference
	verifiedAt time.Time
	mu         sync.Mutex
	consumed   bool
}

// CurrentOperator cannot be constructed from labels, a JSON record, or a bool.
type CurrentOperator struct{ proof *operatorProof }

func NewVerifier(policy ReviewedPolicy) (*Verifier, error) {
	if validatePolicy(policy) != nil {
		return nil, ErrUnavailable
	}
	return &Verifier{policy: clonePolicy(policy), seen: make(map[string]struct{})}, nil
}

// Verify accepts retained JWT bytes but obtains keys only from the fixed
// official HTTPS endpoint. No injected key source, redirect or header URL.
// The caller supplies its existing bounded operation context.
func (v *Verifier) Verify(ctx context.Context, jwt []byte, auth Reference) (CurrentOperator, error) {
	if v == nil || ctx == nil || ctx.Err() != nil || validatePolicy(v.policy) != nil ||
		!matchesOriginal(auth, jwt, "text/plain") {
		return CurrentOperator{}, ErrUnavailable
	}
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) || deadline.Unix() > v.policy.CutoffUnix {
		return CurrentOperator{}, ErrUnavailable
	}
	if _, _, _, err := jwtParts(jwt); err != nil {
		return CurrentOperator{}, ErrUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, officialJWKS, nil)
	if err != nil {
		return CurrentOperator{}, ErrUnavailable
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrUnavailable }}
	response, err := client.Do(request)
	if err != nil {
		return CurrentOperator{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return CurrentOperator{}, ErrUnavailable
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, metadataBytes+1))
	if err != nil || len(wire) > metadataBytes || ctx.Err() != nil {
		return CurrentOperator{}, ErrUnavailable
	}
	return v.verifyWithKeys(jwt, auth, wire, time.Now().UTC())
}

// The pure key seam is unexported and used by package-local synthetic tests.
func (v *Verifier) verifyWithKeys(jwt []byte, auth Reference, jwks []byte, now time.Time) (CurrentOperator, error) {
	deny := func() (CurrentOperator, error) { return CurrentOperator{}, ErrUnavailable }
	if v == nil || validatePolicy(v.policy) != nil || !matchesOriginal(auth, jwt, "text/plain") {
		return deny()
	}
	header, payload, signature, err := jwtParts(jwt)
	if err != nil {
		return deny()
	}
	kid, ok := header["kid"].(string)
	if !ok || kid == "" {
		return deny()
	}
	key, err := rsaKey(jwks, kid)
	if err != nil {
		return deny()
	}
	parts := strings.Split(string(jwt), ".")
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return deny()
	}
	claims, err := validateClaims(payload, v.policy, now)
	if err != nil {
		return deny()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, exists := v.seen[claims.jti]; exists {
		return deny()
	}
	v.seen[claims.jti] = struct{}{}
	return CurrentOperator{&operatorProof{policy: clonePolicy(v.policy), claims: claims,
		auth: auth, verifiedAt: now}}, nil
}

func jwtParts(jwt []byte) (map[string]any, map[string]any, []byte, error) {
	if len(jwt) == 0 || len(jwt) > metadataBytes || !utf8.Valid(jwt) {
		return nil, nil, nil, ErrUnavailable
	}
	parts := strings.Split(string(jwt), ".")
	if len(parts) != 3 {
		return nil, nil, nil, ErrUnavailable
	}
	headerWire, err := canonicalURLBytes(parts[0])
	if err != nil {
		return nil, nil, nil, ErrUnavailable
	}
	header, err := strictObject(headerWire)
	if err != nil || len(header) != 3 || header["alg"] != "RS256" || header["typ"] != "JWT" {
		return nil, nil, nil, ErrUnavailable
	}
	if kid, ok := header["kid"].(string); !ok || kid == "" {
		return nil, nil, nil, ErrUnavailable
	}
	// Exact header excludes jku/x5u, crit, embedded keys and algorithm aliases.
	payloadWire, err := canonicalURLBytes(parts[1])
	if err != nil {
		return nil, nil, nil, ErrUnavailable
	}
	payload, err := strictObject(payloadWire)
	if err != nil {
		return nil, nil, nil, ErrUnavailable
	}
	signature, err := canonicalURLBytes(parts[2])
	if err != nil {
		return nil, nil, nil, ErrUnavailable
	}
	return header, payload, signature, nil
}

func validateClaims(c map[string]any, p ReviewedPolicy, now time.Time) (currentClaims, error) {
	deny := func() (currentClaims, error) { return currentClaims{}, ErrUnavailable }
	for field, expected := range map[string]string{"iss": OfficialIssuer, "aud": p.Audience, "sub": p.Subject,
		"repository": p.Repository, "repository_id": p.RepositoryID, "repository_owner_id": p.OwnerID,
		"actor_id": p.ActorID, "workflow_ref": p.WorkflowRef, "workflow_sha": p.WorkflowSHA,
		"event_name": "workflow_dispatch", "run_id": p.RunID, "run_attempt": "1"} {
		value, ok := c[field].(string)
		if !ok || value != expected {
			return deny()
		}
	}
	iat, e1 := numericDate(c["iat"])
	nbf, e2 := numericDate(c["nbf"])
	exp, e3 := numericDate(c["exp"])
	jti, ok := c["jti"].(string)
	if e1 != nil || e2 != nil || e3 != nil || !ok || !identity.MatchString(jti) ||
		now.Unix() < p.OpensAtUnix || now.Unix() >= p.CutoffUnix ||
		iat < p.OpensAtUnix || nbf < p.OpensAtUnix || iat > now.Unix() || nbf > now.Unix() ||
		exp <= now.Unix() || exp <= iat || exp <= nbf {
		return deny()
	}
	return currentClaims{p.ActorID, p.RunID, jti, p.WorkflowSHA, 1, iat, nbf, exp}, nil
}

func numericDate(value any) (int64, error) {
	n, ok := value.(json.Number)
	if !ok {
		return 0, ErrUnavailable
	}
	if !positiveNumber.MatchString(string(n)) {
		return 0, ErrUnavailable
	}
	v, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil || v <= 0 {
		return 0, ErrUnavailable
	}
	return v, nil
}

func rsaKey(wire []byte, kid string) (*rsa.PublicKey, error) {
	object, err := strictObject(wire)
	if err != nil || len(object) != 1 {
		return nil, ErrUnavailable
	}
	keys, ok := object["keys"].([]any)
	if !ok || len(keys) == 0 {
		return nil, ErrUnavailable
	}
	var selected *rsa.PublicKey
	for _, entry := range keys {
		key, ok := entry.(map[string]any)
		if !ok {
			return nil, ErrUnavailable
		}
		id, ok := key["kid"].(string)
		if !ok || id == "" {
			return nil, ErrUnavailable
		}
		if id != kid {
			continue
		}
		if selected != nil || key["kty"] != "RSA" || key["alg"] != "RS256" || key["use"] != "sig" {
			return nil, ErrUnavailable
		}
		n, nok := key["n"].(string)
		e, eok := key["e"].(string)
		if !nok || !eok {
			return nil, ErrUnavailable
		}
		modulus, err := canonicalURLBytes(n)
		if err != nil || modulus[0] == 0 {
			return nil, ErrUnavailable
		}
		exponent, err := canonicalURLBytes(e)
		if err != nil || exponent[0] == 0 || len(exponent) > 4 {
			return nil, ErrUnavailable
		}
		exp := new(big.Int).SetBytes(exponent).Uint64()
		// RFC 7518 section 3.3 requires RSA keys of at least 2048 bits.
		selected = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(exp)}
		if selected.N.BitLen() < 2048 || exp < 3 || exp > 2147483647 || exp%2 == 0 {
			return nil, ErrUnavailable
		}
	}
	if selected == nil {
		return nil, ErrUnavailable
	}
	return selected, nil
}

func canonicalURLBytes(text string) ([]byte, error) {
	value, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || len(value) == 0 || len(value) > metadataBytes || base64.RawURLEncoding.EncodeToString(value) != text {
		return nil, ErrUnavailable
	}
	return value, nil
}

// Decode every level to reject duplicate keys, nulls and trailing JSON values.
func strictObject(wire []byte) (map[string]any, error) {
	if len(wire) == 0 || len(wire) > metadataBytes || !utf8.Valid(wire) {
		return nil, ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(wire))
	d.UseNumber()
	var read func() (any, error)
	read = func() (any, error) {
		token, err := d.Token()
		if err != nil || token == nil {
			return nil, ErrUnavailable
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				object := make(map[string]any)
				for d.More() {
					t, err := d.Token()
					key, ok := t.(string)
					if err != nil || !ok {
						return nil, ErrUnavailable
					}
					if _, duplicate := object[key]; duplicate {
						return nil, ErrUnavailable
					}
					value, err := read()
					if err != nil {
						return nil, err
					}
					object[key] = value
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return nil, ErrUnavailable
				}
				return object, nil
			case '[':
				values := make([]any, 0)
				for d.More() {
					value, err := read()
					if err != nil {
						return nil, err
					}
					values = append(values, value)
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return nil, ErrUnavailable
				}
				return values, nil
			default:
				return nil, ErrUnavailable
			}
		}
		return token, nil
	}
	value, err := read()
	if err != nil {
		return nil, ErrUnavailable
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrUnavailable
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, ErrUnavailable
	}
	return object, nil
}
