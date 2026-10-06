package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resetD101KeyFixture(t *testing.T) (resetD101SigningKeyPins, ed25519.PublicKey) {
	t.Helper()
	// Public RFC8032 seed. Synthetic custody fixture only, not an operating key.
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	public := key.Public().(ed25519.PublicKey)
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	publicSum := sha256.Sum256(spki)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	envelope := resetD101SigningKeyEnvelope{1, "synthetic-rfc8032", base64.RawURLEncoding.EncodeToString(der), hex.EncodeToString(publicSum[:])}
	wire, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	if err := os.WriteFile(filepath.Join(directory, id+".json"), wire, 0400); err != nil {
		t.Fatal(err)
	}
	return resetD101SigningKeyPins{directory, id, hex.EncodeToString(sum[:]), envelope.KeyID, envelope.PublicKeySpkiSHA}, public
}

func TestResetD101PrivateKeyCustodyPinnedSpkiDomainAndClose(t *testing.T) {
	pins, public := resetD101KeyFixture(t)
	key, err := readResetD101SigningKeyWithUID(pins, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	original := []byte(`{"schemaVersion":1}`)
	sig, err := key.sign("OPENSAMGUK-D101-RESULT-V1\n", original)
	if err != nil || !ed25519.Verify(public, append([]byte("OPENSAMGUK-D101-RESULT-V1\n"), original...), sig) {
		t.Fatal("original signature failed")
	}
	if ed25519.Verify(public, append([]byte("OPENSAMGUK-D101-GRANT-V1\n"), original...), sig) {
		t.Fatal("cross domain accepted")
	}
	key.close()
	if _, err := key.sign("OPENSAMGUK-D101-RESULT-V1\n", original); err == nil {
		t.Fatal("closed key reused")
	}
	for _, change := range []func(*resetD101SigningKeyPins){func(p *resetD101SigningKeyPins) { p.PublicKeySpkiSHA = strings.Repeat("f", 64) }, func(p *resetD101SigningKeyPins) { p.KeyID = "caller-key" }, func(p *resetD101SigningKeyPins) { p.EnvelopeSHA = strings.Repeat("f", 64) }} {
		bad := pins
		change(&bad)
		if _, err := readResetD101SigningKeyWithUID(bad, uint32(os.Getuid())); err == nil {
			t.Fatal("unpinned key accepted")
		}
	}
	if err := os.Chmod(filepath.Join(pins.Directory, pins.CustodyID+".json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readResetD101SigningKeyWithUID(pins, uint32(os.Getuid())); err == nil {
		t.Fatal("mutable key accepted")
	}
}

func TestResetD101PurposeIssuerOriginalClaimsAndClosedMissingAuthority(t *testing.T) {
	wire, sha, plan := resetIntentFixture(t)
	intent, err := decodeResetApprovalIntent(wire, sha)
	if err != nil {
		t.Fatal(err)
	}
	pins, public := resetD101KeyFixture(t)
	now := time.Unix(plan.WindowOpensAtUnix+10, 0)
	authority := resetD101VerifiedPurposeAuthority{intent, pins, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), now}
	source := func(context.Context, string, string) (resetD101VerifiedPurposeAuthority, error) {
		return authority, nil
	}
	body, err := json.Marshal(struct {
		SchemaVersion     int    `json:"schemaVersion"`
		ApprovalIntentSHA string `json:"approvalIntentSha256"`
		IntentBytes       string `json:"approvalIntentBytesBase64url"`
	}{1, sha, base64.RawURLEncoding.EncodeToString(wire)})
	if err != nil {
		t.Fatal(err)
	}
	bodySum := sha256.Sum256(body)
	req := resetD101PurposeGrantRequest{plan.OperationID, sha, hex.EncodeToString(bodySum[:]), "PREPARE", body}
	clock := func() time.Time { return now }
	readKey := func(p resetD101SigningKeyPins) (resetD101SigningKey, error) {
		return readResetD101SigningKeyWithUID(p, uint32(os.Getuid()))
	}
	header, err := issueResetD101PurposeGrantWithKeyReader(context.Background(), source, req, clock, readKey)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(header, ".")
	if len(parts) != 2 {
		t.Fatal("invalid proof")
	}
	original, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims resetD101PurposeGrantClaims
	if err := decodeResetPrivateJSON(original, &claims); err != nil || claims.Action != "PREPARE" || claims.InitialPublicRevision != "1" ||
		claims.ApprovalIntentSHA != sha || claims.RequestBodySHA != req.GatewayPayloadSHA || claims.ExpiresAtUnix-claims.IssuedAtUnix != 60 ||
		!ed25519.Verify(public, append([]byte("OPENSAMGUK-D101-GRANT-V1\n"), original...), signature) {
		t.Fatal("incorrect original claim proof")
	}
	if bytes.Contains(original, []byte("PrivateKey")) {
		t.Fatal("private key in claims")
	}
	if _, err := issueResetD101PurposeGrant(context.Background(), nil, req, clock); err == nil {
		t.Fatal("missing authority signed")
	}
	authority.ClockObservedAt = now.Add(-30 * time.Second)
	if _, err := issueResetD101PurposeGrantWithKeyReader(context.Background(), source, req, clock, readKey); err == nil {
		t.Fatal("stale clock signed")
	}
	authority.ClockObservedAt = now
	req.Body = []byte(`{}`)
	if _, err := issueResetD101PurposeGrantWithKeyReader(context.Background(), source, req, clock, readKey); err == nil {
		t.Fatal("different original body signed")
	}
}
