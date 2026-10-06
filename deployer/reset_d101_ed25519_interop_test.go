package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Shared public RFC8032 fixture: transport interop only, never authority proof.
func TestD101Ed25519SharedLfOriginalBytesGolden(t *testing.T) {
	wire, err := os.ReadFile("testdata/d101-ed25519-interop-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SchemaVersion         int
		PublicKeySpkiDerHex    string
		PublicKeySpkiDerSha256 string
		Vectors               []struct {
			Name, DomainHex, OriginalJsonHex, MessageHex, SignatureHex string
		}
	}
	if err := json.Unmarshal(wire, &fixture); err != nil || fixture.SchemaVersion != 1 || len(fixture.Vectors) != 2 {
		t.Fatal("invalid shared fixture")
	}
	decode := func(value string) []byte {
		t.Helper()
		result, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	der := decode(fixture.PublicKeySpkiDerHex)
	sum := sha256.Sum256(der)
	if hex.EncodeToString(sum[:]) != fixture.PublicKeySpkiDerSha256 || len(der) != 44 ||
		!bytes.Equal(der[:12], decode("302a300506032b6570032100")) {
		t.Fatal("original Ed25519 DER mismatch")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatal("fixture is not Ed25519")
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			domain, original := decode(vector.DomainHex), decode(vector.OriginalJsonHex)
			message, signature := decode(vector.MessageHex), decode(vector.SignatureHex)
			if domain[len(domain)-1] != '\n' || bytes.Count(domain, []byte{'\n'}) != 1 ||
				!bytes.Equal(append(append([]byte{}, domain...), original...), message) ||
				!ed25519.Verify(key, message, signature) {
				t.Fatal("LF/original bytes/shared signature mismatch")
			}
			for _, changed := range [][]byte{
				append(append([]byte{}, domain[:len(domain)-1]...), original...),
				append(append([]byte{}, domain...), append(original, '\n')...),
			} {
				if ed25519.Verify(key, changed, signature) {
					t.Fatal("changed wire accepted with original signature")
				}
			}
		})
	}
}
