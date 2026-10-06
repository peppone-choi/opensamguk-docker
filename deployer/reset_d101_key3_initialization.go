package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
)

// Private memory only. It is neither authenticated custody nor a signing role.
type resetD101UntrustedKey3Material struct {
	role, custodyID, keyID     string
	privateEnvelope, publicDER []byte
	envelopeSHA, publicSPKISHA string
}

func (m *resetD101UntrustedKey3Material) close() { clear(m.privateEnvelope); m.privateEnvelope = nil }

// This pure helper has no filesystem, signing, activation or operation API.
// Only public deterministic fixture entropy invokes it in this local scope.
// Future production must fix crypto/rand after actual authorization, complete
// conflict checks and durable once BEFORE invoking it. CLI/env/card cannot
// select entropy. Partial/unknown preserves receipts and material, no retries.
func prepareResetD101UntrustedKey3(entropy io.Reader) ([]resetD101UntrustedKey3Material, error) {
	if entropy == nil {
		return nil, errResetExecutionEvidence
	}
	out := make([]resetD101UntrustedKey3Material, 0, 3)
	failed := true
	defer func() {
		if failed {
			for i := range out {
				out[i].close()
			}
		}
	}()
	for _, role := range []string{"root-purpose", "approval-issuer", "approved-receipt-issuer"} {
		id := make([]byte, 16)
		if _, err := io.ReadFull(entropy, id); err != nil {
			clear(id)
			return nil, errResetExecutionEvidence
		}
		custody := hex.EncodeToString(id)
		clear(id)
		seed := make([]byte, ed25519.SeedSize)
		if _, err := io.ReadFull(entropy, seed); err != nil {
			clear(seed)
			return nil, errResetExecutionEvidence
		}
		key := ed25519.NewKeyFromSeed(seed)
		clear(seed)
		der, err := x509.MarshalPKCS8PrivateKey(key)
		public, pubErr := x509.MarshalPKIXPublicKey(key.Public())
		clear(key)
		if err != nil || pubErr != nil || len(der) != 48 || len(public) != 44 {
			clear(der)
			return nil, errResetExecutionEvidence
		}
		keyID := "d101-" + role + "-" + custody
		if !resetD101KeyID.MatchString(keyID) {
			clear(der)
			return nil, errResetExecutionEvidence
		}
		envelope := resetD101SigningKeyEnvelope{1, keyID, base64.RawURLEncoding.EncodeToString(der), resetD101OriginalSHA(public)}
		clear(der)
		wire, err := json.Marshal(envelope)
		envelope.PrivateKeyPkcs8Base64url = ""
		if err != nil {
			clear(wire)
			return nil, errResetExecutionEvidence
		}
		for _, prior := range out {
			if prior.custodyID == custody || prior.keyID == keyID || prior.publicSPKISHA == resetD101OriginalSHA(public) {
				clear(wire)
				return nil, errResetExecutionEvidence
			}
		}
		out = append(out, resetD101UntrustedKey3Material{role, custody, keyID, wire, public, resetD101OriginalSHA(wire), resetD101OriginalSHA(public)})
	}
	failed = false
	return out, nil
}

func runResetD101Key3Initialization(ctx context.Context, cardSHA string) int {
	if ctx == nil || ctx.Err() != nil || !resetEvidenceSHA.MatchString(cardSHA) {
		return 2
	}
	// Reader always denies until actual authentication and native once/writer
	// authorization are supplied. No entropy/namespace/FD9/DB call exists here.
	if readResetD101ReviewedKey3Ceremony(ctx, cardSHA) != nil {
		return 2
	}
	return 2
}
