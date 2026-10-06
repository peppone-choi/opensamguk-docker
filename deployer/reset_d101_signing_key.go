package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"time"

	"opensamguk-deployer/internal/d101native"
)

// The installation card supplies these pins and a fixed root-private directory.
// No request, env toggle, JWT or shared service token can select a signing key.
// This custody reader is not the approval/provenance authority.
type resetD101SigningKeyPins struct {
	Directory        string
	CustodyID        string
	EnvelopeSHA      string
	KeyID            string
	PublicKeySpkiSHA string
}

type resetD101SigningKeyEnvelope struct {
	SchemaVersion            int    `json:"schemaVersion"`
	KeyID                    string `json:"keyId"`
	PrivateKeyPkcs8Base64url string `json:"privateKeyPkcs8Base64url"`
	PublicKeySpkiSHA         string `json:"publicKeySpkiSha256"`
}

type resetD101SigningKey struct {
	keyID            string
	publicKeySpkiSHA string
	private          ed25519.PrivateKey
}

func readResetD101SigningKey(pins resetD101SigningKeyPins) (resetD101SigningKey, error) {
	return readResetD101SigningKeyWithUID(pins, 0)
}

// Only synthetic isolated file tests may supply another UID.
func readResetD101SigningKeyWithUID(pins resetD101SigningKeyPins, uid uint32) (resetD101SigningKey, error) {
	empty := resetD101SigningKey{}
	if !resetD101KeyID.MatchString(pins.KeyID) || !resetEvidenceSHA.MatchString(pins.EnvelopeSHA) ||
		!resetEvidenceSHA.MatchString(pins.PublicKeySpkiSHA) {
		return empty, errResetExecutionEvidence
	}
	wire, err := readResetPrivateCustody(pins.Directory, pins.CustodyID, uid)
	if err != nil {
		return empty, errResetExecutionEvidence
	}
	defer clear(wire)
	sum := sha256.Sum256(wire)
	var envelope resetD101SigningKeyEnvelope
	if hex.EncodeToString(sum[:]) != pins.EnvelopeSHA || requireResetIntentShape(wire, reflect.TypeOf(envelope)) != nil ||
		decodeResetPrivateJSON(wire, &envelope) != nil || envelope.SchemaVersion != 1 || envelope.KeyID != pins.KeyID ||
		envelope.PublicKeySpkiSHA != pins.PublicKeySpkiSHA {
		return empty, errResetExecutionEvidence
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(envelope.PrivateKeyPkcs8Base64url)
	if err != nil || len(der) != 48 || base64.RawURLEncoding.EncodeToString(der) != envelope.PrivateKeyPkcs8Base64url {
		return empty, errResetExecutionEvidence
	}
	defer clear(der)
	// RFC8410 Ed25519 PKCS8 v0, absent parameters, exactly one 32-byte seed.
	if !bytes.Equal(der[:16], []byte{0x30, 0x2e, 0x02, 0x01, 0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20}) {
		return empty, errResetExecutionEvidence
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(key) != ed25519.PrivateKeySize {
		return empty, errResetExecutionEvidence
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		clear(key)
		return empty, errResetExecutionEvidence
	}
	publicSum := sha256.Sum256(spki)
	if hex.EncodeToString(publicSum[:]) != pins.PublicKeySpkiSHA {
		clear(key)
		return empty, errResetExecutionEvidence
	}
	return resetD101SigningKey{pins.KeyID, pins.PublicKeySpkiSHA, key}, nil
}

func (key *resetD101SigningKey) close() { clear(key.private); key.private = nil }

// PREPARED has a separate typed route. Generic domain/raw signing remains
// closed to it, and this transfer type does not create purpose authority.
func (key *resetD101SigningKey) signPrepared(ctx context.Context, input *resetD101PreparedSigningInput) ([]byte, error) {
	now := time.Now()
	if key == nil || ctx == nil || ctx.Err() != nil || input == nil ||
		len(key.private) != ed25519.PrivateKeySize || !resetD101KeyID.MatchString(key.keyID) ||
		key.keyID != input.authority.KeyPins.KeyID || key.publicKeySpkiSHA != input.authority.KeyPins.PublicKeySpkiSHA ||
		!resetEvidenceSHA.MatchString(input.authority.KeyPins.EnvelopeSHA) || !resetEvidenceSHA.MatchString(input.originalSHA) ||
		resetD101OriginalSHA(input.original) != input.originalSHA || input.validatedAt.IsZero() ||
		input.validatedAt.After(now) || now.Sub(input.validatedAt) >= resetPreflightMaxAge {
		return nil, errResetExecutionEvidence
	}
	spki, spkiErr := x509.MarshalPKIXPublicKey(key.private.Public())
	if spkiErr != nil || resetD101OriginalSHA(spki) != input.authority.KeyPins.PublicKeySpkiSHA {
		return nil, errResetExecutionEvidence
	}
	proof, err := decodeResetD101PreparedProof(input.original)
	prepared, timeErr := resetC4UTC(proof.PreparedAtUTC)
	intent, authorityErr := requireResetD101Authority(input.authority, input.request, now)
	if err != nil || timeErr != nil || authorityErr != nil || !reflect.DeepEqual(proof, input.proof) ||
		prepared.After(now) || now.Sub(prepared) >= resetPreflightMaxAge || now.Unix() >= proof.DestructiveCutoffUnix ||
		input.request.Action != "DISPATCH_INTENT" ||
		requireResetD101PreparedBinding(proof, input.chain, intent, input.evidence, input.record, now) != nil {
		return nil, errResetExecutionEvidence
	}
	message := append([]byte("OPENSAMGUK-D101-PREPARED-V1\n"), input.original...)
	signature := ed25519.Sign(key.private, message)
	after := time.Now()
	if ctx.Err() != nil || after.Before(now) || after.Sub(prepared) >= resetPreflightMaxAge ||
		after.Unix() >= proof.DestructiveCutoffUnix {
		clear(signature)
		return nil, errResetExecutionEvidence
	}
	return signature, nil
}

func (key *resetD101SigningKey) sign(domain string, original []byte) ([]byte, error) {
	if len(key.private) != ed25519.PrivateKeySize || !resetD101KeyID.MatchString(key.keyID) ||
		(domain != "OPENSAMGUK-D101-GRANT-V1\n" && domain != "OPENSAMGUK-D101-RESULT-V1\n" && domain != resetD101RecoveryResultDomain && domain != resetD101SelectedSourceDomain) {
		return nil, errResetExecutionEvidence
	}
	message := append([]byte(domain), original...)
	return ed25519.Sign(key.private, message), nil
}

// Private typed native route. This does not add to sign(domain,raw)'s whitelist.
func (key *resetD101SigningKey) signNativeAuthority(ctx context.Context, input *resetD101NativeSigningInput) ([]byte, error) {
	if key == nil || ctx == nil || ctx.Err() != nil || input == nil || input.auth == nil || d101native.Missing(input.source) || input.descriptor == nil || input.descriptor.Fd() != 9 || len(key.private) != ed25519.PrivateKeySize {
		return nil, errResetExecutionEvidence
	}
	a := input.auth
	record := nativeResetD101RecordForSigning(a.original)
	h, ok := d101native.HeaderOf(record)
	if pub, isPublic := record.(*d101native.RelaySessionBinding); isPublic {
		ok = pub.OperationID == a.binding.OperationID && pub.TargetFingerprint == a.binding.TargetFingerprint && pub.PublicationRevision == a.binding.PublicationRevision && pub.OriginalCutoffUnix == a.binding.OriginalCutoffUnix && pub.KeeperProcess == a.binding.Keeper.Process && pub.KeeperBirthNonce == a.binding.Keeper.BirthNonce
		h.Binding = a.binding
	}
	if !ok || h.Binding != a.binding || a.binding.IssuerSPKISHA256 != key.publicKeySpkiSHA || key.keyID != a.keyPins.KeyID || key.publicKeySpkiSHA != a.keyPins.PublicKeySpkiSHA || !d101native.ValidRef(a.purposeOriginal) || time.Now().Unix() >= a.binding.OriginalCutoffUnix || input.source.RecheckNativeSigning(ctx, input.descriptor, a) != nil {
		return nil, errResetExecutionEvidence
	}
	preimage := append([]byte(d101native.NativeAuthorityDomain), a.original...)
	defer clear(preimage)
	signature := ed25519.Sign(key.private, preimage)
	defer clear(signature)
	wire, err := d101native.EncodeEnvelope(a.original, key.keyID, signature)
	if err != nil || input.source.RecheckNativeSigning(ctx, input.descriptor, a) != nil || ctx.Err() != nil || time.Now().Unix() >= a.binding.OriginalCutoffUnix {
		return nil, errResetExecutionEvidence
	}
	return wire, nil
}
