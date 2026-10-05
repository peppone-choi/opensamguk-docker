package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"reflect"
	"time"
	"unicode/utf8"
)

const resetD101HostTrustDomain = "OPENSAMGUK-D101-HOST-TRUST-V1\n"
const resetD101ClockAgreementDomain = "OPENSAMGUK-D101-CLOCK-AGREEMENT-V1\n"

// Host installation source material for the existing exact D120 card. Neither
// a transport request nor an enable flag can supply the independent anchor.
type resetD101HostTrustManifest struct {
	SchemaVersion                int               `json:"schemaVersion"`
	Kind                         string            `json:"kind"`
	OperationID                  string            `json:"operationId"`
	ApprovalIntentSHA            string            `json:"approvalIntentSha256"`
	DeploymentCardSHA            string            `json:"deploymentCardSha256"`
	ApprovedReceiptProvenanceSHA string            `json:"approvedReceiptProvenanceSha256"`
	KeyID                        string            `json:"keyId"`
	PublicKeySpkiSHA             string            `json:"publicKeySpkiSha256"`
	SigningKeyEnvelopeSHA        string            `json:"signingKeyEnvelopeSha256"`
	RootPrivateOrigin            string            `json:"rootPrivateOrigin"`
	AppSourceSHA                 string            `json:"appSourceSha"`
	DockerSourceSHA              string            `json:"dockerSourceSha"`
	OldImageDigests              map[string]string `json:"oldImageDigests"`
	NewImageDigests              map[string]string `json:"newImageDigests"`
}

type resetD101SignedHostOriginal struct {
	SchemaVersion          int    `json:"schemaVersion"`
	OriginalBytesBase64url string `json:"originalBytesBase64url"`
	SignatureBase64url     string `json:"signatureBase64url"`
}

type resetD101ClockAgreement struct {
	SchemaVersion         int    `json:"schemaVersion"`
	Kind                  string `json:"kind"`
	OperationID           string `json:"operationId"`
	ApprovalIntentSHA     string `json:"approvalIntentSha256"`
	RootObservedAtUnix    int64  `json:"rootObservedAtUnix"`
	GatewayObservedAtUnix int64  `json:"gatewayObservedAtUnix"`
	ExpiresAtUnix         int64  `json:"expiresAtUnix"`
}

// Strict original DER, no normalization or embedded/caller key adoption.
func resetD101PinnedPublicKey(der []byte, expectedSHA string) (ed25519.PublicKey, error) {
	if len(der) != 44 || !resetEvidenceSHA.MatchString(expectedSHA) || resetD101OriginalSHA(der) != expectedSHA ||
		!reflect.DeepEqual(der[:12], []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}) {
		return nil, errResetExecutionEvidence
	}
	value, err := x509.ParsePKIXPublicKey(der)
	key, ok := value.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize {
		return nil, errResetExecutionEvidence
	}
	return append(ed25519.PublicKey(nil), key...), nil
}

func decodeResetD101SignedHostOriginal(wire []byte, domain string, anchor ed25519.PublicKey) ([]byte, error) {
	var envelope resetD101SignedHostOriginal
	if len(wire) == 0 || len(wire) > resetEvidenceMaxBytes || !utf8.Valid(wire) ||
		len(anchor) != ed25519.PublicKeySize ||
		(domain != resetD101HostTrustDomain && domain != resetD101ClockAgreementDomain && domain != resetD101SelectedSourceDomain) ||
		requireResetIntentShape(wire, reflect.TypeOf(envelope)) != nil ||
		decodeResetPrivateJSON(wire, &envelope) != nil || envelope.SchemaVersion != 1 {
		return nil, errResetExecutionEvidence
	}
	limit := 32 * 1024
	if domain == resetD101SelectedSourceDomain {
		limit = 64 * 1024
	}
	original, err := base64.RawURLEncoding.Strict().DecodeString(envelope.OriginalBytesBase64url)
	signature, sigErr := base64.RawURLEncoding.Strict().DecodeString(envelope.SignatureBase64url)
	if err != nil || sigErr != nil || len(original) == 0 || len(original) > limit || !utf8.Valid(original) ||
		len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(original) != envelope.OriginalBytesBase64url ||
		base64.RawURLEncoding.EncodeToString(signature) != envelope.SignatureBase64url ||
		!ed25519.Verify(anchor, append([]byte(domain), original...), signature) {
		return nil, errResetExecutionEvidence
	}
	return original, nil
}

func decodeResetD101HostTrust(wire []byte, expectedSHA string, intent resetDecodedApprovalIntent,
	card resetDecodedDeploymentCard, origin string, keyPins resetD101SigningKeyPins) (resetD101HostTrustManifest, error) {
	var m resetD101HostTrustManifest
	if !resetEvidenceSHA.MatchString(expectedSHA) || resetD101OriginalSHA(wire) != expectedSHA ||
		requireResetIntentShape(wire, reflect.TypeOf(m)) != nil || decodeResetPrivateJSON(wire, &m) != nil ||
		m.SchemaVersion != 1 || m.Kind != "D101_HOST_TRUST_V1" || m.OperationID != intent.Intent.OperationID ||
		m.ApprovalIntentSHA != intent.SHA || m.DeploymentCardSHA != card.SHA ||
		!resetEvidenceSHA.MatchString(m.ApprovedReceiptProvenanceSHA) ||
		m.RootPrivateOrigin != origin || m.AppSourceSHA != intent.Intent.AppSourceSHA ||
		m.DockerSourceSHA != card.Card.DockerSourceSHA || m.KeyID != keyPins.KeyID ||
		m.PublicKeySpkiSHA != keyPins.PublicKeySpkiSHA || m.SigningKeyEnvelopeSHA != keyPins.EnvelopeSHA ||
		!reflect.DeepEqual(m.OldImageDigests, intent.Intent.OldImageDigests) ||
		!reflect.DeepEqual(m.NewImageDigests, intent.Intent.NewImageDigests) {
		return resetD101HostTrustManifest{}, errResetExecutionEvidence
	}
	return m, nil
}

func decodeResetD101ClockAgreement(wire []byte, op, intentSHA string, now time.Time) (time.Time, error) {
	var receipt resetD101ClockAgreement
	if requireResetIntentShape(wire, reflect.TypeOf(receipt)) != nil || decodeResetPrivateJSON(wire, &receipt) != nil ||
		receipt.SchemaVersion != 1 || receipt.Kind != "D101_CLOCK_AGREEMENT_V1" ||
		receipt.OperationID != op || receipt.ApprovalIntentSHA != intentSHA || now.Unix() <= 0 ||
		receipt.RootObservedAtUnix <= 0 || receipt.GatewayObservedAtUnix <= 0 {
		return time.Time{}, errResetExecutionEvidence
	}
	root := time.Unix(receipt.RootObservedAtUnix, 0)
	gateway := time.Unix(receipt.GatewayObservedAtUnix, 0)
	// Receipt freshness is bounded by the existing 30s preflight window.
	// Both observations must precede this actual reader's clock.
	if root.After(now) || gateway.After(now) || now.Sub(root) >= resetPreflightMaxAge ||
		now.Sub(gateway) >= resetPreflightMaxAge || root.Sub(gateway) > time.Second ||
		gateway.Sub(root) > time.Second || receipt.ExpiresAtUnix <= receipt.RootObservedAtUnix ||
		receipt.ExpiresAtUnix <= receipt.GatewayObservedAtUnix ||
		time.Unix(receipt.ExpiresAtUnix, 0).Sub(root) > resetPreflightMaxAge ||
		time.Unix(receipt.ExpiresAtUnix, 0).Sub(gateway) > resetPreflightMaxAge ||
		now.Unix() >= receipt.ExpiresAtUnix {
		return time.Time{}, errResetExecutionEvidence
	}
	if gateway.Before(root) {
		return gateway, nil
	}
	return root, nil
}
