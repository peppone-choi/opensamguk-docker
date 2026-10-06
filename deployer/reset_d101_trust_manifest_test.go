package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestResetD101SignedTrustCannotUseAnotherDomainOrModifiedOriginal(t *testing.T) {
	f := resetD101HostAuthorityFixture(t)
	anchor, err := resetD101PinnedPublicKey(f.pins.ApprovalAnchorSpki, f.pins.ApprovalAnchorSpkiSHA)
	if err != nil {
		t.Fatal(err)
	}
	wire := resetD101SignedHostFixture(t, f.signing, resetD101HostTrustDomain, []byte("{\"synthetic\":true}"))
	if _, err := decodeResetD101SignedHostOriginal(wire, resetD101HostTrustDomain, anchor); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeResetD101SignedHostOriginal(wire, resetD101ClockAgreementDomain, anchor); err == nil {
		t.Fatal("trust signature became clock evidence")
	}
	var envelope resetD101SignedHostOriginal
	_ = json.Unmarshal(wire, &envelope)
	envelope.OriginalBytesBase64url = "e30"
	changed, _ := json.Marshal(envelope)
	if _, err := decodeResetD101SignedHostOriginal(changed, resetD101HostTrustDomain, anchor); err == nil {
		t.Fatal("modified original accepted")
	}
	for _, bad := range [][]byte{append(wire, []byte("{}")...), []byte("{\"schemaVersion\":null}"), append([]byte("{\"schemaVersion\":1,"), wire[1:]...)} {
		if _, err := decodeResetD101SignedHostOriginal(bad, resetD101HostTrustDomain, anchor); err == nil {
			t.Fatal("non-exact envelope accepted")
		}
	}
}

func TestResetD101ClockAgreementRequiresBothClocksAndFreshCompletion(t *testing.T) {
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	base := resetD101ClockAgreement{1, "D101_CLOCK_AGREEMENT_V1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now.Unix(), now.Unix(), now.Unix() + 30}
	for _, mode := range []string{"fresh", "future-root", "future-gateway", "skew", "expired", "age-boundary", "other-op", "zero", "long-lease"} {
		t.Run(mode, func(t *testing.T) {
			receipt := base
			switch mode {
			case "future-root":
				receipt.RootObservedAtUnix++
			case "future-gateway":
				receipt.GatewayObservedAtUnix++
			case "skew":
				receipt.GatewayObservedAtUnix -= 2
			case "expired":
				receipt.ExpiresAtUnix = now.Unix()
			case "age-boundary":
				receipt.RootObservedAtUnix -= 30
				receipt.GatewayObservedAtUnix -= 30
			case "other-op":
				receipt.OperationID = "cccccccccccccccccccccccccccccccc"
			case "zero":
				receipt.RootObservedAtUnix = 0
			case "long-lease":
				receipt.ExpiresAtUnix++
			}
			wire, _ := json.Marshal(receipt)
			_, err := decodeResetD101ClockAgreement(wire, base.OperationID, base.ApprovalIntentSHA, now)
			if (err == nil) != (mode == "fresh") {
				t.Fatal("clock acceptance mismatch")
			}
		})
	}
}
