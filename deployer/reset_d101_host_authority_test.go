package main

import (
	"context"
	"crypto/ed25519"
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

type resetD101HostFixture struct {
	pins      resetD101HostAuthorityPins
	uid       uint32
	now       time.Time
	originals map[string][]byte
	signing   ed25519.PrivateKey
}

func resetD101SignedHostFixture(t *testing.T, key ed25519.PrivateKey, domain string, original []byte) []byte {
	t.Helper()
	envelope := resetD101SignedHostOriginal{1, base64.RawURLEncoding.EncodeToString(original),
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), original...)))}
	wire, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func resetD101HostAuthorityFixture(t *testing.T) *resetD101HostFixture {
	t.Helper()
	keyPins, public := resetD101KeyFixture(t)
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	signing := ed25519.NewKeyFromSeed(seed) // Published RFC8032 TEST1 only.
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	originals := make(map[string][]byte)
	for _, id := range resetD101HostOriginalIDs {
		if id != "approvalIntent" && id != "deploymentCard" {
			originals[id] = []byte("SYNTHETIC_ONLY " + id)
		}
	}
	intent, cardWire := resetDeploymentCardFixture(t)
	i := intent.Intent
	i.ApprovalReceiptSHA = resetD101OriginalSHA(originals["approvalReceipt"])
	i.CombinedCIReceiptSHA = resetD101OriginalSHA(originals["combinedCiReceipt"])
	i.SelectedSourceReceiptSHA = resetD101OriginalSHA(originals["selectedSourceReceipt"])
	i.IsolatedSeedTickReceiptSHA = resetD101OriginalSHA(originals["isolatedSeedTickReceipt"])
	i.SpaceInventoryReceiptSHA = resetD101OriginalSHA(originals["spaceInventoryReceipt"])
	originals["approvalIntent"], _ = json.Marshal(i)
	intent, err = decodeResetApprovalIntent(originals["approvalIntent"], resetD101OriginalSHA(originals["approvalIntent"]))
	if err != nil {
		t.Fatal(err)
	}
	var card resetD101DeploymentCard
	if json.Unmarshal(cardWire, &card) != nil {
		t.Fatal("synthetic card")
	}
	card.ApprovalIntentSHA = intent.SHA
	card.ConfigInventorySHA = resetD101OriginalSHA(originals["configInventory"])
	card.CommandPlanSHA = resetD101OriginalSHA(originals["commandPlan"])
	card.RecoveryPlanSHA = resetD101OriginalSHA(originals["recoveryPlan"])
	card.ReaderBindingsSHA = resetD101OriginalSHA(originals["readerBindings"])
	card.EvidenceCatalogSHA = resetD101OriginalSHA(originals["evidenceCatalog"])
	card.ReviewBasisSHA = resetD101OriginalSHA(originals["reviewBasis"])
	originals["deploymentCard"], _ = json.Marshal(card)
	pins := resetD101HostAuthorityPins{
		OperationID: intent.Intent.OperationID, ApprovalIntentSHA: intent.SHA,
		RootPrivateOrigin: "http://deployer:8080", ApprovalAnchorSpki: spki,
		ApprovalAnchorSpkiSHA: resetD101OriginalSHA(spki), SigningKey: keyPins,
		OriginalDirectories: make(map[string]string),
	}
	manifest := resetD101HostTrustManifest{1, "D101_HOST_TRUST_V1", pins.OperationID, intent.SHA,
		resetD101OriginalSHA(originals["deploymentCard"]), resetD101OriginalSHA(originals["approvedReceiptProvenance"]),
		keyPins.KeyID, keyPins.PublicKeySpkiSHA, keyPins.EnvelopeSHA, pins.RootPrivateOrigin,
		intent.Intent.AppSourceSHA, card.DockerSourceSHA, intent.Intent.OldImageDigests, intent.Intent.NewImageDigests}
	manifestWire, _ := json.Marshal(manifest)
	pins.ManifestSHA = resetD101OriginalSHA(manifestWire)
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	clockWire, _ := json.Marshal(resetD101ClockAgreement{1, "D101_CLOCK_AGREEMENT_V1",
		pins.OperationID, intent.SHA, now.Unix(), now.Unix(), now.Unix() + 30})
	write := func(leaf string, wire []byte) string {
		dir := filepath.Join(root, leaf)
		if os.Mkdir(dir, 0700) != nil || os.WriteFile(filepath.Join(dir, pins.OperationID+".json"), wire, 0400) != nil {
			t.Fatal("synthetic private custody")
		}
		return dir
	}
	for id, wire := range originals {
		pins.OriginalDirectories[id] = write(id, wire)
	}
	pins.ManifestDirectory = write("manifest", resetD101SignedHostFixture(t, signing, resetD101HostTrustDomain, manifestWire))
	pins.ClockDirectory = write("clock", resetD101SignedHostFixture(t, signing, resetD101ClockAgreementDomain, clockWire))
	return &resetD101HostFixture{pins, uint32(os.Getuid()), now, originals, signing}
}

func TestResetD101HostAuthorityRequiresSeparateActualProducerAndFixedOrigin(t *testing.T) {
	f := resetD101HostAuthorityFixture(t)
	if source, err := newResetD101HostAuthorityWithUID(f.pins, nil, func() time.Time { return f.now }, f.uid); err == nil || source != nil {
		t.Fatal("raw custody/signature became semantic authority")
	}
	for _, origin := range []string{"https://example.com:443", "http://deployer", "http://deployer:99999", "http://deployer:80?", "http://user@deployer:80", "http://deployer:80/path", "http://deployer:80#", "http://deployer:80#fragment"} {
		pins := f.pins
		pins.RootPrivateOrigin = origin
		if source, err := newResetD101HostAuthorityWithUID(pins, func(context.Context, *resetD101HostEvidence) error { return nil }, func() time.Time { return f.now }, f.uid); err == nil || source != nil {
			t.Fatalf("unsafe fixed origin accepted: %s", origin)
		}
	}
}

func TestResetD101HostAuthorityKeepsFrozenPinsAndRechecksClockAfterProducer(t *testing.T) {
	f := resetD101HostAuthorityFixture(t)
	calls := 0
	drift := false
	source, err := newResetD101HostAuthorityWithUID(f.pins, func(ctx context.Context, e *resetD101HostEvidence) error {
		calls++
		wire, err := e.Original("selectedSourceReceipt")
		if err != nil || string(wire) != "SYNTHETIC_ONLY selectedSourceReceipt" {
			return errResetExecutionEvidence
		}
		wire[0] = 0 // Defensive copy; cannot alter provider's originals.
		if drift {
			f.now = f.now.Add(30 * time.Second)
		}
		return nil
	}, func() time.Time { return f.now }, f.uid)
	if err != nil {
		t.Fatal(err)
	}
	op, sha := f.pins.OperationID, f.pins.ApprovalIntentSHA
	f.pins.OriginalDirectories["approvalIntent"] = "/caller/replacement"
	f.pins.ApprovalAnchorSpki[0] = 0
	authority, err := source(context.Background(), op, sha)
	if err != nil || authority.Intent.SHA != sha || authority.KeyPins.KeyID != f.pins.SigningKey.KeyID || calls != 1 {
		t.Fatal("synthetic verified fixed source refused")
	}
	if _, err := source(context.Background(), strings.Repeat("f", 32), sha); err == nil || calls != 1 {
		t.Fatal("other operation reached producer")
	}
	drift = true
	if _, err := source(context.Background(), op, sha); err == nil || calls != 2 {
		t.Fatal("expired during actual producer callback")
	}
}

func TestResetD101HostAuthorityRejectsOriginalDriftAndCustodyBeforeProducer(t *testing.T) {
	for _, mode := range []string{"changed", "public", "symlink", "missing", "producer-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f := resetD101HostAuthorityFixture(t)
			path := filepath.Join(f.pins.OriginalDirectories["selectedSourceReceipt"], f.pins.OperationID+".json")
			switch mode {
			case "changed":
				if os.Chmod(path, 0600) != nil || os.WriteFile(path, []byte("changed"), 0400) != nil || os.Chmod(path, 0400) != nil {
					t.Fatal("fixture drift")
				}
			case "public":
				if os.Chmod(path, 0444) != nil {
					t.Fatal("fixture mode")
				}
			case "missing":
				if os.Remove(path) != nil {
					t.Fatal("fixture missing")
				}
			case "symlink":
				if os.Remove(path) != nil || os.Symlink(filepath.Join(f.pins.ClockDirectory, f.pins.OperationID+".json"), path) != nil {
					t.Fatal("fixture symlink")
				}
			}
			calls := 0
			source, err := newResetD101HostAuthorityWithUID(f.pins, func(context.Context, *resetD101HostEvidence) error { calls++; return errResetExecutionEvidence }, func() time.Time { return f.now }, f.uid)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source(context.Background(), f.pins.OperationID, f.pins.ApprovalIntentSHA); err == nil {
				t.Fatal("unavailable became authority")
			}
			if mode != "producer-unavailable" && calls != 0 {
				t.Fatal("invalid custody reached producer")
			}
			if mode == "producer-unavailable" && calls != 1 {
				t.Fatal("semantic verifier skipped")
			}
		})
	}
}
