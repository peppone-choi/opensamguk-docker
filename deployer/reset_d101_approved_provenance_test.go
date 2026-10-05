package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type resetD101ProvenanceFixture struct {
	host  *resetD101HostFixture
	pins  resetD101ApprovedReceiptPins
	value resetD101ApprovedReceiptProvenance
}

func resetD101ProvenanceReference(id string, wire []byte) resetD101FinalRawReference {
	return resetD101FinalRawReference{id, resetD101OriginalSHA(wire), uint64(len(wire)), "application/json"}
}
func replaceResetD101ProvenanceFixtureOriginal(t *testing.T, dir, op string, wire []byte) {
	t.Helper()
	path := filepath.Join(dir, op+".json")
	if _, err := os.Lstat(path); err == nil {
		if os.Remove(path) != nil {
			t.Fatal("fixture replace")
		}
	}
	if os.WriteFile(path, wire, 0400) != nil {
		t.Fatal("fixture write")
	}
}
func newResetD101ProvenanceFixture(t *testing.T) *resetD101ProvenanceFixture {
	t.Helper()
	h := resetD101HostAuthorityFixture(t)
	op := h.pins.OperationID
	paths := map[string]string{}
	for id, dir := range h.pins.OriginalDirectories {
		paths[id] = filepath.Join(dir, op+".json")
	}
	installation := resetD101ProvenanceReaderInstallation{1, "D101_NATIVE_READER_BINDINGS_V1", filepath.Join(h.pins.ManifestDirectory, op+".json"), filepath.Join(h.pins.ClockDirectory, op+".json"), paths, filepath.Join(h.pins.ClockDirectory, "synthetic-token.json"), filepath.Join(h.pins.ClockDirectory, "synthetic-selected.json")}
	installationWire, _ := json.Marshal(installation)
	h.originals["readerBindings"] = installationWire
	replaceResetD101ProvenanceFixtureOriginal(t, h.pins.OriginalDirectories["readerBindings"], op, installationWire)
	var card resetD101DeploymentCard
	if json.Unmarshal(h.originals["deploymentCard"], &card) != nil {
		t.Fatal("fixture card")
	}
	card.ReaderBindingsSHA = resetD101OriginalSHA(installationWire)
	h.originals["deploymentCard"], _ = json.Marshal(card)
	replaceResetD101ProvenanceFixtureOriginal(t, h.pins.OriginalDirectories["deploymentCard"], op, h.originals["deploymentCard"])
	intent, err := decodeResetApprovalIntent(h.originals["approvalIntent"], h.pins.ApprovalIntentSHA)
	if err != nil {
		t.Fatal(err)
	}
	pins := resetD101ApprovedReceiptPins{OperationID: op, ApprovalIntentSHA: intent.SHA, DeploymentCardSHA: resetD101OriginalSHA(h.originals["deploymentCard"]), IssuerID: "synthetic-independent-issuer", IssuerSourceSHA: strings.Repeat("a", 40), IssuerSPKI: h.pins.ApprovalAnchorSpki, IssuerSPKISHA: h.pins.ApprovalAnchorSpkiSHA, InstallerID: "synthetic-fixed-installer", InstallerSourceSHA: strings.Repeat("b", 40), ReaderInstallationSHA: resetD101OriginalSHA(installationWire), AllowedPurposes: []string{"PREPARE", "QUERY", "DISPATCH_INTENT", "SETTLE_REGISTRY", "RECOVERY_BEGIN", "RECOVERY_CLOSE"}, OriginalDirectories: h.pins.OriginalDirectories, AuxiliaryDirectories: map[string]string{}, RootKey: h.pins.SigningKey}
	root := filepath.Dir(h.pins.OriginalDirectories["readerBindings"])
	writeAux := func(id string, value any) []byte {
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, "aux-"+id)
		if os.Mkdir(dir, 0700) != nil {
			t.Fatal("fixture aux")
		}
		pins.AuxiliaryDirectories[id] = dir
		replaceResetD101ProvenanceFixtureOriginal(t, dir, op, wire)
		return wire
	}
	custody := writeAux("nativeCustody", resetD101ApprovedReceiptNativeCustody{1, "D101_APPROVED_RECEIPT_NATIVE_CUSTODY_V1", op, pins.RootKey.KeyID, pins.RootKey.EnvelopeSHA, pins.RootKey.PublicKeySpkiSHA, pins.ReaderInstallationSHA, 0, "0400", 1})
	installer := writeAux("installerIdentity", resetD101ApprovedReceiptInstallerIdentity{1, "D101_APPROVED_RECEIPT_INSTALLER_IDENTITY_V1", op, pins.InstallerID, pins.InstallerSourceSHA, intent.Intent.AppSourceSHA, card.DockerSourceSHA, resetD101NativeReaderInstallationPath, pins.ReaderInstallationSHA, pins.RootKey.KeyID, pins.RootKey.PublicKeySpkiSHA})
	pins.AuxiliaryDirectories["scopeAttestation"] = filepath.Join(root, "aux-scopeAttestation")
	if os.Mkdir(pins.AuxiliaryDirectories["scopeAttestation"], 0700) != nil {
		t.Fatal("fixture attestation")
	}
	i := intent.Intent
	scope := resetD101FinalOriginalScope{op, "pep", 1, i.TargetFingerprint, resetD101ProvenanceReference("raw:typed-target", intent.targetBytes()), i.AppSourceSHA, card.DockerSourceSHA, i.OldImageDigests, i.NewImageDigests, i.InitialPublicRevision, resetD101FinalScopeWindow{i.WindowOpensAtUnix, i.DestructiveCutoffUnix, i.RecoveryDeadlineUnix}, i.SpaceBudget}
	bindings := map[string]resetD101FinalRawReference{}
	for id, wire := range h.originals {
		if id != "approvedReceiptProvenance" {
			bindings[id] = resetD101ProvenanceReference(id, wire)
		}
	}
	issued := h.now.Unix() - 1
	if issued >= i.DestructiveCutoffUnix {
		issued = i.WindowOpensAtUnix
	}
	value := resetD101ApprovedReceiptProvenance{1, "D101_APPROVED_RECEIPT_PROVENANCE_V1", scope, "FIXED_APPROVED_RECEIPT_ISSUER", resetD101FinalIssuer{"APPROVED_RECEIPT_ISSUER", "FIXED_INSTALLED_ISSUER", pins.IssuerID, pins.IssuerSourceSHA, pins.IssuerSPKISHA, resetD101FinalRawReference{}, resetD101ProvenanceReference("raw:approved-receipt-native-custody", custody)}, issued, pins.AllowedPurposes, pins.InstallerSourceSHA, resetD101ProvenanceReference("raw:approved-receipt-installer-identity", installer), bindings}
	f := &resetD101ProvenanceFixture{h, pins, value}
	f.resign(t, resetD101ApprovedReceiptAttestationDomain)
	return f
}
func (f *resetD101ProvenanceFixture) resign(t *testing.T, domain string) {
	t.Helper()
	v := f.value
	attest := resetD101ApprovedReceiptAttestation{1, "D101_APPROVED_RECEIPT_SCOPE_ATTESTATION_V1", v.Issuer.IssuerID, v.Issuer.IssuerSourceSHA, v.Scope, v.IssuedAtUnix, v.AllowedPurposes, v.InstallerSourceSHA, v.InstallerIdentityRef, v.Issuer.NativeCustodyRef, v.OriginalBindings}
	raw, _ := json.MarshalIndent(attest, "", " ")
	signed := resetD101SignedHostFixture(t, f.host.signing, domain, raw)
	replaceResetD101ProvenanceFixtureOriginal(t, f.pins.AuxiliaryDirectories["scopeAttestation"], f.pins.OperationID, signed)
	f.value.Issuer.ScopeAttestationRef = resetD101ProvenanceReference("raw:approved-receipt-scope-attestation", signed)
	wire, _ := json.MarshalIndent(f.value, "", " ")
	f.pins.ProvenanceSHA = resetD101OriginalSHA(wire)
	f.host.originals["approvedReceiptProvenance"] = wire
	replaceResetD101ProvenanceFixtureOriginal(t, f.pins.OriginalDirectories["approvedReceiptProvenance"], f.pins.OperationID, wire)
}
func (f *resetD101ProvenanceFixture) readInstallation() ([]byte, error) {
	return readResetPrivateCustody(f.pins.OriginalDirectories["readerBindings"], f.pins.OperationID, f.host.uid)
}
func (f *resetD101ProvenanceFixture) verify(ctx context.Context, e *resetD101HostEvidence) error {
	if ctx.Err() != nil || len(e.originals) != 13 {
		return errResetExecutionEvidence
	}
	if _, err := e.Original("approvedReceiptProvenance"); err == nil {
		return errResetExecutionEvidence
	}
	for id, original := range f.host.originals {
		if id != "approvedReceiptProvenance" {
			raw, err := e.Original(id)
			if err != nil || !bytes.Equal(raw, original) {
				return errResetExecutionEvidence
			}
		}
	}
	return nil
}

func TestApprovedReceiptProvenanceUsesFixedIssuerActualKeyAndOriginal13(t *testing.T) {
	f := newResetD101ProvenanceFixture(t)
	wire, err := verifyResetD101ApprovedReceiptProvenanceWithSources(context.Background(), f.pins, f.verify, func() time.Time { return f.host.now }, f.host.uid, f.readInstallation)
	if err != nil || !bytes.Equal(wire, f.host.originals["approvedReceiptProvenance"]) {
		t.Fatal("synthetic native lineage refused", err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(wire, &fields) != nil || len(fields) != 10 {
		t.Fatal("final provenance10 changed")
	}
	key, err := readResetD101SigningKeyWithUID(f.pins.RootKey, f.host.uid)
	if err != nil {
		t.Fatal(err)
	}
	defer key.close()
	if signature, err := key.sign(resetD101ApprovedReceiptAttestationDomain, []byte("synthetic issuer request")); err == nil || signature != nil {
		t.Fatal("purpose key minted approval issuer attestation")
	}
}

func TestApprovedReceiptProvenanceRejectsSignedScopeExpansionOrMissingNativeSource(t *testing.T) {
	for _, mode := range []string{"verifier", "source", "root-key", "scope", "budget", "purposes", "self-binding", "other-issuer", "future-issued", "domain", "fixed-installation"} {
		t.Run(mode, func(t *testing.T) {
			f := newResetD101ProvenanceFixture(t)
			var verify resetD101ProvenanceUpstreamVerifier = f.verify
			reader := f.readInstallation
			switch mode {
			case "verifier":
				verify = nil
			case "source":
				delete(f.pins.OriginalDirectories, "reviewBasis")
			case "root-key":
				f.pins.RootKey.EnvelopeSHA = strings.Repeat("f", 64)
			case "scope":
				f.value.Scope.TargetFingerprint = strings.Repeat("f", 64)
			case "budget":
				f.value.Scope.SpaceBudget.RecoveryBytes = resetBudgetNumber(0)
			case "purposes":
				f.value.AllowedPurposes = []string{"PREPARE", "DEPLOY"}
			case "self-binding":
				f.value.OriginalBindings["approvedReceiptProvenance"] = resetD101ProvenanceReference("approvedReceiptProvenance", []byte("self"))
			case "other-issuer":
				f.value.Issuer.IssuerID = "different-issuer"
			case "future-issued":
				f.value.IssuedAtUnix = f.host.now.Add(time.Hour).Unix()
			case "fixed-installation":
				reader = func() ([]byte, error) { return []byte("different installation"), nil }
			}
			domain := resetD101ApprovedReceiptAttestationDomain
			if mode == "domain" {
				domain = resetD101HostTrustDomain
			}
			f.resign(t, domain)
			wire, err := verifyResetD101ApprovedReceiptProvenanceWithSources(context.Background(), f.pins, verify, func() time.Time { return f.host.now }, f.host.uid, reader)
			if err == nil || wire != nil {
				t.Fatal("unapproved native lineage released")
			}
		})
	}
}

func TestApprovedReceiptProvenanceRechecksNativeBytesAndClockAfterVerifier(t *testing.T) {
	for _, mode := range []string{"upstream-drift", "proof-drift", "key-drift", "clock", "installation-drift"} {
		t.Run(mode, func(t *testing.T) {
			f := newResetD101ProvenanceFixture(t)
			now := f.host.now
			installReads := 0
			verify := func(ctx context.Context, e *resetD101HostEvidence) error {
				if err := f.verify(ctx, e); err != nil {
					return err
				}
				switch mode {
				case "upstream-drift":
					replaceResetD101ProvenanceFixtureOriginal(t, f.pins.OriginalDirectories["reviewBasis"], f.pins.OperationID, []byte("different source"))
				case "proof-drift":
					replaceResetD101ProvenanceFixtureOriginal(t, f.pins.AuxiliaryDirectories["nativeCustody"], f.pins.OperationID, []byte("different proof"))
				case "key-drift":
					replaceResetD101ProvenanceFixtureOriginal(t, f.pins.RootKey.Directory, f.pins.RootKey.CustodyID, []byte("different key fixture"))
				case "clock":
					now = now.Add(30 * time.Second)
				}
				return nil
			}
			reader := func() ([]byte, error) {
				installReads++
				if mode == "installation-drift" && installReads > 1 {
					return []byte("drift"), nil
				}
				return f.readInstallation()
			}
			wire, err := verifyResetD101ApprovedReceiptProvenanceWithSources(context.Background(), f.pins, verify, func() time.Time { return now }, f.host.uid, reader)
			if err == nil || wire != nil {
				t.Fatal("drifted source released")
			}
		})
	}
}
