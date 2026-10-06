package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"opensamguk-deployer/internal/d101custody"
	et "opensamguk-deployer/internal/d101evidencetransport"
	"opensamguk-deployer/internal/d101origin"
	"strings"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101operatorauth"
)

// Pure fixture projections never construct CurrentOperator/TechnicalIssuance,
// install a supplier, authenticate a human, or call a native signer.
func resetD101SemanticReceiptFixture(t *testing.T) (resetD101IssuerSemanticFacts, resetD101IssuerSemanticSnapshot) {
	t.Helper()
	p := newResetD101ProvenanceFixture(t)
	receiptKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{73}, ed25519.SeedSize))
	spki, err := x509.MarshalPKIXPublicKey(receiptKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	p.pins.IssuerSPKI = spki
	p.pins.IssuerSPKISHA = resetD101OriginalSHA(spki)
	v := p.value
	issued := time.Unix(v.IssuedAtUnix, 0).UTC()
	f := resetD101IssuerSemanticFacts{scope: d101operatorauth.TechnicalScope{OperationID: v.Scope.OperationID, AppSourceSHA: v.Scope.AppSourceSHA, DockerSourceSHA: v.Scope.DockerSourceSHA}, issued: issued,
		approval: d101operatorauth.IssuerPins{Role: d101operatorauth.ApprovalIssuerRole, PublicKeySPKISHA256: strings.Repeat("e", 64)},
		receipt:  d101operatorauth.IssuerPins{Role: d101operatorauth.ApprovedReceiptIssuerRole, Identity: p.pins.IssuerID, SourceSHA: p.pins.IssuerSourceSHA, PublicKeySPKI: spki, PublicKeySPKISHA256: p.pins.IssuerSPKISHA}}
	a := resetD101ApprovedReceiptAttestation{1, "D101_APPROVED_RECEIPT_SCOPE_ATTESTATION_V1", v.Issuer.IssuerID, v.Issuer.IssuerSourceSHA, v.Scope, v.IssuedAtUnix, v.AllowedPurposes, v.InstallerSourceSHA, v.InstallerIdentityRef, v.Issuer.NativeCustodyRef, v.OriginalBindings}
	s := resetD101IssuerSemanticSnapshot{Receipt: a, ReceiptPins: p.pins, Original13: map[string][]byte{}}
	for id, original := range p.host.originals {
		if id != "approvedReceiptProvenance" {
			s.Original13[id] = bytes.Clone(original)
		}
	}
	s.NativeCustody, _ = readResetPrivateCustody(p.pins.AuxiliaryDirectories["nativeCustody"], p.pins.OperationID, p.host.uid)
	s.InstallerIdentity, _ = readResetPrivateCustody(p.pins.AuxiliaryDirectories["installerIdentity"], p.pins.OperationID, p.host.uid)
	if validateResetD101ReceiptUnsigned(f, s) != nil {
		t.Fatal("valid synthetic receipt projection refused")
	}
	return f, s
}

func TestIssuerSemanticReceiptExactOriginalsScopeAndTime(t *testing.T) {
	f, s := resetD101SemanticReceiptFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*resetD101IssuerSemanticFacts, *resetD101IssuerSemanticSnapshot)
	}{
		{"original wholebytes", func(_ *resetD101IssuerSemanticFacts, s *resetD101IssuerSemanticSnapshot) {
			s.Original13["reviewBasis"] = append(s.Original13["reviewBasis"], byte('x'))
		}},
		{"reference length", func(_ *resetD101IssuerSemanticFacts, s *resetD101IssuerSemanticSnapshot) {
			r := s.Receipt.OriginalBindings["reviewBasis"]
			r.ByteLength++
			s.Receipt.OriginalBindings["reviewBasis"] = r
		}},
		{"reference media", func(_ *resetD101IssuerSemanticFacts, s *resetD101IssuerSemanticSnapshot) {
			r := s.Receipt.OriginalBindings["reviewBasis"]
			r.MediaType = "text/plain"
			s.Receipt.OriginalBindings["reviewBasis"] = r
		}},
		{"scope image", func(_ *resetD101IssuerSemanticFacts, s *resetD101IssuerSemanticSnapshot) {
			s.Receipt.Scope.NewImageDigests["api"] = "sha256:" + strings.Repeat("b", 64)
		}},
		{"scope target ref", func(_ *resetD101IssuerSemanticFacts, s *resetD101IssuerSemanticSnapshot) {
			s.Receipt.Scope.TypedTargetRef.ByteLength++
		}},
		{"historical issuer time substitution", func(_ *resetD101IssuerSemanticFacts, s *resetD101IssuerSemanticSnapshot) { s.Receipt.IssuedAtUnix-- }},
		{"self provenance in upstream13", func(_ *resetD101IssuerSemanticFacts, s *resetD101IssuerSemanticSnapshot) {
			delete(s.Original13, "reviewBasis")
			s.Original13["approvedReceiptProvenance"] = []byte(`{}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy, err := freezeResetD101IssuerSemanticSnapshot(s)
			if err != nil {
				t.Fatal(err)
			}
			facts := f
			tc.mutate(&facts, &copy)
			if validateResetD101ReceiptUnsigned(facts, copy) == nil {
				t.Fatal("unapproved original/scope/time accepted")
			}
		})
	}
}

func TestIssuerSemanticReceiptPurposesRemainActualApprovedPins(t *testing.T) {
	f, s := resetD101SemanticReceiptFixture(t)
	// Both lists below are valid enum lists. Enum validity cannot authorize a
	// different set or order than the exact independently approved installed pins.
	s.Receipt.AllowedPurposes = []string{"QUERY"}
	if validateResetD101ReceiptUnsigned(f, s) == nil {
		t.Fatal("valid enum replaced actual approved purpose pins")
	}
}

func TestIssuerSemanticReceiptNativeInstallerAndRoleKeyBindings(t *testing.T) {
	f, s := resetD101SemanticReceiptFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*resetD101IssuerSemanticFacts, *resetD101IssuerSemanticSnapshot)
	}{
		{"root purpose as receipt key", func(f *resetD101IssuerSemanticFacts, s *resetD101IssuerSemanticSnapshot) {
			f.receipt.PublicKeySPKISHA256 = s.ReceiptPins.RootKey.PublicKeySpkiSHA
			s.ReceiptPins.IssuerSPKISHA = f.receipt.PublicKeySPKISHA256
		}},
		{"shared role keys", func(f *resetD101IssuerSemanticFacts, _ *resetD101IssuerSemanticSnapshot) {
			f.approval.PublicKeySPKISHA256 = f.receipt.PublicKeySPKISHA256
		}},
		{"native link count", func(_ *resetD101IssuerSemanticFacts, s *resetD101IssuerSemanticSnapshot) {
			var v resetD101ApprovedReceiptNativeCustody
			json.Unmarshal(s.NativeCustody, &v)
			v.LinkCount = 2
			s.NativeCustody, _ = json.Marshal(v)
			s.Receipt.NativeCustodyRef = resetD101ProvenanceReference("raw:approved-receipt-native-custody", s.NativeCustody)
		}},
		{"installer source", func(_ *resetD101IssuerSemanticFacts, s *resetD101IssuerSemanticSnapshot) {
			var v resetD101ApprovedReceiptInstallerIdentity
			json.Unmarshal(s.InstallerIdentity, &v)
			v.InstallerSourceSHA = strings.Repeat("c", 40)
			s.InstallerIdentity, _ = json.Marshal(v)
			s.Receipt.InstallerIdentityRef = resetD101ProvenanceReference("raw:approved-receipt-installer-identity", s.InstallerIdentity)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy, err := freezeResetD101IssuerSemanticSnapshot(s)
			if err != nil {
				t.Fatal(err)
			}
			facts := f
			tc.mutate(&facts, &copy)
			if validateResetD101ReceiptUnsigned(facts, copy) == nil {
				t.Fatal("native/installer/role binding drift accepted")
			}
		})
	}
}

type resetD101CountingSemanticSource struct{ captures, rechecks int }

func (s *resetD101CountingSemanticSource) CaptureAuthenticatedUnsigned(context.Context, d101operatorauth.TechnicalIssuance) (resetD101IssuerSemanticSnapshot, error) {
	s.captures++
	return resetD101IssuerSemanticSnapshot{}, nil
}
func (s *resetD101CountingSemanticSource) RecheckAuthenticatedUnsigned(context.Context, d101operatorauth.TechnicalIssuance, resetD101IssuerSemanticSnapshot) error {
	s.rechecks++
	return nil
}
func TestIssuerSemanticMissingOpaqueCurrentEventNeverCapturesOrReturnsPartialBatch(t *testing.T) {
	source := &resetD101CountingSemanticSource{}
	b, err := newResetD101IssuerUnsignedBatch(context.Background(), d101operatorauth.TechnicalIssuance{}, source)
	if err == nil || source.captures != 0 || source.rechecks != 0 || len(b.ApprovalPayload()) != 0 || len(b.ReceiptAttestation()) != 0 {
		t.Fatal("zero opaque event supplied unsigned authority")
	}
	var typedNil *resetD101CountingSemanticSource
	if _, err := newResetD101IssuerUnsignedBatch(context.Background(), d101operatorauth.TechnicalIssuance{}, typedNil); err == nil {
		t.Fatal("typed nil supplier accepted")
	}
	if value, err := b.ProvenanceAfterRetainedAttestation(context.Background(), []byte(`{}`)); err == nil || len(value) != 0 {
		t.Fatal("partial batch produced provenance")
	}
}

func TestIssuerSemanticSnapshotAndUnsignedGettersDefendMutableAliases(t *testing.T) {
	_, s := resetD101SemanticReceiptFixture(t)
	s.FinalCard = []byte("synthetic-card")
	s.DecisionParents[0] = []byte("synthetic-parent")
	frozen, err := freezeResetD101IssuerSemanticSnapshot(s)
	if err != nil {
		t.Fatal(err)
	}
	s.FinalCard[0] = 'x'
	s.DecisionParents[0][0] = 'x'
	s.Original13["reviewBasis"][0] = 'x'
	s.Receipt.AllowedPurposes[0] = "QUERY"
	if string(frozen.FinalCard) != "synthetic-card" || string(frozen.DecisionParents[0]) != "synthetic-parent" || bytes.Equal(s.Original13["reviewBasis"], frozen.Original13["reviewBasis"]) || s.Receipt.AllowedPurposes[0] == frozen.Receipt.AllowedPurposes[0] {
		t.Fatal("caller alias changed frozen originals")
	}
	b := resetD101IssuerUnsignedBatch{approvalPayload: []byte("synthetic-approval"), receiptAttestation: []byte("synthetic-receipt")}
	b.ApprovalPayload()[0] = 'x'
	b.ReceiptAttestation()[0] = 'x'
	if string(b.ApprovalPayload()) != "synthetic-approval" || string(b.ReceiptAttestation()) != "synthetic-receipt" {
		t.Fatal("unsigned getter leaked mutable alias")
	}
}

func resetD101SemanticBothFixture(t *testing.T) (resetD101IssuerSemanticFacts, resetD101IssuerSemanticSnapshot) {
	t.Helper()
	f, s := resetD101SemanticReceiptFixture(t)
	marshal := func(v any) []byte {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	ref := func(id string, b []byte) et.RawReference {
		return et.RawReference{LogicalID: "raw:" + id, SHA256: resetD101OriginalSHA(b), ByteLength: uint64(len(b)), MediaType: "application/json"}
	}
	technical := func(r et.RawReference) d101operatorauth.Reference {
		return d101operatorauth.Reference{LogicalID: r.LogicalID, SHA256: r.SHA256, ByteLength: r.ByteLength, MediaType: r.MediaType}
	}
	s.ScopeOriginal = []byte(`{"synthetic":"approved scope"}`)
	s.FinalCard = []byte(`{"synthetic":"approved final card"}`)
	s.DecisionSlices = []byte(`["synthetic approved slices"]`)
	f.scope.ScopeOriginal = technical(ref("approved-scope", s.ScopeOriginal))
	f.scope.FinalCard = technical(ref("final-card", s.FinalCard))
	f.scope.DecisionSlicesSHA256 = resetD101OriginalSHA(s.DecisionSlices)
	for i := range s.DecisionParents {
		s.DecisionParents[i] = marshal(map[string]any{"synthetic-parent": i})
		f.scope.DecisionParents[i] = technical(ref("parent-"+string(rune('a'+i)), s.DecisionParents[i]))
	}
	f.event = d101operatorauth.IssuanceEvent{ActorID: "123", RunID: "456", JTI: "synthetic-current-jti", RunAttempt: 1, WorkflowSHA: strings.Repeat("d", 40), ScopeDecisionOriginal: f.scope.FinalCard}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize))
	spki, e := x509.MarshalPKIXPublicKey(key.Public())
	if e != nil {
		t.Fatal(e)
	}
	f.approval = d101operatorauth.IssuerPins{Role: d101operatorauth.ApprovalIssuerRole, Identity: "synthetic-approval-issuer", SourceSHA: strings.Repeat("a", 40), ImageDigest: "sha256:" + strings.Repeat("b", 64), PublicKeySPKI: spki, PublicKeySPKISHA256: resetD101OriginalSHA(spki)}
	f.receipt.ImageDigest = "sha256:" + strings.Repeat("c", 64)
	s.InstalledApprovalIssuer = f.approval
	s.InstalledReceiptIssuer = f.receipt
	s.OriginDependencies = map[string][]byte{}
	dependency := func(id string) et.RawReference {
		b := marshal(map[string]string{"synthetic": id})
		s.OriginDependencies["raw:"+id] = b
		return ref(id, b)
	}
	subject := dependency("human-approval")
	provider := dependency("human-provider")
	process := dependency("process")
	verifier := dependency("verifier")
	historicalAuth := dependency("historical-auth")
	historicalDecision := dependency("historical-decision")
	profile := marshal(map[string]any{"schemaVersion": 1, "kind": "D101_EVIDENCE_ORIGIN_PUBLIC_PINS_V1", "role": d101origin.ApprovalIssuer, "issuerIdentity": f.approval.Identity, "issuerSourceSha": f.approval.SourceSHA, "issuerImageDigest": f.approval.ImageDigest, "publicKeySpkiBase64url": base64.RawURLEncoding.EncodeToString(spki), "publicKeySpkiSha256": f.approval.PublicKeySPKISHA256})
	profileRef := ref("profile", profile)
	s.OriginDependencies[profileRef.LogicalID] = profile
	bindings := marshal(map[string]any{"providerIdentity": "synthetic-provider", "actorIdentity": "synthetic-historical-human", "conversationIdentity": "synthetic-conversation", "eventIdentity": "synthetic-human-event", "originalIssuedAtUtc": f.issued.Add(-5 * time.Second).Format(time.RFC3339Nano), "scopeDecisionRef": historicalDecision, "authenticationRef": historicalAuth})
	scopeRef := et.RawReference{LogicalID: f.scope.ScopeOriginal.LogicalID, SHA256: f.scope.ScopeOriginal.SHA256, ByteLength: f.scope.ScopeOriginal.ByteLength, MediaType: f.scope.ScopeOriginal.MediaType}
	origin := d101origin.OriginRecord{SchemaVersion: 1, Role: d101origin.ApprovalIssuer, IssuerIdentity: f.approval.Identity, IssuerSourceSHA: f.approval.SourceSHA, IssuerImageDigest: f.approval.ImageDigest, OperationID: f.scope.OperationID, ScopeOriginal: scopeRef, Subject: subject, Kind: "D101_EVIDENCE_ORIGIN_RECORD_V1", IssuedAtUTC: f.issued.Add(-3 * time.Second).Format(time.RFC3339Nano), ObservedAtUTC: f.issued.Add(-4 * time.Second).Format(time.RFC3339Nano), ProviderRecord: provider, RoleBindings: bindings}
	installed := d101origin.ExpectedRecordInstallation{Role: origin.Role, OperationID: origin.OperationID, IssuerIdentity: origin.IssuerIdentity, IssuerSourceSHA: origin.IssuerSourceSHA, IssuerImageDigest: origin.IssuerImageDigest, ScopeOriginal: scopeRef, Subject: subject, Profile: profileRef, Verifier: verifier, ProcessIdentity: process, ReaderBindingsSHA: strings.Repeat("a", 64), HelperSHA: strings.Repeat("b", 64), KeyEnvelopeSHA: strings.Repeat("c", 64)}
	custody := d101origin.NativeCustodyRecord{SchemaVersion: 1, Role: origin.Role, IssuerIdentity: origin.IssuerIdentity, IssuerSourceSHA: origin.IssuerSourceSHA, IssuerImageDigest: origin.IssuerImageDigest, OperationID: origin.OperationID, ScopeOriginal: scopeRef, Subject: subject, Kind: "D101_EVIDENCE_ORIGIN_NATIVE_CUSTODY_V1", PublicProfile: profileRef, VerifierSource: verifier, ProviderRecord: provider, ProcessIdentity: process, ReaderBindingsSHA: installed.ReaderBindingsSHA, HelperSHA: installed.HelperSHA, SigningKeyEnvelopeSHA: installed.KeyEnvelopeSHA, ObservedAtUTC: f.issued.Add(-2 * time.Second).Format(time.RFC3339Nano), IssuedAtUTC: f.issued.Add(-time.Second).Format(time.RFC3339Nano)}
	pins := func(o []byte) {
		custody.OriginRecord = ref("origin", o)
		custody.FDPins = map[string]d101custody.NativeFilePin{}
		rs := map[string]et.RawReference{"subject": subject, "originRecord": custody.OriginRecord, "scope": scopeRef, "publicProfile": profileRef, "verifierSource": verifier, "providerRecord": provider, "processIdentity": process}
		for i, id := range []string{"subject", "originRecord", "scope", "publicProfile", "verifierSource", "providerRecord", "processIdentity", "readerBindings", "helper", "signingKeyEnvelope"} {
			sha, length := strings.Repeat("a", 64), uint64(12)
			if r, ok := rs[id]; ok {
				sha, length = r.SHA256, r.ByteLength
			}
			switch id {
			case "readerBindings":
				sha = installed.ReaderBindingsSHA
			case "helper":
				sha = installed.HelperSHA
			case "signingKeyEnvelope":
				sha = installed.KeyEnvelopeSHA
			}
			mode := uint32(0400)
			if id == "helper" {
				mode = 0500
			}
			custody.FDPins[id] = d101custody.NativeFilePin{SHA256: sha, Snapshot: d101custody.PrivateSnapshot{Device: 1, Inode: uint64(i + 1), ByteLength: length, ModifiedAtUnixNano: 1}, FileMode: mode, LinkCount: 1, ParentSnapshot: d101custody.PrivateSnapshot{Device: 1, Inode: 50, ByteLength: 4096, ModifiedAtUnixNano: 1}, ParentMode: 0700}
		}
	}
	payload := func(c []byte) []byte {
		return marshal(map[string]any{"schemaVersion": 1, "kind": "D101_EVIDENCE_ORIGIN_PROOF_V1", "role": origin.Role, "issuerIdentity": origin.IssuerIdentity, "issuerSourceSha": origin.IssuerSourceSHA, "issuerImageDigest": origin.IssuerImageDigest, "operationId": origin.OperationID, "scopeOriginalRef": scopeRef, "subjectRef": subject, "originRecordRef": custody.OriginRecord, "nativeCustodyRef": ref("custody", c), "observedAtUtc": custody.ObservedAtUTC})
	}
	historyOrigin := marshal(origin)
	pins(historyOrigin)
	historyCustody := marshal(custody)
	historyPayload := payload(historyCustody)
	envelope := resetD101SignedHostFixture(t, key, d101operatorauth.ApprovalOriginDomain, historyPayload)
	installed.Envelope = ref("envelope", envelope)
	binding, err := d101origin.VerifyCryptographicBinding(envelope, profile, d101origin.ExpectedBinding{Role: origin.Role, OperationID: origin.OperationID, ProfileSHA256: profileRef.SHA256, ScopeOriginal: scopeRef}, f.issued)
	if err != nil {
		t.Fatal("synthetic historical cryptographic binding", err)
	}
	history, err := d101origin.ParseUnverifiedRecords(binding, historyOrigin, historyCustody, installed, f.issued)
	if err != nil {
		t.Fatal("synthetic historical role7 records", err)
	}
	s.HistoricalApproval = history
	origin.IssuedAtUTC = f.issued.Format(time.RFC3339Nano)
	s.OriginOriginal = marshal(origin)
	pins(s.OriginOriginal)
	custody.ObservedAtUTC = f.issued.Add(time.Millisecond).Format(time.RFC3339Nano)
	custody.IssuedAtUTC = f.issued.Add(2 * time.Millisecond).Format(time.RFC3339Nano)
	s.OriginCustodyOriginal = marshal(custody)
	s.OriginNativeCustodyRef = ref("custody", s.OriginCustodyOriginal)
	s.OriginInstallation = installed
	s.ApprovalPayload = payload(s.OriginCustodyOriginal)
	if validateResetD101ApprovalUnsigned(f, s) != nil {
		t.Fatal("current origin changed valid historical7 mapping")
	}
	return f, s
}

func TestIssuerSemanticBothRolesPreserveHistoricalApprovalAndExactUnsignedBytes(t *testing.T) {
	f, s := resetD101SemanticBothFixture(t)
	b, err := mapResetD101IssuerSemanticUnsigned(context.Background(), f, s)
	if err != nil || len(b.ApprovalPayload()) == 0 || len(b.ReceiptAttestation()) == 0 {
		t.Fatal("both synthetic unsigned roles refused", err)
	}
	var o d101origin.OriginRecord
	json.Unmarshal(s.OriginOriginal, &o)
	if !bytes.Equal(o.RoleBindings, s.HistoricalApproval.Origin().RoleBindings) {
		t.Fatal("historical7 changed")
	}
	for _, mutate := range []func(*d101origin.OriginRecord){func(o *d101origin.OriginRecord) {
		var fields map[string]json.RawMessage
		json.Unmarshal(o.RoleBindings, &fields)
		fields["actorIdentity"], _ = json.Marshal(f.event.ActorID)
		o.RoleBindings, _ = json.Marshal(fields)
	}, func(o *d101origin.OriginRecord) {
		var fields map[string]json.RawMessage
		json.Unmarshal(o.RoleBindings, &fields)
		fields["originalIssuedAtUtc"], _ = json.Marshal(f.issued.Format(time.RFC3339Nano))
		o.RoleBindings, _ = json.Marshal(fields)
	}} {
		copy, _ := freezeResetD101IssuerSemanticSnapshot(s)
		var origin d101origin.OriginRecord
		json.Unmarshal(copy.OriginOriginal, &origin)
		mutate(&origin)
		copy.OriginOriginal, _ = json.Marshal(origin)
		if _, err := mapResetD101IssuerSemanticUnsigned(context.Background(), f, copy); err == nil {
			t.Fatal("current event substituted historical human binding")
		}
	}
}

func TestIssuerSemanticRetainedSignedEnvelopePreservesExistingProvenanceOrder(t *testing.T) {
	f, s := resetD101SemanticBothFixture(t)
	b, err := mapResetD101IssuerSemanticUnsigned(context.Background(), f, s)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{73}, ed25519.SeedSize))
	signed := resetD101SignedHostFixture(t, key, resetD101ApprovedReceiptAttestationDomain, b.ReceiptAttestation())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	wire, err := b.ProvenanceAfterRetainedAttestation(ctx, signed)
	if err != nil {
		t.Fatal("exact retained synthetic envelope refused", err)
	}
	var value resetD101ApprovedReceiptProvenance
	var fields map[string]json.RawMessage
	if json.Unmarshal(wire, &value) != nil || json.Unmarshal(wire, &fields) != nil || len(fields) != 10 || value.Issuer.ScopeAttestationRef != resetD101ProvenanceReference("raw:approved-receipt-scope-attestation", signed) || len(value.OriginalBindings) != 13 {
		t.Fatal("post-sign envelope ref/profile changed")
	}
	for _, raw := range [][]byte{resetD101SignedHostFixture(t, key, d101operatorauth.ApprovalOriginDomain, b.ReceiptAttestation()), resetD101SignedHostFixture(t, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{74}, ed25519.SeedSize)), resetD101ApprovedReceiptAttestationDomain, b.ReceiptAttestation()), resetD101SignedHostFixture(t, key, resetD101ApprovedReceiptAttestationDomain, append(b.ReceiptAttestation(), byte(' ')))} {
		if result, err := b.ProvenanceAfterRetainedAttestation(ctx, raw); err == nil || len(result) != 0 {
			t.Fatal("wrong domain/key/unsigned original created provenance")
		}
	}
}
