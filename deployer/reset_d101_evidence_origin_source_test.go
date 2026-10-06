package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101custody"
	et "opensamguk-deployer/internal/d101evidencetransport"
	"opensamguk-deployer/internal/d101origin"
)

type nativeOriginSourceFixture struct {
	pins      resetD101EvidenceOriginInstallation
	files     map[string]d101custody.Original
	snapshots map[string]d101custody.PrivateSnapshot
	subject   et.RawReference
	now       time.Time
}

func newNativeOriginSourceFixture(t *testing.T) *nativeOriginSourceFixture {
	t.Helper()
	f := &nativeOriginSourceFixture{files: map[string]d101custody.Original{}, snapshots: map[string]d101custody.PrivateSnapshot{}, now: time.Unix(100, 0).UTC()}
	encode := func(value any) []byte {
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	put := func(path string, wire []byte) d101custody.PrivateSnapshot {
		f.files[path] = d101custody.Original{Bytes: append([]byte(nil), wire...), SHA256: et.HashOriginal(wire)}
		snapshot := d101custody.PrivateSnapshot{Device: 1, Inode: uint64(len(f.files) + 1), ByteLength: uint64(len(wire)), ModifiedAtUnixNano: 3}
		f.snapshots[path] = snapshot
		return snapshot
	}
	op := strings.Repeat("a", 32)
	entries := []et.Entry{}
	registered := func(id string, wire []byte) et.RawReference {
		ref := et.RawReference{LogicalID: "raw:" + id, SHA256: et.HashOriginal(wire), ByteLength: uint64(len(wire)), MediaType: "application/json"}
		path, err := et.OriginalPath(op, ref.LogicalID)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := put(path, wire)
		entries = append(entries, et.Entry{Reference: ref, LogicalIDHash: et.LogicalIDDigest(ref.LogicalID), Snapshot: snapshot})
		return ref
	}
	images := map[string]string{}
	for _, id := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		images[id] = "sha256:" + strings.Repeat("b", 64)
	}
	target := registered("target", []byte("{}"))
	scope := et.Scope{OperationID: op, ServerID: "pep", WorldID: 1, TargetFingerprint: target.SHA256, TypedTargetRef: target,
		AppSourceSHA: strings.Repeat("c", 40), DockerSourceSHA: strings.Repeat("d", 40), OldImageDigests: images, NewImageDigests: images,
		InitialPublicRevision: "1", Window: et.Window{WindowOpensAtUnix: 1, DestructiveCutoffUnix: 2, RecoveryDeadlineUnix: 3}}
	f.pins.ScopeOriginal = registered("scope", encode(scope))
	f.subject = registered("subject", []byte(`{"syntheticOnly":true}`))
	f.pins.Roles = map[d101origin.Role]resetD101ReviewedOriginRole{}
	publicPins := []et.PublicPin{}
	proofRefs := []et.RawReference{}
	for _, role := range []d101origin.Role{d101origin.ApprovalIssuer, d101origin.OfficialGitHubCollector, d101origin.IndependentReviewCollector} {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize)) // Synthetic test key only.
		spki, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		profile := encode(map[string]any{"schemaVersion": 1, "kind": "D101_EVIDENCE_ORIGIN_PUBLIC_PINS_V1", "role": role,
			"issuerIdentity": "fixture-issuer", "issuerSourceSha": strings.Repeat("e", 40), "issuerImageDigest": "sha256:" + strings.Repeat("f", 64),
			"publicKeySpkiBase64url": base64.RawURLEncoding.EncodeToString(spki), "publicKeySpkiSha256": et.HashOriginal(spki)})
		profileRef := registered(string(role)+":profile", profile)
		profilePath, _ := et.PublicProfilePath(string(role))
		profileSnapshot := put(profilePath, profile)
		origin := registered(string(role)+":record", []byte(`{"syntheticOnly":true,"authenticatedOrigin":false}`))
		custody := registered(string(role)+":custody", []byte(`{"syntheticOnly":true,"installedAuthority":false}`))
		verifier := registered(string(role)+":verifier", []byte(`{"syntheticOnly":true}`))
		payload := encode(map[string]any{"schemaVersion": 1, "kind": "D101_EVIDENCE_ORIGIN_PROOF_V1", "role": role,
			"issuerIdentity": "fixture-issuer", "issuerSourceSha": strings.Repeat("e", 40), "issuerImageDigest": "sha256:" + strings.Repeat("f", 64),
			"operationId": op, "scopeOriginalRef": f.pins.ScopeOriginal, "subjectRef": f.subject, "originRecordRef": origin,
			"nativeCustodyRef": custody, "observedAtUtc": f.now.Add(-time.Second).Format(time.RFC3339Nano)})
		domain := map[d101origin.Role]string{d101origin.ApprovalIssuer: "OPENSAMGUK_D101_APPROVAL_ORIGIN_V1\n", d101origin.OfficialGitHubCollector: "OPENSAMGUK_D101_GITHUB_ORIGIN_V1\n", d101origin.IndependentReviewCollector: "OPENSAMGUK_D101_REVIEW_ORIGIN_V1\n"}[role]
		envelope := registered(string(role)+":envelope", encode(map[string]any{"schemaVersion": 1, "originalBytesBase64url": base64.RawURLEncoding.EncodeToString(payload),
			"signatureBase64url": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), payload...)))}))
		pin := et.PublicPin{Role: string(role), PublicProfile: profileRef, VerifierSource: verifier, NativeCustody: custody}
		f.pins.Roles[role] = resetD101ReviewedOriginRole{pin, profileSnapshot, envelope}
		publicPins = append(publicPins, pin)
		proofRefs = append(proofRefs, envelope)
	}
	collector := registered("collector", []byte(`{"syntheticOnly":true}`))
	digest, err := et.ScopeDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	page := encode(et.LeafPage{SchemaVersion: 1, Kind: et.LeafKind, OperationID: op, ScopeSHA256: digest, Prefix: "", Entries: entries})
	pageRef := et.PageReference{Prefix: "", SHA256: et.HashOriginal(page), ByteLength: uint64(len(page))}
	pageRef.Snapshot = d101custody.PrivateSnapshot{Device: 1, Inode: uint64(len(f.files) + 2), ByteLength: uint64(len(page)), ModifiedAtUnixNano: 3}
	pagePath, _ := et.PagePath(op, pageRef)
	put(pagePath, page)
	f.snapshots[pagePath] = pageRef.Snapshot
	// Fixture tests native reception, not installed source provenance.
	indexWire := encode(et.Index{SchemaVersion: 1, Kind: et.IndexKind, Scope: scope, PartBytes: d101custody.PrivateOriginalPartBytes,
		CollectorIdentity: "fixture-collector", CollectorSource: collector, CollectorImageDigest: "sha256:" + strings.Repeat("b", 64), RootPage: pageRef, OriginProofs: proofRefs, CapturedAtUnix: 1})
	indexSnapshot := put(et.IndexPath, indexWire)
	f.pins.BindingsSnapshot = put(resetD101NativeReaderBindingsPath, []byte("synthetic-only fixed bindings"))
	f.pins.ReaderBindingsSHA = f.files[resetD101NativeReaderBindingsPath].SHA256
	f.pins.HelperSnapshot = put(resetD101EvidenceHelperPath, []byte("synthetic-only executable original"))
	f.pins.HelperSHA = f.files[resetD101EvidenceHelperPath].SHA256
	pinWire := encode(et.SourcePin{SchemaVersion: 1, Kind: et.SourcePinKind, Scope: scope, ReaderBindingsSHA256: f.pins.ReaderBindingsSHA,
		EvidenceIndexSHA256: et.HashOriginal(indexWire), EvidenceIndexSnapshot: indexSnapshot, HelperSHA256: f.pins.HelperSHA,
		CollectorSource: collector, CollectorImageDigest: "sha256:" + strings.Repeat("b", 64), CollectorIdentity: "fixture-collector",
		InstallerSource: collector, OriginPins: publicPins, Namespace: et.SourceNamespace})
	f.pins.SourcePinSnapshot = put(et.SourcePinPath, pinWire)
	f.pins.SourcePinSHA = f.files[et.SourcePinPath].SHA256
	return f
}

func (f *nativeOriginSourceFixture) capture(path string, limit int64) (d101custody.Original, d101custody.PrivateSnapshot, error) {
	original, ok := f.files[path]
	if !ok || int64(len(original.Bytes)) > limit {
		return d101custody.Original{}, d101custody.PrivateSnapshot{}, errResetExecutionEvidence
	}
	return d101custody.Original{Bytes: append([]byte(nil), original.Bytes...), SHA256: original.SHA256}, f.snapshots[path], nil
}
func (f *nativeOriginSourceFixture) inspect(path string, snapshot d101custody.PrivateSnapshot) error {
	if f.snapshots[path] != snapshot {
		return errResetExecutionEvidence
	}
	return nil
}

func TestNativeOriginSourceReceivesFixedRoleWholeOriginalsWithoutAuthority(t *testing.T) {
	for _, role := range []d101origin.Role{d101origin.ApprovalIssuer, d101origin.OfficialGitHubCollector, d101origin.IndependentReviewCollector} {
		t.Run(string(role), func(t *testing.T) {
			f := newNativeOriginSourceFixture(t)
			captured, err := captureResetD101NativeUnverifiedOriginWithReaders(context.Background(), f.pins, role, f.subject, f.capture, f.capture, f.inspect, func() time.Time { return f.now })
			if err != nil || captured.binding.Role() != role || captured.binding.SubjectReference() != f.subject {
				t.Fatal("fixed native data reception failed", err)
			}
			wire, err := captured.Original(f.subject.LogicalID)
			if err != nil || et.HashOriginal(wire) != f.subject.SHA256 {
				t.Fatal("whole subject bytes lost")
			}
			wire[0] = '!'
			again, _ := captured.Original(f.subject.LogicalID)
			if et.HashOriginal(again) != f.subject.SHA256 {
				t.Fatal("exposed mutable original")
			}
			// Fake role records are intentionally returned only as unverified
			// originals. They cannot instantiate a purpose authority or installer.
		})
	}
}

func TestNativeOriginSourceRejectsMissingPinsRebindingAndNativeDrift(t *testing.T) {
	for _, mode := range []string{"missing-role", "role-body-selection", "profile-pin", "subject-ref", "unregistered-envelope", "source-pin-drift", "profile-drift", "helper-drift", "original-native-drift", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeOriginSourceFixture(t)
			role := d101origin.ApprovalIssuer
			subject := f.subject
			selected := f.pins.Roles[role]
			switch mode {
			case "missing-role":
				delete(f.pins.Roles, d101origin.OfficialGitHubCollector)
			case "role-body-selection":
				role = d101origin.Role("caller")
			case "profile-pin":
				selected.PublicPin.PublicProfile.SHA256 = strings.Repeat("0", 64)
				f.pins.Roles[role] = selected
			case "subject-ref":
				subject.SHA256 = strings.Repeat("0", 64)
			case "unregistered-envelope":
				selected.Envelope.LogicalID = "raw:unregistered-envelope"
				f.pins.Roles[role] = selected
			}
			calls := map[string]int{}
			capture := func(path string, limit int64) (d101custody.Original, d101custody.PrivateSnapshot, error) {
				calls[path]++
				original, snapshot, err := f.capture(path, limit)
				profile, _ := et.PublicProfilePath(string(d101origin.ApprovalIssuer))
				if calls[path] > 1 && (mode == "source-pin-drift" && path == et.SourcePinPath || mode == "profile-drift" && path == profile || mode == "helper-drift" && path == resetD101EvidenceHelperPath) {
					snapshot.Inode++
				}
				return original, snapshot, err
			}
			inspect := func(path string, snapshot d101custody.PrivateSnapshot) error {
				if mode == "original-native-drift" && strings.HasPrefix(path, et.OriginalDirectory+"/") {
					return errResetExecutionEvidence
				}
				return f.inspect(path, snapshot)
			}
			ctx := context.Background()
			if mode == "expired" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := captureResetD101NativeUnverifiedOriginWithReaders(ctx, f.pins, role, subject, capture, capture, inspect, func() time.Time { return f.now }); err == nil {
				t.Fatal("missing/rebound source or native drift accepted")
			}
			if (mode == "missing-role" || mode == "role-body-selection" || mode == "expired") && len(calls) != 0 {
				t.Fatal("missing fixed selection read native inputs")
			}
		})
	}
}
