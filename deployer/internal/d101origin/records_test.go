package d101origin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101custody"
	et "opensamguk-deployer/internal/d101evidencetransport"
)

type recordFixture struct {
	crypto                       originFixture
	origin                       OriginRecord
	custody                      NativeCustodyRecord
	pins                         ExpectedRecordInstallation
	originUnknown, nativeUnknown bool
}

func recordRef(id string, wire []byte) et.RawReference {
	return et.RawReference{LogicalID: "raw:" + id, SHA256: et.HashOriginal(wire), ByteLength: uint64(len(wire)), MediaType: "application/json"}
}
func newRecordFixture(t *testing.T, role Role) *recordFixture {
	t.Helper()
	f := &recordFixture{crypto: newOriginFixture(t, role)}
	ref := func(id string) et.RawReference {
		return et.RawReference{LogicalID: "raw:" + id, SHA256: strings.Repeat("a", 64), ByteLength: 12, MediaType: "application/json"}
	}
	profile := fixtureJSON(t, f.crypto.profile)
	f.pins = ExpectedRecordInstallation{Role: role, OperationID: f.crypto.body.OperationID, IssuerIdentity: f.crypto.profile.IssuerIdentity, IssuerSourceSHA: f.crypto.profile.IssuerSourceSHA, IssuerImageDigest: f.crypto.profile.IssuerImageDigest,
		ScopeOriginal: f.crypto.body.ScopeOriginalRef, Subject: f.crypto.body.SubjectRef, Profile: recordRef("profile", profile), Verifier: ref("verifier"), ProcessIdentity: ref("process"), ReaderBindingsSHA: strings.Repeat("b", 64), HelperSHA: strings.Repeat("c", 64), KeyEnvelopeSHA: strings.Repeat("d", 64)}
	bindings := map[string]any{}
	switch role {
	case ApprovalIssuer:
		bindings = map[string]any{"providerIdentity": "fixture-provider", "actorIdentity": "fixture-human", "conversationIdentity": "fixture-conversation", "eventIdentity": "fixture-event", "originalIssuedAtUtc": f.crypto.now.Add(-4 * time.Second).Format(time.RFC3339Nano), "scopeDecisionRef": ref("scope-decision"), "authenticationRef": ref("authentication")}
	case OfficialGitHubCollector:
		bindings = map[string]any{"repository": "peppone-choi/opensamguk", "requestMethod": "GET", "apiPath": "/repos/peppone-choi/opensamguk/actions/runs/1", "httpStatus": 200, "requestId": "fixture-request", "capturedAtUtc": f.crypto.now.Add(-3 * time.Second).Format(time.RFC3339Nano), "authenticationRef": ref("authentication")}
	case IndependentReviewCollector:
		bindings = map[string]any{"backend": "codex-independent", "reviewerId": "fixture-reviewer", "authorSessionId": "fixture-review-session", "implementerSessionIds": []string{"fixture-implementer"}, "independenceEvidenceRef": ref("independence"), "windowOriginalRef": ref("window"), "reportRef": ref("report"), "publicationRef": ref("publication"), "authenticationRef": ref("authentication"), "issuedAtUnix": f.crypto.now.Add(-5 * time.Second).Unix(), "publishedAtUtc": f.crypto.now.Add(-4 * time.Second).Format(time.RFC3339Nano)}
	}
	f.origin = OriginRecord{1, role, f.pins.IssuerIdentity, f.pins.IssuerSourceSHA, f.pins.IssuerImageDigest, f.pins.OperationID, f.pins.ScopeOriginal, f.pins.Subject, "D101_EVIDENCE_ORIGIN_RECORD_V1", f.crypto.now.Add(-2 * time.Second).Format(time.RFC3339Nano), f.crypto.now.Add(-3 * time.Second).Format(time.RFC3339Nano), ref("provider"), fixtureJSON(t, bindings)}
	f.custody = NativeCustodyRecord{SchemaVersion: 1, Role: role, IssuerIdentity: f.pins.IssuerIdentity, IssuerSourceSHA: f.pins.IssuerSourceSHA, IssuerImageDigest: f.pins.IssuerImageDigest, OperationID: f.pins.OperationID, ScopeOriginal: f.pins.ScopeOriginal, Subject: f.pins.Subject, Kind: "D101_EVIDENCE_ORIGIN_NATIVE_CUSTODY_V1", PublicProfile: f.pins.Profile, VerifierSource: f.pins.Verifier, ProviderRecord: f.origin.ProviderRecord, ProcessIdentity: f.pins.ProcessIdentity, ReaderBindingsSHA: f.pins.ReaderBindingsSHA, HelperSHA: f.pins.HelperSHA, SigningKeyEnvelopeSHA: f.pins.KeyEnvelopeSHA, IssuedAtUTC: f.crypto.now.Format(time.RFC3339Nano), ObservedAtUTC: f.crypto.now.Add(-time.Second).Format(time.RFC3339Nano)}
	return f
}
func (f *recordFixture) originals(t *testing.T) (UnverifiedOriginBinding, []byte, []byte, ExpectedRecordInstallation) {
	t.Helper()
	origin := fixtureJSON(t, f.origin)
	if f.originUnknown {
		origin = append(origin[:len(origin)-1], []byte(`,"authority":true}`)...)
	}
	f.crypto.body.OriginRecordRef = recordRef("origin", origin)
	f.custody.OriginRecord = f.crypto.body.OriginRecordRef
	refs := map[string]et.RawReference{"subject": f.pins.Subject, "originRecord": f.crypto.body.OriginRecordRef, "scope": f.pins.ScopeOriginal, "publicProfile": f.pins.Profile, "verifierSource": f.pins.Verifier, "providerRecord": f.custody.ProviderRecord, "processIdentity": f.pins.ProcessIdentity}
	if f.custody.FDPins == nil {
		f.custody.FDPins = map[string]d101custody.NativeFilePin{}
		for i, id := range []string{"subject", "originRecord", "scope", "publicProfile", "verifierSource", "providerRecord", "processIdentity", "readerBindings", "helper", "signingKeyEnvelope"} {
			sha, length := strings.Repeat("a", 64), uint64(12)
			if ref, ok := refs[id]; ok {
				sha, length = ref.SHA256, ref.ByteLength
			}
			switch id {
			case "readerBindings":
				sha = f.pins.ReaderBindingsSHA
			case "helper":
				sha = f.pins.HelperSHA
			case "signingKeyEnvelope":
				sha = f.pins.KeyEnvelopeSHA
			}
			mode := uint32(0400)
			if id == "helper" {
				mode = 0500
			}
			f.custody.FDPins[id] = d101custody.NativeFilePin{SHA256: sha, Snapshot: d101custody.PrivateSnapshot{Device: 1, Inode: uint64(i + 1), ByteLength: length, ModifiedAtUnixNano: 1}, FileMode: mode, LinkCount: 1, ParentSnapshot: d101custody.PrivateSnapshot{Device: 1, Inode: 50, ByteLength: 4096, ModifiedAtUnixNano: 1}, ParentMode: 0700}
		}
	}
	custody := fixtureJSON(t, f.custody)
	if f.nativeUnknown {
		custody = append(custody[:len(custody)-1], []byte(`,"authority":true}`)...)
	}
	f.crypto.body.NativeCustodyRef = recordRef("custody", custody)
	env, profile, expected := f.crypto.originals(t, f.crypto.body.Role)
	f.pins.Envelope = recordRef("envelope", env)
	binding, err := VerifyCryptographicBinding(env, profile, expected, f.crypto.now)
	if err != nil {
		t.Fatal(err)
	}
	return binding, origin, custody, f.pins
}

func TestOriginRecordsBindExactRolesTimesAndNativePinsWithoutAuthority(t *testing.T) {
	for _, role := range []Role{ApprovalIssuer, OfficialGitHubCollector, IndependentReviewCollector} {
		t.Run(string(role), func(t *testing.T) {
			f := newRecordFixture(t, role)
			binding, origin, custody, pins := f.originals(t)
			records, err := ParseUnverifiedRecords(binding, origin, custody, pins, f.crypto.now)
			if err != nil {
				t.Fatal(err)
			}
			if records.Origin().Role != role || records.Custody().Subject != f.pins.Subject || len(records.Dependencies()) < 3 || records.RequireNativePins(records.Custody().FDPins) != nil {
				t.Fatal("unverified metadata binding lost")
			}
			copy := records.Custody()
			pin := copy.FDPins["subject"]
			pin.Snapshot.Inode++
			copy.FDPins["subject"] = pin
			if records.RequireNativePins(copy.FDPins) == nil {
				t.Fatal("changed actual native pin accepted")
			}
			body := records.Origin()
			body.RoleBindings[0] = '!'
			if records.Origin().RoleBindings[0] == '!' {
				t.Fatal("mutable role original")
			}
		})
	}
}

func TestOriginRecordsRejectResignedMetadataNativeDriftAndCycles(t *testing.T) {
	for _, mode := range []string{"actor-type", "event-future", "issued-order", "native-expired", "payload-observed", "provider-mismatch", "native-mode", "native-unknown", "origin-unknown", "cycle"} {
		t.Run(mode, func(t *testing.T) {
			f := newRecordFixture(t, ApprovalIssuer)
			var fields map[string]any
			if json.Unmarshal(f.origin.RoleBindings, &fields) != nil {
				t.Fatal("fixture")
			}
			switch mode {
			case "actor-type":
				fields["actorIdentity"] = true
				f.origin.RoleBindings = fixtureJSON(t, fields)
			case "event-future":
				fields["originalIssuedAtUtc"] = f.crypto.now.Add(time.Second).Format(time.RFC3339Nano)
				f.origin.RoleBindings = fixtureJSON(t, fields)
			case "issued-order":
				f.origin.IssuedAtUTC = f.crypto.now.Add(-4 * time.Second).Format(time.RFC3339Nano)
			case "native-expired":
				fields["originalIssuedAtUtc"] = f.crypto.now.Add(-33 * time.Second).Format(time.RFC3339Nano)
				f.origin.RoleBindings = fixtureJSON(t, fields)
				f.origin.ObservedAtUTC = f.crypto.now.Add(-32 * time.Second).Format(time.RFC3339Nano)
				f.origin.IssuedAtUTC = f.crypto.now.Add(-31 * time.Second).Format(time.RFC3339Nano)
				f.custody.ObservedAtUTC = f.crypto.now.Add(-30 * time.Second).Format(time.RFC3339Nano)
				f.crypto.body.ObservedAtUTC = f.custody.ObservedAtUTC
			case "payload-observed":
				f.custody.ObservedAtUTC = f.crypto.now.Add(-1500 * time.Millisecond).Format(time.RFC3339Nano)
			case "provider-mismatch":
				f.custody.ProviderRecord.LogicalID = "raw:other-provider"
			case "native-unknown":
				f.nativeUnknown = true
			case "origin-unknown":
				f.originUnknown = true
			case "cycle":
				ref := f.crypto.body.OriginRecordRef
				fields["authenticationRef"] = ref
				f.origin.RoleBindings = fixtureJSON(t, fields)
			}
			binding, origin, custody, pins := f.originals(t)
			if mode == "native-mode" {
				pin := f.custody.FDPins["helper"]
				pin.FileMode = 0400
				f.custody.FDPins["helper"] = pin
				binding, origin, custody, pins = f.originals(t)
			}
			if _, err := ParseUnverifiedRecords(binding, origin, custody, pins, f.crypto.now); err == nil {
				t.Fatal("resigned malformed/rebound/native metadata accepted")
			}
		})
	}
}
