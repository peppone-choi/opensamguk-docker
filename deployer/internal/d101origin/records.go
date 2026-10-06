package d101origin

import (
	"encoding/json"
	"strings"
	"time"

	"opensamguk-deployer/internal/d101custody"
	et "opensamguk-deployer/internal/d101evidencetransport"
)

type OriginRecord struct {
	SchemaVersion     int             `json:"schemaVersion"`
	Role              Role            `json:"role"`
	IssuerIdentity    string          `json:"issuerIdentity"`
	IssuerSourceSHA   string          `json:"issuerSourceSha"`
	IssuerImageDigest string          `json:"issuerImageDigest"`
	OperationID       string          `json:"operationId"`
	ScopeOriginal     et.RawReference `json:"scopeOriginalRef"`
	Subject           et.RawReference `json:"subjectRef"`
	Kind              string          `json:"kind"`
	IssuedAtUTC       string          `json:"issuedAtUtc"`
	ObservedAtUTC     string          `json:"observedAtUtc"`
	ProviderRecord    et.RawReference `json:"providerRecordRef"`
	RoleBindings      json.RawMessage `json:"roleBindings"`
}
type NativeCustodyRecord struct {
	SchemaVersion         int                                  `json:"schemaVersion"`
	Role                  Role                                 `json:"role"`
	IssuerIdentity        string                               `json:"issuerIdentity"`
	IssuerSourceSHA       string                               `json:"issuerSourceSha"`
	IssuerImageDigest     string                               `json:"issuerImageDigest"`
	OperationID           string                               `json:"operationId"`
	ScopeOriginal         et.RawReference                      `json:"scopeOriginalRef"`
	Subject               et.RawReference                      `json:"subjectRef"`
	OriginRecord          et.RawReference                      `json:"originRecordRef"`
	Kind                  string                               `json:"kind"`
	PublicProfile         et.RawReference                      `json:"publicProfileRef"`
	VerifierSource        et.RawReference                      `json:"verifierSourceRef"`
	ProviderRecord        et.RawReference                      `json:"providerRecordRef"`
	ProcessIdentity       et.RawReference                      `json:"processIdentityRef"`
	ReaderBindingsSHA     string                               `json:"readerBindingsSha256"`
	HelperSHA             string                               `json:"helperSha256"`
	SigningKeyEnvelopeSHA string                               `json:"signingKeyEnvelopeSha256"`
	IssuedAtUTC           string                               `json:"issuedAtUtc"`
	ObservedAtUTC         string                               `json:"observedAtUtc"`
	FDPins                map[string]d101custody.NativeFilePin `json:"fdPins"`
}

type ExpectedRecordInstallation struct {
	Role                                         Role
	OperationID, IssuerIdentity                  string
	IssuerSourceSHA, IssuerImageDigest           string
	ScopeOriginal, Subject, Profile, Verifier    et.RawReference
	Envelope, ProcessIdentity                    et.RawReference
	ReaderBindingsSHA, HelperSHA, KeyEnvelopeSHA string
}

// Exact record/time/ref/native metadata binding only. It never authenticates a
// provider, process, installation or key, and cannot construct a purpose grant.
type UnverifiedRecords struct {
	origin       OriginRecord
	custody      NativeCustodyRecord
	dependencies []et.RawReference
}

func (r UnverifiedRecords) Origin() OriginRecord {
	value := r.origin
	value.RoleBindings = append(json.RawMessage(nil), value.RoleBindings...)
	return value
}
func (r UnverifiedRecords) Custody() NativeCustodyRecord {
	value := r.custody
	value.FDPins = make(map[string]d101custody.NativeFilePin, len(r.custody.FDPins))
	for id, pin := range r.custody.FDPins {
		value.FDPins[id] = pin
	}
	return value
}
func (r UnverifiedRecords) Dependencies() []et.RawReference {
	return append([]et.RawReference(nil), r.dependencies...)
}

func ParseUnverifiedRecords(binding UnverifiedOriginBinding, originOriginal, custodyOriginal []byte,
	expected ExpectedRecordInstallation, now time.Time) (UnverifiedRecords, error) {
	deny := func() (UnverifiedRecords, error) { return UnverifiedRecords{}, d101custody.ErrUnavailable }
	if _, ok := roleDomain(expected.Role); !ok || binding.Role() != expected.Role || !opPattern.MatchString(expected.OperationID) ||
		!identityPattern.MatchString(expected.IssuerIdentity) || !sha40Pattern.MatchString(expected.IssuerSourceSHA) || !validImageDigest(expected.IssuerImageDigest) ||
		!sha256Pattern.MatchString(expected.ReaderBindingsSHA) || !sha256Pattern.MatchString(expected.HelperSHA) || !sha256Pattern.MatchString(expected.KeyEnvelopeSHA) || now.Unix() <= 0 {
		return deny()
	}
	for _, ref := range []et.RawReference{expected.ScopeOriginal, expected.Subject, expected.Profile, expected.Verifier, expected.Envelope, expected.ProcessIdentity} {
		if et.ValidateRawReference(ref) != nil {
			return deny()
		}
	}
	for _, ref := range []et.RawReference{expected.ScopeOriginal, expected.Profile, expected.Envelope, expected.ProcessIdentity} {
		if ref.MediaType != "application/json" || ref.ByteLength > et.MetadataMaxBytes {
			return deny()
		}
	}
	if expected.Profile.SHA256 != binding.ProfileSHA256() || expected.Subject != binding.SubjectReference() ||
		!matchesRecordOriginal(binding.OriginRecordReference(), originOriginal) || !matchesRecordOriginal(binding.NativeCustodyReference(), custodyOriginal) {
		return deny()
	}
	originFields, err := exactObject(originOriginal, "schemaVersion", "role", "issuerIdentity", "issuerSourceSha", "issuerImageDigest", "operationId", "scopeOriginalRef", "subjectRef", "kind", "issuedAtUtc", "observedAtUtc", "providerRecordRef", "roleBindings")
	if err != nil {
		return deny()
	}
	var origin OriginRecord
	if json.Unmarshal(originOriginal, &origin) != nil || origin.SchemaVersion != 1 || origin.Kind != "D101_EVIDENCE_ORIGIN_RECORD_V1" ||
		origin.Role != expected.Role || origin.OperationID != expected.OperationID || origin.IssuerIdentity != expected.IssuerIdentity ||
		origin.IssuerSourceSHA != expected.IssuerSourceSHA || origin.IssuerImageDigest != expected.IssuerImageDigest {
		return deny()
	}
	for _, field := range []struct {
		name string
		out  *et.RawReference
	}{{"scopeOriginalRef", &origin.ScopeOriginal}, {"subjectRef", &origin.Subject}, {"providerRecordRef", &origin.ProviderRecord}} {
		ref, err := et.DecodeRawReference(originFields[field.name])
		if err != nil {
			return deny()
		}
		*field.out = ref
	}
	if origin.ScopeOriginal != expected.ScopeOriginal || origin.Subject != expected.Subject {
		return deny()
	}
	dependencies, eventAt, err := parseFixedRoleBindings(expected.Role, origin.RoleBindings, now)
	if err != nil {
		return deny()
	}
	custodyFields, err := exactObject(custodyOriginal, "schemaVersion", "role", "issuerIdentity", "issuerSourceSha", "issuerImageDigest", "operationId", "scopeOriginalRef", "subjectRef", "originRecordRef", "kind", "publicProfileRef", "verifierSourceRef", "providerRecordRef", "processIdentityRef", "readerBindingsSha256", "helperSha256", "signingKeyEnvelopeSha256", "issuedAtUtc", "observedAtUtc", "fdPins")
	if err != nil {
		return deny()
	}
	var custody NativeCustodyRecord
	if json.Unmarshal(custodyOriginal, &custody) != nil || custody.SchemaVersion != 1 || custody.Kind != "D101_EVIDENCE_ORIGIN_NATIVE_CUSTODY_V1" ||
		custody.Role != expected.Role || custody.OperationID != expected.OperationID || custody.IssuerIdentity != expected.IssuerIdentity ||
		custody.IssuerSourceSHA != expected.IssuerSourceSHA || custody.IssuerImageDigest != expected.IssuerImageDigest ||
		custody.ReaderBindingsSHA != expected.ReaderBindingsSHA || custody.HelperSHA != expected.HelperSHA || custody.SigningKeyEnvelopeSHA != expected.KeyEnvelopeSHA {
		return deny()
	}
	for _, field := range []struct {
		name string
		out  *et.RawReference
	}{{"scopeOriginalRef", &custody.ScopeOriginal}, {"subjectRef", &custody.Subject}, {"originRecordRef", &custody.OriginRecord}, {"publicProfileRef", &custody.PublicProfile}, {"verifierSourceRef", &custody.VerifierSource}, {"providerRecordRef", &custody.ProviderRecord}, {"processIdentityRef", &custody.ProcessIdentity}} {
		ref, err := et.DecodeRawReference(custodyFields[field.name])
		if err != nil {
			return deny()
		}
		*field.out = ref
	}
	if custody.ScopeOriginal != expected.ScopeOriginal || custody.Subject != expected.Subject || custody.OriginRecord != binding.OriginRecordReference() ||
		custody.PublicProfile != expected.Profile || custody.VerifierSource != expected.Verifier || custody.ProcessIdentity != expected.ProcessIdentity || custody.ProviderRecord != origin.ProviderRecord {
		return deny()
	}
	var body payload
	if json.Unmarshal(binding.PayloadOriginal(), &body) != nil || body.ScopeOriginalRef != expected.ScopeOriginal || body.OperationID != expected.OperationID ||
		body.IssuerIdentity != expected.IssuerIdentity || body.IssuerSourceSHA != expected.IssuerSourceSHA || body.IssuerImageDigest != expected.IssuerImageDigest {
		return deny()
	}
	originObserved, e1 := recordUTC(origin.ObservedAtUTC, now)
	originIssued, e2 := recordUTC(origin.IssuedAtUTC, now)
	nativeObserved, e3 := recordUTC(custody.ObservedAtUTC, now)
	custodyIssued, e4 := recordUTC(custody.IssuedAtUTC, now)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || eventAt.After(originObserved) || originObserved.After(originIssued) ||
		originIssued.After(nativeObserved) || nativeObserved.After(custodyIssued) || !nativeObserved.Equal(binding.ObservedAt()) || now.Sub(nativeObserved) >= 30*time.Second {
		return deny()
	}
	if expected.Role == OfficialGitHubCollector && !eventAt.Equal(originObserved) {
		return deny()
	}
	pins, err := parseNativePins(custodyFields["fdPins"])
	if err != nil {
		return deny()
	}
	custody.FDPins = pins
	refs := map[string]et.RawReference{"subject": expected.Subject, "originRecord": binding.OriginRecordReference(), "scope": expected.ScopeOriginal,
		"publicProfile": expected.Profile, "verifierSource": expected.Verifier, "providerRecord": origin.ProviderRecord, "processIdentity": expected.ProcessIdentity}
	for id, ref := range refs {
		if pins[id].SHA256 != ref.SHA256 || pins[id].Snapshot.ByteLength != ref.ByteLength {
			return deny()
		}
	}
	if pins["readerBindings"].SHA256 != expected.ReaderBindingsSHA || pins["helper"].SHA256 != expected.HelperSHA || pins["signingKeyEnvelope"].SHA256 != expected.KeyEnvelopeSHA {
		return deny()
	}
	dependencies = append(dependencies, origin.ProviderRecord, expected.ProcessIdentity)
	for _, ref := range dependencies {
		if ref.LogicalID == binding.OriginRecordReference().LogicalID || ref.LogicalID == binding.NativeCustodyReference().LogicalID || ref.LogicalID == expected.Envelope.LogicalID {
			return deny()
		}
	}
	return UnverifiedRecords{origin, custody, dependencies}, nil
}

// Actual pins must come from fixed native FD observations, not fdPins JSON.
// Success here remains metadata binding, never authenticated origin authority.
func (r UnverifiedRecords) RequireNativePins(actual map[string]d101custody.NativeFilePin) error {
	if len(actual) != 10 || len(r.custody.FDPins) != 10 {
		return d101custody.ErrUnavailable
	}
	for id, expected := range r.custody.FDPins {
		pin, ok := actual[id]
		if !ok || pin != expected {
			return d101custody.ErrUnavailable
		}
	}
	return nil
}

func matchesRecordOriginal(ref et.RawReference, wire []byte) bool {
	return ref.MediaType == "application/json" && len(wire) > 0 && len(wire) <= et.MetadataMaxBytes && uint64(len(wire)) == ref.ByteLength && et.HashOriginal(wire) == ref.SHA256
}
func recordUTC(value string, now time.Time) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || !strings.HasSuffix(value, "Z") || parsed.Unix() <= 0 || parsed.After(now) {
		return time.Time{}, d101custody.ErrUnavailable
	}
	return parsed, nil
}

func parseNativePins(wire []byte) (map[string]d101custody.NativeFilePin, error) {
	fields, err := exactObject(wire, "subject", "originRecord", "scope", "publicProfile", "verifierSource", "providerRecord", "processIdentity", "readerBindings", "helper", "signingKeyEnvelope")
	if err != nil {
		return nil, err
	}
	pins := make(map[string]d101custody.NativeFilePin, 10)
	for id, original := range fields {
		parts, err := exactObject(original, "sha256", "nativeSnapshot", "ownerUid", "fileMode", "linkCount", "parentSnapshot", "parentOwnerUid", "parentMode")
		if err != nil {
			return nil, err
		}
		for _, name := range []string{"nativeSnapshot", "parentSnapshot"} {
			if _, err := exactObject(parts[name], "device", "inode", "byteLength", "modifiedAtUnixNano"); err != nil {
				return nil, err
			}
		}
		var pin d101custody.NativeFilePin
		mode := uint32(0400)
		if id == "helper" {
			mode = 0500
		}
		if json.Unmarshal(original, &pin) != nil || !sha256Pattern.MatchString(pin.SHA256) || et.ValidateSnapshot(pin.Snapshot) != nil || et.ValidateSnapshot(pin.ParentSnapshot) != nil ||
			pin.OwnerUID != 0 || pin.ParentOwnerUID != 0 || pin.FileMode != mode || pin.ParentMode != 0700 || pin.LinkCount != 1 {
			return nil, d101custody.ErrUnavailable
		}
		if id == "helper" && pin.Snapshot.ByteLength > 32<<20 || (id == "readerBindings" || id == "signingKeyEnvelope") && pin.Snapshot.ByteLength > et.MetadataMaxBytes {
			return nil, d101custody.ErrUnavailable
		}
		pins[id] = pin
	}
	return pins, nil
}

func parseFixedRoleBindings(role Role, wire []byte, now time.Time) ([]et.RawReference, time.Time, error) {
	var names, refs, identities []string
	var event string
	switch role {
	case ApprovalIssuer:
		names = []string{"providerIdentity", "actorIdentity", "conversationIdentity", "eventIdentity", "originalIssuedAtUtc", "scopeDecisionRef", "authenticationRef"}
		refs = []string{"scopeDecisionRef", "authenticationRef"}
		identities = []string{"providerIdentity", "actorIdentity", "conversationIdentity", "eventIdentity"}
		event = "originalIssuedAtUtc"
	case OfficialGitHubCollector:
		names = []string{"repository", "requestMethod", "apiPath", "httpStatus", "requestId", "capturedAtUtc", "authenticationRef"}
		refs = []string{"authenticationRef"}
		identities = []string{"requestId"}
		event = "capturedAtUtc"
	case IndependentReviewCollector:
		names = []string{"backend", "reviewerId", "authorSessionId", "implementerSessionIds", "independenceEvidenceRef", "windowOriginalRef", "reportRef", "publicationRef", "issuedAtUnix", "publishedAtUtc", "authenticationRef"}
		refs = []string{"independenceEvidenceRef", "windowOriginalRef", "reportRef", "publicationRef", "authenticationRef"}
		identities = []string{"reviewerId", "authorSessionId"}
		event = "publishedAtUtc"
	default:
		return nil, time.Time{}, d101custody.ErrUnavailable
	}
	fields, err := exactObject(wire, names...)
	if err != nil {
		return nil, time.Time{}, err
	}
	text := func(name string) string {
		var s string
		if json.Unmarshal(fields[name], &s) != nil {
			return ""
		}
		return s
	}
	for _, name := range identities {
		if !identityPattern.MatchString(text(name)) {
			return nil, time.Time{}, d101custody.ErrUnavailable
		}
	}
	result := make([]et.RawReference, 0, len(refs))
	for _, name := range refs {
		ref, err := et.DecodeRawReference(fields[name])
		if err != nil {
			return nil, time.Time{}, err
		}
		result = append(result, ref)
	}
	if role == OfficialGitHubCollector {
		var status int
		if text("repository") != "peppone-choi/opensamguk" && text("repository") != "peppone-choi/opensamguk-docker" || text("requestMethod") != "GET" ||
			!strings.HasPrefix(text("apiPath"), "/") || json.Unmarshal(fields["httpStatus"], &status) != nil || status != 200 {
			return nil, time.Time{}, d101custody.ErrUnavailable
		}
	}
	at, err := recordUTC(text(event), now)
	if err != nil {
		return nil, time.Time{}, err
	}
	if role == IndependentReviewCollector {
		var implementers []string
		var issued int64
		if text("backend") != "claude-independent" && text("backend") != "codex-independent" || json.Unmarshal(fields["implementerSessionIds"], &implementers) != nil || len(implementers) < 1 || len(implementers) > 32 ||
			json.Unmarshal(fields["issuedAtUnix"], &issued) != nil || issued <= 0 || time.Unix(issued, 0).After(at) {
			return nil, time.Time{}, d101custody.ErrUnavailable
		}
		for _, id := range implementers {
			if !identityPattern.MatchString(id) || id == text("authorSessionId") {
				return nil, time.Time{}, d101custody.ErrUnavailable
			}
		}
	}
	return result, at, nil
}
