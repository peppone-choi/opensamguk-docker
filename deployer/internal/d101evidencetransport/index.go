package d101evidencetransport

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"opensamguk-deployer/internal/d101custody"
)

const IndexPath = "/etc/opensamguk/d101/evidence-source-index.json"
const SourcePinPath = "/etc/opensamguk/d101/evidence-source-pin.json"
const PageDirectory = "/etc/opensamguk/d101/evidence-pages"
const OriginalDirectory = "/etc/opensamguk/d101/evidence-originals"
const PublicProfileDirectory = "/etc/opensamguk/d101/evidence-origin-public"
const SourceNamespace = "D101_EVIDENCE_SOURCE_V1"
const IndexKind = "D101_EVIDENCE_SOURCE_INDEX_V1"
const SourcePinKind = "D101_EVIDENCE_SOURCE_PIN_V1"
const BranchKind = "D101_EVIDENCE_BRANCH_PAGE_V1"
const LeafKind = "D101_EVIDENCE_LEAF_PAGE_V1"
const ApprovalRole = "APPROVAL_ISSUER"
const GitHubRole = "OFFICIAL_GITHUB_COLLECTOR"
const ReviewRole = "INDEPENDENT_REVIEW_COLLECTOR"

var identityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
var prefixPattern = regexp.MustCompile(`^[0-9a-f]{0,64}$`)

type PageReference struct {
	Prefix     string                      `json:"prefix"`
	SHA256     string                      `json:"sha256"`
	ByteLength uint64                      `json:"byteLength"`
	Snapshot   d101custody.PrivateSnapshot `json:"nativeSnapshot"`
}
type Index struct {
	SchemaVersion        int            `json:"schemaVersion"`
	Kind                 string         `json:"kind"`
	Scope                Scope          `json:"scope"`
	PartBytes            uint64         `json:"partBytes"`
	CollectorIdentity    string         `json:"collectorIdentity"`
	CollectorSource      RawReference   `json:"collectorSourceRef"`
	CollectorImageDigest string         `json:"collectorImageDigest"`
	RootPage             PageReference  `json:"rootPage"`
	OriginProofs         []RawReference `json:"originProofRefs"`
	CapturedAtUnix       int64          `json:"capturedAtUnix"`
}
type PublicPin struct {
	Role           string       `json:"role"`
	PublicProfile  RawReference `json:"publicProfileRef"`
	VerifierSource RawReference `json:"verifierSourceRef"`
	NativeCustody  RawReference `json:"nativeCustodyRef"`
}
type SourcePin struct {
	SchemaVersion         int                         `json:"schemaVersion"`
	Kind                  string                      `json:"kind"`
	Scope                 Scope                       `json:"scope"`
	ReaderBindingsSHA256  string                      `json:"readerBindingsSha256"`
	EvidenceIndexSHA256   string                      `json:"evidenceIndexSha256"`
	EvidenceIndexSnapshot d101custody.PrivateSnapshot `json:"evidenceIndexSnapshot"`
	HelperSHA256          string                      `json:"helperSha256"`
	CollectorSource       RawReference                `json:"collectorSourceRef"`
	CollectorImageDigest  string                      `json:"collectorImageDigest"`
	CollectorIdentity     string                      `json:"collectorIdentity"`
	InstallerSource       RawReference                `json:"installerSourceRef"`
	OriginPins            []PublicPin                 `json:"originPins"`
	Namespace             string                      `json:"namespace"`
}

func ValidateSnapshot(value d101custody.PrivateSnapshot) error {
	if value.Device == 0 || value.Inode == 0 || value.ByteLength == 0 || value.ByteLength > OriginalMaxBytes || value.ModifiedAtUnixNano <= 0 {
		return d101custody.ErrUnavailable
	}
	return nil
}
func ValidatePageReference(value PageReference) error {
	if !prefixPattern.MatchString(value.Prefix) || !shaPattern.MatchString(value.SHA256) || value.ByteLength == 0 || value.ByteLength > MetadataMaxBytes ||
		ValidateSnapshot(value.Snapshot) != nil || value.Snapshot.ByteLength != value.ByteLength {
		return d101custody.ErrUnavailable
	}
	return nil
}
func ValidateIndex(value Index) error {
	if value.SchemaVersion != 1 || value.Kind != IndexKind || ValidateScope(value.Scope) != nil || value.PartBytes != d101custody.PrivateOriginalPartBytes ||
		!identityPattern.MatchString(value.CollectorIdentity) || ValidateRawReference(value.CollectorSource) != nil || !validImageDigest(value.CollectorImageDigest) ||
		ValidatePageReference(value.RootPage) != nil || value.RootPage.Prefix != "" || value.OriginProofs == nil || value.CapturedAtUnix <= 0 {
		return d101custody.ErrUnavailable
	}
	for _, ref := range value.OriginProofs {
		if ValidateRawReference(ref) != nil {
			return d101custody.ErrUnavailable
		}
	}
	return nil
}
func DecodeIndex(wire []byte) (Index, error) {
	var value Index
	if decodeExact(wire, &value, MetadataMaxBytes) != nil || ValidateIndex(value) != nil {
		return Index{}, d101custody.ErrUnavailable
	}
	return value, nil // [] proofs is data-only format, never sufficient origin authority.
}
func validImageDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && shaPattern.MatchString(strings.TrimPrefix(value, "sha256:"))
}
func validRole(role string) bool {
	return role == ApprovalRole || role == GitHubRole || role == ReviewRole
}
func ValidateSourcePin(value SourcePin) error {
	if value.SchemaVersion != 1 || value.Kind != SourcePinKind || value.Namespace != SourceNamespace || ValidateScope(value.Scope) != nil ||
		!shaPattern.MatchString(value.ReaderBindingsSHA256) || !shaPattern.MatchString(value.EvidenceIndexSHA256) || !shaPattern.MatchString(value.HelperSHA256) ||
		ValidateSnapshot(value.EvidenceIndexSnapshot) != nil || ValidateRawReference(value.CollectorSource) != nil || ValidateRawReference(value.InstallerSource) != nil ||
		!identityPattern.MatchString(value.CollectorIdentity) || !validImageDigest(value.CollectorImageDigest) || value.OriginPins == nil {
		return d101custody.ErrUnavailable
	}
	seen := map[string]bool{}
	for _, pin := range value.OriginPins {
		if !validRole(pin.Role) || seen[pin.Role] || ValidateRawReference(pin.PublicProfile) != nil || ValidateRawReference(pin.VerifierSource) != nil || ValidateRawReference(pin.NativeCustody) != nil {
			return d101custody.ErrUnavailable
		}
		seen[pin.Role] = true
	}
	return nil
}
func DecodeSourcePin(wire []byte) (SourcePin, error) {
	var value SourcePin
	if decodeExact(wire, &value, MetadataMaxBytes) != nil || ValidateSourcePin(value) != nil {
		return SourcePin{}, d101custody.ErrUnavailable
	}
	return value, nil
}

// Byte/scope binding only. The expected source pin SHA and snapshot themselves
// must first come from the independent fixed installation's native constructor.
func RequireSourcePinIndexBinding(pin SourcePin, indexOriginal []byte) (Index, error) {
	value, err := DecodeIndex(indexOriginal)
	if err != nil || ValidateSourcePin(pin) != nil || HashOriginal(indexOriginal) != pin.EvidenceIndexSHA256 || uint64(len(indexOriginal)) != pin.EvidenceIndexSnapshot.ByteLength ||
		!reflect.DeepEqual(value.Scope, pin.Scope) || value.CollectorIdentity != pin.CollectorIdentity || value.CollectorSource != pin.CollectorSource || value.CollectorImageDigest != pin.CollectorImageDigest {
		return Index{}, d101custody.ErrUnavailable
	}
	return value, nil
}
func HashOriginal(wire []byte) string  { sum := sha256.Sum256(wire); return hex.EncodeToString(sum[:]) }
func LogicalIDDigest(id string) string { return HashOriginal([]byte(id)) }
func PagePath(op string, ref PageReference) (string, error) {
	if !opPattern.MatchString(op) || ValidatePageReference(ref) != nil {
		return "", d101custody.ErrUnavailable
	}
	return filepath.Join(PageDirectory, op, ref.SHA256+".json"), nil
}
func OriginalPath(op, id string) (string, error) {
	if !opPattern.MatchString(op) || !rawIDPattern.MatchString(id) || len(id) > 128 {
		return "", d101custody.ErrUnavailable
	}
	return filepath.Join(OriginalDirectory, op, LogicalIDDigest(id)+".bin"), nil
}
func PublicProfilePath(role string) (string, error) {
	if !validRole(role) {
		return "", d101custody.ErrUnavailable
	}
	return filepath.Join(PublicProfileDirectory, role, "profile.json"), nil
}
