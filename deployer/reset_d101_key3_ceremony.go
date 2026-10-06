package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
)

const resetD101Key3CardPath = "/etc/opensamguk/d101/key-provisioning-card.json"
const resetD101Key3CardMaxBytes = 32 << 10
const resetD101Key3RefMaxBytes = 16 << 20

// Transport references and native observations do not authenticate human intent.
// This codec is independent of the unapproved native9 codec/purpose.
type resetD101Key3OriginalRef struct {
	Path   string `json:"path"`
	Bytes  uint64 `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type resetD101Key3RoleScope struct {
	Role                      string                   `json:"role"`
	PrivateParent             string                   `json:"privateParent"`
	PublicPath                string                   `json:"publicPath"`
	AllowedPurposeOriginalRef resetD101Key3OriginalRef `json:"allowedPurposeOriginalRef"`
}
type resetD101Key3CeremonyCard struct {
	SchemaVersion                  uint32                   `json:"schemaVersion"`
	Kind                           string                   `json:"kind"`
	CeremonyID                     string                   `json:"ceremonyId"`
	HostInstanceID                 string                   `json:"hostInstanceId"`
	HostArchitecture               string                   `json:"hostArchitecture"`
	InstallerUID                   uint32                   `json:"installerUid"`
	InitializerSourceSHA           string                   `json:"initializerSourceSha"`
	InitializerBinarySHA256        string                   `json:"initializerBinarySha256"`
	HumanApprovalOriginalRef       resetD101Key3OriginalRef `json:"humanApprovalOriginalRef"`
	CustodianAssignmentOriginalRef resetD101Key3OriginalRef `json:"custodianAssignmentOriginalRef"`
	PrivateRetentionOriginalRef    resetD101Key3OriginalRef `json:"privateRetentionOriginalRef"`
	ValidFromUnix                  int64                    `json:"validFromUnix"`
	ValidUntilUnix                 int64                    `json:"validUntilUnix"`
	OncePolicy                     string                   `json:"oncePolicy"`
	PartialPolicy                  string                   `json:"partialPolicy"`
	RootPurpose                    resetD101Key3RoleScope   `json:"rootPurpose"`
	ApprovalIssuer                 resetD101Key3RoleScope   `json:"approvalIssuer"`
	ApprovedReceiptIssuer          resetD101Key3RoleScope   `json:"approvedReceiptIssuer"`
}

// Independent values are frozen before target reads. No target self-adoption.
type resetD101Key3CeremonyExpected struct {
	CardSHA                      string
	CardPin                      d101custody.NativeFilePin
	Card                         resetD101Key3CeremonyCard
	HumanAuthenticationSourceRef resetD101Key3OriginalRef
}
type resetD101UnverifiedKey3Ceremony struct {
	original []byte
	card     resetD101Key3CeremonyCard
}

func validResetD101Key3Ref(ref resetD101Key3OriginalRef) bool {
	return len(ref.Path) > 0 && len(ref.Path) <= 512 && utf8.ValidString(ref.Path) && strings.IndexFunc(ref.Path, unicode.IsControl) < 0 && filepath.IsAbs(ref.Path) && filepath.Clean(ref.Path) == ref.Path &&
		ref.Bytes > 0 && ref.Bytes <= resetD101Key3RefMaxBytes && resetEvidenceSHA.MatchString(ref.SHA256)
}
func validResetD101Key3Card(card resetD101Key3CeremonyCard, now time.Time) bool {
	host, err := strconv.ParseUint(card.HostInstanceID, 10, 64)
	if card.SchemaVersion != 1 || card.Kind != "KEY3_INITIALIZATION" || !lifecycleJobIDRe.MatchString(card.CeremonyID) ||
		err != nil || host == 0 || strconv.FormatUint(host, 10) != card.HostInstanceID || card.HostArchitecture != "linux/amd64" || card.InstallerUID != 0 ||
		!gitSHA40.MatchString(card.InitializerSourceSHA) || !resetEvidenceSHA.MatchString(card.InitializerBinarySHA256) ||
		card.ValidFromUnix <= 0 || card.ValidUntilUnix <= card.ValidFromUnix || now.Unix() < card.ValidFromUnix || now.Unix() >= card.ValidUntilUnix ||
		card.OncePolicy != "durable-before-entropy" || card.PartialPolicy != "preserve-no-retry" {
		return false
	}
	refs := []resetD101Key3OriginalRef{card.HumanApprovalOriginalRef, card.CustodianAssignmentOriginalRef, card.PrivateRetentionOriginalRef}
	roles := []resetD101Key3RoleScope{card.RootPurpose, card.ApprovalIssuer, card.ApprovedReceiptIssuer}
	names := []string{"root-purpose", "approval-issuer", "approved-receipt-issuer"}
	for i, role := range roles {
		if role.Role != names[i] || role.PrivateParent != "/etc/opensamguk/d101/keys/"+names[i] || role.PublicPath != "/etc/opensamguk/d101/key-public/"+names[i]+".spki" {
			return false
		}
		refs = append(refs, role.AllowedPurposeOriginalRef)
	}
	for _, ref := range refs {
		if !validResetD101Key3Ref(ref) {
			return false
		}
	}
	return true
}

// The result remains UNVERIFIED; decoding never manufactures authentication.
func decodeResetD101Key3Ceremony(wire []byte, expected resetD101Key3CeremonyExpected, now time.Time) (resetD101UnverifiedKey3Ceremony, error) {
	var card resetD101Key3CeremonyCard
	if len(wire) == 0 || len(wire) > resetD101Key3CardMaxBytes || !utf8.Valid(wire) || !resetEvidenceSHA.MatchString(expected.CardSHA) ||
		resetD101OriginalSHA(wire) != expected.CardSHA || requireResetIntentShape(wire, reflect.TypeOf(card)) != nil || decodeResetPrivateJSON(wire, &card) != nil ||
		!validResetD101Key3Card(card, now) || !reflect.DeepEqual(card, expected.Card) {
		return resetD101UnverifiedKey3Ceremony{}, errResetExecutionEvidence
	}
	// Reject exponent/decimal/negative-zero numeric aliases without reserializing
	// the original. Strict JSON decoding already rejects non-integer numbers.
	var fields map[string]json.RawMessage
	if decodeResetPrivateJSON(wire, &fields) != nil {
		return resetD101UnverifiedKey3Ceremony{}, errResetExecutionEvidence
	}
	for _, name := range []string{"schemaVersion", "installerUid", "validFromUnix", "validUntilUnix"} {
		raw := fields[name]
		n, err := strconv.ParseUint(string(raw), 10, 64)
		if err != nil || strconv.FormatUint(n, 10) != string(raw) {
			return resetD101UnverifiedKey3Ceremony{}, errResetExecutionEvidence
		}
	}
	return resetD101UnverifiedKey3Ceremony{append([]byte(nil), wire...), card}, nil
}

// The actual authentication provider must bind independently authenticated
// human/custodian/retention originals, current host and reviewed initializer.
// No positive implementation is supplied here. A bool, key self-signature or
// decoded card is not an authentication result.
type resetD101Key3CeremonyAuthentication struct {
	cardSHA, ceremonyID, hostInstanceID, sourceSHA, binarySHA                       string
	humanApproval, custodianAssignment, privateRetention, humanAuthenticationSource []byte
	observedAt                                                                      time.Time
}
type resetD101Key3CeremonyAuthenticationSource interface {
	Authenticate(context.Context, resetD101Key3CeremonyExpected, resetD101UnverifiedKey3Ceremony) (resetD101Key3CeremonyAuthentication, error)
	Recheck(context.Context, resetD101Key3CeremonyExpected, resetD101Key3CeremonyAuthentication) error
}

var resetD101ReviewedKey3CeremonyExpected *resetD101Key3CeremonyExpected
var resetD101ReviewedKey3CeremonySource resetD101Key3CeremonyAuthenticationSource

func requireResetD101Key3Authentication(a resetD101Key3CeremonyAuthentication, expected resetD101Key3CeremonyExpected, now time.Time) error {
	c := expected.Card
	if a.cardSHA != expected.CardSHA || a.ceremonyID != c.CeremonyID || a.hostInstanceID != c.HostInstanceID || a.sourceSHA != c.InitializerSourceSHA || a.binarySHA != c.InitializerBinarySHA256 ||
		a.observedAt.IsZero() || a.observedAt.After(now) || a.observedAt.Unix() < c.ValidFromUnix || a.observedAt.Unix() >= c.ValidUntilUnix || now.Sub(a.observedAt) >= resetPreflightMaxAge || !validResetD101Key3Card(c, now) {
		return errResetExecutionEvidence
	}
	originals := [][]byte{a.humanApproval, a.custodianAssignment, a.privateRetention, a.humanAuthenticationSource}
	refs := []resetD101Key3OriginalRef{c.HumanApprovalOriginalRef, c.CustodianAssignmentOriginalRef, c.PrivateRetentionOriginalRef, expected.HumanAuthenticationSourceRef}
	for i, ref := range refs {
		if !validResetD101Key3Ref(ref) || uint64(len(originals[i])) != ref.Bytes || resetD101OriginalSHA(originals[i]) != ref.SHA256 {
			return errResetExecutionEvidence
		}
	}
	return nil
}

// Hold actual authentication/card descriptors through the guarded consumer.
// This does not register any key or Root purpose authority.
func withResetD101ReviewedKey3Ceremony(ctx context.Context, sha string, consume func(*resetD101Key3AuthenticatedSession) error) error {
	source, p := resetD101ReviewedKey3CeremonySource, resetD101ReviewedKey3CeremonyExpected
	if consume == nil || ctx == nil || ctx.Err() != nil || resetD101Key3SourceMissing(source) || p == nil ||
		runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 || sha != p.CardSHA || !validResetD101Key3Ref(p.HumanAuthenticationSourceRef) {
		return errResetD101InstallationNotSupplied
	}
	expected := *p
	ctx, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
	defer cancel()
	if expected.Card.InitializerSourceSHA != rootBuiltSourceSHA || !validResetD101Key3Card(expected.Card, time.Now()) {
		return errResetExecutionEvidence
	}
	held, err := openResetD101NativeInput(ctx, resetD101Key3CardPath, expected.CardPin, 0400, 0)
	if err != nil {
		return err
	}
	defer held.close()
	parsed, err := decodeResetD101Key3Ceremony(held.wire, expected, time.Now())
	if err != nil {
		return err
	}
	a, err := source.Authenticate(ctx, expected, parsed)
	if err != nil || ctx.Err() != nil || requireResetD101Key3Authentication(a, expected, time.Now()) != nil {
		return errResetExecutionEvidence
	}
	// Retain our own authentication originals; provider-owned buffers cannot
	// mutate the retained result during subsequent rechecks.
	a.humanApproval = append([]byte(nil), a.humanApproval...)
	a.custodianAssignment = append([]byte(nil), a.custodianAssignment...)
	a.privateRetention = append([]byte(nil), a.privateRetention...)
	a.humanAuthenticationSource = append([]byte(nil), a.humanAuthenticationSource...)
	defer func() {
		clear(a.humanApproval)
		clear(a.custodianAssignment)
		clear(a.privateRetention)
		clear(a.humanAuthenticationSource)
	}()
	if ctx.Err() != nil || requireResetD101Key3Authentication(a, expected, time.Now()) != nil || held.recheck(ctx, 0) != nil || source.Recheck(ctx, expected, a) != nil ||
		ctx.Err() != nil || requireResetD101Key3Authentication(a, expected, time.Now()) != nil || held.recheck(ctx, 0) != nil {
		return errResetExecutionEvidence
	}
	// Keep actual originals and native card FD live throughout the writer.
	// No session is returned to a caller after the owner has closed its FD.
	session := &resetD101Key3AuthenticatedSession{expected: expected, authentication: a}
	session.recheck = func(current context.Context) error {
		if current == nil || current.Err() != nil || ctx.Err() != nil || requireResetD101Key3Authentication(a, expected, time.Now()) != nil || held.recheck(current, 0) != nil || source.Recheck(current, expected, a) != nil ||
			current.Err() != nil || requireResetD101Key3Authentication(a, expected, time.Now()) != nil || held.recheck(current, 0) != nil {
			return errResetExecutionEvidence
		}
		return nil
	}
	if session.recheck(ctx) != nil {
		return errResetExecutionEvidence
	}
	if err := consume(session); err != nil {
		return err
	}
	return session.recheck(ctx)
}
