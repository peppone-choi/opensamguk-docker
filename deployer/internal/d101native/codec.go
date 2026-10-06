package d101native

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const NativeAuthorityDomain = "OPENSAMGUK_D101_NATIVE_AUTHORITY_V1\n"

type NativeEnvelope struct {
	PayloadBase64url   string `json:"payloadBase64url"`
	KeyID              string `json:"keyId"`
	SignatureBase64url string `json:"signatureBase64url"`
}
type NativePin struct {
	Device       uint64 `json:"device"`
	Inode        uint64 `json:"inode"`
	OwnerUID     uint32 `json:"ownerUid"`
	Mode         uint32 `json:"mode"`
	Links        uint64 `json:"links"`
	ParentDevice uint64 `json:"parentDevice"`
	ParentInode  uint64 `json:"parentInode"`
}
type RawRef struct {
	Path   string    `json:"path"`
	Bytes  uint64    `json:"bytes"`
	SHA256 string    `json:"sha256"`
	Native NativePin `json:"native"`
}
type Process struct {
	PID              uint32 `json:"pid"`
	StartTicks       uint64 `json:"startTicks"`
	ParentPID        uint32 `json:"parentPid"`
	ParentStartTicks uint64 `json:"parentStartTicks"`
	ExePath          string `json:"exePath"`
	ExeSHA256        string `json:"exeSha256"`
	SourceSHA        string `json:"sourceSha"`
}
type Keeper struct {
	Process    Process   `json:"process"`
	BirthNonce string    `json:"birthNonce"`
	Lock       NativePin `json:"lock"`
	FD         uint32    `json:"fd"`
}

// No freeze, plan, receipt, acquisition, or future child reference in this base.
type PreBinding struct {
	SchemaVersion             uint32 `json:"schemaVersion"`
	OperationID               string `json:"operationId"`
	TargetFingerprint         string `json:"targetFingerprint"`
	PublicationRevision       string `json:"publicationRevision"`
	OriginalCutoffUnix        int64  `json:"originalCutoffUnix"`
	PreAcquisitionApprovalRef RawRef `json:"preAcquisitionApprovalRef"`
	IssuerIdentity            string `json:"issuerIdentity"`
	IssuerSPKISHA256          string `json:"issuerSpkiSha256"`
	Keeper                    Keeper `json:"keeper"`
	IssuedAtUTC               string `json:"issuedAtUtc"`
}

// sequence0 has no previous/ref-to-self. This file is additional to native9.
type Acquired struct {
	Binding  PreBinding         `json:"binding"`
	LeafKind string             `json:"leafKind"` // ACQUISITION
	Phase    string             `json:"phase"`    // ACQUIRED
	Sequence uint64             `json:"sequence"` // exactly0
	Payload  AcquisitionPayload `json:"payload"`
}
type AcquisitionPayload struct {
	LockObservedAtUTC    string `json:"lockObservedAtUtc"`
	ArtifactCustodyRef   RawRef `json:"artifactCustodyRef"`
	SourceConfinementRef RawRef `json:"sourceConfinementRef"`
	PurposeApprovalRef   RawRef `json:"purposeApprovalRef"`
}

// Every subsequent pre-freeze file requires an already retained acquisition.
type PreHeader struct {
	Binding             PreBinding `json:"binding"`
	LeafKind            string     `json:"leafKind"`
	Phase               string     `json:"phase"` // CLOSING, then FROZEN at sequence9
	Sequence            uint64     `json:"sequence"`
	PreviousOriginalRef RawRef     `json:"previousOriginalRef"`
	AcquisitionRef      RawRef     `json:"acquisitionRef"`
}
type WriterEntry struct {
	WriterID            string `json:"writerId"`
	WriterKind          string `json:"writerKind"`
	SourceSHA           string `json:"sourceSha"`
	ImageDigest         string `json:"imageDigest"`
	ObservedOriginalRef RawRef `json:"observedOriginalRef"`
}
type Inventory struct {
	Header               PreHeader     `json:"header"` // seq1 installed-writer-inventory
	Writers              []WriterEntry `json:"writers"`
	CompleteInventoryRef RawRef        `json:"completeInventoryRef"`
}
type ConsoleAdmission struct {
	Header              PreHeader `json:"header"`
	ConsoleInventoryRef RawRef    `json:"consoleInventoryRef"`
	SessionAdmissionRef RawRef    `json:"sessionAdmissionRef"`
	WorkflowClosureRefs []RawRef  `json:"workflowClosureRefs"`
	AdmissionOwnerRef   RawRef    `json:"admissionOwnerRef"`
	Inflight            uint32    `json:"inflight"`
	RestartBarrierRefs  []RawRef  `json:"restartBarrierRefs"`
}
type RootAdmission struct {
	Header                         PreHeader `json:"header"` // seq2 console-admission / seq3 root-admission
	CoordinatorRef                 RawRef    `json:"coordinatorRef"`
	CompleteJobsRef                RawRef    `json:"completeJobsRef"`
	CompleteOperationsRef          RawRef    `json:"completeOperationsRef"`
	CompleteDeferredTransitionsRef RawRef    `json:"completeDeferredTransitionsRef"`
	JournalOriginalRef             RawRef    `json:"journalOriginalRef"`
	MarkerOriginalRef              RawRef    `json:"markerOriginalRef"`
	AdmissionOwnerRef              RawRef    `json:"admissionOwnerRef"`
	Active                         uint32    `json:"active"`                // exactly0
	Preparing                      uint32    `json:"preparing"`             // exactly0
	SettlementPending              uint32    `json:"settlementPending"`     // exactly0
	JournalPending                 uint32    `json:"journalPending"`        // exactly0
	PendingJobs                    uint32    `json:"pendingJobs"`           // exactly0
	NonterminalOperations          uint32    `json:"nonterminalOperations"` // exactly0
	DeferredTransitions            uint32    `json:"deferredTransitions"`   // exactly0
}
type TurnFlush struct {
	Header             PreHeader `json:"header"` // seq4 turn-flush
	RunnerInventoryRef RawRef    `json:"runnerInventoryRef"`
	IntakeClosureRef   RawRef    `json:"intakeClosureRef"`
	FlushSettlementRef RawRef    `json:"flushSettlementRef"`
	ProcessExitRefs    []RawRef  `json:"processExitRefs"`
	RestartBarrierRefs []RawRef  `json:"restartBarrierRefs"`
}
type Publisher struct {
	Header                 PreHeader `json:"header"` // seq5 publisher
	PublisherInventoryRef  RawRef    `json:"publisherInventoryRef"`
	AdmissionClosureRef    RawRef    `json:"admissionClosureRef"`
	InflightSettlementRefs []RawRef  `json:"inflightSettlementRefs"`
	ProcessExitRefs        []RawRef  `json:"processExitRefs"`
	RestartBarrierRefs     []RawRef  `json:"restartBarrierRefs"`
}
type PostgresAdmission struct {
	Header                         PreHeader `json:"header"` // seq6 postgres-admission
	ClientInventoryRef             RawRef    `json:"clientInventoryRef"`
	ConnectionOriginalRef          RawRef    `json:"connectionOriginalRef"`
	PreparedTransactionOriginalRef RawRef    `json:"preparedTransactionOriginalRef"`
	ReconnectBarrierRefs           []RawRef  `json:"reconnectBarrierRefs"`
}
type OldServices struct {
	Header              PreHeader `json:"header"` // seq7 old-services
	ServiceInventoryRef RawRef    `json:"serviceInventoryRef"`
	ExitRefs            []RawRef  `json:"exitRefs"`
	RestartBarrierRefs  []RawRef  `json:"restartBarrierRefs"`
}
type KeeperSession struct {
	Header               PreHeader `json:"header"` // seq8 keeper-session
	OriginalInstallerRef RawRef    `json:"originalInstallerRef"`
	SourceConfinementRef RawRef    `json:"sourceConfinementRef"`
	BarrierOwnerRefs     []RawRef  `json:"barrierOwnerRefs"`
}
type Freeze struct {
	Header               PreHeader `json:"header"` // seq9 writer-freeze-receipt / FROZEN
	InventoryRef         RawRef    `json:"inventoryRef"`
	ConsoleAdmissionRef  RawRef    `json:"consoleAdmissionRef"`
	RootAdmissionRef     RawRef    `json:"rootAdmissionRef"`
	TurnFlushRef         RawRef    `json:"turnFlushRef"`
	PublisherRef         RawRef    `json:"publisherRef"`
	PostgresAdmissionRef RawRef    `json:"postgresAdmissionRef"`
	OldServicesRef       RawRef    `json:"oldServicesRef"`
	KeeperSessionRef     RawRef    `json:"keeperSessionRef"`
}

// Freeze wholeSHA is the actual retained envelope, never a hash of itself.
type PlanHeader struct {
	Pre                  PreHeader `json:"pre"`
	FreezeOriginalRef    RawRef    `json:"freezeOriginalRef"`
	ApprovedFinalPlanRef RawRef    `json:"approvedFinalPlanRef"`
}
type FinalBound struct {
	Header               PlanHeader `json:"header"` // seq10 FINAL_PLAN_BOUND
	FinalPlanApprovalRef RawRef     `json:"finalPlanApprovalRef"`
}

// Issuer starts BEFORE its execution receipt exists. No receipt field here.
type IssuerRunning struct {
	Header PlanHeader `json:"header"` // seq11 ISSUER_RUNNING
	Child  Process    `json:"child"`
}
type IssuerDone struct {
	Header                        PlanHeader `json:"header"` // seq12 ISSUER_DONE
	ChildExitRef                  RawRef     `json:"childExitRef"`
	ApprovalOriginRef             RawRef     `json:"approvalOriginRef"`
	ApprovedReceiptAttestationRef RawRef     `json:"approvedReceiptAttestationRef"`
	ApprovedReceiptProvenanceRef  RawRef     `json:"approvedReceiptProvenanceRef"`
	ExecutionReceiptRef           RawRef     `json:"executionReceiptRef"`
}
type PhysicalHeader struct {
	Plan                PlanHeader `json:"plan"`
	IssuerDoneRef       RawRef     `json:"issuerDoneRef"`
	ExecutionReceiptRef RawRef     `json:"executionReceiptRef"`
}
type PhysicalRunning struct {
	Header           PhysicalHeader `json:"header"` // seq13 PHYSICAL_RUNNING
	Child            Process        `json:"child"`
	BarrierOwnerRefs []RawRef       `json:"barrierOwnerRefs"`
}
type FiveImages struct {
	GameAPI      string `json:"game-api"`
	GameEngine   string `json:"game-engine"`
	WebGame      string `json:"web-game"`
	GamePostgres string `json:"game-postgres"`
	GameRedis    string `json:"game-redis"`
}

// Public certificate references the phase original; it is not a chain advance.
// Public projection is deliberately separate from private chain headers/paths.
type RelaySessionBinding struct {
	SchemaVersion          uint32     `json:"schemaVersion"`
	LeafKind               string     `json:"leafKind"`
	OperationID            string     `json:"operationId"`
	TargetFingerprint      string     `json:"targetFingerprint"`
	PublicationRevision    string     `json:"publicationRevision"`
	OriginalCutoffUnix     int64      `json:"originalCutoffUnix"`
	PhysicalPhaseSHA256    string     `json:"physicalPhaseSha256"`
	KeeperSessionSHA256    string     `json:"keeperSessionSha256"`
	ApprovedPlanSHA256     string     `json:"approvedPlanSha256"`
	ExecutionReceiptSHA256 string     `json:"executionReceiptSha256"`
	KeeperProcess          Process    `json:"keeperProcess"`
	KeeperBirthNonce       string     `json:"keeperBirthNonce"`
	Peer                   Process    `json:"peer"`
	ImageDigests           FiveImages `json:"imageDigests"`
}
type Released struct {
	Header                PhysicalHeader `json:"header"` // seq14 RELEASED
	ChildTerminalRef      RawRef         `json:"childTerminalRef"`
	WorkerAbsenceRef      RawRef         `json:"workerAbsenceRef"`
	HeldBarrierClosureRef RawRef         `json:"heldBarrierClosureRef"`
	ReleaseDecisionRef    RawRef         `json:"releaseDecisionRef"`
}
type RecoveredRelease struct {
	Header                   PhysicalHeader `json:"header"` // seq14 RECOVERED_RELEASED; alternate terminal
	ChildTerminalRef         RawRef         `json:"childTerminalRef"`
	WorkerAbsenceRef         RawRef         `json:"workerAbsenceRef"`
	HeldBarrierClosureRef    RawRef         `json:"heldBarrierClosureRef"`
	ReleaseDecisionRef       RawRef         `json:"releaseDecisionRef"`
	RecoveryClosureRef       RawRef         `json:"recoveryClosureRef"`
	RecoveryAuthorizationRef RawRef         `json:"recoveryAuthorizationRef"`
	RecoveryDeadlineUnix     int64          `json:"recoveryDeadlineUnix"`
	RecoveryAction           string         `json:"recoveryAction"`
}

// phase14 is a held release decision, not proof that the last FD was closed.
// Actual final-release observation is separate, unsigned, non-authoritative,
// and MUST NOT be referenced before it exists or advance this chain.
// HOLD is an internal retained state on any uncertainty, not permission to sign
// after cutoff, release FD9, advance/fork the chain, or produce a new operation.

const EnvelopeMaxBytes = 98304
const PayloadMaxBytes = 65536

var ErrUnavailable = errors.New("D101 native authority unavailable")
var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var sourcePattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var noncePattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func Hash(wire []byte) string  { s := sha256.Sum256(wire); return hex.EncodeToString(s[:]) }
func ValidSHA(s string) bool   { return shaPattern.MatchString(s) }
func ValidNonce(s string) bool { return noncePattern.MatchString(s) }
func validPath(s string) bool {
	return utf8.ValidString(s) && len(s) > 0 && len(s) <= 512 && filepath.IsAbs(s) && filepath.Clean(s) == s && strings.IndexFunc(s, unicode.IsControl) < 0
}
func ValidRef(r RawRef) bool {
	p := r.Native
	return validPath(r.Path) && r.Bytes > 0 && r.Bytes <= 16<<20 && ValidSHA(r.SHA256) && p.Device != 0 && p.Inode != 0 && p.OwnerUID == 0 && (p.Mode == 0400 || p.Mode == 0444) && p.Links == 1 && p.ParentDevice != 0 && p.ParentInode != 0
}
func ValidProcess(p Process) bool {
	return p.PID > 0 && p.StartTicks > 0 && p.ParentPID > 0 && p.ParentStartTicks > 0 && validPath(p.ExePath) && ValidSHA(p.ExeSHA256) && sourcePattern.MatchString(p.SourceSHA)
}
func validKeeper(k Keeper) bool {
	p := k.Lock
	return ValidProcess(k.Process) && ValidNonce(k.BirthNonce) && k.FD == 9 && p.Device != 0 && p.Inode != 0 && p.Links == 1
}
func ValidBinding(b PreBinding) bool {
	revision, e := strconv.ParseInt(b.PublicationRevision, 10, 64)
	at, e2 := time.Parse(time.RFC3339Nano, b.IssuedAtUTC)
	return b.SchemaVersion == 1 && ValidNonce(b.OperationID) && ValidSHA(b.TargetFingerprint) && e == nil && revision > 0 && strconv.FormatInt(revision, 10) == b.PublicationRevision && b.OriginalCutoffUnix > 0 && ValidRef(b.PreAcquisitionApprovalRef) && len(b.IssuerIdentity) > 0 && len(b.IssuerIdentity) <= 128 && ValidSHA(b.IssuerSPKISHA256) && validKeeper(b.Keeper) && e2 == nil && at.Format(time.RFC3339Nano) == b.IssuedAtUTC && at.Location() == time.UTC && at.Unix() > 0 && at.Unix() < b.OriginalCutoffUnix
}

// Decoder preserves raw bytes; signature verification cannot mint authority.
type SignaturePins struct {
	KeyID   string
	SPKIDER []byte
	Domain  string
}
type Unverified struct {
	original, payload []byte
	record            any
	pins              SignaturePins
}

func (u Unverified) Original() []byte        { return bytes.Clone(u.original) }
func (u Unverified) PayloadOriginal() []byte { return bytes.Clone(u.payload) }
func (u Unverified) Payload() any {
	if u.record == nil {
		return nil
	}
	v := reflect.New(reflect.TypeOf(u.record).Elem()).Interface()
	if json.Unmarshal(u.payload, v) != nil {
		return nil
	}
	return v
}
func (u Unverified) KeyID() string      { return u.pins.KeyID }
func (u Unverified) SPKISHA256() string { return Hash(u.pins.SPKIDER) }

// Token parser rejects duplicate keys at every nesting level before struct decode.
func readJSONValue(d *json.Decoder) (any, error) { return readJSONDepth(d, 0) }
func readJSONDepth(d *json.Decoder, depth int) (any, error) {
	if depth > 24 {
		return nil, ErrUnavailable
	}
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, e
				}
				key, ok := k.(string)
				if len(m) >= 256 {
					return nil, ErrUnavailable
				}
				if !ok {
					return nil, ErrUnavailable
				}
				if _, exists := m[key]; exists {
					return nil, ErrUnavailable
				}
				v, e := readJSONDepth(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[key] = v
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, ErrUnavailable
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				if len(a) >= 256 {
					return nil, ErrUnavailable
				}
				v, e := readJSONDepth(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, ErrUnavailable
			}
			return a, nil
		default:
			return nil, ErrUnavailable
		}
	}
	if t == nil {
		return nil, ErrUnavailable
	}
	return t, nil
}
func exactShape(v any, t reflect.Type) error {
	if v == nil {
		return ErrUnavailable
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok || len(m) != t.NumField() {
			return ErrUnavailable
		}
		for n := 0; n < t.NumField(); n++ {
			f := t.Field(n)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				return ErrUnavailable
			}
			x, ok := m[name]
			if !ok || exactShape(x, f.Type) != nil {
				return ErrUnavailable
			}
		}
	case reflect.Slice, reflect.Array:
		a, ok := v.([]any)
		if !ok || len(a) > 256 || (t.Kind() == reflect.Array && len(a) != t.Len()) {
			return ErrUnavailable
		}
		for _, x := range a {
			if exactShape(x, t.Elem()) != nil {
				return ErrUnavailable
			}
		}
	case reflect.String:
		s, ok := v.(string)
		if !ok || !utf8.ValidString(s) || strings.IndexFunc(s, unicode.IsControl) >= 0 {
			return ErrUnavailable
		}
	case reflect.Bool:
		if _, ok := v.(bool); !ok {
			return ErrUnavailable
		}
	case reflect.Uint, reflect.Uint32, reflect.Uint64, reflect.Int, reflect.Int32, reflect.Int64:
		n, ok := v.(json.Number)
		if !ok {
			return ErrUnavailable
		}
		s := string(n)
		if strings.HasPrefix(s, "-") {
			return ErrUnavailable
		}
		x, e := strconv.ParseUint(s, 10, t.Bits())
		if e != nil || strconv.FormatUint(x, 10) != s {
			return ErrUnavailable
		}
		if (t.Kind() == reflect.Int || t.Kind() == reflect.Int32 || t.Kind() == reflect.Int64) && x > uint64(^uint64(0)>>uint(65-t.Bits())) {
			return ErrUnavailable
		}
	default:
		return ErrUnavailable
	}
	return nil
}
func DecodeExact(wire []byte, output any, limit int) error {
	if len(wire) == 0 || len(wire) > limit || !utf8.Valid(wire) || output == nil {
		return ErrUnavailable
	}
	typ := reflect.TypeOf(output)
	if typ.Kind() != reflect.Pointer || reflect.ValueOf(output).IsNil() {
		return ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(wire))
	d.UseNumber()
	v, e := readJSONValue(d)
	if e != nil {
		return ErrUnavailable
	}
	if _, e = d.Token(); e != io.EOF || exactShape(v, typ) != nil {
		return ErrUnavailable
	}
	dec := json.NewDecoder(bytes.NewReader(wire))
	dec.DisallowUnknownFields()
	if dec.Decode(output) != nil {
		return ErrUnavailable
	}
	canonical, e := json.Marshal(output)
	if e != nil || !bytes.Equal(wire, canonical) {
		return ErrUnavailable
	}
	return nil
}
func chooseVariant(wire []byte) any {
	// This dispatch is untrusted; exact decode below rechecks the full tree.
	var v struct {
		LeafKind string
		Phase    string
		Header   struct {
			LeafKind string
			Phase    string
			Pre      struct {
				LeafKind string
				Phase    string
			}
			Plan struct {
				Pre struct {
					LeafKind string
					Phase    string
				}
			}
		}
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(wire, &m) != nil {
		return nil
	}
	_ = json.Unmarshal(m["leafKind"], &v.LeafKind)
	_ = json.Unmarshal(m["phase"], &v.Phase)
	var h map[string]json.RawMessage
	_ = json.Unmarshal(m["header"], &h)
	_ = json.Unmarshal(h["leafKind"], &v.Header.LeafKind)
	_ = json.Unmarshal(h["phase"], &v.Header.Phase)
	var pre map[string]json.RawMessage
	_ = json.Unmarshal(h["pre"], &pre)
	_ = json.Unmarshal(pre["phase"], &v.Header.Pre.Phase)
	var plan map[string]json.RawMessage
	_ = json.Unmarshal(h["plan"], &plan)
	var pp map[string]json.RawMessage
	_ = json.Unmarshal(plan["pre"], &pp)
	_ = json.Unmarshal(pp["phase"], &v.Header.Plan.Pre.Phase)
	if v.LeafKind == "ACQUISITION" {
		return &Acquired{}
	}
	if v.LeafKind == "RELAY_SESSION_BINDING" {
		return &RelaySessionBinding{}
	}
	switch v.Header.LeafKind {
	case "installed-writer-inventory":
		return &Inventory{}
	case "console-admission":
		return &ConsoleAdmission{}
	case "root-admission":
		return &RootAdmission{}
	case "turn-flush":
		return &TurnFlush{}
	case "publisher":
		return &Publisher{}
	case "postgres-admission":
		return &PostgresAdmission{}
	case "old-services":
		return &OldServices{}
	case "keeper-session":
		return &KeeperSession{}
	case "writer-freeze-receipt":
		return &Freeze{}
	}
	switch v.Header.Pre.Phase {
	case "FINAL_PLAN_BOUND":
		return &FinalBound{}
	case "ISSUER_RUNNING":
		return &IssuerRunning{}
	case "ISSUER_DONE":
		return &IssuerDone{}
	}
	switch v.Header.Plan.Pre.Phase {
	case "PHYSICAL_RUNNING":
		return &PhysicalRunning{}
	case "RELEASED":
		return &Released{}
	case "RECOVERED_RELEASED":
		return &RecoveredRelease{}
	}
	return nil
}
func Decode(wire []byte, pins SignaturePins) (Unverified, error) {
	if pins.Domain != NativeAuthorityDomain || !keyPattern.MatchString(pins.KeyID) || len(pins.SPKIDER) != 44 || !bytes.Equal(pins.SPKIDER[:12], []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0}) {
		return Unverified{}, ErrUnavailable
	}
	parsed, e := x509.ParsePKIXPublicKey(pins.SPKIDER)
	key, ok := parsed.(ed25519.PublicKey)
	if e != nil || !ok {
		return Unverified{}, ErrUnavailable
	}
	var env NativeEnvelope
	if DecodeExact(wire, &env, EnvelopeMaxBytes) != nil || env.KeyID != pins.KeyID {
		return Unverified{}, ErrUnavailable
	}
	body, e := base64.RawURLEncoding.Strict().DecodeString(env.PayloadBase64url)
	sig, e2 := base64.RawURLEncoding.Strict().DecodeString(env.SignatureBase64url)
	if e != nil || e2 != nil || len(sig) != 64 || len(body) == 0 || len(body) > PayloadMaxBytes || base64.RawURLEncoding.EncodeToString(body) != env.PayloadBase64url || base64.RawURLEncoding.EncodeToString(sig) != env.SignatureBase64url {
		return Unverified{}, ErrUnavailable
	}
	v := chooseVariant(body)
	if v == nil || DecodeExact(body, v, PayloadMaxBytes) != nil || validateRecord(v) != nil {
		return Unverified{}, ErrUnavailable
	}
	if header, private := HeaderOf(v); private && header.Binding.IssuerSPKISHA256 != Hash(pins.SPKIDER) {
		return Unverified{}, ErrUnavailable
	}
	preimage := append([]byte(pins.Domain), body...)
	if !ed25519.Verify(key, preimage, sig) {
		return Unverified{}, ErrUnavailable
	}
	pins.SPKIDER = bytes.Clone(pins.SPKIDER)
	return Unverified{bytes.Clone(wire), bytes.Clone(body), v, pins}, nil
}
func EncodeEnvelope(payload []byte, keyID string, signature []byte) ([]byte, error) {
	if !keyPattern.MatchString(keyID) || len(signature) != 64 {
		return nil, ErrUnavailable
	}
	v := chooseVariant(payload)
	if v == nil || DecodeExact(payload, v, PayloadMaxBytes) != nil || validateRecord(v) != nil {
		return nil, ErrUnavailable
	}
	b, e := json.Marshal(NativeEnvelope{base64.RawURLEncoding.EncodeToString(payload), keyID, base64.RawURLEncoding.EncodeToString(signature)})
	if e != nil || len(b) > EnvelopeMaxBytes {
		return nil, ErrUnavailable
	}
	return b, nil
}
func HeaderOf(v any) (PreHeader, bool) {
	switch x := v.(type) {
	case *Acquired:
		return PreHeader{Binding: x.Binding, LeafKind: x.LeafKind, Phase: x.Phase, Sequence: x.Sequence}, true
	case *Inventory:
		return x.Header, true
	case *ConsoleAdmission:
		return x.Header, true
	case *RootAdmission:
		return x.Header, true
	case *TurnFlush:
		return x.Header, true
	case *Publisher:
		return x.Header, true
	case *PostgresAdmission:
		return x.Header, true
	case *OldServices:
		return x.Header, true
	case *KeeperSession:
		return x.Header, true
	case *Freeze:
		return x.Header, true
	case *FinalBound:
		return x.Header.Pre, true
	case *IssuerRunning:
		return x.Header.Pre, true
	case *IssuerDone:
		return x.Header.Pre, true
	case *PhysicalRunning:
		return x.Header.Plan.Pre, true
	case *Released:
		return x.Header.Plan.Pre, true
	case *RecoveredRelease:
		return x.Header.Plan.Pre, true
	}
	return PreHeader{}, false
}
func refsIn(v reflect.Value, out *[]RawRef) {
	if !v.IsValid() {
		return
	}
	if v.Kind() == reflect.Pointer {
		if !v.IsNil() {
			refsIn(v.Elem(), out)
		}
		return
	}
	if v.Type() == reflect.TypeOf(RawRef{}) {
		*out = append(*out, v.Interface().(RawRef))
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			refsIn(v.Field(i), out)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			refsIn(v.Index(i), out)
		}
	}
}
func References(v any) []RawRef { out := []RawRef{}; refsIn(reflect.ValueOf(v), &out); return out }
func validateRecord(v any) error {
	if pub, ok := v.(*RelaySessionBinding); ok {
		revision, e := strconv.ParseInt(pub.PublicationRevision, 10, 64)
		if pub.SchemaVersion != 1 || pub.LeafKind != "RELAY_SESSION_BINDING" || !ValidNonce(pub.OperationID) || !ValidSHA(pub.TargetFingerprint) || e != nil || revision <= 0 || strconv.FormatInt(revision, 10) != pub.PublicationRevision || pub.OriginalCutoffUnix <= 0 || !ValidSHA(pub.PhysicalPhaseSHA256) || !ValidSHA(pub.KeeperSessionSHA256) || !ValidSHA(pub.ApprovedPlanSHA256) || !ValidSHA(pub.ExecutionReceiptSHA256) || !ValidProcess(pub.KeeperProcess) || !ValidNonce(pub.KeeperBirthNonce) || !ValidProcess(pub.Peer) {
			return ErrUnavailable
		}
		for _, im := range []string{pub.ImageDigests.GameAPI, pub.ImageDigests.GameEngine, pub.ImageDigests.WebGame, pub.ImageDigests.GamePostgres, pub.ImageDigests.GameRedis} {
			if !strings.HasPrefix(im, "sha256:") || !ValidSHA(strings.TrimPrefix(im, "sha256:")) {
				return ErrUnavailable
			}
		}
		return nil
	}
	h, ok := HeaderOf(v)
	if !ok || !ValidBinding(h.Binding) || h.Sequence > 14 {
		return ErrUnavailable
	}
	for _, r := range References(v) {
		if !ValidRef(r) {
			return ErrUnavailable
		}
	}
	if h.Sequence > 0 && (!ValidRef(h.PreviousOriginalRef) || !ValidRef(h.AcquisitionRef)) {
		return ErrUnavailable
	}
	kind := []string{"ACQUISITION", "installed-writer-inventory", "console-admission", "root-admission", "turn-flush", "publisher", "postgres-admission", "old-services", "keeper-session", "writer-freeze-receipt", "FINAL_PLAN_BOUND", "ISSUER_RUNNING", "ISSUER_DONE", "PHYSICAL_RUNNING", ""}
	phase := "CLOSING"
	if h.Sequence == 0 {
		phase = "ACQUIRED"
	}
	if h.Sequence == 9 {
		phase = "FROZEN"
	}
	if h.Sequence >= 10 && h.Sequence < 14 {
		phase = kind[h.Sequence]
	}
	if h.Sequence < 14 && h.LeafKind != kind[h.Sequence] {
		return ErrUnavailable
	}
	if h.Sequence < 14 && h.Phase != phase {
		return ErrUnavailable
	}
	switch x := v.(type) {
	case *Acquired:
		if h.Sequence != 0 || !validOriginalUTC(x.Payload.LockObservedAtUTC, h.Binding.OriginalCutoffUnix) {
			return ErrUnavailable
		}
	case *Inventory:
		if h.Sequence != 1 || len(x.Writers) == 0 || len(x.Writers) > 256 {
			return ErrUnavailable
		}
		seen := map[string]bool{}
		for _, w := range x.Writers {
			if w.WriterID == "" || w.WriterKind == "" || seen[w.WriterID] || !sourcePattern.MatchString(w.SourceSHA) || !strings.HasPrefix(w.ImageDigest, "sha256:") || !ValidSHA(strings.TrimPrefix(w.ImageDigest, "sha256:")) {
				return ErrUnavailable
			}
			seen[w.WriterID] = true
		}
	case *ConsoleAdmission:
		if h.Sequence != 2 || x.Inflight != 0 || len(x.WorkflowClosureRefs) == 0 || len(x.RestartBarrierRefs) == 0 {
			return ErrUnavailable
		}
	case *RootAdmission:
		if h.Sequence != 3 || x.Active != 0 || x.Preparing != 0 || x.SettlementPending != 0 || x.JournalPending != 0 || x.PendingJobs != 0 || x.NonterminalOperations != 0 || x.DeferredTransitions != 0 {
			return ErrUnavailable
		}
	case *TurnFlush:
		if h.Sequence != 4 || len(x.ProcessExitRefs) == 0 || len(x.RestartBarrierRefs) == 0 {
			return ErrUnavailable
		}
	case *Publisher:
		if h.Sequence != 5 || len(x.InflightSettlementRefs) == 0 || len(x.ProcessExitRefs) == 0 || len(x.RestartBarrierRefs) == 0 {
			return ErrUnavailable
		}
	case *PostgresAdmission:
		if h.Sequence != 6 || len(x.ReconnectBarrierRefs) == 0 {
			return ErrUnavailable
		}
	case *OldServices:
		if h.Sequence != 7 || len(x.ExitRefs) == 0 || len(x.RestartBarrierRefs) == 0 {
			return ErrUnavailable
		}
	case *KeeperSession:
		if h.Sequence != 8 || len(x.BarrierOwnerRefs) == 0 {
			return ErrUnavailable
		}
	case *Freeze:
		if h.Sequence != 9 {
			return ErrUnavailable
		}
	case *FinalBound:
		if h.Sequence != 10 {
			return ErrUnavailable
		}
	case *IssuerRunning:
		if h.Sequence != 11 || !ValidProcess(x.Child) {
			return ErrUnavailable
		}
	case *IssuerDone:
		if h.Sequence != 12 {
			return ErrUnavailable
		}
	case *PhysicalRunning:
		if h.Sequence != 13 || !ValidProcess(x.Child) || len(x.BarrierOwnerRefs) == 0 {
			return ErrUnavailable
		}
	case *Released:
		if h.Sequence != 14 || h.Phase != "RELEASED" {
			return ErrUnavailable
		}
	case *RecoveredRelease:
		if h.Sequence != 14 || h.Phase != "RECOVERED_RELEASED" || x.RecoveryDeadlineUnix <= 0 || x.RecoveryAction == "" {
			return ErrUnavailable
		}
	default:
		return ErrUnavailable
	}
	return nil
}

func DecodePayload(wire []byte) (any, error) {
	v := chooseVariant(wire)
	if v == nil || DecodeExact(wire, v, PayloadMaxBytes) != nil || validateRecord(v) != nil {
		return nil, ErrUnavailable
	}
	return v, nil
}

func validOriginalUTC(value string, deadline int64) bool {
	v, e := time.Parse(time.RFC3339Nano, value)
	return e == nil && v.Location() == time.UTC && v.Format(time.RFC3339Nano) == value && v.Unix() > 0 && v.Unix() < deadline
}
