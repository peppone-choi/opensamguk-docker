package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"time"

	"opensamguk-deployer/internal/d101custody"
)

// Actual sources are absent by default. Shape validation below does not
// authenticate approval, custody, retention, host or execution permission.
type resetD101Key3DirectoryIdentity struct {
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
	OwnerUID uint32 `json:"ownerUid"`
	Mode     uint32 `json:"mode"`
}
type resetD101Key3NativeInitializationExpected struct {
	ExecutionScopeOriginalRef                           resetD101Key3OriginalRef
	InstallerPin                                        d101custody.NativeFilePin
	BaseDirectory, OnceParent, KeysParent, PublicParent resetD101Key3DirectoryIdentity
	// Exact value from actual independently authenticated execution approval.
	// Zero is unavailable; no local capacity number is substituted.
	MinimumAvailableBytes uint64
}
type resetD101Key3AuthenticatedSession struct {
	expected       resetD101Key3CeremonyExpected
	authentication resetD101Key3CeremonyAuthentication
	recheck        func(context.Context) error
}
type resetD101Key3NativeInitializationBinding struct {
	ceremonySHA, executionScopeSHA, hostInstanceID, sourceSHA, binarySHA string
	executionScopeOriginal                                               []byte
	observedAt                                                           time.Time
}
type resetD101Key3NativeInitializationSource interface {
	Authenticate(context.Context, *resetD101Key3AuthenticatedSession, resetD101Key3NativeInitializationExpected) (resetD101Key3NativeInitializationBinding, error)
	Recheck(context.Context, *resetD101Key3AuthenticatedSession, resetD101Key3NativeInitializationExpected, resetD101Key3NativeInitializationBinding) error
}

var resetD101ReviewedKey3NativeInitializationExpected *resetD101Key3NativeInitializationExpected
var resetD101ReviewedKey3NativeInitializationSource resetD101Key3NativeInitializationSource

type resetD101Key3NativeInitializationOutcome struct {
	attempted, complete bool // write progress, never authority
	err                 error
}

type resetD101Key3NativeExecutionScope struct {
	SchemaVersion                  uint32                         `json:"schemaVersion"`
	Kind                           string                         `json:"kind"`
	CeremonyCardSHA256             string                         `json:"ceremonyCardSha256"`
	HostInstanceID                 string                         `json:"hostInstanceId"`
	InitializerSourceSHA           string                         `json:"initializerSourceSha"`
	InitializerBinarySHA256        string                         `json:"initializerBinarySha256"`
	HumanApprovalOriginalRef       resetD101Key3OriginalRef       `json:"humanApprovalOriginalRef"`
	CustodianAssignmentOriginalRef resetD101Key3OriginalRef       `json:"custodianAssignmentOriginalRef"`
	PrivateRetentionOriginalRef    resetD101Key3OriginalRef       `json:"privateRetentionOriginalRef"`
	BasePath                       string                         `json:"basePath"`
	OnceClaim                      string                         `json:"onceClaim"`
	BaseDirectory                  resetD101Key3DirectoryIdentity `json:"baseDirectory"`
	OnceParent                     resetD101Key3DirectoryIdentity `json:"onceParent"`
	KeysParent                     resetD101Key3DirectoryIdentity `json:"keysParent"`
	PublicParent                   resetD101Key3DirectoryIdentity `json:"publicParent"`
	MinimumAvailableBytes          uint64                         `json:"minimumAvailableBytes"`
}

func resetD101Key3SourceMissing(source any) bool {
	if source == nil {
		return true
	}
	v := reflect.ValueOf(source)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func requireResetD101Key3NativeBinding(b resetD101Key3NativeInitializationBinding, session *resetD101Key3AuthenticatedSession, e resetD101Key3NativeInitializationExpected, now time.Time) error {
	if session == nil || session.recheck == nil {
		return errResetExecutionEvidence
	}
	c := session.expected.Card
	if !validResetD101Key3Ref(e.ExecutionScopeOriginalRef) || uint64(len(b.executionScopeOriginal)) != e.ExecutionScopeOriginalRef.Bytes ||
		resetD101OriginalSHA(b.executionScopeOriginal) != e.ExecutionScopeOriginalRef.SHA256 || b.executionScopeSHA != e.ExecutionScopeOriginalRef.SHA256 ||
		b.ceremonySHA != session.expected.CardSHA || b.hostInstanceID != c.HostInstanceID || b.sourceSHA != c.InitializerSourceSHA || b.binarySHA != c.InitializerBinarySHA256 ||
		b.observedAt.IsZero() || b.observedAt.After(now) || b.observedAt.Unix() < c.ValidFromUnix || now.Sub(b.observedAt) >= resetPreflightMaxAge || !validResetD101Key3Card(c, now) ||
		e.MinimumAvailableBytes == 0 || e.InstallerPin.SHA256 != c.InitializerBinarySHA256 || e.InstallerPin.OwnerUID != 0 || e.InstallerPin.FileMode != 0500 || e.InstallerPin.LinkCount != 1 ||
		e.InstallerPin.Snapshot.Device == 0 || e.InstallerPin.Snapshot.Inode == 0 || e.InstallerPin.Snapshot.ByteLength == 0 || e.InstallerPin.ParentOwnerUID != 0 || e.InstallerPin.ParentMode != 0700 ||
		e.InstallerPin.ParentSnapshot.Device == 0 || e.InstallerPin.ParentSnapshot.Inode == 0 {
		return errResetExecutionEvidence
	}
	for _, pin := range []resetD101Key3DirectoryIdentity{e.BaseDirectory, e.OnceParent, e.KeysParent, e.PublicParent} {
		if pin.Device == 0 || pin.Device != e.BaseDirectory.Device || pin.Inode == 0 || pin.OwnerUID != 0 || pin.Mode != 0700 {
			return errResetExecutionEvidence
		}
	}
	pins := []resetD101Key3DirectoryIdentity{e.BaseDirectory, e.OnceParent, e.KeysParent, e.PublicParent}
	for i := range pins {
		for j := 0; j < i; j++ {
			if pins[i].Inode == pins[j].Inode {
				return errResetExecutionEvidence
			}
		}
	}
	want := resetD101Key3NativeExecutionScope{1, "KEY3_NATIVE_INITIALIZATION", session.expected.CardSHA, c.HostInstanceID, c.InitializerSourceSHA, c.InitializerBinarySHA256,
		c.HumanApprovalOriginalRef, c.CustodianAssignmentOriginalRef, c.PrivateRetentionOriginalRef, "/etc/opensamguk/d101", ".once/key3-initialize", e.BaseDirectory, e.OnceParent, e.KeysParent, e.PublicParent, e.MinimumAvailableBytes}
	var actual resetD101Key3NativeExecutionScope
	if requireResetIntentShape(b.executionScopeOriginal, reflect.TypeOf(actual)) != nil || decodeResetPrivateJSON(b.executionScopeOriginal, &actual) != nil || !reflect.DeepEqual(want, actual) {
		return errResetExecutionEvidence
	}
	// uint fields reject negatives/decimals/exponents; explicitly reject -0 on
	// zero-valued nested ownerUid fields accepted by encoding/json.
	var fields map[string]json.RawMessage
	if decodeResetPrivateJSON(b.executionScopeOriginal, &fields) != nil {
		return errResetExecutionEvidence
	}
	for _, name := range []string{"baseDirectory", "onceParent", "keysParent", "publicParent"} {
		var pin map[string]json.RawMessage
		if decodeResetPrivateJSON(fields[name], &pin) != nil || string(pin["ownerUid"]) != "0" {
			return errResetExecutionEvidence
		}
	}
	return nil
}

type resetD101Key3GeneratedPublicRole struct {
	Role               string                    `json:"role"`
	CustodyID          string                    `json:"custodyId"`
	KeyID              string                    `json:"keyId"`
	EnvelopeSHA256     string                    `json:"envelopeSha256"`
	PublicDERBase64url string                    `json:"publicDerBase64url"`
	PublicSPKISHA256   string                    `json:"publicSpkiSha256"`
	PublicNativePin    d101custody.NativeFilePin `json:"publicNativePin"`
}
type resetD101Key3GeneratedPublicManifest struct {
	SchemaVersion             uint32                              `json:"schemaVersion"`
	Kind                      string                              `json:"kind"`
	CeremonyID                string                              `json:"ceremonyId"`
	CeremonyCardSHA256        string                              `json:"ceremonyCardSha256"`
	HostInstanceID            string                              `json:"hostInstanceId"`
	InitializerSourceSHA      string                              `json:"initializerSourceSha"`
	InitializerBinarySHA256   string                              `json:"initializerBinarySha256"`
	HumanApprovalSHA256       string                              `json:"humanApprovalSha256"`
	CustodianAssignmentSHA256 string                              `json:"custodianAssignmentSha256"`
	PrivateRetentionSHA256    string                              `json:"privateRetentionSha256"`
	ExecutionScopeSHA256      string                              `json:"executionScopeSha256"`
	StartedAtUnixNano         int64                               `json:"startedAtUnixNano"`
	CompletedAtUnixNano       int64                               `json:"completedAtUnixNano"`
	Roles                     [3]resetD101Key3GeneratedPublicRole `json:"roles"`
}

// Private memory only. It is neither authenticated custody nor a signing role.
type resetD101UntrustedKey3Material struct {
	role, custodyID, keyID     string
	privateEnvelope, publicDER []byte
	envelopeSHA, publicSPKISHA string
}

func (m *resetD101UntrustedKey3Material) close() { clear(m.privateEnvelope); m.privateEnvelope = nil }

// This pure helper has no filesystem, signing, activation or operation API.
// Only public deterministic fixture entropy invokes it in this local scope.
// Future production must fix crypto/rand after actual authorization, complete
// conflict checks and durable once BEFORE invoking it. CLI/env/card cannot
// select entropy. Partial/unknown preserves receipts and material, no retries.
func prepareResetD101UntrustedKey3(entropy io.Reader) ([]resetD101UntrustedKey3Material, error) {
	if entropy == nil {
		return nil, errResetExecutionEvidence
	}
	out := make([]resetD101UntrustedKey3Material, 0, 3)
	failed := true
	defer func() {
		if failed {
			for i := range out {
				out[i].close()
			}
		}
	}()
	for _, role := range []string{"root-purpose", "approval-issuer", "approved-receipt-issuer"} {
		id := make([]byte, 16)
		if _, err := io.ReadFull(entropy, id); err != nil {
			clear(id)
			return nil, errResetExecutionEvidence
		}
		custody := hex.EncodeToString(id)
		clear(id)
		seed := make([]byte, ed25519.SeedSize)
		if _, err := io.ReadFull(entropy, seed); err != nil {
			clear(seed)
			return nil, errResetExecutionEvidence
		}
		key := ed25519.NewKeyFromSeed(seed)
		clear(seed)
		der, err := x509.MarshalPKCS8PrivateKey(key)
		public, pubErr := x509.MarshalPKIXPublicKey(key.Public())
		clear(key)
		if err != nil || pubErr != nil || len(der) != 48 || len(public) != 44 {
			clear(der)
			return nil, errResetExecutionEvidence
		}
		keyID := "d101-" + role + "-" + custody
		if !resetD101KeyID.MatchString(keyID) {
			clear(der)
			return nil, errResetExecutionEvidence
		}
		envelope := resetD101SigningKeyEnvelope{1, keyID, base64.RawURLEncoding.EncodeToString(der), resetD101OriginalSHA(public)}
		clear(der)
		wire, err := json.Marshal(envelope)
		envelope.PrivateKeyPkcs8Base64url = ""
		if err != nil {
			clear(wire)
			return nil, errResetExecutionEvidence
		}
		for _, prior := range out {
			if prior.custodyID == custody || prior.keyID == keyID || prior.publicSPKISHA == resetD101OriginalSHA(public) {
				clear(wire)
				return nil, errResetExecutionEvidence
			}
		}
		out = append(out, resetD101UntrustedKey3Material{role, custody, keyID, wire, public, resetD101OriginalSHA(wire), resetD101OriginalSHA(public)})
	}
	failed = false
	return out, nil
}

func runResetD101Key3Initialization(ctx context.Context, cardSHA string) int {
	if ctx == nil || ctx.Err() != nil || !resetEvidenceSHA.MatchString(cardSHA) {
		return 2
	}
	source, p := resetD101ReviewedKey3NativeInitializationSource, resetD101ReviewedKey3NativeInitializationExpected
	// The unavailable source gate is before target reads, namespace and entropy.
	if resetD101Key3SourceMissing(source) || p == nil {
		return 2
	}
	expected := *p
	outcome := resetD101Key3NativeInitializationOutcome{}
	err := withResetD101ReviewedKey3Ceremony(ctx, cardSHA, func(session *resetD101Key3AuthenticatedSession) error {
		binding, err := source.Authenticate(ctx, session, expected)
		if err != nil || session.recheck(ctx) != nil || requireResetD101Key3NativeBinding(binding, session, expected, time.Now()) != nil || source.Recheck(ctx, session, expected, binding) != nil {
			return errResetExecutionEvidence
		}
		binding.executionScopeOriginal = append([]byte(nil), binding.executionScopeOriginal...)
		defer clear(binding.executionScopeOriginal)
		outcome = initializeResetD101Key3Native(ctx, session, expected, binding, source)
		return outcome.err
	})
	return resetD101Key3InitializationStatus(outcome, err)
}

func resetD101Key3InitializationStatus(outcome resetD101Key3NativeInitializationOutcome, err error) int {
	if err != nil || outcome.err != nil || !outcome.complete {
		if outcome.attempted {
			return 3
		}
		return 2
	}
	if !outcome.attempted {
		return 2
	}
	return 0
}
