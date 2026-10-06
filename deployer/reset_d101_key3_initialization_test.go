package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Entirely public fixture inputs. These are not actual actors, custody,
// authentication or installation approval; no positive provider is installed.
func key3PublicFixture(t *testing.T) ([]byte, resetD101Key3CeremonyExpected, time.Time) {
	t.Helper()
	now := time.Unix(2000000000, 0)
	ref := func(name string) resetD101Key3OriginalRef {
		wire := []byte("public fixture " + name)
		return resetD101Key3OriginalRef{"/fixture/" + name, uint64(len(wire)), resetD101OriginalSHA(wire)}
	}
	role := func(name string) resetD101Key3RoleScope {
		return resetD101Key3RoleScope{name, "/etc/opensamguk/d101/keys/" + name, "/etc/opensamguk/d101/key-public/" + name + ".spki", ref(name)}
	}
	card := resetD101Key3CeremonyCard{
		SchemaVersion: 1, Kind: "KEY3_INITIALIZATION", CeremonyID: strings.Repeat("a", 32), HostInstanceID: "123456789",
		HostArchitecture: "linux/amd64", InstallerUID: 0, InitializerSourceSHA: strings.Repeat("b", 40), InitializerBinarySHA256: strings.Repeat("c", 64),
		HumanApprovalOriginalRef: ref("human"), CustodianAssignmentOriginalRef: ref("custodian"), PrivateRetentionOriginalRef: ref("retention"),
		ValidFromUnix: now.Unix() - 10, ValidUntilUnix: now.Unix() + 60, OncePolicy: "durable-before-entropy", PartialPolicy: "preserve-no-retry",
		RootPurpose: role("root-purpose"), ApprovalIssuer: role("approval-issuer"), ApprovedReceiptIssuer: role("approved-receipt-issuer"),
	}
	wire, err := json.Marshal(card)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	return wire, resetD101Key3CeremonyExpected{CardSHA: resetD101OriginalSHA(wire), Card: card, HumanAuthenticationSourceRef: ref("authentication")}, now
}

func TestKey3CeremonyStrictOriginalAndIndependentExpected(t *testing.T) {
	wire, expected, now := key3PublicFixture(t)
	original := append([]byte(" \n"), wire...)
	original = append(original, '\n')
	expected.CardSHA = resetD101OriginalSHA(original)
	decoded, err := decodeResetD101Key3Ceremony(original, expected, now)
	if err != nil || !bytes.Equal(decoded.original, original) || !reflect.DeepEqual(decoded.card, expected.Card) {
		t.Fatal("exact original was not preserved")
	}
	original[0] = '\t'
	if decoded.original[0] != ' ' {
		t.Fatal("decoded original aliases caller memory")
	}
	independent := expected
	independent.Card.HostInstanceID = "987654321"
	if _, err := decodeResetD101Key3Ceremony(decoded.original, independent, now); err == nil {
		t.Fatal("target adopted independent expected values")
	}
	if _, err := decodeResetD101Key3Ceremony(original, expected, now); err == nil {
		t.Fatal("modified original retained previous digest")
	}
}

func TestKey3CeremonyRejectsStrictShapeAndNumericAliases(t *testing.T) {
	wire, expected, now := key3PublicFixture(t)
	cases := map[string][]byte{
		"duplicate-root":   []byte(strings.Replace(string(wire), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1)),
		"duplicate-nested": []byte(strings.Replace(string(wire), `"bytes":20`, `"bytes":20,"bytes":20`, 1)),
		"unknown-root":     []byte(strings.Replace(string(wire), `"schemaVersion":1`, `"extra":true,"schemaVersion":1`, 1)),
		"unknown-nested":   []byte(strings.Replace(string(wire), `"path":"/fixture/human"`, `"extra":true,"path":"/fixture/human"`, 1)),
		"missing-root":     []byte(strings.Replace(string(wire), `"schemaVersion":1,`, "", 1)),
		"missing-nested":   []byte(strings.Replace(string(wire), `"path":"/fixture/human",`, "", 1)),
		"null-root":        []byte("null"),
		"null-nested":      []byte(strings.Replace(string(wire), `"path":"/fixture/human"`, `"path":null`, 1)),
		"wrong-type":       []byte(strings.Replace(string(wire), `"installerUid":0`, `"installerUid":"0"`, 1)),
		"negative-zero":    []byte(strings.Replace(string(wire), `"installerUid":0`, `"installerUid":-0`, 1)),
		"decimal":          []byte(strings.Replace(string(wire), `"schemaVersion":1`, `"schemaVersion":1.0`, 1)),
		"exponent":         []byte(strings.Replace(string(wire), `"schemaVersion":1`, `"schemaVersion":1e0`, 1)),
		"overflow":         []byte(strings.Replace(string(wire), `"schemaVersion":1`, `"schemaVersion":4294967296`, 1)),
		"field-case":       []byte(strings.Replace(string(wire), `"schemaVersion":1`, `"SchemaVersion":1`, 1)),
		"trailing-value":   append(append([]byte(nil), wire...), []byte(" {}")...),
		"invalid-utf8":     append(append([]byte(nil), wire...), 0xff),
		"oversize":         bytes.Repeat([]byte(" "), resetD101Key3CardMaxBytes+1),
		"empty":            nil,
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(bad, wire) {
				t.Fatal("mutation did not change fixture")
			}
			e := expected
			e.CardSHA = resetD101OriginalSHA(bad)
			if _, err := decodeResetD101Key3Ceremony(bad, e, now); err == nil {
				t.Fatal("ambiguous ceremony accepted")
			}
		})
	}
}

func TestKey3CeremonyRejectsScopeRefAndTimeBounds(t *testing.T) {
	_, expected, now := key3PublicFixture(t)
	mutations := map[string]func(*resetD101Key3CeremonyCard){
		"wrong-kind":       func(c *resetD101Key3CeremonyCard) { c.Kind = "KEY4_INITIALIZATION" },
		"wrong-role":       func(c *resetD101Key3CeremonyCard) { c.RootPurpose.Role = "approval-issuer" },
		"private-parent":   func(c *resetD101Key3CeremonyCard) { c.RootPurpose.PrivateParent += "/alternate" },
		"public-path":      func(c *resetD101Key3CeremonyCard) { c.RootPurpose.PublicPath = "/tmp/public" },
		"relative-ref":     func(c *resetD101Key3CeremonyCard) { c.HumanApprovalOriginalRef.Path = "fixture/human" },
		"noncanonical-ref": func(c *resetD101Key3CeremonyCard) { c.HumanApprovalOriginalRef.Path = "/fixture/../human" },
		"nul-ref":          func(c *resetD101Key3CeremonyCard) { c.HumanApprovalOriginalRef.Path = "/fixture/hu\x00man" },
		"control-ref":      func(c *resetD101Key3CeremonyCard) { c.HumanApprovalOriginalRef.Path = "/fixture/hu\nman" },
		"long-ref":         func(c *resetD101Key3CeremonyCard) { c.HumanApprovalOriginalRef.Path = "/" + strings.Repeat("a", 512) },
		"empty-ref":        func(c *resetD101Key3CeremonyCard) { c.HumanApprovalOriginalRef.Bytes = 0 },
		"oversize-ref":     func(c *resetD101Key3CeremonyCard) { c.HumanApprovalOriginalRef.Bytes = resetD101Key3RefMaxBytes + 1 },
		"uppercase-sha":    func(c *resetD101Key3CeremonyCard) { c.HumanApprovalOriginalRef.SHA256 = strings.Repeat("A", 64) },
		"host-alias":       func(c *resetD101Key3CeremonyCard) { c.HostInstanceID = "0123456789" },
		"host-overflow":    func(c *resetD101Key3CeremonyCard) { c.HostInstanceID = "18446744073709551616" },
		"arch":             func(c *resetD101Key3CeremonyCard) { c.HostArchitecture = "linux/arm64" },
		"uid":              func(c *resetD101Key3CeremonyCard) { c.InstallerUID = 1 },
		"source":           func(c *resetD101Key3CeremonyCard) { c.InitializerSourceSHA = strings.Repeat("b", 39) },
		"binary":           func(c *resetD101Key3CeremonyCard) { c.InitializerBinarySHA256 = "" },
		"before-window":    func(c *resetD101Key3CeremonyCard) { c.ValidFromUnix = now.Unix() + 1 },
		"at-cutoff":        func(c *resetD101Key3CeremonyCard) { c.ValidUntilUnix = now.Unix() },
		"reversed-window":  func(c *resetD101Key3CeremonyCard) { c.ValidUntilUnix = c.ValidFromUnix },
		"retry-policy":     func(c *resetD101Key3CeremonyCard) { c.PartialPolicy = "retry" },
		"late-once":        func(c *resetD101Key3CeremonyCard) { c.OncePolicy = "after-entropy" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			e := expected
			mutate(&e.Card)
			wire, err := json.Marshal(e.Card)
			if err != nil {
				t.Fatal("fixture encoding failed")
			}
			e.CardSHA = resetD101OriginalSHA(wire)
			if _, err := decodeResetD101Key3Ceremony(wire, e, now); err == nil {
				t.Fatal("out-of-scope ceremony accepted")
			}
		})
	}
}

func TestKey3AuthenticationResultRequiresBoundOriginalsAndFreshness(t *testing.T) {
	_, expected, now := key3PublicFixture(t)
	fixture := func() resetD101Key3CeremonyAuthentication {
		return resetD101Key3CeremonyAuthentication{
			cardSHA: expected.CardSHA, ceremonyID: expected.Card.CeremonyID, hostInstanceID: expected.Card.HostInstanceID, sourceSHA: expected.Card.InitializerSourceSHA, binarySHA: expected.Card.InitializerBinarySHA256,
			humanApproval: []byte("public fixture human"), custodianAssignment: []byte("public fixture custodian"), privateRetention: []byte("public fixture retention"), humanAuthenticationSource: []byte("public fixture authentication"), observedAt: now,
		}
	}
	// Structural validation alone is not actual authentication. No provider
	// registration or positive initializer execution occurs in this fixture.
	if requireResetD101Key3Authentication(fixture(), expected, now) != nil {
		t.Fatal("bound public fixture invalid")
	}
	mutations := map[string]func(*resetD101Key3CeremonyAuthentication){
		"empty-result":      func(a *resetD101Key3CeremonyAuthentication) { *a = resetD101Key3CeremonyAuthentication{} },
		"card":              func(a *resetD101Key3CeremonyAuthentication) { a.cardSHA = strings.Repeat("d", 64) },
		"ceremony":          func(a *resetD101Key3CeremonyAuthentication) { a.ceremonyID = strings.Repeat("d", 32) },
		"host":              func(a *resetD101Key3CeremonyAuthentication) { a.hostInstanceID = "987654321" },
		"source":            func(a *resetD101Key3CeremonyAuthentication) { a.sourceSHA = strings.Repeat("d", 40) },
		"binary":            func(a *resetD101Key3CeremonyAuthentication) { a.binarySHA = strings.Repeat("d", 64) },
		"human-mutation":    func(a *resetD101Key3CeremonyAuthentication) { a.humanApproval[0] = 'X' },
		"custodian-missing": func(a *resetD101Key3CeremonyAuthentication) { a.custodianAssignment = nil },
		"retention-label":   func(a *resetD101Key3CeremonyAuthentication) { a.privateRetention = []byte("approved") },
		"source-missing":    func(a *resetD101Key3CeremonyAuthentication) { a.humanAuthenticationSource = nil },
		"future":            func(a *resetD101Key3CeremonyAuthentication) { a.observedAt = now.Add(time.Nanosecond) },
		"stale":             func(a *resetD101Key3CeremonyAuthentication) { a.observedAt = now.Add(-resetPreflightMaxAge) },
		"before-approval": func(a *resetD101Key3CeremonyAuthentication) {
			a.observedAt = time.Unix(expected.Card.ValidFromUnix-1, 0)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			a := fixture()
			mutate(&a)
			if requireResetD101Key3Authentication(a, expected, now) == nil {
				t.Fatal("unbound authentication result accepted")
			}
		})
	}
}

func key3PublicEntropy() []byte {
	wire := make([]byte, 3*(16+ed25519.SeedSize))
	for i := 0; i < 3; i++ {
		for j := 0; j < 16+ed25519.SeedSize; j++ {
			wire[i*48+j] = byte(i*53 + j + 1)
		}
	}
	return wire
}

func TestKey3PublicFixtureDistinctMaterialUsesExistingEnvelope(t *testing.T) {
	material, err := prepareResetD101UntrustedKey3(bytes.NewReader(key3PublicEntropy()))
	if err != nil || len(material) != 3 {
		t.Fatal("public fixture preparation failed")
	}
	defer func() {
		for i := range material {
			material[i].close()
		}
	}()
	seen := map[string]bool{}
	for i, m := range material {
		if m.role != []string{"root-purpose", "approval-issuer", "approved-receipt-issuer"}[i] || seen[m.custodyID] || seen[m.keyID] || seen[m.publicSPKISHA] {
			t.Fatal("roles or identifiers not distinct")
		}
		seen[m.custodyID] = true
		seen[m.keyID] = true
		seen[m.publicSPKISHA] = true
		var e resetD101SigningKeyEnvelope
		if requireResetIntentShape(m.privateEnvelope, reflect.TypeOf(e)) != nil || decodeResetPrivateJSON(m.privateEnvelope, &e) != nil || e.SchemaVersion != 1 || e.KeyID != m.keyID || e.PublicKeySpkiSHA != m.publicSPKISHA || resetD101OriginalSHA(m.privateEnvelope) != m.envelopeSHA {
			t.Fatal("existing exact four-field envelope not preserved")
		}
		der, err := base64.RawURLEncoding.Strict().DecodeString(e.PrivateKeyPkcs8Base64url)
		if err != nil || len(der) != 48 || len(m.publicDER) != 44 {
			t.Fatal("invalid fixture DER lengths")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		clear(der)
		key, ok := parsed.(ed25519.PrivateKey)
		if err != nil || !ok {
			t.Fatal("invalid fixture PKCS8")
		}
		public, err := x509.MarshalPKIXPublicKey(key.Public())
		clear(key)
		if err != nil || !bytes.Equal(public, m.publicDER) || resetD101OriginalSHA(public) != m.publicSPKISHA {
			t.Fatal("derived public fixture mismatch")
		}
		held := m.privateEnvelope
		material[i].close()
		if material[i].privateEnvelope != nil || !bytes.Equal(held, make([]byte, len(held))) {
			t.Fatal("owned private envelope buffer not cleared")
		}
	}
}

func TestKey3PublicFixtureRejectsDuplicateAndPartialEntropy(t *testing.T) {
	cases := map[string][]byte{"partial-id": {1}, "partial-seed": bytes.Repeat([]byte{1}, 47), "partial-second": key3PublicEntropy()[:49]}
	duplicateID := key3PublicEntropy()
	copy(duplicateID[48:64], duplicateID[:16])
	cases["duplicate-custody"] = duplicateID
	duplicateSPKI := key3PublicEntropy()
	copy(duplicateSPKI[64:96], duplicateSPKI[16:48])
	cases["duplicate-spki"] = duplicateSPKI
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			m, err := prepareResetD101UntrustedKey3(bytes.NewReader(wire))
			if err == nil || m != nil {
				t.Fatal("failed or duplicate generation returned material")
			}
		})
	}
	if m, err := prepareResetD101UntrustedKey3(nil); err == nil || m != nil {
		t.Fatal("missing entropy accepted")
	}
}

func TestKey3EarlyCommandDeniesWithoutAuthorityAndNeverFallsThrough(t *testing.T) {
	oldSource, oldExpected := resetD101ReviewedKey3CeremonySource, resetD101ReviewedKey3CeremonyExpected
	resetD101ReviewedKey3CeremonySource = nil
	resetD101ReviewedKey3CeremonyExpected = nil
	defer func() {
		resetD101ReviewedKey3CeremonySource = oldSource
		resetD101ReviewedKey3CeremonyExpected = oldExpected
	}()
	sha := strings.Repeat("a", 64)
	cases := map[string][]string{
		"missing-args":             {"deployer", "--d101-initialize-key3"},
		"wrong-flag":               {"deployer", "--d101-initialize-key3", "--operation-id", sha},
		"wrong-sha":                {"deployer", "--d101-initialize-key3", "--ceremony-card-sha256", "approved"},
		"uppercase-sha":            {"deployer", "--d101-initialize-key3", "--ceremony-card-sha256", strings.Repeat("A", 64)},
		"extra-entropy-selector":   {"deployer", "--d101-initialize-key3", "--ceremony-card-sha256", sha, "--entropy=/tmp/input"},
		"missing-actual-authority": {"deployer", "--d101-initialize-key3", "--ceremony-card-sha256", sha},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			envCalls := 0
			handled, status := earlyResetD101HostCommand(args, func(string) string { envCalls++; return "caller supplied approval" }, &out, &errOut)
			if !handled || status != 2 || envCalls != 0 || out.Len() != 0 || errOut.Len() != 0 {
				t.Fatal("unauthorized key command fell through, read config or produced output")
			}
		})
	}
	if handled, status := earlyResetD101HostCommand([]string{"deployer"}, nil, nil, nil); handled || status != 0 {
		t.Fatal("ordinary no-command selection changed")
	}
	if runResetD101Key3Initialization(nil, sha) != 2 || runResetD101Key3Initialization(context.Background(), sha) != 2 {
		t.Fatal("missing source reached positive initializer")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if runResetD101Key3Initialization(canceled, sha) != 2 {
		t.Fatal("canceled ceremony accepted")
	}
}

// New selectors below do not install an actual authority source. The trap
// provider must never be reached by an unavailable production entry.
type key3MissingExecutionTrap struct{ calls *int }

func (s *key3MissingExecutionTrap) Authenticate(context.Context, *resetD101Key3AuthenticatedSession, resetD101Key3NativeInitializationExpected) (resetD101Key3NativeInitializationBinding, error) {
	*s.calls++
	return resetD101Key3NativeInitializationBinding{}, errResetExecutionEvidence
}
func (s *key3MissingExecutionTrap) Recheck(context.Context, *resetD101Key3AuthenticatedSession, resetD101Key3NativeInitializationExpected, resetD101Key3NativeInitializationBinding) error {
	*s.calls++
	return errResetExecutionEvidence
}

func TestKey3NativeInitializationNilExecutionSourceNeverReachesWriter(t *testing.T) {
	oldSource, oldExpected := resetD101ReviewedKey3NativeInitializationSource, resetD101ReviewedKey3NativeInitializationExpected
	oldCeremony, oldCeremonyExpected := resetD101ReviewedKey3CeremonySource, resetD101ReviewedKey3CeremonyExpected
	defer func() {
		resetD101ReviewedKey3NativeInitializationSource = oldSource
		resetD101ReviewedKey3NativeInitializationExpected = oldExpected
		resetD101ReviewedKey3CeremonySource = oldCeremony
		resetD101ReviewedKey3CeremonyExpected = oldCeremonyExpected
	}()
	for _, name := range []string{"nil-source", "typed-nil-source", "missing-expected", "missing-ceremony-source", "nil-context", "canceled", "bad-sha"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			source := &key3MissingExecutionTrap{&calls}
			resetD101ReviewedKey3NativeInitializationSource = source
			resetD101ReviewedKey3NativeInitializationExpected = &resetD101Key3NativeInitializationExpected{}
			resetD101ReviewedKey3CeremonySource = nil
			resetD101ReviewedKey3CeremonyExpected = nil
			ctx := context.Background()
			sha := strings.Repeat("a", 64)
			switch name {
			case "nil-source":
				resetD101ReviewedKey3NativeInitializationSource = nil
			case "typed-nil-source":
				resetD101ReviewedKey3NativeInitializationSource = (*key3MissingExecutionTrap)(nil)
			case "missing-expected":
				resetD101ReviewedKey3NativeInitializationExpected = nil
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "bad-sha":
				sha = "caller supplied approval"
			}
			if runResetD101Key3Initialization(ctx, sha) != 2 || calls != 0 {
				t.Fatal("unavailable source reached actual execution or writer")
			}
			if withResetD101ReviewedKey3Ceremony(ctx, sha, nil) == nil {
				t.Fatal("nil held callback admitted")
			}
		})
	}
}

func TestKey3NativeInitializationOutcomeDoesNotPromotePartial(t *testing.T) {
	for _, tc := range []struct {
		name   string
		out    resetD101Key3NativeInitializationOutcome
		err    error
		status int
	}{
		{"empty", resetD101Key3NativeInitializationOutcome{}, nil, 2},
		{"denied", resetD101Key3NativeInitializationOutcome{err: errResetExecutionEvidence}, errResetExecutionEvidence, 2},
		{"partial", resetD101Key3NativeInitializationOutcome{attempted: true}, nil, 3},
		{"false-completion", resetD101Key3NativeInitializationOutcome{complete: true}, nil, 2},
		{"durable-complete", resetD101Key3NativeInitializationOutcome{attempted: true, complete: true}, nil, 0},
		{"post-complete-failure", resetD101Key3NativeInitializationOutcome{attempted: true, complete: true}, errResetExecutionEvidence, 3},
		{"outcome-error", resetD101Key3NativeInitializationOutcome{attempted: true, complete: true, err: errResetExecutionEvidence}, nil, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if resetD101Key3InitializationStatus(tc.out, tc.err) != tc.status {
				t.Fatal("partial or late failure promoted to success")
			}
		})
	}
	_, card, now := key3PublicFixture(t)
	directory := resetD101Key3DirectoryIdentity{Device: 1, Inode: 1, OwnerUID: 0, Mode: 0700}
	expected := resetD101Key3NativeInitializationExpected{BaseDirectory: directory, OnceParent: directory, KeysParent: directory, PublicParent: directory, MinimumAvailableBytes: 1}
	expected.OnceParent.Inode = 2
	expected.KeysParent.Inode = 3
	expected.PublicParent.Inode = 4
	expected.InstallerPin.SHA256 = card.Card.InitializerBinarySHA256
	expected.InstallerPin.OwnerUID = 0
	expected.InstallerPin.FileMode = 0500
	expected.InstallerPin.LinkCount = 1
	expected.InstallerPin.Snapshot.Device = 1
	expected.InstallerPin.Snapshot.Inode = 1
	expected.InstallerPin.Snapshot.ByteLength = 1
	expected.InstallerPin.ParentSnapshot.Device = 1
	expected.InstallerPin.ParentSnapshot.Inode = 1
	expected.InstallerPin.ParentOwnerUID = 0
	expected.InstallerPin.ParentMode = 0700
	session := &resetD101Key3AuthenticatedSession{expected: card, recheck: func(context.Context) error { return errResetExecutionEvidence }}
	c := card.Card
	scope := resetD101Key3NativeExecutionScope{1, "KEY3_NATIVE_INITIALIZATION", card.CardSHA, c.HostInstanceID, c.InitializerSourceSHA, c.InitializerBinarySHA256, c.HumanApprovalOriginalRef, c.CustodianAssignmentOriginalRef, c.PrivateRetentionOriginalRef,
		"/etc/opensamguk/d101", ".once/key3-initialize", expected.BaseDirectory, expected.OnceParent, expected.KeysParent, expected.PublicParent, 1}
	wire, err := json.Marshal(scope)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	expected.ExecutionScopeOriginalRef = resetD101Key3OriginalRef{Path: "/fixture/execution", Bytes: uint64(len(wire)), SHA256: resetD101OriginalSHA(wire)}
	binding := resetD101Key3NativeInitializationBinding{card.CardSHA, expected.ExecutionScopeOriginalRef.SHA256, c.HostInstanceID, c.InitializerSourceSHA, c.InitializerBinarySHA256, wire, now}
	// This validates shape only, with no actual source or positive entry call.
	if requireResetD101Key3NativeBinding(binding, session, expected, now) != nil {
		t.Fatal("public shape fixture invalid")
	}
	for _, name := range []string{"missing-original", "source-mismatch", "host-mismatch", "binary-mismatch", "capacity-zero", "foreign-pin", "future", "stale", "unknown-field", "duplicate-field", "owner-negative-zero", "once-scope-change"} {
		t.Run(name, func(t *testing.T) {
			b := binding
			e := expected
			b.executionScopeOriginal = append([]byte(nil), wire...)
			switch name {
			case "missing-original":
				b.executionScopeOriginal = nil
			case "source-mismatch":
				b.sourceSHA = strings.Repeat("d", 40)
			case "host-mismatch":
				b.hostInstanceID = "987654321"
			case "binary-mismatch":
				e.InstallerPin.SHA256 = strings.Repeat("d", 64)
			case "capacity-zero":
				e.MinimumAvailableBytes = 0
			case "foreign-pin":
				e.KeysParent.OwnerUID = 1
			case "future":
				b.observedAt = now.Add(time.Nanosecond)
			case "stale":
				b.observedAt = now.Add(-resetPreflightMaxAge)
			case "unknown-field":
				b.executionScopeOriginal = []byte(strings.Replace(string(wire), `"schemaVersion":1`, `"extra":true,"schemaVersion":1`, 1))
			case "duplicate-field":
				b.executionScopeOriginal = []byte(strings.Replace(string(wire), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1))
			case "owner-negative-zero":
				b.executionScopeOriginal = []byte(strings.Replace(string(wire), `"ownerUid":0`, `"ownerUid":-0`, 1))
			case "once-scope-change":
				b.executionScopeOriginal = []byte(strings.Replace(string(wire), `".once/key3-initialize"`, `".once/new-ceremony"`, 1))
			}
			// Freeze the mutated raw hash too, so parser/scope checks are exercised.
			e.ExecutionScopeOriginalRef.Bytes = uint64(len(b.executionScopeOriginal))
			e.ExecutionScopeOriginalRef.SHA256 = resetD101OriginalSHA(b.executionScopeOriginal)
			b.executionScopeSHA = e.ExecutionScopeOriginalRef.SHA256
			if requireResetD101Key3NativeBinding(b, session, e, now) == nil {
				t.Fatal("unavailable or mismatched native execution binding accepted")
			}
		})
	}
}
