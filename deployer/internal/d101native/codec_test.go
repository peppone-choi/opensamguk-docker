package d101native

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

type native9Fixture struct {
	binding   PreBinding
	pins      SignaturePins
	key       ed25519.PrivateKey
	records   []Unverified
	refs      []RawRef
	originals map[RawRef][]byte
}

func native9Ref(path string, wire []byte) RawRef {
	return RawRef{Path: path, Bytes: uint64(len(wire)), SHA256: Hash(wire), Native: NativePin{Device: 1, Inode: 2, OwnerUID: 0, Mode: 0400, Links: 1, ParentDevice: 1, ParentInode: 3}}
}
func native9Process() Process {
	return Process{PID: 42, StartTicks: 101, ParentPID: 41, ParentStartTicks: 100, ExePath: "/fixture/deployer", ExeSHA256: strings.Repeat("a", 64), SourceSHA: strings.Repeat("b", 40)}
}
func native9FillRefs(v reflect.Value, r RawRef) {
	if v.Kind() == reflect.Pointer {
		native9FillRefs(v.Elem(), r)
		return
	}
	if v.Type() == reflect.TypeOf(RawRef{}) {
		if !ValidRef(v.Interface().(RawRef)) {
			v.Set(reflect.ValueOf(r))
		}
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			native9FillRefs(v.Field(i), r)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			native9FillRefs(v.Index(i), r)
		}
	}
}
func native9NewFixture(t *testing.T, last uint64) *native9Fixture {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	external := native9Ref("/fixture/actual-original", []byte("fixture original"))
	now := time.Now().UTC().Add(-time.Second)
	f := &native9Fixture{key: key, pins: SignaturePins{KeyID: "fixture-native", SPKIDER: der, Domain: NativeAuthorityDomain}, originals: map[RawRef][]byte{external: []byte("fixture original")}}
	f.binding = PreBinding{SchemaVersion: 1, OperationID: strings.Repeat("c", 32), TargetFingerprint: strings.Repeat("d", 64), PublicationRevision: "7", OriginalCutoffUnix: now.Add(time.Hour).Unix(), PreAcquisitionApprovalRef: external, IssuerIdentity: "fixture-issuer", IssuerSPKISHA256: Hash(der), Keeper: Keeper{Process: native9Process(), BirthNonce: strings.Repeat("e", 32), Lock: NativePin{Device: 1, Inode: 44, OwnerUID: 0, Mode: 0600, Links: 1, ParentDevice: 1, ParentInode: 3}, FD: 9}, IssuedAtUTC: now.Format(time.RFC3339Nano)}
	kinds := []string{"ACQUISITION", "installed-writer-inventory", "console-admission", "root-admission", "turn-flush", "publisher", "postgres-admission", "old-services", "keeper-session", "writer-freeze-receipt", "FINAL_PLAN_BOUND", "ISSUER_RUNNING", "ISSUER_DONE", "PHYSICAL_RUNNING", ""}
	for seq := uint64(0); seq <= last; seq++ {
		phase := "CLOSING"
		if seq == 0 {
			phase = "ACQUIRED"
		}
		if seq == 9 {
			phase = "FROZEN"
		}
		if seq >= 10 {
			phase = kinds[seq]
		}
		if seq == 14 {
			phase = "RELEASED"
		}
		h := PreHeader{Binding: f.binding, Sequence: seq, LeafKind: kinds[seq], Phase: phase}
		if seq > 0 {
			h.PreviousOriginalRef = f.refs[seq-1]
			h.AcquisitionRef = f.refs[0]
		}
		plan := PlanHeader{Pre: h, ApprovedFinalPlanRef: external}
		if seq >= 10 {
			plan.FreezeOriginalRef = f.refs[9]
		}
		physical := PhysicalHeader{Plan: plan, ExecutionReceiptRef: external}
		if seq >= 13 {
			physical.IssuerDoneRef = f.refs[12]
		}
		var record any
		switch seq {
		case 0:
			record = &Acquired{Binding: f.binding, LeafKind: kinds[seq], Phase: phase, Sequence: seq, Payload: AcquisitionPayload{LockObservedAtUTC: now.Format(time.RFC3339Nano)}}
		case 1:
			record = &Inventory{Header: h, Writers: []WriterEntry{{WriterID: "writer-a", WriterKind: "console", SourceSHA: strings.Repeat("b", 40), ImageDigest: "sha256:" + strings.Repeat("a", 64)}}}
		case 2:
			record = &ConsoleAdmission{Header: h, WorkflowClosureRefs: []RawRef{external}, RestartBarrierRefs: []RawRef{external}}
		case 3:
			record = &RootAdmission{Header: h}
		case 4:
			record = &TurnFlush{Header: h, ProcessExitRefs: []RawRef{external}, RestartBarrierRefs: []RawRef{external}}
		case 5:
			record = &Publisher{Header: h, InflightSettlementRefs: []RawRef{external}, ProcessExitRefs: []RawRef{external}, RestartBarrierRefs: []RawRef{external}}
		case 6:
			record = &PostgresAdmission{Header: h, ReconnectBarrierRefs: []RawRef{external}}
		case 7:
			record = &OldServices{Header: h, ExitRefs: []RawRef{external}, RestartBarrierRefs: []RawRef{external}}
		case 8:
			record = &KeeperSession{Header: h, BarrierOwnerRefs: []RawRef{external}}
		case 9:
			record = &Freeze{Header: h, InventoryRef: f.refs[1], ConsoleAdmissionRef: f.refs[2], RootAdmissionRef: f.refs[3], TurnFlushRef: f.refs[4], PublisherRef: f.refs[5], PostgresAdmissionRef: f.refs[6], OldServicesRef: f.refs[7], KeeperSessionRef: f.refs[8]}
		case 10:
			record = &FinalBound{Header: plan}
		case 11:
			record = &IssuerRunning{Header: plan, Child: native9Process()}
		case 12:
			record = &IssuerDone{Header: plan}
		case 13:
			record = &PhysicalRunning{Header: physical, Child: native9Process(), BarrierOwnerRefs: []RawRef{external}}
		case 14:
			record = &Released{Header: physical}
		}
		native9FillRefs(reflect.ValueOf(record), external)
		wire := f.sign(t, record)
		u, err := Decode(wire, f.pins)
		if err != nil {
			t.Fatalf("seq %d fixture: %v", seq, err)
		}
		ref := native9Ref("/fixture/"+kinds[seq]+phase, wire)
		f.records = append(f.records, u)
		f.refs = append(f.refs, ref)
		f.originals[ref] = wire
	}
	return f
}
func (f *native9Fixture) sign(t *testing.T, v any) []byte {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeEnvelope(body, f.pins.KeyID, ed25519.Sign(f.key, append([]byte(NativeAuthorityDomain), body...)))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func TestNative9CodecStrictNestedVariants(t *testing.T) {
	f := native9NewFixture(t, 14)
	for i, u := range f.records {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			body := u.PayloadOriginal()
			if _, err := DecodePayload(body); err != nil {
				t.Fatal(err)
			}
			variants := map[string][]byte{"duplicate": bytes.Replace(body, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1), "null": bytes.Replace(body, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":null`), 1), "fraction": bytes.Replace(body, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1.0`), 1), "exponent": bytes.Replace(body, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1e0`), 1), "unknown": append([]byte(`{"unknown":0,`), body[1:]...), "noncanonical": append([]byte(" "), body...), "trailing": append(bytes.Clone(body), []byte("{}")...)}
			for name, bad := range variants {
				t.Run(name, func(t *testing.T) {
					if _, err := DecodePayload(bad); err == nil {
						t.Fatal("nonexact tree accepted")
					}
				})
			}
		})
	}
}
func TestNative9CodecSignedRawPhaseOrderAndPublicProjection(t *testing.T) {
	f := native9NewFixture(t, 14)
	if VerifyChain(f.records, f.refs, f.binding) != nil {
		t.Fatal("actual fixture chain denied")
	}
	bad := append([]Unverified(nil), f.records...)
	bad[11], bad[12] = bad[12], bad[11]
	if VerifyChain(bad, f.refs, f.binding) == nil {
		t.Fatal("phase reorder accepted")
	}
	pins := f.pins
	pins.Domain = "OPENSAMGUK_D101_NATIVE_AUTHORITY_V1"
	if _, err := Decode(f.records[0].Original(), pins); err == nil {
		t.Fatal("missing LF accepted")
	}
	wire := f.records[0].Original()
	wire[len(wire)-4] ^= 1
	if _, err := Decode(wire, f.pins); err == nil {
		t.Fatal("tampered signature accepted")
	}
	original := f.records[0].Original()
	original[0] = 'x'
	if f.records[0].Original()[0] == 'x' {
		t.Fatal("raw original alias")
	}
	x := f.records[11].Payload().(*IssuerRunning)
	body, _ := json.Marshal(x)
	if bytes.Contains(body, []byte("executionReceipt")) {
		t.Fatal("issuer start requires future receipt")
	}
	var pub RelaySessionBinding
	badPublic := []byte(`{"header":{}}`)
	if DecodeExact(badPublic, &pub, PayloadMaxBytes) == nil {
		t.Fatal("private header accepted in public projection")
	}
}
