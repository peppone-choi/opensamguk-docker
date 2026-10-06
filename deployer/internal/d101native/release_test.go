package d101native

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

type native9ReleaseFixtureSource struct {
	observation LastOwnerObservation
	changed     bool
	commits     int
}

func (s *native9ReleaseFixtureSource) AuthenticateRelease(context.Context, HeldTerminalDisposition, *UnverifiedReleaseEvent, ReleaseExpected) (LastOwnerObservation, error) {
	return s.observation, nil
}
func (s *native9ReleaseFixtureSource) RecheckRelease(context.Context, HeldTerminalDisposition, *UnverifiedReleaseEvent, ReleaseExpected, LastOwnerObservation) error {
	if s.changed {
		return ErrUnavailable
	}
	return nil
}
func (s *native9ReleaseFixtureSource) CommitCompletionOnce(context.Context, ReleaseExpected, RawRef) error {
	s.commits++
	if s.commits != 1 {
		return ErrUnavailable
	}
	return nil
}
func native9ReleaseFixture(t *testing.T) (HeldTerminalDisposition, *UnverifiedReleaseEvent, ReleaseExpected, *native9ReleaseFixtureSource) {
	t.Helper()
	f := native9NewFixture(t, 14)
	d, err := DecodeHeldTerminal(f.records[14].Original(), f.refs[14], f.pins)
	if err != nil {
		t.Fatal(err)
	}
	r := f.binding.PreAcquisitionApprovalRef
	released := time.Now().UTC().Add(-2 * time.Second)
	observed := released.Add(time.Second)
	e := ReleaseExpected{Terminal: f.refs[14], HeldClosure: r, ReleaseDecision: r, ObserverOrigin: r, ReleaseActorOrigin: r, ReleaseAuthorization: r, Binding: f.binding, ApplicableDeadlineUnix: f.binding.OriginalCutoffUnix, AuthorizedReleaseAction: "approved-normal-release"}
	event := ReleaseEvent{SchemaVersion: 1, Kind: "NATIVE_RELEASE_OBSERVATION", TerminalOriginalRef: e.Terminal, HeldClosureRef: r, ReleaseDecisionRef: r, Keeper: f.binding.Keeper, OperationID: f.binding.OperationID, TargetFingerprint: f.binding.TargetFingerprint, PublicationRevision: f.binding.PublicationRevision, ObserverOriginRef: r, ReleaseActorOriginRef: r, LastOwnerReleaseObservationRef: r, BarrierObservationRefs: []RawRef{r}, ActualReleaseAtUTC: released.Format(time.RFC3339Nano), ObservedAtUTC: observed.Format(time.RFC3339Nano)}
	wire, _ := json.Marshal(event)
	ref := native9Ref("/fixture/actual-release-event", wire)
	raw, err := DecodeReleaseEvent(wire, ref)
	if err != nil {
		t.Fatal(err)
	}
	source := &native9ReleaseFixtureSource{observation: LastOwnerObservation{Keeper: f.binding.Keeper, Terminal: e.Terminal, Event: ref, LastOwner: r, ActualReleaseAt: released, ObservedAt: observed, OwnerProcesses: []Process{native9Process()}, Originals: []RawRef{r}}}
	return d, raw, e, source
}
func TestNative9ReleaseCompletionActualEventGuard(t *testing.T) {
	for _, name := range []string{"actual-event", "missing-event", "missing-source", "unknown-last-owner", "observer-change", "late-release", "wrong-terminal", "deadline-renewal"} {
		t.Run(name, func(t *testing.T) {
			d, event, e, source := native9ReleaseFixture(t)
			var actual ReleaseCompletionSource = source
			switch name {
			case "missing-event":
				event = nil
			case "missing-source":
				actual = nil
			case "unknown-last-owner":
				source.observation.OwnerProcesses = nil
			case "observer-change":
				source.changed = true
			case "late-release":
				event.event.ActualReleaseAtUTC = time.Unix(e.ApplicableDeadlineUnix, 0).UTC().Format(time.RFC3339Nano)
			case "wrong-terminal":
				e.Terminal = e.HeldClosure
			case "deadline-renewal":
				e.ApplicableDeadlineUnix++
			}
			v, err := ConsumeReleaseCompletion(context.Background(), d, event, e, actual)
			if name != "actual-event" {
				if err == nil || v != nil || source.commits != 0 {
					t.Fatal("nonactual release consumed completion")
				}
				return
			}
			if err != nil || !v.Complete() || v.NewOperationAllowed() || source.commits != 1 {
				t.Fatal("actual release denied")
			}
			if ValidateReleaseCompletion(context.Background(), v, d, event, e, source) != nil || source.commits != 1 {
				t.Fatal("completion reread repeated CAS")
			}
			source.changed = true
			if ValidateReleaseCompletion(context.Background(), v, d, event, e, source) == nil {
				t.Fatal("cached completion bypassed actual source")
			}
		})
	}
}
func TestNative9RecoveryOriginalAuthorizationGuard(t *testing.T) {
	_, event, e, source := native9ReleaseFixture(t)
	f := native9NewFixture(t, 14)
	released := f.records[14].Payload().(*Released)
	record := &RecoveredRelease{Header: released.Header, ChildTerminalRef: released.ChildTerminalRef, WorkerAbsenceRef: released.WorkerAbsenceRef, HeldBarrierClosureRef: released.HeldBarrierClosureRef, ReleaseDecisionRef: released.ReleaseDecisionRef, RecoveryClosureRef: f.binding.PreAcquisitionApprovalRef, RecoveryAuthorizationRef: f.binding.PreAcquisitionApprovalRef, RecoveryDeadlineUnix: f.binding.OriginalCutoffUnix + 60, RecoveryAction: "approved-existing-operation-release"}
	record.Header.Plan.Pre.Phase = "RECOVERED_RELEASED"
	wire := f.sign(t, record)
	ref := native9Ref("/fixture/recovered-terminal", wire)
	d, err := DecodeHeldTerminal(wire, ref, f.pins)
	if err != nil {
		t.Fatal(err)
	}
	e.Binding = f.binding
	e.Terminal = ref
	e.AuthorizedReleaseAction = record.RecoveryAction
	e.ApplicableDeadlineUnix = record.RecoveryDeadlineUnix
	event.event.TerminalOriginalRef = ref
	event.event.Keeper = f.binding.Keeper
	eventWire, _ := json.Marshal(event.event)
	eventRef := native9Ref("/fixture/recovery-event", eventWire)
	event, err = DecodeReleaseEvent(eventWire, eventRef)
	if err != nil {
		t.Fatal(err)
	}
	source.observation.Terminal = ref
	source.observation.Event = eventRef
	source.observation.Keeper = f.binding.Keeper
	if _, err := ConsumeReleaseCompletion(context.Background(), d, event, e, source); err != nil {
		t.Fatal(err)
	}
	e.ReleaseAuthorization = e.Terminal
	if _, err := ConsumeReleaseCompletion(context.Background(), d, event, e, source); err == nil {
		t.Fatal("different recovery authority adopted")
	}
	var zero VerifiedReleaseCompletion
	if zero.Complete() || zero.NewOperationAllowed() {
		t.Fatal("zero completion grants authority")
	}
}
