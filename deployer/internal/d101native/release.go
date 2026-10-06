package d101native

import (
	"bytes"
	"context"
	"time"
)

type HeldTerminalDisposition struct {
	terminal              Unverified
	originalRef           RawRef
	closure, decision     RawRef
	binding               PreBinding
	recoveryAuthorization RawRef
	recoveryDeadline      int64
	recoveryAction        string
}

func DecodeHeldTerminal(wire []byte, ref RawRef, pins SignaturePins) (HeldTerminalDisposition, error) {
	if !ValidRef(ref) || Hash(wire) != ref.SHA256 || uint64(len(wire)) != ref.Bytes {
		return HeldTerminalDisposition{}, ErrUnavailable
	}
	u, e := Decode(wire, pins)
	if e != nil {
		return HeldTerminalDisposition{}, e
	}
	h, ok := HeaderOf(u.record)
	if !ok || h.Sequence != 14 {
		return HeldTerminalDisposition{}, ErrUnavailable
	}
	v := HeldTerminalDisposition{terminal: u, originalRef: ref, binding: h.Binding}
	switch x := u.record.(type) {
	case *Released:
		v.closure = x.HeldBarrierClosureRef
		v.decision = x.ReleaseDecisionRef
	case *RecoveredRelease:
		v.closure = x.HeldBarrierClosureRef
		v.decision = x.ReleaseDecisionRef
		v.recoveryAuthorization = x.RecoveryAuthorizationRef
		v.recoveryDeadline = x.RecoveryDeadlineUnix
		v.recoveryAction = x.RecoveryAction
	default:
		return HeldTerminalDisposition{}, ErrUnavailable
	}
	return v, nil
}
func (v HeldTerminalDisposition) TerminalRef() RawRef { return v.originalRef }
func (v HeldTerminalDisposition) Binding() PreBinding { return v.binding }

// This unsigned original is observed after real last-owner release. It is not
// a new sequence, signing authority or permission to reacquire an operation.
type ReleaseEvent struct {
	SchemaVersion                  uint32   `json:"schemaVersion"`
	Kind                           string   `json:"kind"`
	TerminalOriginalRef            RawRef   `json:"terminalOriginalRef"`
	HeldClosureRef                 RawRef   `json:"heldClosureRef"`
	ReleaseDecisionRef             RawRef   `json:"releaseDecisionRef"`
	Keeper                         Keeper   `json:"keeper"`
	OperationID                    string   `json:"operationId"`
	TargetFingerprint              string   `json:"targetFingerprint"`
	PublicationRevision            string   `json:"publicationRevision"`
	ObserverOriginRef              RawRef   `json:"observerOriginRef"`
	ReleaseActorOriginRef          RawRef   `json:"releaseActorOriginRef"`
	LastOwnerReleaseObservationRef RawRef   `json:"lastOwnerReleaseObservationRef"`
	BarrierObservationRefs         []RawRef `json:"barrierObservationRefs"`
	ActualReleaseAtUTC             string   `json:"actualReleaseAtUtc"`
	ObservedAtUTC                  string   `json:"observedAtUtc"`
}
type UnverifiedReleaseEvent struct {
	original []byte
	ref      RawRef
	event    ReleaseEvent
}

func DecodeReleaseEvent(wire []byte, ref RawRef) (*UnverifiedReleaseEvent, error) {
	var event ReleaseEvent
	if !ValidRef(ref) || uint64(len(wire)) != ref.Bytes || Hash(wire) != ref.SHA256 || DecodeExact(wire, &event, PayloadMaxBytes) != nil || event.SchemaVersion != 1 || event.Kind != "NATIVE_RELEASE_OBSERVATION" || !ValidNonce(event.OperationID) || !ValidSHA(event.TargetFingerprint) || !validKeeper(event.Keeper) || len(event.BarrierObservationRefs) == 0 {
		return nil, ErrUnavailable
	}
	for _, r := range References(event) {
		if !ValidRef(r) || r == ref {
			return nil, ErrUnavailable
		}
	}
	return &UnverifiedReleaseEvent{bytes.Clone(wire), ref, event}, nil
}

type ReleaseExpected struct {
	Terminal, HeldClosure, ReleaseDecision, ObserverOrigin, ReleaseActorOrigin, ReleaseAuthorization RawRef
	Binding                                                                                          PreBinding
	ApplicableDeadlineUnix                                                                           int64
	AuthorizedReleaseAction                                                                          string
}
type LastOwnerObservation struct {
	Keeper                      Keeper
	Terminal, Event, LastOwner  RawRef
	ActualReleaseAt, ObservedAt time.Time
	// Exact actual processes including dup/inherited handles and descendants.
	OwnerProcesses []Process
	Originals      []RawRef
}
type ReleaseCompletionSource interface {
	AuthenticateRelease(context.Context, HeldTerminalDisposition, *UnverifiedReleaseEvent, ReleaseExpected) (LastOwnerObservation, error)
	RecheckRelease(context.Context, HeldTerminalDisposition, *UnverifiedReleaseEvent, ReleaseExpected, LastOwnerObservation) error
	CommitCompletionOnce(context.Context, ReleaseExpected, RawRef) error
}
type VerifiedReleaseCompletion struct {
	terminal, event RawRef
	binding         PreBinding
	observed        time.Time
}

func (v *VerifiedReleaseCompletion) Complete() bool {
	return v != nil && ValidRef(v.terminal) && ValidRef(v.event) && ValidBinding(v.binding) && !v.observed.IsZero()
}
func (v *VerifiedReleaseCompletion) NewOperationAllowed() bool { return false }
func (v *VerifiedReleaseCompletion) OperationID() string {
	if v == nil {
		return ""
	}
	return v.binding.OperationID
}
func (v *VerifiedReleaseCompletion) Matches(e ReleaseExpected) bool {
	return v.Complete() && v.terminal == e.Terminal && v.binding == e.Binding
}

// One common route is used by native overall state/public consumers. Physical
// RESULT/job success and physical child exit are earlier independent facts.
func checkReleaseCompletion(ctx context.Context, d HeldTerminalDisposition, event *UnverifiedReleaseEvent, e ReleaseExpected, source ReleaseCompletionSource, commit bool) (*VerifiedReleaseCompletion, error) {
	if ctx == nil || ctx.Err() != nil || event == nil || Missing(source) || !ValidBinding(e.Binding) || d.binding != e.Binding || d.originalRef != e.Terminal || d.closure != e.HeldClosure || d.decision != e.ReleaseDecision || e.AuthorizedReleaseAction == "" || e.ApplicableDeadlineUnix <= 0 {
		return nil, ErrUnavailable
	}
	for _, r := range []RawRef{e.Terminal, e.HeldClosure, e.ReleaseDecision, e.ObserverOrigin, e.ReleaseActorOrigin, e.ReleaseAuthorization} {
		if !ValidRef(r) {
			return nil, ErrUnavailable
		}
	}
	if d.recoveryAction == "" {
		if e.ApplicableDeadlineUnix != e.Binding.OriginalCutoffUnix {
			return nil, ErrUnavailable
		}
	} else if d.recoveryAction != e.AuthorizedReleaseAction || d.recoveryDeadline != e.ApplicableDeadlineUnix || d.recoveryAuthorization != e.ReleaseAuthorization {
		return nil, ErrUnavailable
	}
	r := event.event
	b := e.Binding
	if r.TerminalOriginalRef != e.Terminal || r.HeldClosureRef != e.HeldClosure || r.ReleaseDecisionRef != e.ReleaseDecision || r.ObserverOriginRef != e.ObserverOrigin || r.ReleaseActorOriginRef != e.ReleaseActorOrigin || r.Keeper != b.Keeper || r.OperationID != b.OperationID || r.TargetFingerprint != b.TargetFingerprint || r.PublicationRevision != b.PublicationRevision {
		return nil, ErrUnavailable
	}
	released, err := time.Parse(time.RFC3339Nano, r.ActualReleaseAtUTC)
	observed, err2 := time.Parse(time.RFC3339Nano, r.ObservedAtUTC)
	if err != nil || err2 != nil || released.Format(time.RFC3339Nano) != r.ActualReleaseAtUTC || observed.Format(time.RFC3339Nano) != r.ObservedAtUTC || released.Location() != time.UTC || observed.Location() != time.UTC || released.Unix() <= 0 || released.Unix() >= e.ApplicableDeadlineUnix || !observed.After(released) || observed.After(time.Now()) {
		return nil, ErrUnavailable
	}
	o, err := source.AuthenticateRelease(ctx, d, event, e)
	check := func() error {
		if ctx.Err() != nil || o.Keeper != b.Keeper || o.Terminal != e.Terminal || o.Event != event.ref || o.LastOwner != r.LastOwnerReleaseObservationRef || !o.ActualReleaseAt.Equal(released) || !o.ObservedAt.Equal(observed) || len(o.OwnerProcesses) == 0 || len(o.Originals) == 0 {
			return ErrUnavailable
		}
		for _, p := range o.OwnerProcesses {
			if !ValidProcess(p) {
				return ErrUnavailable
			}
		}
		for _, ref := range o.Originals {
			if !ValidRef(ref) {
				return ErrUnavailable
			}
		}
		return source.RecheckRelease(ctx, d, event, e, o)
	}
	if err != nil || check() != nil {
		return nil, ErrUnavailable
	}
	if (commit && source.CommitCompletionOnce(ctx, e, event.ref) != nil) || check() != nil {
		return nil, ErrUnavailable
	}
	return &VerifiedReleaseCompletion{e.Terminal, event.ref, e.Binding, observed}, nil
}

func ConsumeReleaseCompletion(ctx context.Context, d HeldTerminalDisposition, event *UnverifiedReleaseEvent, e ReleaseExpected, source ReleaseCompletionSource) (*VerifiedReleaseCompletion, error) {
	return checkReleaseCompletion(ctx, d, event, e, source, true)
}

// Cached completion is consumed through the same actual event/original/native
// checks. The already committed completion CAS is never executed a second time.
func ValidateReleaseCompletion(ctx context.Context, v *VerifiedReleaseCompletion, d HeldTerminalDisposition, event *UnverifiedReleaseEvent, e ReleaseExpected, source ReleaseCompletionSource) error {
	if v == nil || event == nil || !v.Matches(e) || v.event != event.ref {
		return ErrUnavailable
	}
	current, err := checkReleaseCompletion(ctx, d, event, e, source, false)
	if err != nil || current == nil || current.terminal != v.terminal || current.event != v.event || current.binding != v.binding || !current.observed.Equal(v.observed) {
		return ErrUnavailable
	}
	return nil
}
