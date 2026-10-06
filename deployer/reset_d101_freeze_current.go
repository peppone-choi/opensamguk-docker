package main

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
)

const resetD101CurrentFreezeLimit = 64 << 10
const resetD101CurrentFreezeDeadline = 2 * time.Second

// This is the C9 strict8 wire, not an installation or an authority receipt.
type resetD101CurrentFreezeWire struct {
	ObservedAt             string `json:"observedAt"`
	ServerID               string `json:"serverId"`
	OperationID            string `json:"operationId"`
	TargetFingerprint      string `json:"targetFingerprint"`
	PublicationState       string `json:"publicationState"`
	PublicationRevision    string `json:"publicationRevision"`
	WriterFreezeReceiptSHA string `json:"writerFreezeReceiptSha256"`
	WriterFreezeHeld       bool   `json:"writerFreezeHeld"`
}

func decodeResetD101CurrentFreeze(wire []byte) (resetExecutionPhaseSnapshot, error) {
	empty := resetExecutionPhaseSnapshot{}
	var value resetD101CurrentFreezeWire
	if len(wire) == 0 || len(wire) > resetD101CurrentFreezeLimit || !utf8.Valid(wire) || requireResetIntentShape(wire, reflect.TypeOf(value)) != nil || decodeResetPrivateJSON(wire, &value) != nil {
		return empty, errResetExecutionEvidence
	}
	observed, err := time.Parse(time.RFC3339Nano, value.ObservedAt)
	revision, revisionErr := strconv.ParseInt(value.PublicationRevision, 10, 64)
	if err != nil || !strings.HasSuffix(value.ObservedAt, "Z") || observed.IsZero() || value.ServerID != "pep" || !lifecycleJobIDRe.MatchString(value.OperationID) || !resetEvidenceSHA.MatchString(value.TargetFingerprint) || value.PublicationState != "VERIFYING" || !resetEvidenceSHA.MatchString(value.WriterFreezeReceiptSHA) || !value.WriterFreezeHeld || revisionErr != nil || revision <= 0 || strconv.FormatInt(revision, 10) != value.PublicationRevision {
		return empty, errResetExecutionEvidence
	}
	return resetExecutionPhaseSnapshot{ObservedAt: observed, ServerID: value.ServerID, OperationID: value.OperationID, TargetFingerprint: value.TargetFingerprint, PublicationState: value.PublicationState, PublicationRevision: value.PublicationRevision, WriterFreezeReceiptSHA: value.WriterFreezeReceiptSHA, WriterFreezeHeld: value.WriterFreezeHeld}, nil
}

// The independently installed host supplier must invoke the actual host launcher
// AFTER started and authenticate every writer component, same-OFD custody and
// retained original. This is an internal handoff, never an extra snapshot field.
// Container exec, a cached file, a self-reported PID or a SHA label cannot supply it.
type resetD101CurrentFreezeSupplier interface {
	CaptureAfter(context.Context, resetExecutionPhaseBinding, time.Time) (resetD101CurrentFreezeCapture, error)
}
type resetD101CurrentFreezeCapture struct {
	captureNonce     string
	wholeSHA         string
	collectorStarted time.Time
	completed        time.Time
}
type resetD101CurrentFreezePins struct {
	operationID         string
	targetFingerprint   string
	approvalPlanSHA     string
	publicationRevision string
	freezeSHA           string
	directory           string
	parentDevice        uint64
	parentInode         uint64
	destructiveCutoff   time.Time
	supplier            resetD101CurrentFreezeSupplier
}
type resetD101CurrentFreezeReader func(string, int64) (d101custody.Original, d101custody.NativeFilePin, error)

func newResetD101CurrentFreezeSource(pins resetD101CurrentFreezePins) (resetExecutionPhaseSource, error) {
	return newResetD101CurrentFreezeSourceWithReader(pins, d101custody.CapturePrivateOriginalPin, time.Now)
}

// Reader/clock injection is private to portable custody fixtures. Production
// always uses root-private FD/path/parent native capture and the actual clock.
func newResetD101CurrentFreezeSourceWithReader(pins resetD101CurrentFreezePins, read resetD101CurrentFreezeReader, clock func() time.Time) (resetExecutionPhaseSource, error) {
	if !lifecycleJobIDRe.MatchString(pins.operationID) || !resetEvidenceSHA.MatchString(pins.targetFingerprint) || !resetEvidenceSHA.MatchString(pins.approvalPlanSHA) || !resetEvidenceSHA.MatchString(pins.freezeSHA) || pins.publicationRevision == "" || !filepath.IsAbs(pins.directory) || filepath.Clean(pins.directory) != pins.directory || pins.parentDevice == 0 || pins.parentInode == 0 || pins.destructiveCutoff.IsZero() || pins.supplier == nil || (reflect.ValueOf(pins.supplier).Kind() == reflect.Pointer && reflect.ValueOf(pins.supplier).IsNil()) || read == nil || clock == nil {
		return nil, errResetExecutionEvidence
	}
	slots := make(chan struct{}, 2)
	var mu sync.Mutex
	consumed := make(map[string]bool)
	return func(ctx context.Context, binding resetExecutionPhaseBinding) (resetExecutionPhaseSnapshot, error) {
		empty := resetExecutionPhaseSnapshot{}
		if ctx == nil || ctx.Err() != nil || binding.OperationID != pins.operationID || resetRequestFingerprint("pep", binding.Target) != pins.targetFingerprint || binding.Evidence.ApprovalPlanSHA != pins.approvalPlanSHA {
			return empty, errResetExecutionEvidence
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			return empty, errResetExecutionEvidence
		}
		started := clock()
		deadline := started.Add(resetD101CurrentFreezeDeadline)
		if pins.destructiveCutoff.Before(deadline) {
			deadline = pins.destructiveCutoff
		}
		if !started.Before(deadline) {
			return empty, errResetExecutionEvidence
		}
		bounded, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		capture, err := pins.supplier.CaptureAfter(bounded, binding, started)
		now := clock()
		if err != nil || bounded.Err() != nil || !now.Before(deadline) || !lifecycleJobIDRe.MatchString(capture.captureNonce) || !resetEvidenceSHA.MatchString(capture.wholeSHA) || capture.collectorStarted.Before(started) || capture.completed.Before(capture.collectorStarted) || capture.completed.After(now) {
			return empty, errResetExecutionEvidence
		}
		// Nonces are private capture lifetimes, not approval identities. A supplier
		// cannot replay the same retained capture in a later guard even with new times.
		mu.Lock()
		used := consumed[capture.captureNonce] || consumed[capture.wholeSHA]
		mu.Unlock()
		if used {
			return empty, errResetExecutionEvidence
		}
		visible := filepath.Join(pins.directory, "current-freeze-"+pins.operationID)
		originalPath := visible + "-" + capture.captureNonce + ".original"
		first, pin, err := read(visible, resetD101CurrentFreezeLimit)
		if err != nil || !resetD101CurrentFreezePinMatches(pin, pins, capture.wholeSHA) || first.SHA256 != capture.wholeSHA {
			return empty, errResetExecutionEvidence
		}
		original, originalPin, err := read(originalPath, resetD101CurrentFreezeLimit)
		if err != nil || !resetD101CurrentFreezePinMatches(originalPin, pins, capture.wholeSHA) || original.SHA256 != first.SHA256 || !bytes.Equal(original.Bytes, first.Bytes) || originalPin.Snapshot.Inode == pin.Snapshot.Inode {
			return empty, errResetExecutionEvidence
		}
		current, err := decodeResetD101CurrentFreeze(first.Bytes)
		after, afterPin, readErr := read(visible, resetD101CurrentFreezeLimit)
		originalAfter, originalAfterPin, originalErr := read(originalPath, resetD101CurrentFreezeLimit)
		now = clock()
		if err != nil || readErr != nil || originalErr != nil || !reflect.DeepEqual(pin, afterPin) || !reflect.DeepEqual(originalPin, originalAfterPin) || !bytes.Equal(first.Bytes, after.Bytes) || !bytes.Equal(original.Bytes, originalAfter.Bytes) || bounded.Err() != nil || !now.Before(deadline) || current.ObservedAt.Before(capture.collectorStarted) || current.ObservedAt.After(capture.completed) || current.ObservedAt.After(now) || now.Sub(current.ObservedAt) >= resetPreflightMaxAge || current.OperationID != pins.operationID || current.TargetFingerprint != pins.targetFingerprint || current.PublicationRevision != pins.publicationRevision || current.WriterFreezeReceiptSHA != pins.freezeSHA {
			return empty, errResetExecutionEvidence
		}
		mu.Lock()
		defer mu.Unlock()
		if consumed[capture.captureNonce] || consumed[capture.wholeSHA] {
			return empty, errResetExecutionEvidence
		}
		consumed[capture.captureNonce] = true
		consumed[capture.wholeSHA] = true
		return current, nil
	}, nil
}
func resetD101CurrentFreezePinMatches(pin d101custody.NativeFilePin, pins resetD101CurrentFreezePins, sha string) bool {
	return pin.SHA256 == sha && pin.Snapshot.Device == pins.parentDevice && pin.Snapshot.Inode != 0 && pin.Snapshot.ByteLength > 0 && pin.Snapshot.ByteLength <= resetD101CurrentFreezeLimit && pin.OwnerUID == 0 && pin.FileMode == 0400 && pin.LinkCount == 1 && pin.ParentSnapshot.Device == pins.parentDevice && pin.ParentSnapshot.Inode == pins.parentInode && pin.ParentOwnerUID == 0 && pin.ParentMode == 0700
}
