package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101custody"
)

func currentFreezeFixtureWire(t *testing.T, now time.Time, target resetLifecycleTarget) []byte {
	t.Helper()
	raw, err := json.Marshal(resetD101CurrentFreezeWire{ObservedAt: now.UTC().Format(time.RFC3339Nano), ServerID: "pep", OperationID: strings.Repeat("1", 32), TargetFingerprint: resetRequestFingerprint("pep", target), PublicationState: "VERIFYING", PublicationRevision: "2", WriterFreezeReceiptSHA: strings.Repeat("a", 64), WriterFreezeHeld: true})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestCurrentFreezeStrict8RejectsMalformedAndUnboundWire(t *testing.T) {
	wire := currentFreezeFixtureWire(t, time.Now(), resetLifecycleTarget{})
	if _, err := decodeResetD101CurrentFreeze(wire); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if json.Unmarshal(wire, &fields) != nil {
		t.Fatal("fixture")
	}
	cases := map[string][]byte{"duplicate": append([]byte(`{"serverId":"pep",`), wire[1:]...), "trailing": append(bytes.Clone(wire), []byte(` {}`)...), "array": []byte(`[]`), "bad-utf8": append(bytes.Clone(wire), 0xff), "oversize": bytes.Repeat([]byte(" "), resetD101CurrentFreezeLimit+1)}
	for _, name := range []string{"missing", "unknown", "null", "wrong-type", "noncanonical-revision", "zero-revision", "false-held", "wrong-server", "wrong-state", "wrong-sha", "wrong-op", "timezone-offset"} {
		copy := map[string]any{}
		for k, v := range fields {
			copy[k] = v
		}
		switch name {
		case "missing":
			delete(copy, "writerFreezeHeld")
		case "unknown":
			copy["captureNonce"] = strings.Repeat("f", 32)
		case "null":
			copy["writerFreezeHeld"] = nil
		case "wrong-type":
			copy["writerFreezeHeld"] = "true"
		case "noncanonical-revision":
			copy["publicationRevision"] = "02"
		case "zero-revision":
			copy["publicationRevision"] = "0"
		case "false-held":
			copy["writerFreezeHeld"] = false
		case "wrong-server":
			copy["serverId"] = "other"
		case "wrong-state":
			copy["publicationState"] = "PUBLISHED"
		case "wrong-sha":
			copy["writerFreezeReceiptSha256"] = strings.Repeat("G", 64)
		case "wrong-op":
			copy["operationId"] = "unknown"
		case "timezone-offset":
			copy["observedAt"] = time.Now().Format("2006-01-02T15:04:05-07:00")
		}
		raw, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		cases[name] = raw
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeResetD101CurrentFreeze(raw); err == nil {
				t.Fatal("malformed/unbound strict8 accepted")
			}
		})
	}
}

type currentFreezeFixtureSupplier struct {
	capture resetD101CurrentFreezeCapture
	err     error
	calls   int
}

func (s *currentFreezeFixtureSupplier) CaptureAfter(_ context.Context, _ resetExecutionPhaseBinding, _ time.Time) (resetD101CurrentFreezeCapture, error) {
	s.calls++
	return s.capture, s.err
}
func TestCurrentFreezeCausalRetainedNativeSource(t *testing.T) {
	cases := []string{"control", "supplier-error", "before-guard", "future-completion", "wrong-visible-sha", "wrong-parent", "wrong-mode", "hardlink", "same-inode", "changed-visible", "changed-original", "wrong-revision", "wrong-freeze", "expired-cutoff", "wrong-binding"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			target := resetLifecycleTarget{}
			wire := currentFreezeFixtureWire(t, now, target)
			sha := resetD101OriginalSHA(wire)
			supplier := &currentFreezeFixtureSupplier{capture: resetD101CurrentFreezeCapture{captureNonce: strings.Repeat("b", 32), wholeSHA: sha, collectorStarted: now, completed: now}}
			pins := resetD101CurrentFreezePins{operationID: strings.Repeat("1", 32), targetFingerprint: resetRequestFingerprint("pep", target), approvalPlanSHA: strings.Repeat("c", 64), publicationRevision: "2", freezeSHA: strings.Repeat("a", 64), directory: "/fixed/preflights", parentDevice: 1, parentInode: 2, destructiveCutoff: now.Add(time.Minute), supplier: supplier}
			binding := resetExecutionPhaseBinding{OperationID: pins.operationID, Target: target, Evidence: resetExecutionEvidenceRefs{ApprovalPlanSHA: pins.approvalPlanSHA}}
			visible := filepath.Join(pins.directory, "current-freeze-"+pins.operationID)
			visibleReads, originalReads := 0, 0
			read := func(path string, _ int64) (d101custody.Original, d101custody.NativeFilePin, error) {
				inode := uint64(3)
				if path == visible {
					visibleReads++
				} else {
					originalReads++
					inode = 4
				}
				pin := d101custody.NativeFilePin{SHA256: sha, Snapshot: d101custody.PrivateSnapshot{Device: 1, Inode: inode, ByteLength: uint64(len(wire)), ModifiedAtUnixNano: now.UnixNano()}, OwnerUID: 0, FileMode: 0400, LinkCount: 1, ParentSnapshot: d101custody.PrivateSnapshot{Device: 1, Inode: 2, ByteLength: 4096, ModifiedAtUnixNano: now.UnixNano()}, ParentOwnerUID: 0, ParentMode: 0700}
				if name == "wrong-parent" {
					pin.ParentSnapshot.Inode = 5
				}
				if name == "wrong-mode" {
					pin.FileMode = 0600
				}
				if name == "hardlink" {
					pin.LinkCount = 2
				}
				if name == "same-inode" {
					pin.Snapshot.Inode = 3
				}
				if name == "changed-visible" && visibleReads > 1 && path == visible {
					pin.Snapshot.Inode = 9
				}
				if name == "changed-original" && originalReads > 1 && path != visible {
					pin.Snapshot.Inode = 9
				}
				result := d101custody.Original{Bytes: bytes.Clone(wire), SHA256: sha}
				if name == "wrong-visible-sha" {
					result.SHA256 = strings.Repeat("d", 64)
				}
				return result, pin, nil
			}
			switch name {
			case "supplier-error":
				supplier.err = errors.New("synthetic supplier refusal")
			case "before-guard":
				supplier.capture.collectorStarted = now.Add(-time.Nanosecond)
			case "future-completion":
				supplier.capture.completed = now.Add(time.Nanosecond)
			case "wrong-revision":
				pins.publicationRevision = "3"
			case "wrong-freeze":
				pins.freezeSHA = strings.Repeat("e", 64)
			case "expired-cutoff":
				pins.destructiveCutoff = now
			case "wrong-binding":
				binding.Evidence.ApprovalPlanSHA = strings.Repeat("d", 64)
			}
			source, err := newResetD101CurrentFreezeSourceWithReader(pins, read, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			result, err := source(context.Background(), binding)
			if name != "control" {
				if err == nil {
					t.Fatal("invalid source accepted")
				}
				return
			}
			if err != nil || result.OperationID != pins.operationID || visibleReads != 2 || originalReads != 2 {
				t.Fatal("fixture current/retained binding", err, visibleReads, originalReads)
			}
			if _, err = source(context.Background(), binding); err == nil {
				t.Fatal("immutable current capture replay accepted")
			}
			supplier.capture.captureNonce = strings.Repeat("f", 32)
			if _, err = source(context.Background(), binding); err == nil {
				t.Fatal("same original reissued under another private nonce accepted")
			}
		})
	}
}
func TestCurrentFreezeMissingInstalledSupplierNeverReadsCurrent(t *testing.T) {
	now := time.Now()
	pins := resetD101CurrentFreezePins{operationID: strings.Repeat("1", 32), targetFingerprint: strings.Repeat("a", 64), approvalPlanSHA: strings.Repeat("c", 64), publicationRevision: "2", freezeSHA: strings.Repeat("a", 64), directory: "/fixed/preflights", parentDevice: 1, parentInode: 2, destructiveCutoff: now.Add(time.Minute)}
	reads := 0
	source, err := newResetD101CurrentFreezeSourceWithReader(pins, func(string, int64) (d101custody.Original, d101custody.NativeFilePin, error) {
		reads++
		return d101custody.Original{}, d101custody.NativeFilePin{}, nil
	}, time.Now)
	if err == nil || source != nil || reads != 0 {
		t.Fatal("nil actual supplier enabled a current reader")
	}
}
