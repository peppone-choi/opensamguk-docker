package main

import (
	"bytes"
	"context"
	"sync"

	"opensamguk-deployer/internal/d101custody"
)

// Integrity and lifetime of originals supplied by the management installer.
// This collection is deliberately NOT an authenticated installation/session.
// Its caller must first authenticate the independent installer delegation and
// delivery. Neither constructing it nor reading an original registers a source.
// The management delivery producer is a separate, still required connection.
type resetD101ProductionOriginals struct {
	mu     sync.Mutex
	closed bool
	refs   []resetD101Key3OriginalRef
	held   map[string]*resetD101NativeHeldInput
	// Frozen by the production constructor to root. Disposable test custody
	// can use its actual file owner; this is not installation authentication.
	custodyUID uint32
}

// Freeze the complete expected set before opening any target. The expected
// references/pins come from private independent installation input; readback
// never supplies or repairs a missing expectation. Reuse the existing nofollow
// reader and hold both file and parent descriptors through guarded use.
func holdResetD101ProductionOriginals(ctx context.Context, refs []resetD101Key3OriginalRef, pins map[string]d101custody.NativeFilePin) (*resetD101ProductionOriginals, error) {
	if ctx == nil || ctx.Err() != nil || len(refs) == 0 || len(refs) != len(pins) {
		return nil, errResetD101InstallationNotSupplied
	}
	frozen := append([]resetD101Key3OriginalRef(nil), refs...)
	expected := make(map[string]d101custody.NativeFilePin, len(pins))
	for _, ref := range frozen {
		pin, ok := pins[ref.Path]
		if !ok || !validResetD101Key3Ref(ref) || ref.Bytes > 64<<10 ||
			pin.SHA256 != ref.SHA256 || pin.Snapshot.ByteLength != ref.Bytes ||
			pin.OwnerUID != 0 || pin.FileMode != 0400 || pin.LinkCount != 1 ||
			pin.ParentOwnerUID != 0 || pin.ParentMode != 0700 ||
			pin.Snapshot.Device == 0 || pin.Snapshot.Inode == 0 ||
			pin.ParentSnapshot.Device == 0 || pin.ParentSnapshot.Inode == 0 {
			return nil, errResetExecutionEvidence
		}
		if _, duplicate := expected[ref.Path]; duplicate {
			return nil, errResetExecutionEvidence
		}
		expected[ref.Path] = pin
	}
	v := &resetD101ProductionOriginals{refs: frozen, held: make(map[string]*resetD101NativeHeldInput, len(frozen)), custodyUID: 0}
	for _, ref := range frozen {
		h, err := openResetD101NativeInput(ctx, ref.Path, expected[ref.Path], 0400, 0)
		if err != nil {
			v.close()
			return nil, err
		}
		v.held[ref.Path] = h
	}
	if v.recheck(ctx) != nil {
		v.close()
		return nil, errResetExecutionEvidence
	}
	return v, nil
}

func (v *resetD101ProductionOriginals) recheckLocked(ctx context.Context) error {
	if v.closed || ctx == nil || ctx.Err() != nil || len(v.refs) == 0 || len(v.refs) != len(v.held) {
		return errResetExecutionEvidence
	}
	for _, ref := range v.refs {
		h := v.held[ref.Path]
		if h == nil || h.pin.SHA256 != ref.SHA256 || h.pin.Snapshot.ByteLength != ref.Bytes ||
			uint64(len(h.wire)) != ref.Bytes || resetD101OriginalSHA(h.wire) != ref.SHA256 || h.recheck(ctx, v.custodyUID) != nil {
			return errResetExecutionEvidence
		}
	}
	if ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func (v *resetD101ProductionOriginals) recheck(ctx context.Context) error {
	if v == nil {
		return errResetD101InstallationNotSupplied
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.recheckLocked(ctx)
}

// Return a caller-owned byte copy only while the whole original set still
// matches. An individual matching original cannot hide a replaced sibling.
func (v *resetD101ProductionOriginals) original(ctx context.Context, ref resetD101Key3OriginalRef) (d101custody.Original, error) {
	wire, _, err := v.originalPinned(ctx, ref)
	return wire, err
}

func (v *resetD101ProductionOriginals) originalPinned(ctx context.Context, ref resetD101Key3OriginalRef) (d101custody.Original, d101custody.NativeFilePin, error) {
	if v == nil {
		return d101custody.Original{}, d101custody.NativeFilePin{}, errResetD101InstallationNotSupplied
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.recheckLocked(ctx) != nil {
		return d101custody.Original{}, d101custody.NativeFilePin{}, errResetExecutionEvidence
	}
	var exact bool
	for _, expected := range v.refs {
		if expected == ref {
			exact = true
			break
		}
	}
	if !exact {
		return d101custody.Original{}, d101custody.NativeFilePin{}, errResetExecutionEvidence
	}
	h := v.held[ref.Path]
	wire := bytes.Clone(h.wire)
	if v.recheckLocked(ctx) != nil {
		clear(wire)
		return d101custody.Original{}, d101custody.NativeFilePin{}, errResetExecutionEvidence
	}
	return d101custody.Original{Bytes: wire, SHA256: ref.SHA256}, h.pin, nil
}

func (v *resetD101ProductionOriginals) close() {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return
	}
	v.closed = true
	for path, h := range v.held {
		if h != nil {
			h.close()
			clear(h.wire)
			h.wire = nil
		}
		delete(v.held, path)
	}
	v.refs = nil
}
