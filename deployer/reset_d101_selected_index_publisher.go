package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101selectedtransport"
)

// Complete index is published only after the actual retained child, native
// originals and selected issuer have completed in this source invocation.
// The separately approved fixed namespace must already exist; no installer,
// mkdir, key creation, request-supplied destination or implicit retry exists.
func (c config) publishResetD101SelectedCaptureIndex(ctx context.Context, r *resetD101PreIntentCaptureReception) (string, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || !resetEvidenceSHA.MatchString(r.issuedReceiptSHA) || !resetEvidenceSHA.MatchString(r.issuedEnvelopeSHA) ||
		resetD101OriginalSHA(r.issuedReceipt) != r.issuedReceiptSHA || resetD101OriginalSHA(r.issuedEnvelope) != r.issuedEnvelopeSHA ||
		!bytes.Equal(r.issuedReceipt, r.originals["captureFacts"].Bytes) || r.requireUnsignedSnapshot() != nil || c.requireResetD101PreIntentRetainedChild(ctx, r) != nil || !r.indexAttempted.CompareAndSwap(false, true) {
		return "", errResetExecutionEvidence
	}
	directory := filepath.Join(d101selectedtransport.OriginalDirectory, r.source.reviewed.OperationID)
	if requireResetD101PreIntentDirectory(directory, true) != nil || requireResetD101PreIntentDirectory(filepath.Dir(d101selectedtransport.IndexPath), false) != nil {
		return "", errResetExecutionEvidence
	}
	if _, err := os.Lstat(d101selectedtransport.IndexPath); !os.IsNotExist(err) {
		return "", errResetExecutionEvidence
	}
	index := d101selectedtransport.Index{SchemaVersion: 1, Kind: d101selectedtransport.IndexKind, OriginalOp: r.manifest.OriginalOp, TargetFingerprint: r.manifest.TargetFingerprint,
		AppSourceSHA: r.manifest.AppSourceSHA, ImagePins: cloneResetD101Strings(r.manifest.ImagePins), ProducerIdentity: r.source.reviewed.ProducerIdentity,
		ProducerContainerID: r.child.ID, ProducerImageID: r.child.ImageID, SelectedEnvelopeSHA: r.issuedEnvelopeSHA, SelectedReceiptSHA: r.issuedReceiptSHA,
		PartBytes: d101custody.PrivateOriginalPartBytes, CapturedAtUTC: r.manifest.CapturedAtUTC, Originals: map[string]d101selectedtransport.SourceReference{}}
	originals := map[string][]byte{}
	for id, original := range r.originals {
		if id != "captureFacts" {
			originals[id] = append([]byte(nil), original.Bytes...)
		}
	}
	originals["selectedReceipt"] = append([]byte(nil), r.issuedReceipt...)
	originals["selectedEnvelope"] = append([]byte(nil), r.issuedEnvelope...)
	for id, wire := range originals {
		if !d101selectedtransport.ValidSourceID(id) || r.beforeCommand(ctx) != nil || r.recheck() != nil {
			return "", errResetExecutionEvidence
		}
		path := d101selectedtransport.OriginalPath(index.OriginalOp, id)
		if writeResetD101FixedCaptureOriginal(path, wire) != nil {
			return "", errResetExecutionEvidence
		}
		actual, snapshot, err := d101custody.CapturePrivateOriginal(path, int64(len(wire)))
		if err != nil || !bytes.Equal(actual.Bytes, wire) {
			return "", errResetExecutionEvidence
		}
		index.Originals[id] = d101selectedtransport.SourceReference{FilePath: path, RawSHA: actual.SHA256, ByteLength: uint64(len(wire)), Snapshot: snapshot, MediaType: resetD101PreIntentMedia(id)}
	}
	wire, err := json.Marshal(index)
	if err != nil || len(wire) > 64<<10 {
		return "", errResetExecutionEvidence
	}
	decoded, err := d101selectedtransport.Decode(wire, time.Now())
	if err != nil || !reflect.DeepEqual(index, decoded) {
		return "", errResetExecutionEvidence
	}
	if c.requireResetD101PreIntentRetainedChild(ctx, r) != nil {
		return "", errResetExecutionEvidence
	}
	// Complete index is the final immutable publication. Partial originals stay
	// retained and unavailable if any native check/write/sync becomes uncertain.
	if writeResetD101FixedCaptureOriginal(d101selectedtransport.IndexPath, wire) != nil {
		return "", errResetExecutionEvidence
	}
	actual, err := d101custody.ReadPrivate(d101selectedtransport.IndexPath, 64<<10)
	if err != nil || !bytes.Equal(actual.Bytes, wire) || r.recheck() != nil || ctx.Err() != nil {
		return "", errResetExecutionEvidence
	}
	for _, ref := range index.Originals {
		if d101custody.InspectPrivateSnapshot(ref.FilePath, ref.Snapshot) != nil {
			return "", errResetExecutionEvidence
		}
	}
	return actual.SHA256, nil
}

func writeResetD101FixedCaptureOriginal(path string, wire []byte) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(wire) == 0 || len(wire) > 64<<20 || requireResetD101PreIntentDirectory(filepath.Dir(path), false) != nil {
		return errResetExecutionEvidence
	}
	before, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return errResetExecutionEvidence
	}
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0400)
	if err != nil {
		return errResetExecutionEvidence
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if n, err := file.Write(wire); err != nil || n != len(wire) || file.Sync() != nil {
		return errResetExecutionEvidence
	}
	info, err := file.Stat()
	if err != nil || info.Size() != int64(len(wire)) || info.Mode().Perm() != 0400 {
		return errResetExecutionEvidence
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return errResetExecutionEvidence
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, after) {
		return errResetExecutionEvidence
	}
	afterDirectory, err := os.Lstat(filepath.Dir(path))
	if err != nil || !os.SameFile(before, afterDirectory) || requireResetD101PreIntentDirectory(filepath.Dir(path), false) != nil || syncResetPrivateDirectory(filepath.Dir(path)) != nil {
		return errResetExecutionEvidence
	}
	return nil
}
