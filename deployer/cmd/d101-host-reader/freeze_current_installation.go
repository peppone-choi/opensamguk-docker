package main

import (
	"context"
	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101freeze"
	"opensamguk-deployer/internal/d101native"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Extra private typed installation data, outside reader exact7/original14.
// Expected native pins MUST originate independently before any file is read.
type currentFreezeAuthorityExpected struct {
	operationID, targetSHA, revision, freezeSHA, readerSHA string
	cutoff                                                 time.Time
	anchorPath                                             string
	anchorPin                                              d101custody.NativeFilePin
	leaves                                                 map[string]d101custody.NativeFilePin
}

var reviewedCurrentFreezeAuthorityExpected *currentFreezeAuthorityExpected
var currentFreezeAuthorityLeaves = [...]string{"writer-freeze-receipt.bin", "installed-writer-inventory.bin", "keeper-session.bin", "console-admission.bin", "root-admission.bin", "old-services.bin", "turn-flush.bin", "publisher.bin", "postgres-admission.bin"}

func validateCurrentFreezeAuthorityExpected(v *currentFreezeAuthorityExpected, original d101custody.Original) error {
	if v == nil || !currentFreezeOp.MatchString(v.operationID) || !currentFreezeSHA.MatchString(v.targetSHA) || !currentFreezeSHA.MatchString(v.freezeSHA) || !currentFreezeSHA.MatchString(v.readerSHA) || original.SHA256 != v.readerSHA || v.revision == "" || v.cutoff.IsZero() || v.anchorPath != "/etc/opensamguk/d101/installation-anchor.spki" || !currentFreezeSHA.MatchString(v.anchorPin.SHA256) || len(v.leaves) != len(currentFreezeAuthorityLeaves) {
		return d101custody.ErrUnavailable
	}
	for _, leaf := range currentFreezeAuthorityLeaves {
		path := filepath.Join("/etc/opensamguk/d101/current-authority", v.operationID, leaf)
		p, ok := v.leaves[path]
		if !ok || !currentFreezeSHA.MatchString(p.SHA256) || p.OwnerUID != 0 || p.FileMode != 0400 || p.LinkCount != 1 || p.ParentOwnerUID != 0 || p.ParentMode != 0700 || p.Snapshot.Inode == 0 || p.ParentSnapshot.Inode == 0 {
			return d101custody.ErrUnavailable
		}
	}
	return nil
}
func readCurrentFreezeInstallationNegative(ctx context.Context, original d101custody.Original) (*currentFreezeHostInstallation, error) {
	if !d101native.Missing(d101native.ReviewedReaderFactory) {
		if ctx == nil || ctx.Err() != nil || runtime.GOOS != "linux" {
			return nil, d101custody.ErrUnavailable
		}
		actual, err := d101native.OpenActualReader(ctx, original)
		if err != nil {
			return nil, err
		}
		b := actual.Binding
		return &currentFreezeHostInstallation{installationSHA: actual.InstallationSHA, operationID: b.OperationID, targetFingerprint: b.TargetFingerprint, publicationRevision: b.PublicationRevision, freezeSHA: actual.FreezeSHA, destructiveCutoff: time.Unix(b.OriginalCutoffUnix, 0), directory: actual.Directory, parentDevice: actual.ParentDevice, parentInode: actual.ParentInode, lockPins: actual.LockPins, supplier: &nativeCurrentFreezeReaderSupplier{input: *actual}}, nil
	}
	if ctx == nil || ctx.Err() != nil || runtime.GOOS != "linux" || validateCurrentFreezeAuthorityExpected(reviewedCurrentFreezeAuthorityExpected, original) != nil {
		return nil, d101custody.ErrUnavailable
	}
	// The nine concrete original codecs/issuers/current admission producers are
	// absent. Paths, hashes and file ownership cannot populate the C3 supplier.
	return nil, d101custody.ErrUnavailable
}

type nativeCurrentFreezeReaderSupplier struct{ input d101native.ReaderInput }

func (s *nativeCurrentFreezeReaderSupplier) CollectAuthenticated(ctx context.Context, started time.Time, lock d101freeze.UnverifiedProductionLock) ([]byte, error) {
	if s == nil {
		return nil, d101custody.ErrUnavailable
	}
	inheritedCurrentFreezeDescriptor.Lock()
	descriptor := inheritedCurrentFreezeDescriptor.file
	inheritedCurrentFreezeDescriptor.Unlock()
	if descriptor == nil {
		descriptor = os.NewFile(9, "borrowed-native-reader-fd9")
	}
	return d101native.CollectReaderCurrent(ctx, s.input, descriptor, started, lock)
}
