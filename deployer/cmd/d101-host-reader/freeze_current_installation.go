package main

import (
	"context"
	"opensamguk-deployer/internal/d101custody"
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
	if ctx == nil || ctx.Err() != nil || runtime.GOOS != "linux" || validateCurrentFreezeAuthorityExpected(reviewedCurrentFreezeAuthorityExpected, original) != nil {
		return nil, d101custody.ErrUnavailable
	}
	// The nine concrete original codecs/issuers/current admission producers are
	// absent. Paths, hashes and file ownership cannot populate the C3 supplier.
	return nil, d101custody.ErrUnavailable
}
