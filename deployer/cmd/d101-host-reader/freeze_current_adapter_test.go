package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101freeze"
)

type hostCurrentAdapterDenySupplier struct{}

func (hostCurrentAdapterDenySupplier) CollectAuthenticated(context.Context, time.Time, d101freeze.UnverifiedProductionLock) ([]byte, error) {
	return nil, d101custody.ErrUnavailable
}

func TestHostCurrentFreezeFixedAdapterMissingInputNeverWrapsDescriptor(t *testing.T) {
	for _, mode := range []string{"nil-input", "non-linux", "wrong-source", "missing-supplier", "typed-nil-supplier", "wrong-op", "wrong-target", "missing-freeze", "missing-lock", "missing-parent", "relative-parent"} {
		t.Run(mode, func(t *testing.T) {
			pins := currentFreezeHostInstallation{installationSHA: strings.Repeat("a", 64), operationID: strings.Repeat("b", 32), targetFingerprint: strings.Repeat("c", 64), freezeSHA: strings.Repeat("d", 64), destructiveCutoff: time.Now().Add(time.Minute), directory: "/synthetic-originals", parentDevice: 1, parentInode: 2, lockPins: d101freeze.ProductionLockPins{Inode: 3}, supplier: hostCurrentAdapterDenySupplier{}}
			original := d101custody.Original{SHA256: pins.installationSHA}
			input := &pins
			platform := "linux"
			switch mode {
			case "nil-input":
				input = nil
			case "non-linux":
				platform = "portable-test"
			case "wrong-source":
				original.SHA256 = strings.Repeat("e", 64)
			case "missing-supplier":
				pins.supplier = nil
			case "typed-nil-supplier":
				pins.supplier = (*hostCurrentAdapterDenySupplier)(nil)
			case "wrong-op":
				pins.operationID = "invalid"
			case "wrong-target":
				pins.targetFingerprint = "invalid"
			case "missing-freeze":
				pins.freezeSHA = ""
			case "missing-lock":
				pins.lockPins.Inode = 0
			case "missing-parent":
				pins.parentInode = 0
			case "relative-parent":
				pins.directory = "relative"
			}
			before := inheritedCurrentFreezeDescriptor.file
			value, err := fixedCurrentFreezeHostInstallationWithInput(original, input, platform)
			if err == nil || value.descriptor != nil || inheritedCurrentFreezeDescriptor.file != before || value.captureNonce != "" {
				t.Fatal("missing authentic producer acquired descriptor/capture", mode, err)
			}
		})
	}
}
