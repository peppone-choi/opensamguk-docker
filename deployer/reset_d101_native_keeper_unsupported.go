//go:build !linux || !amd64

package main

import (
	"context"
	"io"
	"os"

	"opensamguk-deployer/internal/d101native"
)

// Data types are needed by the shared private source adapters on every platform.
type resetD101NativePreAcquisition struct {
	binding                         d101native.PreBinding
	lockPath, directory             string
	directoryDevice, directoryInode uint64
	approvalOriginal                []byte
	existing                        *resetD101NativeExistingKeeper
}
type resetD101NativeExistingKeeper struct {
	binding         d101native.PreBinding
	peer            d101native.Process
	requestOriginal []byte
}
type resetD101NativePreAcquisitionSource interface {
	AuthenticatePreAcquisition(context.Context, string, bool) (*resetD101NativePreAcquisition, error)
	RecheckPreAcquisition(context.Context, *resetD101NativePreAcquisition) error
	RequestExistingKeeper(context.Context, *resetD101NativeExistingKeeper, bool) error
}
type resetD101NativeStageSource interface {
	CaptureAuthenticatedStage(context.Context, *resetD101NativeKeeper, uint64) (any, error)
	RecheckAuthenticatedStage(context.Context, *resetD101NativeKeeper, uint64, any) error
	AwaitAuthenticatedPhysicalHandoff(context.Context, *resetD101NativeKeeper) error
	AuthenticateLastOwnedHandles(context.Context, *resetD101NativeKeeper, d101native.HeldTerminalDisposition) error
	ObserveActualRelease(context.Context, *resetD101NativeKeeper, d101native.HeldTerminalDisposition) (*resetD101NativeReleaseInputs, error)
}
type resetD101NativeKeeper struct{ descriptor *os.File }

var resetD101HeldNativeKeeper *resetD101NativeKeeper

func runResetD101NativeKeeper(context.Context, string, bool, io.Reader, io.Writer) int { return 2 }
func awaitResetD101NativeBirth(context.Context, *resetD101NativeAuthorityInstaller, string) error {
	return errResetD101InstallationNotSupplied
}
func resetD101NativeHoldMessage(w io.Writer) {
	if w != nil {
		_, _ = io.WriteString(w, "D101 native same operation HOLD\n")
	}
}

// Unsupported platforms cannot create production owners or namespaces.
func openResetD101RootOwnerAt(*os.File, string) (*os.File, error) {
	return nil, errResetExecutionEvidence
}
