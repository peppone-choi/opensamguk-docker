package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101operatorauth"
)

// Independently installed private native values, never an env/HTTP registry.
// The actual original/policy/whole-OFD semantic verifier and existing issuer
// producer are mandatory. Native file pins do not supply either authority.
type resetD101HostInstallerInputs struct {
	operation            resetD101HostOperationInstallation
	issuer               resetD101HostIssuerInstallation
	ledger               resetD101IssuerLedgerInputs
	originalPins         map[string]d101custody.NativeFilePin
	issuerReferencePaths map[string]string
	binaryPin            d101custody.NativeFilePin
	authenticate         func(context.Context, *os.File, string, string) error
}
type resetD101NativeHostInstaller struct{ inputs resetD101HostInstallerInputs }

// Missing actual registration stays nil/deny. A concrete installer below binds
// one frozen input bundle and native custody to both exact callers. Supplying
// labels or the data-shaped reader-installation record cannot populate this.
var resetD101ReviewedHostInstallerInputs *resetD101HostInstallerInputs

func newResetD101NativeHostInstaller(v *resetD101HostInstallerInputs) (*resetD101NativeHostInstaller, error) {
	if v == nil || v.authenticate == nil ||
		v.ledger.authenticate == nil || v.ledger.emitter == nil ||
		!lifecycleJobIDRe.MatchString(v.operation.operationID) || v.operation.operationID != v.issuer.operationID || v.issuer.operationID != v.ledger.operationID ||
		!gitSHA40.MatchString(v.operation.sourceSHA) || v.operation.sourceSHA != v.issuer.sourceSHA ||
		!resetEvidenceSHA.MatchString(v.operation.binarySHA) || v.operation.binarySHA != v.issuer.binarySHA || v.binaryPin.SHA256 != v.operation.binarySHA ||
		v.issuer.policy.Scope.OperationID != v.issuer.operationID || v.issuer.policy.Scope.DockerSourceSHA != v.issuer.sourceSHA ||
		!reflect.DeepEqual(v.ledger.policy, v.issuer.policy) || v.ledger.jwtLogicalID != v.issuer.jwtLogicalID ||
		len(v.originalPins) < 8 || len(v.originalPins) > 64 {
		return nil, errResetD101InstallationNotSupplied
	}
	if _, err := newResetD101NativeIssuerCustody(v.ledger); err != nil {
		return nil, err
	}
	if v.binaryPin.FileMode != 0500 || v.binaryPin.OwnerUID != 0 || v.binaryPin.LinkCount != 1 || v.binaryPin.ParentOwnerUID != 0 || v.binaryPin.ParentMode != 0700 || v.binaryPin.Snapshot.ByteLength == 0 || v.binaryPin.Snapshot.ByteLength > 32<<20 {
		return nil, errResetExecutionEvidence
	}
	copy := *v
	copy.originalPins = make(map[string]d101custody.NativeFilePin, len(v.originalPins))
	for path, pin := range v.originalPins {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || !resetEvidenceSHA.MatchString(pin.SHA256) || pin.FileMode != 0400 || pin.OwnerUID != 0 || pin.LinkCount != 1 || pin.ParentOwnerUID != 0 || pin.ParentMode != 0700 || pin.Snapshot.ByteLength == 0 || pin.Snapshot.ByteLength > 64<<10 {
			return nil, errResetExecutionEvidence
		}
		copy.originalPins[path] = pin
	}
	if _, ok := copy.originalPins[resetD101NativeReaderInstallationPath]; !ok {
		return nil, errResetExecutionEvidence
	}
	refs := []d101operatorauth.Reference{v.issuer.policy.ReviewOriginal, v.issuer.policy.Scope.FinalCard, v.issuer.policy.Scope.ScopeOriginal}
	refs = append(refs, v.issuer.policy.Scope.DecisionParents[:]...)
	copy.issuerReferencePaths = make(map[string]string, len(refs))
	seenPaths := map[string]bool{}
	for _, ref := range refs {
		path, ok := v.issuerReferencePaths[ref.LogicalID]
		pin, present := copy.originalPins[path]
		if !ok || !present || seenPaths[path] || pin.SHA256 != ref.SHA256 || pin.Snapshot.ByteLength != ref.ByteLength {
			return nil, errResetExecutionEvidence
		}
		seenPaths[path] = true
		copy.issuerReferencePaths[ref.LogicalID] = path
	}
	copy.issuer.policy = cloneResetD101TechnicalPolicy(v.issuer.policy)
	copy.ledger.policy = cloneResetD101TechnicalPolicy(v.ledger.policy)
	if v.operation.bootstrap != nil {
		bootstrap := *v.operation.bootstrap
		bootstrap.anchorDER = bytes.Clone(bootstrap.anchorDER)
		copy.operation.bootstrap = &bootstrap
	}
	copy.operation.target.ImageDigests = cloneResetD101Strings(v.operation.target.ImageDigests)
	copy.operation.target.StorageImageDigests = cloneResetD101Strings(v.operation.target.StorageImageDigests)
	return &resetD101NativeHostInstaller{copy}, nil
}

func (v *resetD101NativeHostInstaller) authenticate(ctx context.Context, fd *os.File, op, phase string) error {
	if v == nil || ctx == nil || ctx.Err() != nil || fd == nil || fd.Fd() != 9 || runtime.GOOS != "linux" || os.Geteuid() != 0 ||
		op != v.inputs.operation.operationID || rootBuiltSourceSHA != v.inputs.operation.sourceSHA || v.inputs.authenticate == nil ||
		v.inputs.authenticate(ctx, fd, op, phase+"-before-pins") != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	// Read the actual running image through /proc/self/exe; also compare the
	// approved installed binary. An argv/path label cannot select another source.
	actual, err := os.Readlink("/proc/self/exe")
	const binaryPath = "/etc/opensamguk/d101/native-helper/deployer"
	if err != nil || actual != binaryPath {
		return errResetExecutionEvidence
	}
	binary, pin, err := d101custody.CapturePrivateExecutablePin(binaryPath, 32<<20)
	if err != nil || pin != v.inputs.binaryPin || binary.SHA256 != v.inputs.operation.binarySHA {
		return errResetExecutionEvidence
	}
	before := make(map[string]d101custody.Original, len(v.inputs.originalPins))
	for path, want := range v.inputs.originalPins {
		wire, pin, err := d101custody.CapturePrivateOriginalPin(path, int64(want.Snapshot.ByteLength))
		if err != nil || pin != want {
			return errResetExecutionEvidence
		}
		before[path] = wire
	}
	if v.inputs.authenticate(ctx, fd, op, phase+"-semantic") != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	for path, want := range v.inputs.originalPins {
		wire, pin, err := d101custody.CapturePrivateOriginalPin(path, int64(want.Snapshot.ByteLength))
		if err != nil || pin != want || !bytes.Equal(wire.Bytes, before[path].Bytes) {
			return errResetExecutionEvidence
		}
	}
	after, afterPin, err := d101custody.CapturePrivateExecutablePin(binaryPath, 32<<20)
	if err != nil || afterPin != pin || !bytes.Equal(binary.Bytes, after.Bytes) || ctx.Err() != nil ||
		v.inputs.authenticate(ctx, fd, op, phase+"-after-pins") != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	runtime.KeepAlive(fd)
	return nil
}

func (v *resetD101NativeHostInstaller) hostOperation(ctx context.Context, fd *os.File, op string) (*resetD101HostOperationInstallation, error) {
	if v == nil || v.inputs.operation.bootstrap == nil || v.inputs.operation.bootstrap.producer == nil || v.authenticate(ctx, fd, op, "operation-registration") != nil {
		return nil, errResetD101InstallationNotSupplied
	}
	p := v.inputs.operation
	p.authenticate = v.authenticate
	return &p, nil
}

func (v *resetD101NativeHostInstaller) hostIssuer(ctx context.Context, fd *os.File, op string) (*resetD101HostIssuerInstallation, error) {
	if v == nil || v.authenticate(ctx, fd, op, "issuer-registration") != nil {
		return nil, errResetD101InstallationNotSupplied
	}
	inputs := v.inputs.ledger
	// Both the independent issuer semantic verifier and the concrete installer
	// are required before/after ledger IO. Neither callback has a success default.
	issuerAuthenticate := inputs.authenticate
	inputs.authenticate = func(ctx context.Context, fd *os.File, op, phase string) error {
		if v.authenticate(ctx, fd, op, phase) != nil || issuerAuthenticate(ctx, fd, op, phase) != nil || ctx.Err() != nil {
			return errResetExecutionEvidence
		}
		return nil
	}
	custody, err := newResetD101NativeIssuerCustody(inputs)
	if err != nil {
		return nil, err
	}
	p := v.inputs.issuer
	p.custody = custody
	p.policy = cloneResetD101TechnicalPolicy(p.policy)
	return &p, nil
}

func resetD101InstalledHostOperationSupplier(ctx context.Context, fd *os.File, op string) (*resetD101HostOperationInstallation, error) {
	installer, err := newResetD101NativeHostInstaller(resetD101ReviewedHostInstallerInputs)
	if err != nil {
		return nil, err
	}
	return installer.hostOperation(ctx, fd, op)
}
func resetD101InstalledHostIssuerSupplier(ctx context.Context, fd *os.File, op string) (*resetD101HostIssuerInstallation, error) {
	installer, err := newResetD101NativeHostInstaller(resetD101ReviewedHostInstallerInputs)
	if err != nil {
		return nil, err
	}
	return installer.hostIssuer(ctx, fd, op)
}
