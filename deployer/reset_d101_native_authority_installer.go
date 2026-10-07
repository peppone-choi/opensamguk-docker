package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"time"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101hostlaunch"
	"opensamguk-deployer/internal/d101native"
	"opensamguk-deployer/internal/d101operatorauth"
)

// Defaults are absent. The exact real input card supplies independently
// authenticated actors/keys/purposes/sources/native namespaces. No file body,
// environment, HTTP switch or service transport credential registers them.
var resetD101ReviewedNativeAuthorityInstaller *resetD101NativeAuthorityInstaller
var resetD101ReviewedNativeEntryFactory resetD101NativeEntryFactory

type resetD101NativeEntryFactory interface {
	OpenApprovedEntry(context.Context, string, string) (*resetD101NativeAuthorityInstaller, error)
}
type resetD101NativeCurrentSource interface {
	Current(context.Context, *os.File, string, uint64) (*d101native.CurrentVerifier, error)
}
type resetD101NativeInstallerSource interface {
	AuthenticateInstallation(context.Context, string, string) error
	RecheckInstallation(context.Context, string, string) error
}
type resetD101NativeKey3Inputs struct {
	ceremony        *resetD101Key3CeremonyExpected
	ceremonySource  resetD101Key3CeremonyAuthenticationSource
	execution       *resetD101Key3NativeInitializationExpected
	executionSource resetD101Key3NativeInitializationSource
}
type resetD101NativeAuthorityInstaller struct {
	operationID    string
	current        resetD101NativeCurrentSource
	installation   resetD101NativeInstallerSource
	rootSource     resetD101RootSource
	preAcquisition resetD101NativePreAcquisitionSource
	stages         resetD101NativeStageSource
	signing        resetD101NativeSigningSource
	issuerLedger   *resetD101IssuerLedgerInputs
	issuer         *resetD101HostIssuerInstallation
	physical       *resetD101HostInstallerInputs
	technical      resetD101TechnicalInstallationProducer
	mainBootstrap  *resetD101InstalledBootstrap
	launcherPins   d101hostlaunch.Pins
	relay          *resetD101NativeRelayInputs
	release        *resetD101NativeReleaseInputs
	completion     atomic.Pointer[d101native.VerifiedReleaseCompletion]
	completionBusy atomic.Bool
	mainCurrent    resetD101NativeMainCurrentSource
	key3           *resetD101NativeKey3Inputs

	nativeOwnerContext        context.Context
	managementSession         *d101native.ManagementSession
	managementBinding         *d101native.ManagementConnectionBinding
	expectedManagementBinding []byte
}

func actualResetD101NativeEntry(ctx context.Context, entry, op string) (*resetD101NativeAuthorityInstaller, error) {
	if ctx == nil || ctx.Err() != nil || d101native.Missing(resetD101ReviewedNativeEntryFactory) {
		return nil, errResetD101InstallationNotSupplied
	}
	v, err := resetD101ReviewedNativeEntryFactory.OpenApprovedEntry(ctx, entry, op)
	if err != nil || v == nil || (op != "" && op != v.operationID) || d101native.Missing(v.installation) || v.installation.AuthenticateInstallation(ctx, v.operationID, entry) != nil || ctx.Err() != nil || v.installation.RecheckInstallation(ctx, v.operationID, entry) != nil {
		return nil, errResetD101InstallationNotSupplied
	}
	return v, nil
}

// This is bounded resource plumbing only. An independently authenticated
// current native original must supply the owner bound and expected wire.
func resetD101ManagedEntryContext(caller context.Context, v *resetD101NativeAuthorityInstaller, op string) (context.Context, context.CancelFunc, error) {
	if d101native.Missing(caller) || caller.Err() != nil || v == nil || op != v.operationID || !lifecycleJobIDRe.MatchString(op) ||
		d101native.Missing(v.installation) || d101native.Missing(v.nativeOwnerContext) || v.nativeOwnerContext.Err() != nil ||
		len(v.expectedManagementBinding) == 0 || len(v.expectedManagementBinding) > d101native.PayloadMaxBytes {
		return nil, nil, errResetD101InstallationNotSupplied
	}
	deadline, bounded := v.nativeOwnerContext.Deadline()
	if !bounded || !deadline.After(time.Now()) {
		return nil, nil, errResetD101InstallationNotSupplied
	}
	if callerDeadline, bounded := caller.Deadline(); bounded {
		if !callerDeadline.After(time.Now()) {
			return nil, nil, errResetD101InstallationNotSupplied
		}
		if callerDeadline.Before(deadline) { deadline = callerDeadline }
	}
	child, childCancel := context.WithDeadline(v.nativeOwnerContext, deadline)
	stopCaller := context.AfterFunc(caller, childCancel)
	// AfterFunc stop and CancelFunc are individually safe to call repeatedly.
	cancel := func() { stopCaller(); childCancel() }
	if caller.Err() != nil || v.nativeOwnerContext.Err() != nil || child.Err() != nil {
		cancel()
		return nil, nil, errResetD101InstallationNotSupplied
	}
	return child, cancel, nil
}

func resetD101ManagedEntryRequired(v *resetD101NativeAuthorityInstaller) bool {
	return v != nil && (v.nativeOwnerContext != nil || v.managementSession != nil || v.managementBinding != nil || len(v.expectedManagementBinding) != 0)
}

func (v *resetD101NativeAuthorityInstaller) recheckManagedEntry(ctx context.Context, entry, op string) error {
	if v == nil || d101native.Missing(ctx) || ctx.Err() != nil || entry != "--d101-host-operation" || op != v.operationID || !lifecycleJobIDRe.MatchString(op) ||
		d101native.Missing(v.installation) || d101native.Missing(v.nativeOwnerContext) || v.nativeOwnerContext.Err() != nil ||
		v.managementSession == nil || v.managementBinding == nil || len(v.expectedManagementBinding) == 0 || len(v.expectedManagementBinding) > d101native.PayloadMaxBytes {
		return errResetD101InstallationNotSupplied
	}
	deadline, bounded := ctx.Deadline()
	ownerDeadline, ownerBounded := v.nativeOwnerContext.Deadline()
	if !bounded || !ownerBounded || !deadline.After(time.Now()) || !ownerDeadline.After(time.Now()) || deadline.After(ownerDeadline) ||
		v.managementBinding.RecheckExpected(ctx, v.expectedManagementBinding) != nil {
		return errResetD101InstallationNotSupplied
	}
	if v.installation.AuthenticateInstallation(ctx, op, entry) != nil || ctx.Err() != nil ||
		v.installation.RecheckInstallation(ctx, op, entry) != nil || v.nativeOwnerContext.Err() != nil ||
		v.managementBinding.RecheckExpected(ctx, v.expectedManagementBinding) != nil {
		return errResetD101InstallationNotSupplied
	}
	return nil
}

func (v *resetD101NativeAuthorityInstaller) closeManagementEntry() error {
	if v == nil || v.managementSession == nil { return nil }
	// Keep these opaque fields set: a closed managed instance cannot become an
	// ordinary unguarded instance. Never cancel the original native owner here.
	return v.managementSession.Close()
}

func (v *resetD101NativeAuthorityInstaller) consumePhase(ctx context.Context, fd *os.File, op string, sequence uint64, use func(*d101native.VerifiedCurrent) error) error {
	if v == nil || ctx == nil || ctx.Err() != nil || op != v.operationID || d101native.Missing(v.current) || d101native.Missing(v.installation) || use == nil {
		return errResetD101InstallationNotSupplied
	}
	if resetD101ManagedEntryRequired(v) && v.recheckManagedEntry(ctx, "--d101-host-operation", op) != nil {
		return errResetD101InstallationNotSupplied
	}
	if v.installation.AuthenticateInstallation(ctx, op, "current") != nil {
		return errResetD101InstallationNotSupplied
	}
	current, err := v.current.Current(ctx, fd, op, sequence)
	if err != nil || current == nil {
		return errResetExecutionEvidence
	}
	err = current.Consume(ctx, func(a *d101native.VerifiedCurrent) error {
		b, ok := a.Binding()
		seq, ok2 := a.Sequence()
		if !ok || !ok2 || b.OperationID != op || seq != sequence {
			return errResetExecutionEvidence
		}
		if resetD101ManagedEntryRequired(v) && v.recheckManagedEntry(ctx, "--d101-host-operation", op) != nil {
			return errResetExecutionEvidence
		}
		if err := use(a); err != nil { return err }
		if resetD101ManagedEntryRequired(v) && v.recheckManagedEntry(ctx, "--d101-host-operation", op) != nil {
			return errResetExecutionEvidence
		}
		return nil
	})
	if err != nil || ctx.Err() != nil || (resetD101ManagedEntryRequired(v) && v.recheckManagedEntry(ctx, "--d101-host-operation", op) != nil) ||
		v.installation.RecheckInstallation(ctx, op, "current") != nil ||
		(resetD101ManagedEntryRequired(v) && v.recheckManagedEntry(ctx, "--d101-host-operation", op) != nil) {
		return errResetExecutionEvidence
	}
	return nil
}
func (v *resetD101NativeAuthorityInstaller) hostIssuer(ctx context.Context, fd *os.File, op string) (*resetD101HostIssuerInstallation, error) {
	if v == nil || v.issuer == nil || v.issuerLedger == nil {
		return nil, errResetD101InstallationNotSupplied
	}
	var out *resetD101HostIssuerInstallation
	err := v.consumePhase(ctx, fd, op, 11, func(a *d101native.VerifiedCurrent) error {
		p := *v.issuer
		ledger := *v.issuerLedger
		b, _ := a.Binding()
		if p.operationID != op || p.sourceSHA != rootBuiltSourceSHA || p.binarySHA != b.Keeper.Process.ExeSHA256 || ledger.operationID != op || !reflect.DeepEqual(ledger.policy, p.policy) || ledger.authenticate == nil || d101native.Missing(ledger.emitter) {
			return errResetExecutionEvidence
		}
		custody, err := newResetD101NativeIssuerCustody(ledger)
		if err != nil {
			return err
		}
		p.custody = custody
		p.policy = cloneResetD101TechnicalPolicy(p.policy)
		out = &p
		return nil
	})
	if err != nil || out == nil {
		return nil, errResetD101InstallationNotSupplied
	}
	return out, nil
}
func (v *resetD101NativeAuthorityInstaller) hostOperation(ctx context.Context, fd *os.File, op string) (*resetD101HostOperationInstallation, error) {
	if v == nil || v.physical == nil {
		return nil, errResetD101InstallationNotSupplied
	}
	var out *resetD101HostOperationInstallation
	err := v.consumePhase(ctx, fd, op, 13, func(a *d101native.VerifiedCurrent) error {
		// Final originals/receipt now actually exist. Keep the original constructor
		// and all its original14/reader/policy/native-source checks intact.
		installer, err := newResetD101NativeHostInstaller(v.physical)
		if err != nil {
			return err
		}
		p, err := installer.hostOperation(ctx, fd, op)
		if err != nil || p == nil || p.bootstrap == nil {
			return errResetExecutionEvidence
		}
		bootstrap := *p.bootstrap
		producer, ok := bootstrap.producer.(*resetD101TechnicalBootstrapProducer)
		if !ok || producer == nil {
			return errResetExecutionEvidence
		}
		// Never copy synchronization state from a live producer. New one-attempt
		// wrapper owns the actual typed verifier/policy/JWT and concrete adapter.
		bootstrap.producer = &resetD101TechnicalBootstrapProducer{policy: cloneResetD101TechnicalPolicy(producer.policy), event: producer.event, jwtPath: producer.jwtPath, jwtPin: producer.jwtPin, authenticate: producer.authenticate, installation: &resetD101NativeTechnicalAdapter{installer: v, descriptor: fd}}
		p.bootstrap = &bootstrap
		p.configuration.d101NativeInstaller = v
		if resetD101ManagedEntryRequired(v) {
			authenticate := p.authenticate
			if authenticate == nil { return errResetExecutionEvidence }
			p.authenticate = func(ctx context.Context, descriptor *os.File, op, phase string) error {
				if v.recheckManagedEntry(ctx, "--d101-host-operation", op) != nil { return errResetExecutionEvidence }
				if err := authenticate(ctx, descriptor, op, phase); err != nil { return err }
				return v.recheckManagedEntry(ctx, "--d101-host-operation", op)
			}
		}
		out = p
		return nil
	})
	if err != nil || out == nil {
		return nil, errResetD101InstallationNotSupplied
	}
	return out, nil
}

// Concrete typed technical producer adapter; it never fabricates an opaque C1
// TechnicalIssuance or returns an empty successful fixed installation.
type resetD101NativeTechnicalAdapter struct {
	installer  *resetD101NativeAuthorityInstaller
	descriptor *os.File
}

func (a *resetD101NativeTechnicalAdapter) BuildFromTechnicalIssuance(ctx context.Context, issuance d101operatorauth.TechnicalIssuance, native resetD101BootstrapNativeOriginals) (*resetD101FixedInstallation, error) {
	if a == nil || a.installer == nil || d101native.Missing(a.installer.technical) {
		return nil, errResetD101InstallationNotSupplied
	}
	var out *resetD101FixedInstallation
	err := a.installer.consumePhase(ctx, a.descriptor, native.operationID, 13, func(current *d101native.VerifiedCurrent) error {
		b, _ := current.Binding()
		scope, err := issuance.Scope()
		if err != nil || scope.OperationID != b.OperationID {
			return errResetExecutionEvidence
		}
		p, err := a.installer.technical.BuildFromTechnicalIssuance(ctx, issuance, cloneResetD101BootstrapNative(native))
		if err != nil || p == nil {
			return errResetExecutionEvidence
		}
		if p.authority.OperationID != b.OperationID || p.current.operationID != b.OperationID || p.current.targetFingerprint != b.TargetFingerprint || p.current.publicationRevision != b.PublicationRevision || p.current.destructiveCutoff.Unix() != b.OriginalCutoffUnix || p.current.freezeSHA != resetD101OriginalSHA(current.Original(9)) {
			return errResetExecutionEvidence
		}
		// Existing host helper/held reader and PREPARED witness stay the real
		// collector. Its authenticator now consumes full current native authority.
		pins := p.current
		if a.descriptor == nil {
			if d101native.Missing(a.installer.mainCurrent) {
				return errResetD101InstallationNotSupplied
			}
			p.current.supplier = &resetD101NativeMainCurrentSupplier{installer: a.installer, pins: pins}
			p.nativeInstaller = a.installer
			out = p
			return nil
		}
		supplier, err := newResetD101CurrentHostSupplier(a.descriptor, a.installer.launcherPins, pins, func(call context.Context, binding resetExecutionPhaseBinding, obs resetD101CurrentHostObservation) error {
			if binding.OperationID != b.OperationID || obs.captureNonce == "" || len(obs.original) == 0 {
				return errResetExecutionEvidence
			}
			return a.installer.consumePhase(call, a.descriptor, b.OperationID, 13, func(next *d101native.VerifiedCurrent) error {
				actual, _ := next.Binding()
				if actual != b {
					return errResetExecutionEvidence
				}
				raw, err := decodeResetD101CurrentFreeze(obs.original)
				if err != nil || raw.OperationID != b.OperationID || raw.TargetFingerprint != b.TargetFingerprint || raw.PublicationRevision != b.PublicationRevision || raw.WriterFreezeReceiptSHA != resetD101OriginalSHA(next.Original(9)) {
					return errResetExecutionEvidence
				}
				return nil
			})
		})
		if err != nil {
			return err
		}
		p.current.supplier = supplier
		p.nativeInstaller = a.installer
		out = p
		return nil
	})
	if err != nil || out == nil {
		return nil, errResetD101InstallationNotSupplied
	}
	return out, nil
}
func (v *resetD101NativeAuthorityInstaller) fixedForMain(ctx context.Context, c config, original d101custody.Original, pin d101custody.NativeFilePin) (*resetD101FixedInstallation, error) {
	if v == nil || v.mainBootstrap == nil {
		return nil, errResetD101InstallationNotSupplied
	}
	// Actual typed bootstrap, retained JWT and complete final originals are used.
	copy := *v.mainBootstrap
	producer, ok := copy.producer.(*resetD101TechnicalBootstrapProducer)
	if !ok || producer == nil {
		return nil, errResetExecutionEvidence
	}
	p := &resetD101TechnicalBootstrapProducer{policy: cloneResetD101TechnicalPolicy(producer.policy), event: producer.event, jwtPath: producer.jwtPath, jwtPin: producer.jwtPin, authenticate: producer.authenticate, installation: &resetD101NativeTechnicalAdapter{installer: v}}
	copy.producer = p
	installed, err := loadResetD101ReviewedInstallation(ctx, c, &copy)
	if err != nil || installed.d101FixedInstallation == nil || installed.d101FixedInstallation.readerSHA != original.SHA256 || installed.d101FixedInstallation.readerPin != pin {
		return nil, errResetExecutionEvidence
	}
	return installed.d101FixedInstallation, nil
}

// Native fixed-loader reads remain held against independent whole file pins.
// They are data input to the shared actual verifier, never authentication alone.
type resetD101NativeOriginalReader struct {
	pins map[d101native.RawRef]d101custody.NativeFilePin
}
type resetD101NativeHeldOriginal struct {
	held *resetD101NativeHeldInput
	ref  d101native.RawRef
}

func (r *resetD101NativeOriginalReader) HoldOriginal(ctx context.Context, ref d101native.RawRef) (d101native.HeldOriginal, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !d101native.ValidRef(ref) {
		return nil, errResetExecutionEvidence
	}
	pin, ok := r.pins[ref]
	n := ref.Native
	if !ok || pin.SHA256 != ref.SHA256 || pin.Snapshot.ByteLength != ref.Bytes || pin.Snapshot.Device != n.Device || pin.Snapshot.Inode != n.Inode || pin.OwnerUID != n.OwnerUID || pin.FileMode != n.Mode || pin.LinkCount != n.Links || pin.ParentSnapshot.Device != n.ParentDevice || pin.ParentSnapshot.Inode != n.ParentInode {
		return nil, errResetExecutionEvidence
	}
	h, err := openResetD101NativeInput(ctx, ref.Path, pin, n.Mode, 0)
	if err != nil {
		return nil, err
	}
	return &resetD101NativeHeldOriginal{h, ref}, nil
}
func (h *resetD101NativeHeldOriginal) Original() []byte {
	if h == nil || h.held == nil {
		return nil
	}
	return bytes.Clone(h.held.wire)
}
func (h *resetD101NativeHeldOriginal) Reference() d101native.RawRef {
	if h == nil {
		return d101native.RawRef{}
	}
	return h.ref
}
func (h *resetD101NativeHeldOriginal) Recheck(ctx context.Context) error {
	if h == nil || h.held == nil {
		return errResetExecutionEvidence
	}
	return h.held.recheck(ctx, 0)
}
func (h *resetD101NativeHeldOriginal) Close() error {
	if h != nil && h.held != nil {
		h.held.close()
	}
	return nil
}

type resetD101NativeRelayInputs struct {
	publicPin    d101custody.NativeFilePin
	signature    d101native.SignaturePins
	installation resetD101HostRelayInstallation
	peerSource   resetD101NativeRelayPeerSource
}
type resetD101NativeRelayPeerSource interface {
	AuthenticateConnectedPeer(context.Context, resetD101RelayPeerObservation) (d101native.Process, error)
	RecheckConnectedPeer(context.Context, resetD101RelayPeerObservation, d101native.Process) error
}

func (v *resetD101NativeAuthorityInstaller) relayInstallation(ctx context.Context) (*resetD101HostRelayInstallation, error) {
	if v == nil || v.relay == nil || d101native.Missing(v.current) || d101native.Missing(v.relay.peerSource) || d101native.Missing(v.installation) || v.installation.AuthenticateInstallation(ctx, v.operationID, "relay") != nil {
		return nil, errResetD101InstallationNotSupplied
	}
	p := *v.relay
	held, err := openResetD101NativeInput(ctx, resetD101RelayPublicPinsPath, p.publicPin, 0444, 0)
	if err != nil {
		return nil, err
	}
	defer held.close()
	certificate, err := d101native.Decode(held.wire, p.signature)
	if err != nil {
		return nil, err
	}
	if _, ok := certificate.Payload().(*d101native.RelaySessionBinding); !ok {
		return nil, errResetExecutionEvidence
	}
	out := p.installation
	out.publicSPKI = bytes.Clone(out.publicSPKI)
	originalAuth := out.authenticate
	if originalAuth == nil {
		return nil, errResetD101InstallationNotSupplied
	}
	wire := bytes.Clone(held.wire)
	out.authenticate = func(call context.Context, op, plan, receipt string, obs resetD101RelayPeerObservation) error {
		peer, err := p.peerSource.AuthenticateConnectedPeer(call, obs)
		if err != nil || originalAuth(call, op, plan, receipt, obs) != nil {
			return errResetExecutionEvidence
		}
		actual, e := openResetD101NativeInput(call, resetD101RelayPublicPinsPath, p.publicPin, 0444, 0)
		if e != nil {
			return errResetExecutionEvidence
		}
		defer actual.close()
		if !bytes.Equal(actual.wire, wire) {
			return errResetExecutionEvidence
		}
		current, e := v.current.Current(call, nil, op, 13)
		if e != nil || current == nil {
			return errResetExecutionEvidence
		}
		err = current.ConsumePublic(call, wire, p.signature, peer, func(a *d101native.VerifiedCurrent, pub *d101native.RelaySessionBinding) error {
			if pub.ApprovedPlanSHA256 != plan || pub.ExecutionReceiptSHA256 != receipt {
				return errResetExecutionEvidence
			}
			return nil
		})
		if err != nil || p.peerSource.RecheckConnectedPeer(call, obs, peer) != nil || actual.recheck(call, 0) != nil {
			return errResetExecutionEvidence
		}
		return nil
	}
	if held.recheck(ctx, 0) != nil || v.installation.RecheckInstallation(ctx, v.operationID, "relay") != nil {
		return nil, errResetExecutionEvidence
	}
	return &out, nil
}

type resetD101NativeReleaseInputs struct {
	disposition d101native.HeldTerminalDisposition
	event       *d101native.UnverifiedReleaseEvent
	expected    d101native.ReleaseExpected
	source      d101native.ReleaseCompletionSource
}

func (v *resetD101NativeAuthorityInstaller) overallCompletion(ctx context.Context) (*d101native.VerifiedReleaseCompletion, error) {
	if v == nil || v.release == nil || !v.completionBusy.CompareAndSwap(false, true) {
		return nil, errResetD101InstallationNotSupplied
	}
	defer v.completionBusy.Store(false)
	r := v.release
	if cached := v.completion.Load(); cached != nil {
		if d101native.ValidateReleaseCompletion(ctx, cached, r.disposition, r.event, r.expected, r.source) != nil {
			return nil, errResetExecutionEvidence
		}
		return cached, nil
	}
	completion, err := d101native.ConsumeReleaseCompletion(ctx, r.disposition, r.event, r.expected, r.source)
	if err != nil {
		return nil, err
	}
	v.completion.Store(completion)
	return completion, nil
}
func (v *resetD101NativeAuthorityInstaller) publishOverallState(ctx context.Context, use func(*d101native.VerifiedReleaseCompletion) error) error {
	if use == nil {
		return errResetExecutionEvidence
	}
	completion, err := v.overallCompletion(ctx)
	if err != nil || completion == nil || !completion.Complete() || completion.NewOperationAllowed() {
		return errResetExecutionEvidence
	}
	if err := use(completion); err != nil {
		return err
	}
	r := v.release
	return d101native.ValidateReleaseCompletion(ctx, completion, r.disposition, r.event, r.expected, r.source)
}
func (v *resetD101NativeAuthorityInstaller) registerKey3(ctx context.Context) error {
	if v == nil || v.key3 == nil || d101native.Missing(v.installation) {
		return errResetD101InstallationNotSupplied
	}
	p := v.key3
	if p.ceremony == nil || p.execution == nil || d101native.Missing(p.ceremonySource) || d101native.Missing(p.executionSource) || v.installation.AuthenticateInstallation(ctx, "", "key3") != nil || v.installation.RecheckInstallation(ctx, "", "key3") != nil {
		return errResetD101InstallationNotSupplied
	}
	// One source bundle, no partial registry publication or target learned pins.
	c, e := *p.ceremony, *p.execution
	if !validResetD101Key3Ref(c.HumanAuthenticationSourceRef) || c.Card.InitializerSourceSHA != rootBuiltSourceSHA || !validResetD101Key3Card(c.Card, time.Now()) || !validResetD101Key3Ref(e.ExecutionScopeOriginalRef) {
		return errResetExecutionEvidence
	}
	resetD101ReviewedKey3CeremonyExpected = &c
	resetD101ReviewedKey3CeremonySource = p.ceremonySource
	resetD101ReviewedKey3NativeInitializationExpected = &e
	resetD101ReviewedKey3NativeInitializationSource = p.executionSource
	return nil
}

// Native signing remains separate from the generic four-purpose whitelist.
type resetD101NativeSigningAuthentication struct {
	keyPins         resetD101SigningKeyPins
	binding         d101native.PreBinding
	purposeOriginal d101native.RawRef
	original        []byte
}
type resetD101NativeSigningSource interface {
	AuthenticateNativeSigning(context.Context, *os.File, []byte) (*resetD101NativeSigningAuthentication, error)
	RecheckNativeSigning(context.Context, *os.File, *resetD101NativeSigningAuthentication) error
}
type resetD101NativeSigningInput struct {
	auth       *resetD101NativeSigningAuthentication
	source     resetD101NativeSigningSource
	descriptor *os.File
}

func (v *resetD101NativeAuthorityInstaller) signStage(ctx context.Context, fd *os.File, record any) ([]byte, error) {
	if v == nil || d101native.Missing(v.signing) || ctx == nil || ctx.Err() != nil || fd == nil || fd.Fd() != 9 {
		return nil, errResetD101InstallationNotSupplied
	}
	body, err := json.Marshal(record)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	defer clear(body)
	a, err := v.signing.AuthenticateNativeSigning(ctx, fd, bytes.Clone(body))
	if err != nil || a == nil || !bytes.Equal(a.original, body) || !d101native.ValidBinding(a.binding) || !d101native.ValidRef(a.purposeOriginal) || a.binding.OperationID != v.operationID || ctx.Err() != nil || time.Now().Unix() >= a.binding.OriginalCutoffUnix || v.signing.RecheckNativeSigning(ctx, fd, a) != nil {
		return nil, errResetExecutionEvidence
	}
	key, err := readResetD101SigningKey(a.keyPins)
	if err != nil {
		return nil, err
	}
	defer key.close()
	return key.signNativeAuthority(ctx, &resetD101NativeSigningInput{a, v.signing, fd})
}

// Bridge shape checking never authenticates inputs or extends the cutoff.
func resetD101NativeSameDirectory(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func nativeResetD101RecordForSigning(body []byte) any {
	v, err := d101native.DecodePayload(body)
	if err != nil {
		return nil
	}
	return v
}

// Main asks the real keeper through an independently authenticated source. It
// never creates or reacquires the keeper OFD to serve an ordinary HTTP request.
type resetD101NativeMainCurrentSource interface {
	CaptureActualCurrent(context.Context, resetExecutionPhaseBinding, time.Time) (resetD101CurrentHostObservation, error)
	RecheckActualCurrent(context.Context, resetExecutionPhaseBinding, resetD101CurrentHostObservation) error
}
type resetD101NativeMainCurrentSupplier struct {
	installer *resetD101NativeAuthorityInstaller
	pins      resetD101CurrentFreezePins
}

func (s *resetD101NativeMainCurrentSupplier) CaptureAfter(ctx context.Context, binding resetExecutionPhaseBinding, started time.Time) (resetD101CurrentFreezeCapture, error) {
	deny := func() (resetD101CurrentFreezeCapture, error) {
		return resetD101CurrentFreezeCapture{}, errResetExecutionEvidence
	}
	if s == nil || s.installer == nil || d101native.Missing(s.installer.mainCurrent) || ctx == nil || ctx.Err() != nil || started.IsZero() || binding.OperationID != s.pins.operationID || binding.Evidence.ApprovalPlanSHA != s.pins.approvalPlanSHA || resetRequestFingerprint("pep", binding.Target) != s.pins.targetFingerprint {
		return deny()
	}
	obs, err := s.installer.mainCurrent.CaptureActualCurrent(ctx, binding, started)
	if err != nil || obs.started.Before(started) || obs.ended.Before(obs.started) || obs.ended.After(time.Now()) || !lifecycleJobIDRe.MatchString(obs.captureNonce) {
		return deny()
	}
	raw, err := decodeResetD101CurrentFreeze(obs.original)
	if err != nil || raw.OperationID != s.pins.operationID || raw.TargetFingerprint != s.pins.targetFingerprint || raw.PublicationRevision != s.pins.publicationRevision || raw.WriterFreezeReceiptSHA != s.pins.freezeSHA || raw.ObservedAt.Before(obs.started) || raw.ObservedAt.After(obs.ended) {
		return deny()
	}
	check := func() error {
		retained, rpin, e1 := d101custody.CapturePrivateOriginalPin(obs.retainedPath, resetD101CurrentFreezeLimit)
		visible, vpin, e2 := d101custody.CapturePrivateOriginalPin(filepath.Join(s.pins.directory, "current-freeze-"+binding.OperationID), resetD101CurrentFreezeLimit)
		if e1 != nil || e2 != nil || rpin != obs.retainedPin || vpin != obs.visiblePin || rpin.Snapshot.Inode == vpin.Snapshot.Inode || !resetD101CurrentFreezePinMatches(rpin, s.pins, retained.SHA256) || !resetD101CurrentFreezePinMatches(vpin, s.pins, visible.SHA256) || !bytes.Equal(retained.Bytes, obs.original) || !bytes.Equal(visible.Bytes, obs.original) || ctx.Err() != nil || !time.Now().Before(s.pins.destructiveCutoff) {
			return errResetExecutionEvidence
		}
		return s.installer.mainCurrent.RecheckActualCurrent(ctx, binding, obs)
	}
	if check() != nil {
		return deny()
	}
	err = s.installer.consumePhase(ctx, nil, binding.OperationID, 13, func(v *d101native.VerifiedCurrent) error {
		b, _ := v.Binding()
		if b.OperationID != raw.OperationID || b.TargetFingerprint != raw.TargetFingerprint || b.PublicationRevision != raw.PublicationRevision || resetD101OriginalSHA(v.Original(9)) != raw.WriterFreezeReceiptSHA {
			return errResetExecutionEvidence
		}
		return check()
	})
	if err != nil || check() != nil {
		return deny()
	}
	return resetD101CurrentFreezeCapture{obs.captureNonce, resetD101OriginalSHA(obs.original), obs.started, obs.ended}, nil
}
func (v *resetD101NativeAuthorityInstaller) completionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			writeJSON(w, 503, errorResponse{Error: "native completion unavailable"})
			return
		}
		var projection struct {
			OperationID         string `json:"operationId"`
			Complete            bool   `json:"complete"`
			NewOperationAllowed bool   `json:"newOperationAllowed"`
		}
		err := v.publishOverallState(r.Context(), func(c *d101native.VerifiedReleaseCompletion) error {
			projection.OperationID = c.OperationID()
			projection.Complete = c.Complete()
			projection.NewOperationAllowed = c.NewOperationAllowed()
			return nil
		})
		if err != nil {
			writeJSON(w, 503, errorResponse{Error: "native completion HOLD"})
			return
		}
		writeJSON(w, 200, projection)
	}
}

// Public runtime binding is a separate typed projection of phase13. It neither
// advances the chain nor claims overall completion before terminal release.
func (v *resetD101NativeAuthorityInstaller) signRuntimeCertificate(ctx context.Context, fd *os.File, pub d101native.RelaySessionBinding, peerObservation resetD101RelayPeerObservation) ([]byte, error) {
	if v == nil || v.relay == nil || d101native.Missing(v.relay.peerSource) {
		return nil, errResetD101InstallationNotSupplied
	}
	peer, err := v.relay.peerSource.AuthenticateConnectedPeer(ctx, peerObservation)
	if err != nil || peer != pub.Peer {
		return nil, errResetExecutionEvidence
	}
	if v.consumePhase(ctx, fd, v.operationID, 13, func(a *d101native.VerifiedCurrent) error {
		b, _ := a.Binding()
		if pub.OperationID != b.OperationID || pub.TargetFingerprint != b.TargetFingerprint || pub.PublicationRevision != b.PublicationRevision || pub.OriginalCutoffUnix != b.OriginalCutoffUnix || pub.KeeperProcess != b.Keeper.Process || pub.KeeperBirthNonce != b.Keeper.BirthNonce || pub.PhysicalPhaseSHA256 != resetD101OriginalSHA(a.Original(13)) || pub.KeeperSessionSHA256 != resetD101OriginalSHA(a.Original(8)) {
			return errResetExecutionEvidence
		}
		return nil
	}) != nil {
		return nil, errResetExecutionEvidence
	}
	wire, err := v.signStage(ctx, fd, &pub)
	if err != nil {
		return nil, err
	}
	actual, err := v.current.Current(ctx, fd, v.operationID, 13)
	if err != nil || actual == nil {
		return nil, errResetExecutionEvidence
	}
	if actual.ConsumePublic(ctx, wire, v.relay.signature, peer, func(*d101native.VerifiedCurrent, *d101native.RelaySessionBinding) error {
		return v.relay.peerSource.RecheckConnectedPeer(ctx, peerObservation, peer)
	}) != nil || v.relay.peerSource.RecheckConnectedPeer(ctx, peerObservation, peer) != nil {
		return nil, errResetExecutionEvidence
	}
	return wire, nil
}
