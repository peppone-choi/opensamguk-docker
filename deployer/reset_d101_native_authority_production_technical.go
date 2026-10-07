package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"opensamguk-deployer/internal/d101native"
	"opensamguk-deployer/internal/d101operatorauth"
)

// Concrete assembler behind the existing native technical adapter. It accepts
// only C1's opaque issuance, and freezes independently installed inputs before
// I/O. Its installation/source connections still must be supplied by the real
// management factory; this constructor does not authenticate that bootstrap or
// register globals. Required historical/recovery sources are never invented.
type resetD101ProductionTechnicalBuilder struct {
	installation resetD101NativeInstallerSource
	originals    *resetD101ProductionOriginals
	policy       d101operatorauth.ReviewedPolicy
	event        d101operatorauth.IssuanceEvent
	fixed        resetD101FixedInstallation
}

func cloneResetD101ProductionFixed(v resetD101FixedInstallation) resetD101FixedInstallation {
	v.authority.OriginalDirectories = cloneResetD101Strings(v.authority.OriginalDirectories)
	v.authority.ApprovalAnchorSpki = bytes.Clone(v.authority.ApprovalAnchorSpki)
	v.provenance.OriginalDirectories = cloneResetD101Strings(v.provenance.OriginalDirectories)
	v.provenance.AuxiliaryDirectories = cloneResetD101Strings(v.provenance.AuxiliaryDirectories)
	v.provenance.IssuerSPKI = bytes.Clone(v.provenance.IssuerSPKI)
	v.provenance.AllowedPurposes = append([]string(nil), v.provenance.AllowedPurposes...)
	return v
}

func newResetD101ProductionTechnicalBuilder(ctx context.Context, installation resetD101NativeInstallerSource, originals *resetD101ProductionOriginals, policy d101operatorauth.ReviewedPolicy, event d101operatorauth.IssuanceEvent, fixed resetD101FixedInstallation) (*resetD101ProductionTechnicalBuilder, error) {
	// Deep-copy all independent maps/keys before the first external check.
	policy = cloneResetD101TechnicalPolicy(policy)
	fixed = cloneResetD101ProductionFixed(fixed)
	if ctx == nil || ctx.Err() != nil || d101native.Missing(installation) || originals == nil ||
		!lifecycleJobIDRe.MatchString(policy.Scope.OperationID) || fixed.authority.OperationID != policy.Scope.OperationID ||
		event.ScopeDecisionOriginal != policy.Scope.FinalCard ||
		d101native.Missing(fixed.upstream) || d101native.Missing(fixed.evidence) || fixed.preStop.verify == nil ||
		d101native.Missing(fixed.current.supplier) || d101native.Missing(fixed.recovery) ||
		installation.AuthenticateInstallation(ctx, policy.Scope.OperationID, "technical") != nil || originals.recheck(ctx) != nil ||
		installation.RecheckInstallation(ctx, policy.Scope.OperationID, "technical") != nil || ctx.Err() != nil {
		return nil, errResetD101InstallationNotSupplied
	}
	return &resetD101ProductionTechnicalBuilder{installation: installation, originals: originals, policy: policy, event: event, fixed: fixed}, nil
}

func (p *resetD101ProductionTechnicalBuilder) BuildFromTechnicalIssuance(ctx context.Context, issuance d101operatorauth.TechnicalIssuance, native resetD101BootstrapNativeOriginals) (*resetD101FixedInstallation, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || d101native.Missing(p.installation) || p.originals == nil {
		return nil, errResetD101InstallationNotSupplied
	}
	// Reject an absent/forged capability before installation or target reads.
	scope, e1 := issuance.Scope()
	event, e2 := issuance.Event()
	approval, e3 := issuance.Issuer(d101operatorauth.ApprovalIssuerRole)
	receipt, e4 := issuance.Issuer(d101operatorauth.ApprovedReceiptIssuerRole)
	issued, e5 := issuance.IssuedAtUTC()
	deadline, bounded := ctx.Deadline()
	now := time.Now()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil ||
		scope != p.policy.Scope || event != p.event || !reflect.DeepEqual(approval, p.policy.ApprovalIssuer) ||
		!reflect.DeepEqual(receipt, p.policy.ReceiptIssuer) || issued.IsZero() || issued.After(now) ||
		issued.Unix() < p.policy.OpensAtUnix || now.Unix() >= p.policy.CutoffUnix ||
		!bounded || !deadline.After(now) || deadline.After(time.Unix(p.policy.CutoffUnix, 0)) ||
		scope.DockerSourceSHA != rootBuiltSourceSHA {
		return nil, errResetExecutionEvidence
	}
	native = cloneResetD101BootstrapNative(native)
	fixed := cloneResetD101ProductionFixed(p.fixed)
	if requireResetD101TechnicalBootstrapScope(native, p.policy, p.event) != nil ||
		requireResetD101TechnicalInstalledBinding(issuance, p.policy, &fixed) != nil ||
		requireResetD101FixedReaderMapping(native.reader, native.readerPin, fixed) != nil ||
		p.installation.AuthenticateInstallation(ctx, scope.OperationID, "technical") != nil {
		return nil, errResetExecutionEvidence
	}
	// Reader7 and the signed manifest are the exact held originals, including
	// native file and parent identity. A caller's SHA cannot enroll a new pin.
	readerRef := resetD101Key3OriginalRef{resetD101NativeReaderInstallationPath, uint64(len(native.reader.Bytes)), native.reader.SHA256}
	reader, readerPin, err := p.originals.originalPinned(ctx, readerRef)
	if err != nil || readerPin != native.readerPin || !bytes.Equal(reader.Bytes, native.reader.Bytes) {
		clear(reader.Bytes)
		return nil, errResetExecutionEvidence
	}
	defer clear(reader.Bytes)
	manifestRef := resetD101Key3OriginalRef{filepath.Join(fixed.authority.ManifestDirectory, scope.OperationID+".json"), uint64(len(native.manifest)), resetD101OriginalSHA(native.manifest)}
	manifest, manifestPin, err := p.originals.originalPinned(ctx, manifestRef)
	if err != nil || manifestPin != native.manifestPin || !bytes.Equal(manifest.Bytes, native.manifest) {
		clear(manifest.Bytes)
		return nil, errResetExecutionEvidence
	}
	defer clear(manifest.Bytes)
	// The existing mapper will construct all eight consumers and rerun the
	// independent historical/purpose/recovery semantics on every guarded use.
	// No current JWT is substituted for historical authentication originals.
	if p.originals.recheck(ctx) != nil || p.installation.RecheckInstallation(ctx, scope.OperationID, "technical") != nil ||
		ctx.Err() != nil || time.Now().Unix() >= p.policy.CutoffUnix {
		return nil, errResetExecutionEvidence
	}
	return &fixed, nil
}

// A separate private lifetime for the original restore1. It never consumes
// destructive phase13/FD9 after release and never registers a new operation.
// Its actual management source, historical verifier and retained recovery
// producer are mandatory connections; their absence is not repaired by data.
type resetD101ProductionRecoveryInstallation struct {
	installation resetD101NativeInstallerSource
	originals    *resetD101ProductionOriginals
	operationID, intentSHA, cardSHA string
	deadline     time.Time
	purpose      resetD101PurposeAuthoritySource
	producer     resetD101FixedRecoveryProducer
}

func openResetD101RetainedRecoverySource(ctx context.Context, installation resetD101NativeInstallerSource, originals *resetD101ProductionOriginals, fixed resetD101FixedInstallation, originalIntent resetDecodedApprovalIntent) (*resetD101ProductionRecoveryInstallation, error) {
	fixed = cloneResetD101ProductionFixed(fixed)
	intent, err := decodeResetApprovalIntent(originalIntent.originalBytes(), originalIntent.SHA)
	if err != nil || ctx == nil || ctx.Err() != nil || d101native.Missing(installation) || originals == nil ||
		d101native.Missing(fixed.recovery) || d101native.Missing(fixed.upstream) || d101native.Missing(fixed.evidence) ||
		intent.Intent.OperationID != fixed.authority.OperationID || intent.SHA != fixed.authority.ApprovalIntentSHA ||
		!resetEvidenceSHA.MatchString(fixed.provenance.DeploymentCardSHA) {
		return nil, errResetD101InstallationNotSupplied
	}
	p := &resetD101ProductionRecoveryInstallation{installation: installation, originals: originals,
		operationID: intent.Intent.OperationID, intentSHA: intent.SHA, cardSHA: fixed.provenance.DeploymentCardSHA,
		deadline: time.Unix(intent.Intent.RecoveryDeadlineUnix, 0), producer: fixed.recovery}
	if p.RecheckInstallation(ctx) != nil {
		return nil, errResetD101InstallationNotSupplied
	}
	// Reuse historical signature/provenance/purpose validators with the actual
	// dedicated management source. Never reuse the mapper's phase13 callback.
	verify := func(call context.Context, evidence *resetD101HostEvidence) error {
		if evidence == nil || p.RecheckInstallation(call) != nil {
			return errResetExecutionEvidence
		}
		readerRef := resetD101Key3OriginalRef{resetD101NativeReaderInstallationPath, fixed.readerPin.Snapshot.ByteLength, fixed.readerSHA}
		wire, verifyErr := verifyResetD101ApprovedReceiptProvenanceWithSources(call, fixed.provenance, fixed.upstream, time.Now, 0, func() ([]byte, error) {
			if p.RecheckInstallation(call) != nil {
				return nil, errResetExecutionEvidence
			}
			reader, pin, err := p.originals.originalPinned(call, readerRef)
			if err != nil || pin != fixed.readerPin {
				clear(reader.Bytes)
				return nil, errResetExecutionEvidence
			}
			return reader.Bytes, nil
		})
		expected, originalErr := evidence.Original("approvedReceiptProvenance")
		if verifyErr != nil || originalErr != nil || !bytes.Equal(wire, expected) ||
			fixed.evidence(call, evidence) != nil || p.RecheckInstallation(call) != nil {
			return errResetExecutionEvidence
		}
		return nil
	}
	p.purpose, err = newResetD101HostAuthority(fixed.authority, verify, time.Now)
	if err != nil || p.RecheckInstallation(ctx) != nil {
		return nil, errResetD101InstallationNotSupplied
	}
	return p, nil
}

func (p *resetD101ProductionRecoveryInstallation) RecheckInstallation(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil || d101native.Missing(p.installation) || p.originals == nil ||
		!lifecycleJobIDRe.MatchString(p.operationID) || !resetEvidenceSHA.MatchString(p.intentSHA) ||
		!resetEvidenceSHA.MatchString(p.cardSHA) || d101native.Missing(p.producer) || p.deadline.IsZero() || !time.Now().Before(p.deadline) ||
		p.installation.AuthenticateInstallation(ctx, p.operationID, "recovery") != nil ||
		p.originals.recheck(ctx) != nil || p.installation.RecheckInstallation(ctx, p.operationID, "recovery") != nil ||
		ctx.Err() != nil || !time.Now().Before(p.deadline) {
		return errResetD101InstallationNotSupplied
	}
	return nil
}

func (p *resetD101ProductionRecoveryInstallation) Authority(ctx context.Context, op, intentSHA, action string) (resetD101VerifiedPurposeAuthority, error) {
	closed := resetD101VerifiedPurposeAuthority{}
	// Reject wrong actions before touching any source, including inside the
	// original destructive window. This bundle is never PREPARE/DISPATCH input.
	if p == nil || (action != "QUERY" && action != "RECOVERY_CLOSE") || op != p.operationID || intentSHA != p.intentSHA ||
		p.purpose == nil || p.RecheckInstallation(ctx) != nil {
		return closed, errResetD101InstallationNotSupplied
	}
	a, err := p.purpose(ctx, op, intentSHA)
	intent, scopeErr := requireResetD101Authority(a, resetD101PurposeGrantRequest{OperationID: op, ApprovalIntentSHA: intentSHA, Action: action}, time.Now())
	_, recoveryErr := requireResetD101RecoveryAuthority(a, op, intentSHA, time.Now())
	if err != nil || scopeErr != nil || recoveryErr != nil || a.DeploymentCardSHA != p.cardSHA || intent.Intent.RecoveryDeadlineUnix != p.deadline.Unix() ||
		p.RecheckInstallation(ctx) != nil {
		return closed, errResetExecutionEvidence
	}
	return a, nil
}

func (p *resetD101ProductionRecoveryInstallation) ReadClosure(ctx context.Context, op, sha string) ([]byte, error) {
	if p == nil || op != p.operationID || !resetEvidenceSHA.MatchString(sha) || d101native.Missing(p.producer) || p.RecheckInstallation(ctx) != nil {
		return nil, errResetD101InstallationNotSupplied
	}
	wire, err := p.producer.ReadClosure(ctx, op, sha)
	wire = bytes.Clone(wire)
	if err != nil || len(wire) == 0 || len(wire) > 16<<10 || resetD101OriginalSHA(wire) != sha || p.RecheckInstallation(ctx) != nil {
		clear(wire)
		return nil, errResetExecutionEvidence
	}
	return wire, nil
}

func (p *resetD101ProductionRecoveryInstallation) VerifyRecovery(ctx context.Context, binding resetD101RecoveryBinding) error {
	if p == nil || binding.operation.OperationID != p.operationID || binding.intent.SHA != p.intentSHA ||
		binding.intent.Intent.RecoveryDeadlineUnix != p.deadline.Unix() || d101native.Missing(p.producer) ||
		p.RecheckInstallation(ctx) != nil || p.producer.VerifyRecovery(ctx, binding) != nil || p.RecheckInstallation(ctx) != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func (p *resetD101ProductionRecoveryInstallation) ReadDatabase(ctx context.Context, op, sha string) (resetD101RestoredDatabaseObservation, error) {
	closed := resetD101RestoredDatabaseObservation{}
	if p == nil || op != p.operationID || !resetEvidenceSHA.MatchString(sha) || d101native.Missing(p.producer) || p.RecheckInstallation(ctx) != nil {
		return closed, errResetD101InstallationNotSupplied
	}
	value, err := p.producer.ReadDatabase(ctx, op, sha)
	value.original = bytes.Clone(value.original)
	if err != nil || value.sha != sha || resetD101OriginalSHA(value.original) != sha || p.RecheckInstallation(ctx) != nil {
		clear(value.original)
		return closed, errResetExecutionEvidence
	}
	return value, nil
}

func (c config) resetD101RecoveryAuthority(ctx context.Context, op, intentSHA, action string) (resetD101VerifiedPurposeAuthority, error) {
	if c.d101RetainedRecovery == nil {
		return resetD101VerifiedPurposeAuthority{}, errResetD101InstallationNotSupplied
	}
	return c.d101RetainedRecovery.Authority(ctx, op, intentSHA, action)
}

func (c config) issueResetD101RecoveryQueryGrant(ctx context.Context, request resetD101PurposeGrantRequest) (string, error) {
	if request.Action != "QUERY" || c.d101RetainedRecovery == nil {
		return "", errResetD101InstallationNotSupplied
	}
	source := func(call context.Context, op, sha string) (resetD101VerifiedPurposeAuthority, error) {
		return c.resetD101RecoveryAuthority(call, op, sha, "QUERY")
	}
	return issueResetD101PurposeGrant(ctx, source, request, time.Now)
}

// Post-executor observations only. This reader does not implement or register
// the preclaim recovery authority: its constructor requires the already owned
// restore1 claim and completed archive. Missing actual management/preclaim/old
// settlement sources remain missing. No method creates, starts or retries jobs.
type resetD101ProductionRetainedJobReader struct {
	c config
	installation resetD101NativeInstallerSource
	originals *resetD101ProductionOriginals
	attempt resetD101SucceededRestore
}

func newResetD101ProductionRetainedJobReader(ctx context.Context, c config, installation resetD101NativeInstallerSource, originals *resetD101ProductionOriginals, attempt resetD101SucceededRestore) (*resetD101ProductionRetainedJobReader, error) {
	if ctx == nil || ctx.Err() != nil || d101native.Missing(installation) || originals == nil ||
		attempt.lease == nil || len(attempt.claim) == 0 || len(attempt.claim) > 64<<10 || !resetEvidenceSHA.MatchString(attempt.claimSHA) ||
		len(attempt.root) == 0 || len(attempt.root) > 16<<10 || len(attempt.begin.original) == 0 || len(attempt.begin.original) > 16<<10 ||
		len(attempt.begin.gatewayOriginal) == 0 || len(attempt.begin.gatewayOriginal) > 64<<10 || len(attempt.archive.Original) == 0 || len(attempt.archive.Original) > resetEvidenceMaxBytes ||
		!resetEvidenceSHA.MatchString(attempt.archive.ContainerID) || !resetManifestDigest.MatchString(attempt.archive.ImageID) ||
		c.dockerRunner != nil || c.dockerRunnerContext != nil {
		return nil, errResetD101InstallationNotSupplied
	}
	// Preserve the actual live cfg/coordinator/store/lease pointers. Copy every
	// mutable expected byte/map before any authentication or physical command.
	intent, err := decodeResetApprovalIntent(attempt.binding.intent.originalBytes(), attempt.binding.intent.SHA)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	attempt.binding.intent = intent
	evidenceWire, err := json.Marshal(attempt.binding.evidence)
	var evidence resetExecutionEvidence
	if err != nil || decodeResetPrivateJSON(evidenceWire, &evidence) != nil {
		return nil, errResetExecutionEvidence
	}
	attempt.binding.evidence = evidence
	attempt.binding.restoredDatabase = nil
	attempt.root = bytes.Clone(attempt.root)
	attempt.claim = bytes.Clone(attempt.claim)
	attempt.archive.Original = bytes.Clone(attempt.archive.Original)
	attempt.begin.original = bytes.Clone(attempt.begin.original)
	attempt.begin.gatewayOriginal = bytes.Clone(attempt.begin.gatewayOriginal)
	execution, preReset, err := decodeResetD101GatewayQueryCapture(attempt.begin.gatewayOriginal, true)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	gateway, err := decodeResetD101GatewayExecution(execution)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	attempt.begin.gateway, attempt.begin.preReset = gateway, preReset
	var claim resetD101SucceededRestoreClaim
	recordWire, recordErr := json.Marshal(attempt.binding.operation)
	if recordErr != nil || requireResetIntentShape(attempt.claim, reflect.TypeOf(claim)) != nil || decodeResetPrivateJSON(attempt.claim, &claim) != nil ||
		claim.SchemaVersion != 1 || claim.Kind != "D101_SUCCEEDED_RESTORE1_CLAIM_V1" || claim.Attempt != 1 ||
		claim.OperationID != intent.Intent.OperationID || claim.ApprovalIntentSHA != intent.SHA ||
		claim.DeploymentCardSHA != attempt.binding.deploymentCardSHA || claim.OriginalRootResultSHA != resetD101OriginalSHA(attempt.root) ||
		claim.OriginalRootRecordSHA != resetD101OriginalSHA(recordWire) || claim.RecoveryBeginReceiptSHA != attempt.begin.SHA() ||
		claim.BackupManifestSHA != attempt.binding.backup.manifestSHA || claim.BackupManifestSHA != attempt.archive.BackupManifestSHA ||
		claim.ArchiveContainerID != attempt.archive.ContainerID || claim.ArchiveImageID != attempt.archive.ImageID ||
		claim.ArchiveListOriginalSHA != attempt.archive.ListOriginalSHA || claim.RecoveryDeadlineUnix != intent.Intent.RecoveryDeadlineUnix ||
		!reflect.DeepEqual(claim.OldImageDigests, intent.Intent.OldImageDigests) {
		return nil, errResetExecutionEvidence
	}
	p := &resetD101ProductionRetainedJobReader{c: c, installation: installation, originals: originals, attempt: attempt}
	if p.RecheckRetainedAttempt(ctx) != nil {
		return nil, errResetD101InstallationNotSupplied
	}
	return p, nil
}

func (p *resetD101ProductionRetainedJobReader) RecheckRetainedAttempt(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil || d101native.Missing(p.installation) || p.originals == nil ||
		p.attempt.lease == nil || p.c.dockerRunner != nil || p.c.dockerRunnerContext != nil {
		return errResetD101InstallationNotSupplied
	}
	op := p.attempt.binding.operation.OperationID
	if !lifecycleJobIDRe.MatchString(op) || p.attempt.binding.intent.Intent.OperationID != op ||
		!time.Now().Before(time.Unix(p.attempt.binding.intent.Intent.RecoveryDeadlineUnix, 0)) ||
		p.installation.AuthenticateInstallation(ctx, op, "recovery") != nil || p.originals.recheck(ctx) != nil ||
		p.c.requireResetD101SucceededRestore(ctx, p.attempt, true) != nil ||
		p.installation.RecheckInstallation(ctx, op, "recovery") != nil || ctx.Err() != nil {
		return errResetExecutionEvidence
	}
	return nil
}

// In addition to the existing caps/mount/command/image checks, bind the actual
// exited job incarnation to the retained collector's interval and once name.
// Parsed Docker fields are observations, not management or settlement authority.
const resetD101ProductionRetainedExecutionFormat = `{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"startedAt":{{json .State.StartedAt}},"finishedAt":{{json .State.FinishedAt}},"pid":{{json .State.Pid}},"restartCount":{{json .RestartCount}},"oomKilled":{{json .State.OOMKilled}},"error":{{json .State.Error}},"dead":{{json .State.Dead}},"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},"autoRemove":{{json .HostConfig.AutoRemove}}}`

type resetD101ProductionRetainedExecution struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Image string `json:"image"`
	StartedAt string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	PID *int `json:"pid"`
	RestartCount *int `json:"restartCount"`
	OOMKilled *bool `json:"oomKilled"`
	Error *string `json:"error"`
	Dead *bool `json:"dead"`
	Paused *bool `json:"paused"`
	Restarting *bool `json:"restarting"`
	AutoRemove *bool `json:"autoRemove"`
}

func requireResetD101ProductionRetainedExecution(wire []byte, id, image, name string, started, completed time.Time) error {
	var v resetD101ProductionRetainedExecution
	if !resetEvidenceSHA.MatchString(id) || !resetManifestDigest.MatchString(image) || name == "" ||
		started.IsZero() || completed.Before(started) || completed.After(time.Now()) || completed.Sub(started) >= resetPreflightMaxAge ||
		len(wire) == 0 || len(wire) > 4096 || requireResetIntentShape(wire, reflect.TypeOf(v)) != nil || decodeResetPrivateJSON(wire, &v) != nil ||
		v.ID != id || v.Image != image || v.Name != name || v.PID == nil || *v.PID != 0 ||
		v.RestartCount == nil || *v.RestartCount != 0 || v.OOMKilled == nil || *v.OOMKilled ||
		v.Error == nil || *v.Error != "" || v.Dead == nil || *v.Dead || v.Paused == nil || *v.Paused ||
		v.Restarting == nil || *v.Restarting || v.AutoRemove == nil || *v.AutoRemove {
		return errResetExecutionEvidence
	}
	birth, e1 := resetD101RecoveryUTC(v.StartedAt)
	finish, e2 := resetD101RecoveryUTC(v.FinishedAt)
	if e1 != nil || e2 != nil || birth.Unix() <= 0 || birth.Before(started) || finish.Before(birth) || finish.After(completed) {
		return errResetExecutionEvidence
	}
	return nil
}

func (p *resetD101ProductionRetainedJobReader) guardedRead(ctx context.Context, read func(context.Context) (string, error)) (string, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || read == nil {
		return "", errResetExecutionEvidence
	}
	bounded, cancel := context.WithDeadline(ctx, time.Unix(p.attempt.binding.intent.Intent.RecoveryDeadlineUnix, 0))
	defer cancel()
	if p.RecheckRetainedAttempt(bounded) != nil {
		return "", errResetExecutionEvidence
	}
	wire, err := read(bounded)
	if err != nil || p.RecheckRetainedAttempt(bounded) != nil {
		return "", errResetExecutionEvidence
	}
	return wire, nil
}

func (p *resetD101ProductionRetainedJobReader) VerifyArchive(ctx context.Context) error {
	if p.RecheckRetainedAttempt(ctx) != nil {
		return errResetD101InstallationNotSupplied
	}
	a := p.attempt.archive
	op := p.attempt.binding.operation.OperationID
	if len(a.Original) == 0 || len(a.Original) > resetEvidenceMaxBytes || resetD101OriginalSHA(a.Original) != a.ListOriginalSHA ||
		a.BackupManifestSHA != p.attempt.binding.backup.manifestSHA || !filepath.IsAbs(p.c.composeHostDir) || filepath.Clean(p.c.composeHostDir) != p.c.composeHostDir {
		return errResetExecutionEvidence
	}
	hostDump := filepath.Join(p.c.composeHostDir, "backups", "pep", op, "postgres.dump")
	var before, after resetD101CapsJob
	for i, job := range []*resetD101CapsJob{&before, &after} {
		if _, err := p.guardedRead(ctx, func(call context.Context) (string, error) {
			backup, err := verifyResetRecoveryBackup(call, filepath.Join(p.c.composeDir, "backups", "pep", op), a.BackupManifestSHA, p.attempt.binding.evidence.Plan.SpaceBudget, p.attempt.binding.intent.Intent.OldImageDigests, 0)
			if err != nil || backup != p.attempt.binding.backup {
				return "", errResetExecutionEvidence
			}
			return "", nil
		}); err != nil {
			return errResetExecutionEvidence
		}
		if _, err := p.guardedRead(ctx, func(call context.Context) (string, error) {
			var err error
			*job, err = p.c.observeResetD101CapsJob(call, a.ContainerID)
			return "", err
		}); err != nil || job.Running || job.Status != "exited" || job.ExitCode != 0 || job.ImageID != a.ImageID || job.Network != "none" || !validResetD101RestoreArchiveMounts(*job, hostDump) {
			return errResetExecutionEvidence
		}
		if _, err := p.guardedRead(ctx, func(call context.Context) (string, error) {
			return "", p.c.requireResetD101RestoreArchiveCommand(call, a.ContainerID)
		}); err != nil {
			return errResetExecutionEvidence
		}
		wire, err := p.guardedRead(ctx, func(call context.Context) (string, error) {
			return p.c.runServerDockerContext(call, "inspect", "--format", resetD101ProductionRetainedExecutionFormat, a.ContainerID)
		})
		if err != nil || requireResetD101ProductionRetainedExecution([]byte(wire), a.ContainerID, a.ImageID, "/d101-restore-list-"+op, a.StartedAt, a.CompletedAt) != nil {
			return errResetExecutionEvidence
		}
		if _, err := p.guardedRead(ctx, func(call context.Context) (string, error) {
			return "", p.c.requireResetD101CapsImage(call, a.ImageID, p.attempt.binding.intent.Intent.OldImageDigests["game-postgres"])
		}); err != nil {
			return errResetExecutionEvidence
		}
		if i == 0 {
			logs, err := p.guardedRead(ctx, func(call context.Context) (string, error) { return p.c.runServerDockerContext(call, "logs", a.ContainerID) })
			if err != nil || !bytes.Equal([]byte(logs), a.Original) {
				return errResetExecutionEvidence
			}
		}
	}
	if !reflect.DeepEqual(before, after) || p.RecheckRetainedAttempt(ctx) != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func (p *resetD101ProductionRetainedJobReader) ReadDatabase(ctx context.Context, op, sha string, input resetD101RestoredDatabaseInputs, observed resetD101RestoredDatabaseObservation) (resetD101RestoredDatabaseObservation, error) {
	closed := resetD101RestoredDatabaseObservation{}
	identifier := regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	resource := regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	if p == nil || op != p.attempt.binding.operation.OperationID || !resetEvidenceSHA.MatchString(sha) || observed.sha != sha ||
		!identifier.MatchString(input.Database) || !identifier.MatchString(input.User) || !resource.MatchString(input.Project) || !resource.MatchString(input.Network) ||
		len(observed.original) == 0 || len(observed.original) > 16<<10 || resetD101OriginalSHA(observed.original) != sha ||
		input.PostgresContainerID != observed.postgresID || !resetEvidenceSHA.MatchString(observed.jobID) || observed.jobID == observed.postgresID {
		return closed, errResetExecutionEvidence
	}
	observed.original = bytes.Clone(observed.original)
	if resetD101OriginalSHA(observed.original) != sha || p.RecheckRetainedAttempt(ctx) != nil || p.VerifyArchive(ctx) != nil {
		return closed, errResetExecutionEvidence
	}
	host, err := resetD101SeedHostPath(p.c, input.LocalPassFile)
	if err != nil || host != input.HostPassFile || strings.ContainsAny(host, ",\r\n") {
		return closed, errResetExecutionEvidence
	}
	// The password original comes from the independently held sibling set.
	// No inode/hash learned from this Docker inspection enrolls a new original.
	var passRef resetD101Key3OriginalRef
	p.originals.mu.Lock()
	refs := append([]resetD101Key3OriginalRef(nil), p.originals.refs...)
	p.originals.mu.Unlock()
	for _, ref := range refs {
		if ref.Path == input.LocalPassFile && ref.SHA256 == input.PassFileSHA {
			passRef = ref
		}
	}
	pass, err := p.originals.original(ctx, passRef)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	clear(pass.Bytes)
	var firstPG, lastPG resetRuntimeContainer
	var firstJob, lastJob resetD101CapsJob
	for i, pg := range []*resetRuntimeContainer{&firstPG, &lastPG} {
		if _, err := p.guardedRead(ctx, func(call context.Context) (string, error) {
			var err error
			*pg, err = p.c.observeResetD101RestoredPostgres(call, observed.postgresID, input.Project)
			return "", err
		}); err != nil || pg.ImageID != observed.postgresImage {
			return closed, errResetExecutionEvidence
		}
		address, err := p.guardedRead(ctx, func(call context.Context) (string, error) { return p.c.observeResetD101CapsAddress(call, pg.ID, input.Network) })
		if err != nil || address != observed.value.ServerAddress {
			return closed, errResetExecutionEvidence
		}
		job := &firstJob
		if i == 1 { job = &lastJob }
		if _, err := p.guardedRead(ctx, func(call context.Context) (string, error) {
			var err error
			*job, err = p.c.observeResetD101CapsJob(call, observed.jobID)
			return "", err
		}); err != nil || job.Running || job.Status != "exited" || job.ExitCode != 0 || job.ImageID != observed.jobImage || job.Network != input.Network || !validResetD101CapsMount(*job, host) {
			return closed, errResetExecutionEvidence
		}
		args := []string{"-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-h", address, "-p", "5432", "-U", input.User, "-d", input.Database, "-c", resetD101RestoredDatabaseSQL}
		if _, err := p.guardedRead(ctx, func(call context.Context) (string, error) { return "", p.c.requireResetD101RestoredPSQLCommand(call, observed.jobID, args) }); err != nil {
			return closed, errResetExecutionEvidence
		}
		wire, err := p.guardedRead(ctx, func(call context.Context) (string, error) { return p.c.runServerDockerContext(call, "inspect", "--format", resetD101ProductionRetainedExecutionFormat, observed.jobID) })
		if err != nil || requireResetD101ProductionRetainedExecution([]byte(wire), observed.jobID, observed.jobImage, "/d101-restored-db-"+op, observed.started, observed.completed) != nil {
			return closed, errResetExecutionEvidence
		}
		for _, image := range []string{pg.ImageID, job.ImageID} {
			if _, err := p.guardedRead(ctx, func(call context.Context) (string, error) { return "", p.c.requireResetD101CapsImage(call, image, p.attempt.binding.intent.Intent.OldImageDigests["game-postgres"]) }); err != nil {
				return closed, errResetExecutionEvidence
			}
		}
		if i == 0 {
			logs, err := p.guardedRead(ctx, func(call context.Context) (string, error) { return p.c.runServerDockerContext(call, "logs", observed.jobID) })
			if err != nil || !bytes.Equal([]byte(logs), observed.original) {
				return closed, errResetExecutionEvidence
			}
		}
	}
	value, err := decodeResetD101RestoredDatabase(observed.original, input.Database, input.User, observed.value.ServerAddress, observed.started, observed.completed)
	if err != nil || resetD101OriginalSHA(observed.original) != sha || !reflect.DeepEqual(value, observed.value) || !reflect.DeepEqual(firstPG, lastPG) || !reflect.DeepEqual(firstJob, lastJob) || p.RecheckRetainedAttempt(ctx) != nil {
		return closed, errResetExecutionEvidence
	}
	return observed, nil
}
