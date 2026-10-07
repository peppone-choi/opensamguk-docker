package main

import (
	"context"
	"errors"

	"opensamguk-deployer/internal/d101custody"
)

var errResetD101InstallationNotSupplied = errors.New("D101 authenticated fixed installation inputs not supplied")

// This bundle is internal installed input, not a JSON request or an environment
// enable switch. Its factory must authenticate actual original14/aux3, historic
// issuer/session, installer/anchor and native producer sources before returning.
// The six execution sources and two candidate sources are explicitly separate.
type resetD101InstalledSources struct {
	purposeAuthority          resetD101PurposeAuthoritySource
	phaseSource               resetExecutionPhaseSource
	preStopNativeInstallation *resetD101PreStopNativeInstallation
	recoveryClosureReader     resetD101RecoveryClosureReader
	recoveryVerifier          resetD101RecoveryVerifier
	recoveryDatabaseSource    resetD101RecoveryDatabaseSource
	seedMaterialInputs        *resetD101SeedMaterialInputs
	candidatePipeline         *resetD101CandidatePipeline
}
type resetD101InstallationInputReader func(context.Context, config) (resetD101InstalledSources, error)

// The existing record is consumed by the concrete mapper below. Independent
// reviewed pins/actual producers are private installer input, never learned
// from that record or exposed through HTTP/env. Missing input stays closed.
func readFixedResetD101InstalledSources(ctx context.Context, c config) (resetD101InstalledSources, error) {
	if ctx == nil || ctx.Err() != nil {
		return resetD101InstalledSources{}, errResetExecutionEvidence
	}
	original, pin, err := d101custody.CapturePrivateOriginalPin(resetD101NativeReaderInstallationPath, 64<<10)
	if err != nil {
		return resetD101InstalledSources{}, err
	}
	input := c.d101FixedInstallation
	if c.d101NativeInstaller != nil && input == nil {
		input, err = c.d101NativeInstaller.fixedForMain(ctx, c, original, pin)
		if err != nil {
			return resetD101InstalledSources{}, err
		}
	}
	return mapResetD101FixedInstallation(ctx, c, original, pin, input)
}
func closeResetD101InstalledSources(c config) config {
	c.d101PurposeAuthority = nil
	c.d101PhaseSource = nil
	c.d101PreStopNativeInstallation = nil
	c.d101RecoveryClosureReader = nil
	c.d101RecoveryVerifier = nil
	c.d101RecoveryDatabaseSource = nil
	c.d101SeedMaterialInputs = nil
	c.d101CandidatePipeline = nil
	// Destructive atomic8 closes independently of a separately authenticated
	// retained restore1 lifetime. Its callbacks reauthenticate on every use.
	return bindResetD101RetainedRecovery(c)
}
func assembleResetD101InstalledSources(ctx context.Context, c config) (config, error) {
	if resetD101ReviewedRetainedRecoveryInstallation != nil {
		var err error
		c, err = registerResetD101RetainedRecovery(ctx, c, resetD101ReviewedRetainedRecoveryInstallation)
		if err != nil {
			c = closeResetD101RetainedRecovery(c)
		}
	}
	return assembleResetD101InstalledSourcesWithReader(ctx, c, readFixedResetD101InstalledSources)
}

// Independently installed private source; never populated by reader7, an HTTP
// body, an environment value, or the generic/destructive phase13 mapper.
var resetD101ReviewedRetainedRecoveryInstallation *resetD101ProductionRecoveryInstallation

func bindResetD101RetainedRecovery(c config) config {
	if p := c.d101RetainedRecovery; p != nil {
		c.d101RecoveryClosureReader = p.ReadClosure
		c.d101RecoveryVerifier = p.VerifyRecovery
		c.d101RecoveryDatabaseSource = p.ReadDatabase
	}
	return c
}

func closeResetD101RetainedRecovery(c config) config {
	c.d101RetainedRecovery = nil
	c.d101RecoveryClosureReader = nil
	c.d101RecoveryVerifier = nil
	c.d101RecoveryDatabaseSource = nil
	return c
}

func registerResetD101RetainedRecovery(ctx context.Context, c config, p *resetD101ProductionRecoveryInstallation) (config, error) {
	if c.d101RetainedRecovery != nil && c.d101RetainedRecovery != p {
		return c, errResetD101InstallationNotSupplied
	}
	closed := closeResetD101RetainedRecovery(c)
	if p == nil || p.RecheckInstallation(ctx) != nil {
		return closed, errResetD101InstallationNotSupplied
	}
	if _, err := p.Authority(ctx, p.operationID, p.intentSHA, "QUERY"); err != nil || p.RecheckInstallation(ctx) != nil {
		return closed, errResetD101InstallationNotSupplied
	}
	closed.d101RetainedRecovery = p
	return bindResetD101RetainedRecovery(closed), nil
}

// Input-reader injection is private to isolated assembly fixtures. Production
// above always uses the fixed native adapter, never request/env registration.
func assembleResetD101InstalledSourcesWithReader(ctx context.Context, c config, read resetD101InstallationInputReader) (config, error) {
	closed := closeResetD101InstalledSources(c)
	deny := func(err error) (config, error) { closed.d101InstallationError = err; return closed, err }
	if ctx == nil || ctx.Err() != nil || read == nil {
		return deny(errResetExecutionEvidence)
	}
	sources, err := read(ctx, closed)
	if err != nil || ctx.Err() != nil {
		if err == nil {
			err = ctx.Err()
		}
		return deny(err)
	}
	// No partially assembled sources are ever published, including seed/pipeline.
	if sources.purposeAuthority == nil || sources.phaseSource == nil || sources.preStopNativeInstallation == nil || sources.preStopNativeInstallation.verify == nil || sources.recoveryClosureReader == nil || sources.recoveryVerifier == nil || sources.recoveryDatabaseSource == nil || sources.seedMaterialInputs == nil || sources.candidatePipeline == nil {
		return deny(errResetD101InstallationNotSupplied)
	}
	native := *sources.preStopNativeInstallation
	seed := *sources.seedMaterialInputs
	if !gitSHA40.MatchString(native.sourceSHA) || native.parentDevice == 0 || native.parentInode == 0 || sources.candidatePipeline.seeder == nil || sources.candidatePipeline.caps == nil {
		return deny(errResetExecutionEvidence)
	}
	// Value-copy native/seed pins; the pipeline's constructor already owns its
	// original bytes/maps. Factories must return that constructor's frozen object.
	installed := closed
	installed.d101PurposeAuthority = sources.purposeAuthority
	installed.d101PhaseSource = sources.phaseSource
	installed.d101PreStopNativeInstallation = &native
	installed.d101RecoveryClosureReader = sources.recoveryClosureReader
	installed.d101RecoveryVerifier = sources.recoveryVerifier
	installed.d101RecoveryDatabaseSource = sources.recoveryDatabaseSource
	installed.d101SeedMaterialInputs = &seed
	installed.d101CandidatePipeline = sources.candidatePipeline
	installed.d101InstallationError = nil
	return bindResetD101RetainedRecovery(installed), nil
}
