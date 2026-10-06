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
	return c
}
func assembleResetD101InstalledSources(ctx context.Context, c config) (config, error) {
	return assembleResetD101InstalledSourcesWithReader(ctx, c, readFixedResetD101InstalledSources)
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
	return installed, nil
}
