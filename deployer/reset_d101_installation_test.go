package main

import (
	"context"
	"errors"
	"testing"
)

func assertInstalledSourcesClosed(t *testing.T, c config) {
	t.Helper()
	if c.d101PurposeAuthority != nil || c.d101PhaseSource != nil || c.d101PreStopNativeInstallation != nil || c.d101RecoveryClosureReader != nil || c.d101RecoveryVerifier != nil || c.d101RecoveryDatabaseSource != nil || c.d101SeedMaterialInputs != nil || c.d101CandidatePipeline != nil {
		t.Fatal("partial D101 sources became visible")
	}
}
func TestInstalledSourcesMissingAnyOfEightCannotPartiallyActivate(t *testing.T) {
	for _, name := range []string{"authority", "current", "pre-stop", "closure", "recovery-verifier", "restored-database", "seed-inputs", "candidate-pipeline"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			// Denying synthetic functions ensure this assembly test cannot issue any
			// approval or physical evidence even if a function is accidentally invoked.
			sources := resetD101InstalledSources{
				purposeAuthority: func(context.Context, string, string) (resetD101VerifiedPurposeAuthority, error) {
					calls++
					return resetD101VerifiedPurposeAuthority{}, errResetExecutionEvidence
				},
				phaseSource: func(context.Context, resetExecutionPhaseBinding) (resetExecutionPhaseSnapshot, error) {
					calls++
					return resetExecutionPhaseSnapshot{}, errResetExecutionEvidence
				},
				preStopNativeInstallation: &resetD101PreStopNativeInstallation{verify: func(context.Context, resetD101PreStopNativeBinding) error { calls++; return errResetExecutionEvidence }},
				recoveryClosureReader:     func(context.Context, string, string) ([]byte, error) { calls++; return nil, errResetExecutionEvidence },
				recoveryVerifier:          func(context.Context, resetD101RecoveryBinding) error { calls++; return errResetExecutionEvidence },
				recoveryDatabaseSource: func(context.Context, string, string) (resetD101RestoredDatabaseObservation, error) {
					calls++
					return resetD101RestoredDatabaseObservation{}, errResetExecutionEvidence
				},
				seedMaterialInputs: &resetD101SeedMaterialInputs{}, candidatePipeline: &resetD101CandidatePipeline{},
			}
			switch name {
			case "authority":
				sources.purposeAuthority = nil
			case "current":
				sources.phaseSource = nil
			case "pre-stop":
				sources.preStopNativeInstallation = nil
			case "closure":
				sources.recoveryClosureReader = nil
			case "recovery-verifier":
				sources.recoveryVerifier = nil
			case "restored-database":
				sources.recoveryDatabaseSource = nil
			case "seed-inputs":
				sources.seedMaterialInputs = nil
			case "candidate-pipeline":
				sources.candidatePipeline = nil
			}
			cfg := config{token: "synthetic ordinary-service fixture"}
			out, err := assembleResetD101InstalledSourcesWithReader(context.Background(), cfg, func(context.Context, config) (resetD101InstalledSources, error) { return sources, nil })
			if !errors.Is(err, errResetD101InstallationNotSupplied) || out.token != cfg.token || calls != 0 || out.d101InstallationError == nil {
				t.Fatal("missing input did not close assembly without changing ordinary service", err, calls)
			}
			assertInstalledSourcesClosed(t, out)
		})
	}
}
func TestInstalledSourcesInputRefusalPreservesOriginalErrorAndCaller(t *testing.T) {
	expected := errors.New("synthetic independent issuer refusal")
	cfg := config{token: "synthetic ordinary service"}
	cfg.d101PhaseSource = func(context.Context, resetExecutionPhaseBinding) (resetExecutionPhaseSnapshot, error) {
		t.Fatal("partial input current called")
		return resetExecutionPhaseSnapshot{}, errResetExecutionEvidence
	}
	readCalls := 0
	out, err := assembleResetD101InstalledSourcesWithReader(context.Background(), cfg, func(_ context.Context, closed config) (resetD101InstalledSources, error) {
		readCalls++
		assertInstalledSourcesClosed(t, closed)
		return resetD101InstalledSources{}, expected
	})
	if !errors.Is(err, expected) || !errors.Is(out.d101InstallationError, expected) || cfg.d101PhaseSource == nil || out.token != cfg.token || readCalls != 1 {
		t.Fatal("lost original input failure or mutated caller")
	}
	assertInstalledSourcesClosed(t, out)
}
func TestInstalledSourcesCancelledEntryCannotReadOrEnableInstallation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	readCalls := 0
	out, err := assembleResetD101InstalledSourcesWithReader(ctx, config{}, func(context.Context, config) (resetD101InstalledSources, error) {
		readCalls++
		return resetD101InstalledSources{}, nil
	})
	if err == nil || readCalls != 0 {
		t.Fatal("cancelled assembly read actual installation")
	}
	assertInstalledSourcesClosed(t, out)
	out, err = assembleResetD101InstalledSources(ctx, config{})
	if err == nil {
		t.Fatal("fixed production entry bypassed unavailable/cancelled source")
	}
	assertInstalledSourcesClosed(t, out)
}
