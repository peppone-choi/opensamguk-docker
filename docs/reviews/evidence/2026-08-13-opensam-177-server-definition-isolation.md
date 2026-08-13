# OPENSAM-177 Secret-Safe Evidence Record

All commands below run from the isolated worktree's `deployer/` directory.
They use Go test temporary directories and synthetic non-secret values only.
No operator definition, deployment configuration, Docker daemon, or Compose
project was read or invoked.

## Red proof

Before the ordering and parser changes, this focused command failed as intended:

```text
go test -count=1 -run '^(TestV1ServerDefinitionRejectsUnmanagedSyntaxBeforeDocker|TestResetRejectsV2DefinitionBeforeDockerAdmission|TestLifecycleRecoveryRejectsV2DefinitionBeforeDockerPreflight)$' ./...
```

Observed failures showed the unmanaged `export` inputs reaching the fake Docker
runner, while reset and recovery reached the fake Docker preflight before V2
rejection.

## Current focused gate

```text
go test -count=1 -run '^(TestV1ServerDefinition|TestResetRejectsV2DefinitionBeforeDockerAdmission|TestLifecycleRecoveryRejectsV2DefinitionBeforeDockerPreflight|TestResetRecoveryRejectsV2DefinitionBeforeApplyingResetTarget|TestServerComposeEnvironmentDropsAmbientDefinitionControls|TestRunServerDockerContextSanitizesChildEnvironment|TestV1ServerComposeInterpolationKeysAreSanitized|TestV1ServerComposeExcludesV2ControlsWhenSelectingServices)$' ./...
```

Observed result: `ok opensamguk-deployer`.

The test cases assert zero fake Docker calls for invalid canonical and staged
definitions, reset admission, and lifecycle recovery. The child-environment
test executes only a generated local test stub named `docker`; it asserts that
ambient server/V2/Compose control keys are absent and a synthetic Docker
endpoint plus configured host mount path remain present.

During broader regression testing, the existing unavailable-Docker test first
exposed a behavior regression: recovery without a journal has no target to
validate and must still report a Docker reachability failure. The implementation
now preserves that no-target behavior while keeping journal-present definitions
validated before preflight. This focused regression command passes:

```text
go test -count=1 -run '^TestDockerUnreachableFailsMutationsBeforeIrreversibleBoundary$' ./...
```

Observed result: `ok opensamguk-deployer`.

The same gate also passed under race detection and randomized ordering:

```text
go test -race -shuffle=on -count=1 -run '^(TestV1ServerDefinition|TestResetRejectsV2DefinitionBeforeDockerAdmission|TestLifecycleRecoveryRejectsV2DefinitionBeforeDockerPreflight|TestResetRecoveryRejectsV2DefinitionBeforeApplyingResetTarget|TestServerComposeEnvironmentDropsAmbientDefinitionControls|TestRunServerDockerContextSanitizesChildEnvironment|TestV1ServerComposeInterpolationKeysAreSanitized|TestV1ServerComposeExcludesV2ControlsWhenSelectingServices)$' ./...
```

Observed result: `ok opensamguk-deployer`.

## Static and broader checks

```text
gofmt -w main.go main_test.go
git diff --check
go vet ./...
go build ./...
```

Observed results: `git diff --check`, `go vet ./...`, and a build directed to a
temporary path all passed. A broader regression subset also passed:

```text
go test -count=1 -run '^(TestServerEnv|TestLifecycle|TestReset|TestDeploy)' ./...
```

Observed result: `ok opensamguk-deployer`.

## Full-suite baseline

On the base `origin/main` snapshot, `go test ./...` failed only these unrelated
recreate-workflow tests:

- `TestRecreateWorkflowBoundsEveryExternalCommandAfterProductionLock`
- `TestRecreateWorkflowLostJobAbortsBoundedAndKeepsMarkerClosed`
- `TestRecreateWorkflowAcceptAndStallPathsAreBoundedAndFailClosed`

This record does not treat that baseline as a passing gate. A final full-suite
check using `go test -count=1 -v -run '^TestRecreateWorkflow' ./...` reproduced
that exact set; the other recreate-workflow tests passed. The failing test
output was not used as implementation evidence because it is unrelated to this
server-definition change.
