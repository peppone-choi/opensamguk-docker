# OPENSAM-177 Server-Definition Isolation Review

## Scope

This review covers the sibling deployment repository's existing per-server
definition path: `servers/s<public-id>.env` through `deployer` and
`docker-compose.server.yml`. It does not inspect, modify, or deploy any
operator environment file.

## Observed v1 contract

- The deployer maps a canonical public ID to one server definition and one
  compose project before any Docker invocation.
- The v1 server compose template explicitly wires only its v1 game services.
  It does not pass V2 feature controls or Spring V2 controls to those services.
- Existing v1 world and scenario controls remain valid, including the world ID,
  scenario code, and scenario directory.

## Isolation decision

`validateServerEnvFile` now rejects a v1 server definition that includes one
of the following V2-only controls:

- any key with the `V2_` prefix;
- `SPRING_PROFILES_ACTIVE`;
- `SPRING_FLYWAY_LOCATIONS`.

It also rejects any nonblank, noncomment line the managed parser cannot
classify, including `export KEY=value`. Failures name only a key or line number,
never a value. Reset validates before Docker admission and again inside the
asynchronous worker; recovery validates before Docker preflight and before a
reset recovery can write the definition. The server Compose child receives a
sanitized environment so host variables cannot override its `--env-file`.

This prevents a manual definition from silently becoming a V2 launch surface
while preserving the existing v1 world/scenario controls and the configured
host scenario mount path.

## Secret-safe verification

- Tests create only temporary, synthetic server definitions with non-secret
  values. No checked-in or operator definition was opened.
- The focused test suite covers direct V2 rejection, unmanaged `export` syntax,
  canonical and staged Docker paths, reset admission, lifecycle recovery, and
  reset recovery write ordering.
- The compose tests assert that v1 services receive no V2 controls, every
  template interpolation key is sanitized, and a fake local Docker executable
  observes a filtered child environment while retaining its synthetic endpoint.
- Exact commands and observed outcomes are recorded in the
  [secret-safe evidence record](evidence/2026-08-13-opensam-177-server-definition-isolation.md).

## Known baseline

The base `origin/main` full suite has three existing recreate-workflow failures:
one bounded-command expectation and two bounded-abort deadline cases. They are
outside OPENSAM-177, remain unmodified, and are not treated as a pass for this
change. Focused server-definition tests run with `-count=1` so their contract is
not hidden by the Go test cache; see the evidence record for exact test names.

## Non-actions

No Docker command, deployment, production mutation, secret extraction, or
operator environment-file write was performed. The command harness emitted
intermittent warnings on successful read-only source inspections; this tooling
noise is isolated from the recorded test evidence and is not treated as a
successful gate.
