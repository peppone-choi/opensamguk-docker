# Isolated local fixture recovery

This is a separate maintenance tool for the approved F fixture and its copies. It does not
modify the fresh acceptance harness, its template, nginx or the original database contents.
Source/fake CLI tests are separate from real backup, restore, rollback and USER acceptance.
All real stages currently remain **NOT_RUN** until C0 and the Docker owner hand over a window.

## Preconditions

- Finish F build/health/strict smoke, C0 USER01/02 and the first frontend GUI window first.
  C0 hands the window to the Docker writing session; do not interrupt those activities.
- The source must be that writer's `SMOKE_PASSED` fresh custody, 11 healthy owned containers,
  five local named volumes, exact six app/three support images and canonical config/source.
  C/E and foreign volume consumers are refused. Use a fully resolved private path on macOS,
  not a path through `/tmp` or another symlink.
- The existing USER fixture must already own a general and have a successful existing request
  with one APPLIED row, immutable committed world version and at least one request log.
  The tool never registers, joins, promotes users, fabricates a death or submits game commands.
- Use JDK/build/GUI-free maintenance under the shared atomic heavy-run lock. A held foreign
  lock is waited on and never removed; an expired window is refused. The metarepo must own
  this Docker Git repository. Actual ENOSPC is failure; this tool has no disk-number gate.
- Keep all outputs on the local host: custody/bundle/targets/log directories0700, files0600.
  No secrets, compose output, tokens, raw database data or raw logs belong in PRs/chat.

## Handoff

C0/the Docker owner supplies a new private JSON file with these fields. It is an explicit
maintenance-window guard, not independent authentication or a substitute for the human handoff.
It must refer to F's exact original contract file. It is checked before Docker is contacted.

```json
{
  "schema": 1,
  "scope": "F_FULL_RECOVERY",
  "sourceCustody": "/absolute/resolved/private/F",
  "sourceContractSha256": "<verified SHA256 of F contract.json>",
  "ownerSession": "<Docker writing app chat UUID>",
  "windowId": "<C0 maintenance window identifier>",
  "expiresAt": "<UTC ISO timestamp with timezone>"
}
```

The writer sets `OPENSAMGUK_TASK_OWNER_SESSION` to its existing chat ID. Do not read or copy
another installation's env/key files. A backup preserves F's private files internally; it never
prints their values. Use an independently approved fresh log directory for **each** invocation.
Logs must be outside the immutable backup bundle and original custody.

## Ordered commands

Set `R` to this `recovery.py`, `F` to C0's F custody, `P` to the private handoff, `M` to the
metarepo, and choose previously nonexistent private output paths. Global arguments precede
the action. These commands are future maintenance instructions, not permission to run now.

```sh
python3 -B "$R" --handoff "$P" --source-custody "$F" --meta "$M" --logs "$L1" \
  backup --bundle "$A" --general-id "$GID" --request-id "$RID"
```

Backup first checks normal USER login/readback before stopping anything. It then normally
stops ingress, APIs and engine, captures the committed USER checkpoint while
PG is still online, then normally stops both PostgreSQL and both Redis instances. Data service
exit must be clean (exit0, not OOM); no SIGKILL fallback exists. Only then does it read-only
archive all five volumes, including **all** Redis AOF segments/manifest and profile icons.
It also preserves private runtime/config/fixture/certs/nginx and exact image bytes in `images.tar`.
Every archive entry is validated; checksum, content, internal ownership/modes and source pins
are verified. On success F stays stopped for the same-origin exercise. On backup failure the
tool attempts to resume only the original IDs it stopped. A failed resume remains `RESUME_REQUIRED`.
Do not run acceptance-harness `down`: that deletes volumes/images. Its `up` is a fresh-start
operation, not the resume operation below.

For a direct same-version restore, use:

```sh
python3 -B "$R" --handoff "$P" --source-custody "$F" --meta "$M" --logs "$L2" \
  restore --bundle "$A" --target "$RESTORED_A"
python3 -B "$R" --handoff "$P" --source-custody "$F" --meta "$M" --logs "$L3" \
  observe --target "$RESTORED_A"
python3 -B "$R" --handoff "$P" --source-custody "$F" --meta "$M" --logs "$L4" \
  stop-target --target "$RESTORED_A"
```

Restore preserves app serverId/world160/gen0/origin, registry, credentials, environment and
network aliases. Only resource project/nonce/labels/volume/network names, private bind paths
and verified image IDs change. The new `osgfr<nonce>` project is deliberately not a fresh
`osglha<nonce>` fixture. Original F's data is never mounted writable or SQL-adjusted. Restore
requires original F stopped and443 free. Before boot, each new volume must be empty and its
restored content root must equal A's. No data-service version change is allowed.

## Different-version rollback

An actual B image bundle is mandatory. The tool does not build B or reinterpret a tag as a
version. The Docker owner must first supply six built B image IDs and its clean exact-source
checkout. B must have a different app SHA and different IDs for all six app images. Its image
labels, exported tracked-source hash and Dockerfile hashes must match that B source. Public
build arguments must still match **A's app identity**, notably the gateway's game URL. Fresh
images built for a different serverId are refused; retagging cannot repair that discrepancy.
The owner arranges any B build in a separate approved build window before maintenance.

```sh
python3 -B "$R" --handoff "$P" --source-custody "$F" --meta "$M" --logs "$L5" \
  pin-version --bundle "$A" --source "$B_SOURCE" --app-sha "$B_SHA" --output "$B_VERSION" \
  --image gateway-api="$B_GATEWAY" --image board-api="$B_BOARD" \
  --image game-api="$B_API" --image game-engine="$B_ENGINE" \
  --image web-gateway="$B_WEB_GATEWAY" --image web-game="$B_WEB_GAME"
python3 -B "$R" --handoff "$P" --source-custody "$F" --meta "$M" --logs "$L6" \
  restore --bundle "$A" --target "$B_TARGET" --version "$B_VERSION"
python3 -B "$R" --handoff "$P" --source-custody "$F" --meta "$M" --logs "$L7" \
  observe --target "$B_TARGET"
python3 -B "$R" --handoff "$P" --source-custody "$F" --meta "$M" --logs "$L8" \
  stop-target --target "$B_TARGET"
python3 -B "$R" --handoff "$P" --source-custody "$F" --meta "$M" --logs "$L9" \
  rollback --bundle "$A" --from-target "$B_TARGET" --target "$ROLLBACK_A"
python3 -B "$R" --handoff "$P" --source-custody "$F" --meta "$M" --logs "$L10" \
  observe --target "$ROLLBACK_A"
python3 -B "$R" --handoff "$P" --source-custody "$F" --meta "$M" --logs "$L11" \
  stop-target --target "$ROLLBACK_A"
python3 -B "$R" --handoff "$P" --source-custody "$F" --meta "$M" --logs "$L12" \
  resume-original --bundle "$A"
```

B runs against a new copy of A, never the original. Its migrations affect only that copy.
A rollback uses **another** new nonce and A's unchanged backup/image bytes, never a schema
downgrade of B's data. The failed/upgraded B copy and observations remain preserved. Both
copies use only `127.0.0.1:443`/`https://localhost`, at different times. Missing B, same-version
restart, unobserved B or running B cannot yield a rollback observation.

`observe` requires current healthy images/mounts/ports, world160 and original PUBLIC registry,
strict unauthenticated boundaries and TLS-verified normal USER login. It rereads the owned
general and prior resolved request through the public BFF and checks the committed SQL result
version, exact APPLIED count1 and request log count against the quiesced checkpoint. Cookies
and raw auth bodies stay in process memory. A persisted request with changed/multiple APPLIED
rows fails. Offline volume-content equality covers both complete PG stores, all Redis files
and icons before boot; the USER probe is not a replay of all gameplay stories.

`resume-original` refuses any live copy and changed original container IDs. It starts only the
original IDs this operation stopped, waits for data/gateway dependencies and health, and checks
the original USER/checkpoint. Its `fullFlowObserved` is false for backup-only or a same-version
exercise; true requires the B observation, stopped B, observed rollback A and original return.
This is tool evidence, not an automatic readiness score or independent acceptance verdict.

## Failures and evidence

- Never delete a partial bundle, failed B target, original volume/image or journal to retry.
  Restore outputs are single-use. Use `stop-target` on an owned partial target before returning
  to F. Repeating stop only follows its recorded IDs. Expired handoffs need C0's renewed window.
- A Docker client timeout can leave an owned helper/container alive. Inventory/foreign-consumer
  checks then refuse resume. Preserve its private child log and ask the Docker owner to reconcile
  the exact owned helper in the same window; do not prune or force-remove it.
- There is no automatic fixture/bundle deletion, background schedule, remote context, external upload, env
  reconfiguration or fresh-harness gate relaxation. Children use a pinned Unix Docker endpoint;
  helper runs/Compose never pull/rebuild images. A disappeared/changed ID fails closed.
  Importing A's saved images refuses any app/support tag now owned by a different image ID.
- Child receipts contain return codes and byte counts in the private log directory, without
  raw stdout/stderr, auth bodies or argv. Application log observation reads each verified
  container's last500 lines into memory and persists only line/error/request counts.
  Public stdout is fixed status/counts/
  version identifiers. `journal.json`, `manifest.json`, `target.json` and stop journals preserve
  phase/identity; JSON phase updates use fsync+atomic replacement. Hashes detect corruption,
  not tampering by a malicious process with the same OS-user privileges.
- Captured private diagnostics and safe observation records support diagnosis; they do not
  establish broader monitoring/alert delivery or a successful real exercise before it runs.

Source verification (no Docker CLI, database, network or real keys):

```sh
python3 -B -m unittest discover -s tools/fixture-recovery -p 'test_*.py' -v
```

The stateful fake CLI covers A→B→A, source preservation, AOF segments, partial restore,
ENOSPC, private output, unsafe archives, foreign ownership, changed IDs/config, handoff binding,
normal-stop failures and missing/unobserved versions. Run the real fixture stages separately
after current-head independent review and explicit C0/Docker handoff. Fake successes are never
recorded as actual backup, restore, rollback, USER or operational3-point acceptance.
