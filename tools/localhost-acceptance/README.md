# Source-built localhost acceptance stack

This harness builds all six app images from one clean exact main SHA, without CI run IDs or GHCR. It uses Docker main's unmodified `infra/nginx/nginx.conf`, new local RSA/TLS fixtures, separate fresh auth/game databases and Redis instances, and a nonce project. Existing `tools/qa/local-stack.py`, qa160 resources and deployment files are never used.

A remote Docker host/context is refused; daemon access must use a local Unix socket. The only host publish is `127.0.0.1:443:443`; origin is exactly `https://localhost`. Occupied 443 fails closed. On macOS, when the nonroot bind probe is denied, a refused loopback TCP connection is required and Docker Desktop’s port bind remains authoritative. TLS verification uses the custody certificate, or the USER runner's temporary browser context. Never install this certificate into the host trust store.

## Commands

Run from this Docker worktree. Set `OPENSAMGUK_TASK_OWNER_SESSION` to the writing app chat ID. Obtain the integration owner's final app SHA first. `--source` must point at a clean checkout at that SHA with no untracked or ignored files. The harness reads only Git-tracked source via `git archive`, not a developer working directory's env/build output. It refuses symlinks, traversal and tracked credential files.

```sh
export OPENSAMGUK_TASK_OWNER_SESSION=<writer-chat-uuid>
python3 tools/localhost-acceptance/harness.py prepare \
  --source <clean-app-checkout> --app-sha <40-hex-main-sha> \
  --docker-sha <40-hex-docker-main-sha> --custody <new-private-directory>
python3 tools/localhost-acceptance/harness.py build --custody <directory> --meta <metarepo>
python3 tools/localhost-acceptance/harness.py validate --custody <directory>
python3 tools/localhost-acceptance/harness.py up --custody <directory> --meta <metarepo>
python3 tools/localhost-acceptance/harness.py smoke --custody <directory>
python3 tools/localhost-acceptance/harness.py resume-startup --custody <directory>
python3 tools/localhost-acceptance/harness.py snapshot --custody <directory> --general-id <positive-id>
python3 tools/localhost-acceptance/harness.py snapshot --custody <directory> --general-id <positive-id> --request-id <uuid>
python3 tools/localhost-acceptance/harness.py down --custody <directory> --meta <metarepo>
```

`prepare` exports tracked source, copies canonical nginx, creates fixtures, and writes private Compose JSON. No containers are started. Both fetched `origin/main` refs must match the supplied full SHAs. It never fetches refs, changes app source, loads `.env`, or obtains external API credentials. Optional `--clone-source-custody <owned-prior-custody>` uses macOS APFS cloning for public source only. Both the prior export and new clone must match the clean current Git archive byte-for-byte and mode-for-mode. New credentials/certificates/nonce are always generated; the prior source stays independent and untouched. There is no full-copy fallback when cloning is unsupported.

`build` runs the four JVM and two web Dockerfiles sequentially under the metarepo's atomic `.locks/heavy-run` lock. It waits for another owner and never removes that lock. Source-build disk must be at least **12 GiB**, Docker VM allocation at least **2 CPUs / 6 GiB**, available Docker memory at least **6 GiB**, and host five-minute load at most **400**, with the load bound matching app main `tools/qa/local-stack.py:46–51`. Gates rerun before each image. Compilation uses the source Dockerfiles as written, including real packaged map/curated inputs. No RTK14 credential enrichment or toy source is injected. Original private build, startup and nginx-test output is retained even on failure. Full Gradle test suites are not run here.

Receipt fields in `contract.json` bind the exact app SHA, source bytes/modes digest, nginx digest from Docker main, Dockerfile digests, explicit public build arguments, nonce/session labels and image IDs. `up` checks these again and never rebuilds or pulls app images. `build` prepares missing public postgres/Redis/nginx support images under the same lock and records their IDs, preserving existing shared images. `up --pull never` checks their IDs too. Normal source Docker builds may download their public base images/dependencies.

Inventory/image inspect uses explicit projections that exclude environment, commands, health logs and volume driver options, including collision candidates. `up` refuses any existing container/network/volume matching the project name, compose project label or nonce label. It checks all services become healthy, actual runtime image IDs/networks/mounts/loopback bindings, `nginx -t`, HTTPS health and unauthenticated boundary routes, actual world160, and registry PUBLIC revision1/gen0. A partial failure leaves the original custody/resources intact. It never silently retries or substitutes a synthetic nginx.

`smoke` does not claim a successful USER journey. The app's separate runner owns normal ADMIN login/me, enabling/readback of allow_join and allow_login, normal USER register/login/join, and all original US-WAND-01/02 assertions. Only the new throwaway DB's AdminSeeder fixture is authorized. No SQL account promotion exists. `RESET_TURNTERM=2` means **two minutes / tickSeconds120**, not two seconds.

## Private handoff and logs

For a separately approved fresh fixture whose exact app pin includes the engine startup-pause support, add `--startup-paused` to `prepare`. It records boolean `startupPaused=true` and supplies only game-engine with `OPENSAMGUK_DAEMON_STARTUP_PAUSED=true`, the Spring environment binding for `opensamguk.daemon.startup-paused` (default false). Without the flag, no contract field or environment key is added; existing standard, tactical and selected-map models stay unchanged. The flag composes with `--profile tactical` and all three explicit topdown inputs. Unknown pause keys, nonboolean records, missing/false flags and other-service leaks are refused.

The conditional strict smoke reads the owned engine's status and requires paused, materialized, live, recovery READY, the exact world and no unfinished scheduled tick before SMOKE_PASSED. This is a scheduled-tick hold: IMMEDIATE intake and health remain available. After fresh H strict smoke, the owning writer runs the separately reviewed 1723 fresh16 account/role Given before C0's USER01/02 and battle acceptance. Normal engine `POST /admin/turn-daemon/resume` releases the hold; every process restart under the same startup-paused environment begins paused again, including role bootstrap and recovery restarts. Recheck paused/readiness after restart and explicitly resume only when the operator approves. This option never modifies an existing custody, accounts, database rows or startup source.

`resume-startup` revalidates an existing STARTING or unpassed RUNNING stack without building, restarting, or changing Compose/fixtures/databases. It requires a clean verifier checkout, unchanged source/config/image receipts, eleven healthy owned services, exact model/runtime mount pairs, port/network boundaries, 6016MiB service caps, VM capacity and host load. Only then does it save the original contract, record the separate `runtimeVerifierHead` and `runtimeVerifierPath` without changing the build `dockerSha`, transition to RUNNING, and execute the normal strict smoke. A validation failure leaves the contract unchanged; a smoke failure cannot mark SMOKE_PASSED. Runtime mount matching permits an exact `/host_mnt` + declared host path alias only on macOS with a current local Unix Docker Desktop daemon. Missing, extra, duplicate or mismatched type/source/destination/write-mode mounts are refused, including named volumes.

Custody is owned by the current OS user, mode0700; JSON/log/key files are mode0600. `contract.json` is safe to summarize but remains private. It supplies project, nonce, dynamic `serverId=lha<nonce>`, world160/gen0, exact origin/source and image identities. `fixture.json` is only `{admin:{username,password}, user:{username,password,name}}`; the USER runner consumes it internally. DB/JWT/internal credentials live in separate `runtime.json` and `compose.json`. Never print or commit these files, run `compose config` to the terminal, dump container inspect/env/logs, or record raw auth/cookie bodies.

All child process stdout/stderr is captured. Errors returned to chat are fixed messages, never argv or child output. Build output is held in private per-service files; container logs stay with their nonce containers, bounded to two 10MB files per service. Only the fixed read-only `snapshot` projection crosses stdout. It validates general ID/UUID, checks running resource ownership, and executes only SELECT inside `BEGIN READ ONLY`. It returns actor IDs, numeric progress, turn timestamps, selected reservation/terminal fields and log count. World counters `world.worldVersion` and `world.writerEpoch` are returned unchanged; a clean engine restart may leave the epoch unchanged. With a request ID, `appliedCount` counts successful APPLIED command-result rows for that world/request, including duplicates. These observations do not establish BattleSession epoch handover. No log text, arbitrary metadata or credentials are returned. Same-user integration runners may call snapshot without assuming the writer session; mutations require the writer session.

`down` does not require healthy services or spare build memory/disk. It takes the shared lock, inventories all name/label matches, verifies nonce + writing session + compose project on every resource, checks no foreign network members or volume consumers, then removes only inspected owned container IDs, network IDs, volume names and validated app image tags. It does not prune Docker caches, remove shared base images, touch other stacks, remove the private custody or erase failure records. If any ownership check fails, it performs no deletion.

## 전술 실행 opt-in profile

새 fixture를 준비할 때만 `prepare ... --profile tactical`을 지정할 수 있다. 생략한 기본
profile의 구성은 유지되며, 준비된 custody나 기존 스택을 이 옵션으로 변경하지 않는다.
실제 전술 runtime/readiness를 포함한 앱 main이 선행해야 한다.

이 profile은 fixture 전용 32바이트 join-ticket 키를 private `runtime.json`에 생성하고,
game-api에 기존 네 전술 flag·serverId·정확한 `https://localhost` WS origin을 결속한다.
engine에는 `BATTLE_PIPELINE_ENABLED=true`와
`BATTLE_PIPELINE_API_BASE_URL=http://game-api:8081`을 지정한다. 키는 game-api만 받으며
JWT·DB·internal-service 비밀을 재사용하지 않는다. nginx는 아래 계약의 두 WS alias만 연결한다.

전술 profile의 무인증 WS 경계 기대값은 **403**이다. 기본 profile의 미노출 **404**를
전술 기능 성공으로 인정하지 않는다. 추가 smoke는 owned game-api 내부의 읽기 전용
readiness를 호출해 정확한 world·D177 encoding·여섯 hash·5초 이내 UTC 시각·빈 reasons와
READY를 확인한다. HTTP 200 하나나 일반 health를 readiness 대신 사용하지 않는다.
이 검사는 실제 조우·한 판 종료·캠페인 정산·성능 인수를 대신하지 않는다.

Tactical prepare writes exactly one private `battle-ws/localhost-allowlist.map` entry:
the contract's exact server ID to `http://s<serverId>-game-api:8081`. The canonical nginx
already includes this directory; prepare copies canonical nginx as-is, and Compose/Dockerfiles remain unchanged. Standard
prepare keeps the directory empty. The contract binds canonical map bytes and SHA256;
verification rejects extra files, arbitrary targets, changed receipts, symlinks/hardlinks,
public or foreign-owned files, and changed model/runtime aliases. Only the owned game-api
endpoint may carry that alias. Canonical HTTP and HTTPS locations accept the actual browser
contract `/ws/battles/...` and the compatibility `/api/battle-ws/...` through the same strict
SID/world/battle ID expression, short-ticket/Origin handling and stripped cookie/auth headers.
No general `/ws` proxy exists. Strict smoke requires own SID **403**, foreign SID **404** and
malformed world/battle paths **404** on both aliases.

### Existing d35 tactical boundary failure

The d35 build created an empty map while expecting tactical 403, and lacked the browser's
`/ws/battles` public path. The existing H's six
images and eleven healthy containers can be retained through a separately approved,
single-attempt `repair-tactical-route`. Source review alone does not authorize this operation.
Use a **separately registered stable verifier worktree**, for example
`localhost-h-route-verifier-20261019`, at the exact reviewed revision. Keep the author PR's
worktree separate because normal post-merge cleanup may remove it. C0 must also update
its private USER/snapshot wrappers to this exact verifier path/revision and harness blob;
the original d35 verifier intentionally rejects a nonempty map.

```sh
python3 -B <stable-verifier>/tools/localhost-acceptance/harness.py repair-tactical-route \
  --custody <existing-H-directory> --meta <metarepo> \
  --verifier-sha <exact-reviewed-verifier-SHA> --authorize-project <exact-owned-project>
```

Admission requires the original d35 tactical RUNNING contract, the original supervisor's
specific WS boundary failure, unchanged source/config/images/custody, eleven healthy owned
services, actual model/mount/network/alias bindings and 6016MiB caps, a clean exact verifier,
the writing session, an explicit project and the global heavy lock with no GUI operation.
The reload adds no container workload, so it retains resume-startup's 2CPU/6GiB VM/load5≤400
checks rather than reserving another six GiB. Any separately authorized D174 disk-floor
override remains an operator concern; this command does not disable source smoke checks.

The operation preserves the original contract bytes in `tactical-route-original-contract.json`
and public nginx bytes in `tactical-route-original-nginx.conf` inside the same private custody. It leaves
`h-execution.json` and all original failure/diagnosis logs untouched, makes no copies of
auth/runtime/certificates, and records the separate verifier SHA/path/harness SHA256 in the
current contract and `tactical-route-recovery.json`. Build `dockerSha` and `nginxSha256` remain
d35's original pins. Separate `runtimeNginxSha256` and `runtimeNginxFileIdentity` bind the new
canonical config to that reviewed verifier revision and the original host device/inode.
Only the exact two-location alias/fallback addition is allowed; an unrelated nginx change
is refused. All other original contract fields must match, except status and these explicit
routing/config/verifier bindings. Normal validation and snapshot recheck them against the
preserved originals and exact Git bytes. Compose and Dockerfiles remain unchanged.

Only then does it write the canonical map and new canonical nginx bytes. The nginx file is
a file-level bind: an atomic rename would leave the container on the old inode. The writer
opens the original with O_NOFOLLOW, checks fstat device/inode/owner/private mode/single-link
and old bytes, writes in place, fsyncs, and rechecks the inode and bytes. A write exception
attempts to restore the old bytes through the same FD. It then runs `nginx -t` and sends
**one normal nginx reload**. It waits for own403/foreign404 on both aliases with a 30-second
observation deadline, runs the complete
tactical/map/startup-pause smoke, and verifies unchanged container/image/network/volume IDs
before publishing `SMOKE_PASSED`. No image build/pull, Compose up/recreate, engine restart,
SQL, policy/account/role mutation or resume occurs. `tactical-route-execution.json` records
the attempt. On failure, restoration first rechecks the same healthy resource IDs, original
backups, exact known current contract/map/config bytes and original inode. If they match,
it restores the old config in place, removes only its canonical map file, and restores the
original FAIL-state contract bytes. If a reload was attempted, restoration runs `nginx -t`
and at most **one additional normal reload** for the old config. This is restoration of the
original failing configuration, not a USER pass. Foreign edits, changed IDs or failed restore
checks prevent overwrites and are recorded as requiring operator action. Both failure records
and originals remain; no automatic repair retry is allowed.

## Regression

```sh
python3 -B tools/localhost-acceptance/test_harness.py -v
python3 -B scripts/test_nginx_campaign_routes.py
```

The unit suite includes real Compose CLI normalization and negative ownership/port/mount/image/source/redaction/cleanup checks. The existing synthetic nginx runtime suite remains separate from real app acceptance. CI is retired; no definition/dispatch is restored and no skipped/canceled job is labeled PASS. Current-head independent review is required before integration.

## Explicit topdown supply for a new custody

The standard profile supplies no map bake. For a separately approved **new** localhost custody, `prepare` accepts all three public inputs together:

```sh
python3 -B tools/localhost-acceptance/harness.py prepare \
  --source '<clean app checkout>' --app-sha '<exact fetched app main SHA>' \
  --docker-sha '<exact fetched Docker main SHA>' --custody '<new absolute custody>' \
  --topdown-bundle '<approved full bundle directory ending in its bake ID>' \
  --topdown-bake-id '<approved 64-hex ID>' \
  --topdown-manifest-sha256 '<approved manifest byte SHA256>'
```

This copies existing public bytes and never generates art, bakes a map, or rebuilds images. It checks full/nonpartial identity, complete chunk/file inventory, transport/raw hashes, the fresh scenario_3190 province-world catalog and its tiles/world/roads, and the app's approved kit export and both web mirrors. An absent or mismatched bundle fails before custody/runtime/key preparation. Existing custody, source bundle and other stacks are not modified. Partial regions, path traversal, symlinks, hardlinks and source/output overlap are refused.

Only the validated bundle is copied under `<custody>/topdown/<bakeId>` with public directories0755/files0644; the custody remains0700. The contract records the explicit selection and source pins. Every normal source/config verification rechecks the copied bytes, file inventory and public modes. Only game-api receives the fixed `TOPDOWN_MAP_ROOT=/app/data/map/topdown`, exact bake ID and `<custody>/topdown` read-only bind with `create_host_path:false`. Missing/extra/foreign/RW runtime mounts still fail the exact mount guard. Conditional smoke also requires the actual preview's bake ID and served manifest hash before `SMOKE_PASSED`; it does not prove browser rendering or gameplay.

The approved existing candidate is artifact11486607528 from app run37632390499, bake `dc7b0ad33600721cd9c10db2fa31b08d3d13d24a120c4fc25d8cb162bd2d36e1`, manifest SHA `3c6e5a2fb672cd7a6867c82a92ec6d5bad348b60d04df000282c9f45b2d7ea28`. These are explicit operator inputs, not fallback defaults. Recheck source compatibility for every new custody; a later source drift is a refusal, never a reason to reuse an old pin blindly.

This profile cannot be added to G by editing its existing contract/Compose/environment. Existing role bootstrap1723 and full-recovery83 have separate strict mount assumptions: their current versions must not be treated as accepting this additional bind. C0 coordinates their compatibility and the frozen tactical profile82 separately before a combined acceptance run. Actual new H startup, image reuse/build approval, USER/GUI acceptance and runtime rollback remain separate.

The new pure suite is `python3 -B tools/localhost-acceptance/test_topdown_bundle.py`. It uses temporary public fixtures and mocked runtime/key operations only. The existing suite's real Docker image-inspect and Compose-normalization cases still require a separately allowed Docker window.

`python3 -B tools/localhost-acceptance/test_tactical_route.py -v` covers routing tampering,
endpoint aliases, exact verifier binding, operation refusals, original failure retention,
reload boundaries and refusal to publish PASS when final runtime identities change. It uses
temporary custody and mocked runtime calls; it is not an actual H repair result.

Startup uses an explicit separate phase: **8 GiB** free disk, with the same **2 CPUs / 6 GiB allocated and available Docker memory / load5 ≤400** checks. Unknown phases are refused. All six app images and three support images are already verified, and startup retains `--no-build --pull never`; new writes are the five nonce volumes, eleven container writable layers and bounded logs (11 × 20MiB). Service memory ceilings total 6016MiB. This separates source compilation storage from runtime admission. `startup-disk.json` records initial and observed disk consumption. After startup and immediately before `SMOKE_PASSED`, free disk must remain **at least 3 GiB**; failure preserves resources and cannot pass smoke. DB/WAL growth is not hard-capped, so these observations remain required. Original resource refusals remain in custody.

Registry seed coordinates follow the app canonical contract: `deployProject=opensamguk-s<serverId>`, `gameApiUrl=http://s<serverId>-game-api:8081`, `gameEngineUrl=http://s<serverId>-game-engine:8082`. The deployProject field is separate from the nonce Compose project name `osglha<nonce>`; using that Compose name makes the app reject the entire registry seed even while healthy.

`repair-registry --custody <directory> --meta <meta-root>` is a single-attempt repair for the exact legacy Compose-name registry defect. It requires the private original c56171e verification receipt, six verified images, eleven healthy owned services, actual 6016MiB caps, registry count 0 and initialized=false. It rejects every other model difference, saves original private Compose/contract files, changes only the public registry deployment coordinate and config hash, then recreates only gateway-api with `--no-build --pull never --no-deps`. Its explicit replacement phase keeps disk≥8GiB, VM capacity≥6GiB, CPU/load checks, and requires 768MiB available memory for the existing 768MiB service replacement. Other containers, networks and volumes must retain their IDs. Credentials, source, image receipts and scenario remain unchanged; no SQL writes or engine/DB restart occur. The normal app seeder must produce the original strict PUBLIC/revision1 identity before smoke passes. A failed attempt is preserved and cannot automatically retry.
