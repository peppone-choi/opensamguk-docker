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
JWT·DB·internal-service 비밀을 재사용하지 않는다. 공개 gateway/nginx 경로는 추가하지 않는다.

전술 profile의 무인증 WS 경계 기대값은 **403**이다. 기본 profile의 미노출 **404**를
전술 기능 성공으로 인정하지 않는다. 추가 smoke는 owned game-api 내부의 읽기 전용
readiness를 호출해 정확한 world·D177 encoding·여섯 hash·5초 이내 UTC 시각·빈 reasons와
READY를 확인한다. HTTP 200 하나나 일반 health를 readiness 대신 사용하지 않는다.
이 검사는 실제 조우·한 판 종료·캠페인 정산·성능 인수를 대신하지 않는다.

## Regression

```sh
python3 -B tools/localhost-acceptance/test_harness.py -v
python3 -B scripts/test_nginx_campaign_routes.py
```

The unit suite includes real Compose CLI normalization and negative ownership/port/mount/image/source/redaction/cleanup checks. The existing synthetic nginx runtime suite remains separate from real app acceptance. CI is retired; no definition/dispatch is restored and no skipped/canceled job is labeled PASS. Current-head independent review is required before integration.

Startup uses an explicit separate phase: **8 GiB** free disk, with the same **2 CPUs / 6 GiB allocated and available Docker memory / load5 ≤400** checks. Unknown phases are refused. All six app images and three support images are already verified, and startup retains `--no-build --pull never`; new writes are the five nonce volumes, eleven container writable layers and bounded logs (11 × 20MiB). Service memory ceilings total 6016MiB. This separates source compilation storage from runtime admission. `startup-disk.json` records initial and observed disk consumption. After startup and immediately before `SMOKE_PASSED`, free disk must remain **at least 3 GiB**; failure preserves resources and cannot pass smoke. DB/WAL growth is not hard-capped, so these observations remain required. Original resource refusals remain in custody.

Registry seed coordinates follow the app canonical contract: `deployProject=opensamguk-s<serverId>`, `gameApiUrl=http://s<serverId>-game-api:8081`, `gameEngineUrl=http://s<serverId>-game-engine:8082`. The deployProject field is separate from the nonce Compose project name `osglha<nonce>`; using that Compose name makes the app reject the entire registry seed even while healthy.

`repair-registry --custody <directory> --meta <meta-root>` is a single-attempt repair for the exact legacy Compose-name registry defect. It requires the private original c56171e verification receipt, six verified images, eleven healthy owned services, actual 6016MiB caps, registry count 0 and initialized=false. It rejects every other model difference, saves original private Compose/contract files, changes only the public registry deployment coordinate and config hash, then recreates only gateway-api with `--no-build --pull never --no-deps`. Its explicit replacement phase keeps disk≥8GiB, VM capacity≥6GiB, CPU/load checks, and requires 768MiB available memory for the existing 768MiB service replacement. Other containers, networks and volumes must retain their IDs. Credentials, source, image receipts and scenario remain unchanged; no SQL writes or engine/DB restart occur. The normal app seeder must produce the original strict PUBLIC/revision1 identity before smoke passes. A failed attempt is preserved and cannot automatically retry.
