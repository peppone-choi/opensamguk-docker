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

`prepare` exports tracked source, copies canonical nginx, creates fixtures, and writes private Compose JSON. No containers are started. Both fetched `origin/main` refs must match the supplied full SHAs. It never fetches refs, changes app source, loads `.env`, or obtains external API credentials.

`build` runs the four JVM and two web Dockerfiles sequentially under the metarepo's atomic `.locks/heavy-run` lock. It waits for another owner and never removes that lock. Fresh disk must be at least **12 GiB**, Docker VM allocation at least **2 CPUs / 6 GiB**, available Docker memory at least **6 GiB**, and host five-minute load at most **400**, matching app main `tools/qa/local-stack.py:46–51`. Gates rerun before each image. Compilation uses the source Dockerfiles as written, including real packaged map/curated inputs. No RTK14 credential enrichment or toy source is injected. Original private build, startup and nginx-test output is retained even on failure. Full Gradle test suites are not run here.

Receipt fields in `contract.json` bind the exact app SHA, source bytes/modes digest, nginx digest from Docker main, Dockerfile digests, explicit public build arguments, nonce/session labels and image IDs. `up` checks these again and never rebuilds or pulls app images. `build` prepares missing public postgres/Redis/nginx support images under the same lock and records their IDs, preserving existing shared images. `up --pull never` checks their IDs too. Normal source Docker builds may download their public base images/dependencies.

Inventory/image inspect uses explicit projections that exclude environment, commands, health logs and volume driver options, including collision candidates. `up` refuses any existing container/network/volume matching the project name, compose project label or nonce label. It checks all services become healthy, actual runtime image IDs/networks/mounts/loopback bindings, `nginx -t`, HTTPS health and unauthenticated boundary routes, actual world160, and registry PUBLIC revision1/gen0. A partial failure leaves the original custody/resources intact. It never silently retries or substitutes a synthetic nginx.

`smoke` does not claim a successful USER journey. The app's separate runner owns normal ADMIN login/me, enabling/readback of allow_join and allow_login, normal USER register/login/join, and all original US-WAND-01/02 assertions. Only the new throwaway DB's AdminSeeder fixture is authorized. No SQL account promotion exists. `RESET_TURNTERM=2` means **two minutes / tickSeconds120**, not two seconds.

## Private handoff and logs

Custody is owned by the current OS user, mode0700; JSON/log/key files are mode0600. `contract.json` is safe to summarize but remains private. It supplies project, nonce, dynamic `serverId=lha<nonce>`, world160/gen0, exact origin/source and image identities. `fixture.json` is only `{admin:{username,password}, user:{username,password,name}}`; the USER runner consumes it internally. DB/JWT/internal credentials live in separate `runtime.json` and `compose.json`. Never print or commit these files, run `compose config` to the terminal, dump container inspect/env/logs, or record raw auth/cookie bodies.

All child process stdout/stderr is captured. Errors returned to chat are fixed messages, never argv or child output. Build output is held in private per-service files; container logs stay with their nonce containers, bounded to two 10MB files per service. Only the fixed read-only `snapshot` projection crosses stdout. It validates general ID/UUID, checks running resource ownership, and executes only SELECT inside `BEGIN READ ONLY`. It returns actor IDs, numeric progress, turn timestamps, selected reservation/terminal fields and log count. No log text, arbitrary metadata or credentials are returned. Same-user integration runners may call snapshot without assuming the writer session; mutations require the writer session.

`down` does not require healthy services or spare build memory/disk. It takes the shared lock, inventories all name/label matches, verifies nonce + writing session + compose project on every resource, checks no foreign network members or volume consumers, then removes only inspected owned container IDs, network IDs, volume names and validated app image tags. It does not prune Docker caches, remove shared base images, touch other stacks, remove the private custody or erase failure records. If any ownership check fails, it performs no deletion.

## Regression

```sh
python3 -B tools/localhost-acceptance/test_harness.py -v
python3 -B scripts/test_nginx_campaign_routes.py
```

The unit suite includes real Compose CLI normalization and negative ownership/port/mount/image/source/redaction/cleanup checks. The existing synthetic nginx runtime suite remains separate from real app acceptance. CI is retired; no definition/dispatch is restored and no skipped/canceled job is labeled PASS. Current-head independent review is required before integration.
