# Hostinger fresh QA opt-in (not deployment)

This policy is opt-in only at `prepare --hostinger-qa-task t_<8 lowercase hex>`.
The existing localhost443 template/model, JVM options, image receipts, source archive
rules and TLS certificate generation are unchanged. No option changes an existing
custody, chooses another port, or publishes a public interface.

After this source has independently passed review and been merged, use the normal
README prepare command with the additional `--hostinger-qa-task <actual task ID>`.
Do not pass a branch SHA as `origin/main` or rewrite that ref. Both app and Docker
must still be exact clean fetched main revisions. The generated project is
`opensamguk-qa-<task-id>-<fresh nonce>`. Public origin is exactly
`https://localhost:18443`, publish exactly `127.0.0.1:18443 -> nginx:443/tcp`.
Port occupation/permission uncertainty is refusal, never automatic replacement.

Origin is bound through frontend build arguments/receipts, registry JSON, tactical
WebSocket CORS, HTTP probes, recovery identities, and generated custody nginx.
Only the QA nginx copy changes: its upstream Host is `localhost:18443`, forwarded
port is18443, and redirect target retains18443. The repository nginx is untouched;
TLS still verifies the freshly generated localhost SAN certificate. QA smoke refuses
redirects, including redirects to the protected443 listener.
`hostinger-qa.json` seals the original nonce/selection; canonical Docker source must
contain the exact policy helper hash. New policy bytes require a new custody.

## Admission and limits

Every QA runtime container has `cgroup_parent: user-999.slice`, fixed individual CPU
caps, unchanged canonical RAM cap, and memory+swap ceiling equal to its RAM cap.
The11 canonical containers sum6016MiB RAM and1.4CPU. No low-memory JVM variant is
introduced and no #1724 cold/warm/JVM result is claimed.

Admission uses the managed Linux cgroup v2 memory.current, memory.stat inactive_file,
finite memory.max/memory.high and all finite ancestor CPU quotas; it also checks
/proc/meminfo MemAvailable. Nonreclaimable = current - inactive_file. Every bounded
ancestor must fit its nonreclaimable usage + full prospective concurrent caps +
256MiB safety reserve. CPU caps +0.1CPU reserve must fit every ancestor. A helper
requires full runtime cap +32MiB and1.5CPU +0.1CPU reserve (conservative even while
runtime is stopped). Host availability must independently cover requested caps and
reserve. Unknown/unreadable state refuses. Existing Hermes usage is never killed or
subtracted as if it were our workload. This is admission evidence, not a memory
reservation; the kernel slice and individual container ceilings remain authoritative.

With memory.max4539912192, even an idle slice cannot admit6016MiB +256MiB reserve
(6576668672bytes before existing nonreclaimable usage). This policy therefore
INTENTIONALLY REFUSES current full-stack startup. A larger managed budget and actual
free headroom are necessary. Never lower the numbers just to obtain PASS.

QA build uses an explicit isolated docker-container Buildx builder:2GiB RAM+swap,
CPU1.0, cgroup_parent user-999.slice. Driver caps are inspected after bootstrap;
all six builds use that named builder/--load and original Dockerfiles/JVM settings.
The builder is removed in finally and absence is checked. Per-service admission is
conservative and can refuse after builder allocation. This does not establish that
original full-memory Gradle builds can complete inside2GiB. Actual builder capability,
cold/warm/cache hits and image identity are downstream QA, not synthetic evidence.

QA volume archive/empty-check helpers have32MiB/CPU0.1/managed cgroup ceilings,
random owned name/nonce/session/project/purpose labels and finally cleanup by
verified exact owned ID. A timeout/failure never authorizes foreign cleanup. Existing
containers, volumes, caches, Buzz, DBs and their443 listener are never adopted.

The Hostinger path uses the existing flock files
`/srv/hermes-workspace/projects/opensamguk/locks/host-heavy.lock` and `browser.lock`.
Build/start/recovery use heavy; smoke/recovery probes use browser. Runtime operations
refuse immediately if another owner holds the lock. Read-only Compose test may wait
up to300seconds without removing/replacing the lock. Legacy meta mkdir-lock behavior
is retained for non-Hostinger custody. `--meta` remains required by the existing CLI,
but Hostinger does not redirect its flock to that argument.

## Recovery / native boundaries

PR83 backup, distinct B-version pins, A rollback, normal stop proof, exact RO mounts
and nonce ownership remain required. QA selection/origin/caps survive source backup,
version pins, restored target and original resume. Recovery project names include
`-recovery-<new nonce>`; source and target never run concurrently. Admission is repeated
before target creation/helper containers/start and original resume. USER probes retain
the18443 origin and reject redirects. Fake adapter A-B-A is not real A-B-A evidence.

PR95 native source/image/config/RO-mount and actual grant/lease proof must be retained
when integrating this branch. App1748 remains a required predecessor; this card does
not merge or activate it. PR83 has no native grant re-enrollment/rebinding protocol:
recovery of any nativeWriter-selected custody is explicitly refused before quiesce,
not silently downgraded or counted as accepted. Native new-stack proof and non-native
A-B-A recovery require distinct downstream acceptance lanes; an end-to-end native
recovery acceptance requires a separately designed/reviewed product grant protocol.

## Verification scope

`python3 -B -m unittest discover -s tools/localhost-acceptance` contains pure/mocked
checks plus explicit readonly CLI tests. For the new normalization test only:

    OPENSAMGUK_QA_READONLY_COMPOSE=1 python3 -B tools/localhost-acceptance/test_hostinger_qa.py HostingerTests.test_real_compose_hostinger_normalization -v

This invokes local context inspect and Compose config only on synthetic temporary
fixtures, under the shared lock. It does NOT pull/build/up a container or output its
private normalized environment. Numeric byte strings and default ingress mode emitted
by real Compose are checked without allowing a different bind, cap or origin.

`python3 -B -m unittest discover -s tools/fixture-recovery` covers synthetic recovery.
All existing source/hash/nonce/USER/stop/RO-mount negative checks remain. Real stack,
M01, actual PNGs, product QA, cold/warm, native lease/handover and actual recovery are
NOT_RUN until independent review and resource/port/lock/predecessor conditions pass.
No production start, merge, new cost, GCP, Windows or operational DB initialization is
authorized by these commands.
