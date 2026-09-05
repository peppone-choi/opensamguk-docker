# Non-cancelling maintenance entry implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Complete this one bounded task with TDD and independent review before integration.

**Goal:** Let an approved operator acquire maintenance only when the deployer is idle, without cancelling another operation or claiming an existing maintenance window.

**Architecture:** Add a loopback/authenticated POST `/maintenance/enter-if-idle` which atomically checks coordinator and persisted state under the existing mutex. Success uses the existing maintenance-v1 response and lease model; conflicts have no side effects. Preserve the old explicitly cancelling endpoint for compatibility, but use only the new endpoint in this repository's automated orchestration workflow.

**Tech Stack:** Go standard library, existing Go tests and GitHub Actions shell.

**Spec:** Approved conversation design on 2026-09-05: temporary shared management/deployment admission maintenance, allow existing operations to finish without cancellation, then PEP-only recovery proof and promotion/reset. This task is only the deployer prerequisite. The existing recovery contract is in sibling opensamguk `docs/admin/game-server-recovery.md`; the first deployment bootstrap is a separately reviewed operator procedure, not solved merely by adding this endpoint.

## Global Constraints

- Never cancel an active job when invoking the new endpoint; no wait and no marker, lease or closed-state mutation on conflict.
- Never claim or reopen pre-existing maintenance or lifecycle-repair state.
- Preserve authentication, loopback restriction, old endpoint behavior and maintenance-v1 JSON compatibility.
- Never expose tokens, env values, maintenance leases or production data in logs, reports or commits.
- Production authority belongs to the parent operator only. No production calls, push, merge, rollout or destructive cleanup by the implementer.
- You are not alone in the codebase. Preserve others' edits. Do not spawn subagents.
- Use apply_patch for edits. Do not commit until the parent has obtained independent review. Parent owns plan/ledger/review artifacts.

### Task 1: Atomic idle admission and fail-closed workflow consumer

**Files:**
- Modify `deployer/main.go`: coordinator error/method, HTTP branch and authenticated-HTTP CLI startup isolation.
- Modify `deployer/main_test.go`: real coordinator and authenticated/loopback handler tests.
- Modify `.github/workflows/deploy-orchestration.yml`: running-deployer entry must call `/maintenance/enter-if-idle`, never fall back to the cancelling endpoint. Busy or unavailable capability exits before checkout/replacement. Existing stopped/missing-container bootstrap remains unchanged.
- Modify `README.md`: document the new endpoint, conflicts, no fallback, and one-time legacy bootstrap requirement without inventing an unsafe procedure.

**Interfaces:**
- Consumes `operationCoordinator.mu`, `active`, `closed`, `journalPending`, `markerPath`, `journalPath`, `maintenanceLease`; existing marker and token helpers.
- Produces `enterMaintenanceIfIdle() (maintenanceState, string, error)` and the new POST route.
- Success HTTP 200 with `{capability:"maintenance-v1",state:"drained",lease:<32 lowercase hex>}`. Conflict HTTP 409 with stable non-sensitive error. Nil coordinator HTTP 503; persistence/randomness failures HTTP 500. Other methods remain rejected.

- [ ] **Step 1: Baseline.** Run `go test ./...` from `deployer`, record exit and test result. Do not claim existing failures as caused by this patch.
- [ ] **Step 2: RED tests.** Add focused behavior tests, run them before implementation and save expected missing-function/route failures. Exercise active real lease and prove its context is not cancelled, job cancellation state unchanged, no marker/lease created and coordinator remains open; finish it and show a later request succeeds. Test existing closed/marker/journal states, successful durable marker and rejection of later begin, duplicate idle-entry refusal (no lease disclosure), correct auth and loopback checks, unwritable marker path and nil coordinator. Use synchronization channels or barriers for the atomic admission race, not timing sleeps or repeated probabilistic loops.

```go
// Representative real-behavior contract; use existing fixture helpers.
lease, err := coordinator.begin("")
if err != nil { t.Fatal(err) }
_, token, err := coordinator.enterMaintenanceIfIdle()
if err == nil || token != "" { t.Fatal("busy admission must fail without a lease") }
if lease.Context().Err() != nil { t.Fatal("busy operation was cancelled") }
if coordinator.maintenanceState() != maintenanceStateOpen { t.Fatal("busy admission changed barrier") }
lease.Done()
```

- [ ] **Step 3: Minimal implementation.** Under `mu`, reject active/closed/journalPending or present/unreadable marker/journal before mutation. Prepare a fresh token before persisting the marker, then set closed and lease only after successful persistence, and return drained. Keep cancellation and blocking wait out of this method. HTTP code maps busy/existing state to 409, unavailable coordinator to 503 and persistence error to 500. Keep response and secrets discipline unchanged.

```go
// Ordering contract (adapt exact error names to the source):
// lock -> reject conflicting live/persisted state -> generate token ->
// persist marker -> set closed+lease -> return drained -> unlock.
```

- [ ] **Step 4: Workflow and docs.** Switch the running-deployer branch to the new route. Any response failure exits before control mutation; do not add automatic retry, legacy fallback, forced cancellation, marker deletion or repair. Add a behavioral test that executes the affected shell entry block against fake command boundaries: idle success proceeds, 409/busy and old-controller unavailable stop before git or docker replacement. Do not substitute a test that only greps exact source strings; place this boundary test in `scripts/` if needed and wire it into CI. Keep its ownership scope limited to this consumer.

  Required prerequisite discovered during bootstrap audit: current `main()` calls `loadConfig()` before `--authenticated-http` dispatch; `loadConfig()` opens/reconciles the live durable operation store. Therefore an apparently read-only helper can mutate an active operation before sending HTTP. Dispatch this HTTP-only CLI path (and invalid/usage argument rejection) before lifecycle initialization, using only the minimal token/local URL/timeout configuration it needs. Add the new endpoint to its existing route allowlist. Do not initialize/open/recover a lifecycle store in HTTP-only mode. Keep daemon startup recovery unchanged. Add a subprocess regression proving existing nonterminal store bytes remain unchanged when this mode exits (including missing token/invalid timeout cases), with no network call on invalid input, plus existing CLI route tests. This is part of ensuring the chosen workflow consumer is genuinely non-cancelling, not a general CLI redesign.

  First-rollout constraint: the workflow can execute against the OLD installed binary. Its pre-admission GET/POST therefore must not invoke that binary at all. Use fixed Python urllib or curl inside the existing container (both already installed), reading DEPLOYER_TOKEN solely from that container's environment; do not put the token in host arguments/logs. A new-route rejection on old control must cause no operation-store recovery, fallback or replacement. Cover that legacy path in the workflow boundary test. The CLI fix remains necessary for future helper calls after upgrade.
- [ ] **Step 5: GREEN and self-review.** Run focused tests, then once `go test ./...`, `go test -race ./...`, `go vet ./...`, `go build ./...`, the workflow boundary test and `git diff --check`. Test outputs may include intentional fixture logs; distinguish them from unexpected warnings. Report exact commands/results and files changed.
- [ ] **Step 6: Report for review.** Write task report with RED/GREEN evidence and concerns; do not commit/push. Parent prepares an uncommitted diff package and independent task/whole-branch review, then commits and integrates with the required coauthor trailer.
