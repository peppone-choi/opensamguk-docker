# D101 Root intent and result transport

The approval intent hashes original bytes (32 KiB maximum), binds the existing
Root typed target fingerprint, explicit settings, five image digests, source,
window and space budget. A linked plan re-reads the immutable intent on every
execution evidence read. Legacy plans omit the new intent field without changing
their serialized representation.

Purpose grants use pure Ed25519 and the original claims after
`OPENSAMGUK-D101-GRANT-V1` plus LF. A pinned root-private PKCS8 envelope is read
only after the independent approved source validates intent, source provenance,
deployment trust and current clock agreement. No provider is installed by
`loadConfig`; there is no request or environment switch that enables issuance.

The existing authenticated CLI admits only the exact GET result route and
buffers at most 16 KiB before writing any result bytes. It does not add a reset
route before the worker and trusted physical sources are connected.

The separately authenticated result route is
`GET /operations/{operationId}/execution-result/{originalResultSha256}`.
It rechecks the current durable reset record, accepted/completed times, immutable
intent/plan/preflight bindings, and referenced journal/runtime originals.
The proof header is `X-D101-Result-Proof: keyId.signatureBase64url`, signing
`OPENSAMGUK-D101-RESULT-V1` plus LF and the original result bytes. Response bytes
are capped at 16 KiB; readers have two slots, no queue and a two second HTTP
budget. An expired caller retains its slot until its source exits.

This result records physical outcome. Gateway canonical settlement and final
PUBLIC publication require their own evidence. Missing/pruned/currently running
or changed durable records never become success through a retained file.

Successful D101 durable transitions preserve the live journal until an immutable
result is published. The issuer binds the actual original PREPARE body, original
intent/plan/preflight, all three phase observations and the runtime original to
the current durable accepted/completed times. Its failure preserves physical
success and the journal. Completed-journal recovery uses the same receipt-only
path without Docker or registry replay. The runtime writer uses the actual
Docker/raw ADMIN collector before the durable terminal transition; the physical
worker call site is still pending.

The physical worker body requires the current RUNNING record and consumed
maintenance lease. It collects prepared/before-journal/before-down observations,
checks all candidate pins, persists the phase chain, and applies the approved
target. Down and the first up share the original cutoff; there is no automatic
retry. A fresh authority is required again before env/down/up, and the actual
runtime is persisted before physical success. This body is not yet connected to
ingress or an approved authority provider. Negative lease/source
tests do not establish a successful physical execution.

The Gateway dispatch source queries the exact internal operation route with the
existing service credential and a freshly signed QUERY grant. It requires
DISPATCH_INTENT, matching original prepare/intent, Root request fingerprint and
R/V, and no terminal/publication result. Fixed private origin and credential
custody prevent caller selection. Reads use 16 KiB, two seconds, two slots and no
redirects/queue. The worker reobserves this real remote state before env/down/up;
missing authority/key/credential custody cannot be replaced by local proof flags.

D101 durable records carry an immutable intent reference and are exempt from
ordinary terminal pruning, including restart and capacity pruning. Same-ID
legacy or changed-intent admission conflicts. The bounded store can refuse new
admission when its retained identities fill capacity; there is no automatic
identity removal or reuse. Empty legacy references retain prior pruning and
serialized shape.

Still unconnected: the approved authority producer and installation card,
physical D101 worker, coordinator, and approved physical recovery path.
The result route remains unavailable in production configuration. Local tests
use public synthetic keys and isolated files, not operating trust or keys.
# First admission and PREPARED proof

Root preparation now reserves the D101 intent identity in the existing durable
operation store before observing an actual phase. The published maintenance
preparation and unconsumed lease are pinned to that operation. First `CreatedAt`,
original plan/preflight references, target, R/V and cutoffs remain unchanged.
The first actual phase chain and its 20-field proof are separate immutable
private files under `.deployer-reset-prepared-phases` and
`.deployer-reset-prepared-proofs`. The directories must already have approved
root-private custody; this code does not create them or install keys.

`GET /operations/{operationId}/prepared-proof/{approvalPlanSha256}/{executionReceiptSha256}`
returns the original proof bytes with `X-D101-Prepared-Sha256` and
`X-D101-Prepared-Proof` (`keyId.signature`, Ed25519 over
`OPENSAMGUK-D101-PREPARED-V1\n` plus those original bytes). The route is subject
to existing Root authentication, exact identity, body/query/encoded-path refusal,
16 KiB, two-second deadline and the shared two-reader limit. A timed-out reader
holds its slot until it actually exits. `preparedAtUtc` is the actual snapshot's
observation time; reads require it to remain younger than 30 seconds and inside
the original destructive cutoff. Signing does not renew that time.

The proof fields are schemaVersion, serverId, worldId, operationId, phase,
approvalIntentSha256, approvalPlanSha256, executionReceiptSha256,
targetFingerprint, rootRequestFingerprint, gatewayPayloadSha256,
initialPublicRevision, verifyingRevision, appSourceSha, imageDigests,
acceptedAtUtc, preparedAtUtc, preparedJournalSha256, destructiveCutoffUnix and
recoveryDeadlineUnix. It describes actual preparation, not operating approval.

Gateway must verify this proof and commit DISPATCH_INTENT before Root activation.
Activation reads that actual Gateway state before consuming the same lease.
The physical worker reuses the persisted initial chain, then observes its later
phases freshly. Preparation does not pull, write env, advance the lifecycle
journal, down or up. A durable admission with incomplete proof cannot repeat its
initial observation. Restart loses the in-memory preparation and closes proof
issuance/activation while retaining the durable identity for explicit recovery.

Actual approved authority, phase source, host custody, key provisioning and
request/CLI wiring remain required. Their unavailable defaults remain closed;
source tests and CI do not attest a physical reset or operating readiness.
