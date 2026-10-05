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
