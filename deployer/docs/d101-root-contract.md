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

Still unconnected: the approved authority producer and installation card,
physical D101 worker, immutable result issuer, coordinator, and recovery path.
The result route remains unavailable in production configuration. Local tests
use public synthetic keys and isolated files, not operating trust or keys.
