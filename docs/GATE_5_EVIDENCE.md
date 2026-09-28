# Gate 5 Local Share Evidence

Status: partial gate evidence; Gate 5 remains open.

## Proven locally

Implementation baseline: `d309200` (poster publication), `9dd6456` (deterministic
share renderer), `3fc4256` (trusted video storage), `bbc3392` (public video
route), `8c94547` (renderer reliability), and `696f89f` (verified motion
sharing).

- Only immutable published results can expose public share controls. Fixture
  previews expose none.
- A complete or honestly partial result with one defensible hero opens a modal
  preview and receives two controlled artifacts: a strict 1080 × 1080, 8-bit
  RGBA, non-interlaced PNG no larger than 5,000,000 bytes and, when encoding
  succeeds, a deterministic 1080 × 1080 H.264 (`avc1`) MP4 that is exactly five
  seconds, 30 fps, 150 frames, and no larger than 8,000,000 bytes. Exact
  SHA-256, byte length, and source-result hashes bind each published sidecar,
  which is written before the JSON commit envelope.
- A partial poster carries `PARTIAL CAPTURE` and the exact product-authored
  limitation message bound to the admitted scan. A complete neutral result stays
  link-only and cannot manufacture a poster claim.
- The headline is recomputed from structured scan evidence. Aggregate forms
  require the exact complete set of typed source references and must reproduce
  numerically from the record; exact-resource and request-count forms likewise
  fail closed on provenance drift.
- The preview and PNG source are product-owned. Target URLs, page titles,
  selectors, resource URLs, raw scene/record identifiers, scripts, fonts, live
  assets, and deletion authority are not accepted as poster inputs; client pixel
  uploads are not accepted.
- `GET`/`HEAD /api/results/{resultId}/poster.png` and `/video.mp4` are
  same-origin and return their exact media type, strong SHA ETag, length,
  `no-store`, and `nosniff`; matching `If-None-Match` returns `304`. Unsupported
  exact-route methods return `405` with `Allow: GET, HEAD`, while missing,
  ineligible, deleted, expired, and corrupt artifacts are content-free `404`s.
- The browser verifies each route, status, final URL, type, ETag, length, file
  signature, and full SHA before preview/copy/download. Rejected or absent video
  falls back to the verified poster; rejected poster falls back to the bounded
  local export.
- The share sheet exposes an explicit still/motion switch, native video controls,
  exact hosted-artifact links, and separate verified downloads. Motion autoplay
  is disabled when the visitor requests reduced motion.
- The share dialog traps focus, closes with Escape, restores the initiating
  control, announces clipboard failures, and routes directly to a selected new
  scan task.
- The provider-neutral delivery reference binds bundle/poster/video to private
  result-scoped keys, stages all bytes before one live marker, fences reads
  before purge, persists pending retries with one operation ID, records exact
  route/object coverage in confirmed receipts, and lets retirement tombstones
  defeat stale restored state. Shared caching is rejected when no purger is
  configured; the actual HTTP service remains `no-store`.
- ADR-002 selects private S3 plus transactional control state behind the
  application origin and CloudFront for same-origin edge delivery. The first
  provider adapter uses one durable operation ID as `CallerReference`, covers
  canonical and query-string variants, validates echoed provider identity, and
  accepts only CloudFront `Completed` as confirmed. Pending state and its final
  receipt are bound to the configured distribution, so target drift fails
  closed across restart.
- The credential-free S3 adapter requires a private, versioned,
  bucket-owner-enforced target; conditionally creates only allowlisted keys;
  verifies checksum, metadata, and complete bytes against the exact returned
  `VersionId`; and permanently deletes that version while rejecting any
  residual version or delete marker. It does not make objects public or replace
  the transactional visibility record.
- The credential-free DynamoDB adapter binds each result to the exact S3
  target/version registry, immutable publication, retention boundary, cache
  policy, and deletion-capability digest. It preflights the table, expiry GSI,
  cleanly disabled native TTL, and a conservative one-hour post-disable
  quarantine; accepts only full-identity staging retries; hides results at the
  exact epoch-millisecond expiry; uses conditional
  state/revision/identity/expiry fences plus strong conflict rereads; and
  persists one purge operation through confirmation, retirement, cleanup, and
  a permanent tombstone. The expiry index is candidate discovery only, not a
  visibility authority.

## Reproducible evidence

From `viewer/`, with the local API and Vite viewer running:

```powershell
npm run typecheck
npm test
npm run build
python scripts/verify-ui.py http://127.0.0.1:5173/
python ../scripts/verify_png_validation.py
python ../scripts/verify_poster_renderer.py
python ../scripts/verify_mp4_validation.py
python ../scripts/verify_video_renderer.py --attempts 15
python ../scripts/verify_artifact_delivery.py
python ../scripts/verify_s3_object_store.py
python ../scripts/verify_dynamodb_control_store.py
python ../scripts/verify_cloudfront_purger.py
```

The unit suite proves deterministic poster/video source binding, exact
result/record/scene/hero hashes, trusted-origin stable links, partial disclosure,
link-only gating, and hostile provenance rejection. It also exercises
URL/status/type/ETag/length/signature/SHA verification, stale-result isolation,
bounded body handling, abort behavior, and safe fallback. The Chromium verifier
then opens actual published complete, partial, and neutral results; waits for
both manifest-verified hosted artifacts; compares them with the registered
server bytes; exercises the interactive motion preview; downloads exact PNG and
MP4 bytes; checks their envelopes; and compares repeated poster pixel digests.

One recorded local run on 2026-09-25 with Chromium `140.0.7339.16` produced:

- image-heavy: two 260,258-byte PNG downloads in 0.104 s and 0.119 s, both
  decoding to pixel digest
  `9feca4d2b6d0f5c089bee2ce49a8a2ea5a3819e8902a1d95f9fa77e0cdc28ef7`,
  plus an exact 1,085,010-byte MP4 download in 0.176 s with SHA-256
  `556dec368f0f05318099f9f3ea2591bf85883b78a0ef818a6bf1f73b2753265d`;
- third-party-heavy: two 272,768-byte PNG downloads in 0.275 s and 0.367 s,
  both decoding to pixel digest
  `f192b0f97295e2f1cf8aa31a01ba70f6cd3d4bc38bfdd894f8c5e458abfddaa6`,
  plus an exact 1,064,141-byte MP4 download in 0.161 s with SHA-256
  `be0240fc24b839b2afeea28f9b0a7dd76c1c0601cbe781d6fc40aa6e5ef8bb3e`.

The controlled renderer also completed 15/15 consecutive deterministic attempts
for the image-heavy fixture at 5.317 s p50 and 6.723 s maximum. These timings and
digests are reproducible single-environment evidence, not the representative
production success-rate or p90 benchmark.

The local delivery verifier additionally covers object-before-live ordering,
failed activation, exact-byte collisions, abort cleanup, restart validation,
single-process concurrent idempotency, retiring-over-live crash recovery,
simultaneous, pending, and post-confirmation purge retries, exact coverage receipts, root
symlink rejection where the operating system permits the fixture, and
fail-closed object tampering. This is state-machine evidence against a scripted
purger, not a warmed-CDN purge test or multi-writer object-store proof.

The CloudFront verifier drives `InProgress → Completed` through a deterministic
client, proves identical retries reuse one invalidation, rejects mismatched
provider coverage, and persists the CloudFront ID into the delivery receipt.
It uses no credentials and creates no AWS resource, so it is adapter-contract
evidence rather than a real edge-purge result.

The S3 verifier uses a deterministic injected client to cover privacy,
versioning, and ownership preflight; `If-None-Match: *`; SHA/checksum and fixed
identity metadata; exact-version readback; 412 convergence; bounded 409 retry;
target/version drift; malformed deletion evidence; and exact-version permanent
deletion. It uses no credentials and creates no AWS resource, so it is adapter
contract evidence rather than a deployed object-store result.

The DynamoDB verifier uses a deterministic low-level client to cover schema and
TTL/drain preflight, strict AttributeValue decoding, bounded metadata-only
items, insert-only full-identity staging, exact millisecond visibility, strong
reads, bounded expiry pagination, conditional lifecycle fencing, operation-ID
convergence, persisted purge evidence, cleanup receipts, and tombstone
non-reuse. It uses no credentials and creates no AWS resource. It therefore
does not prove Botocore model validation, real DynamoDB contention, IAM
isolation, truthful deployment timestamps, or composite HMAC ownership.
Production additionally requires a dedicated table on which TTL has never been
enabled and a runtime role without `dynamodb:UpdateTimeToLive`.

The reviewed desktop and mobile surfaces are committed at
`.impeccable/review/gate5-hosted-share-desktop.png` and
`.impeccable/review/gate5-hosted-share-mobile.png`; their motion states are at
`.impeccable/review/gate5-hosted-share-motion-desktop.png` and
`.impeccable/review/gate5-hosted-share-motion-mobile.png`.

Independent finish reviews for the implementation baseline returned `PASS` for
the responsive/accessibility surface and `PASS` for the share-boundary security
contract. The production build completes; its existing large-chunk warning is a
performance backlog item, not Gate 5 evidence.

## Not yet proven

- composite `ResultBackend`/HMAC/HTTP integration, deployed S3 and DynamoDB
  behavior, IAM proof, warmed-cache purge and in-flight stale-fill drill,
  moderation, or takedown workflow;
- current X web/mobile upload, playback, and recompression behavior;
- the representative production 99% poster / 95% video benchmark thresholds
  (the current 15-run video sample is local evidence only);
- p90 submit-to-share-ready and export-time measurements under the defined
  production environment;
- share-intent and viral-handoff instrumentation; or
- public arbitrary-page scanning, which remains blocked by the separate scanner
  containment and policy gates.

The next Gate 5 checkpoint is the composite `ResultBackend`: it must calculate
and verify deletion HMACs, coordinate exact-version S3 objects, DynamoDB
control transitions, and CloudFront purge as the single visibility authority
behind the existing HTTP seam. After that comes deployed S3/DynamoDB plus the
warmed/in-flight CloudFront purge drill, followed by a current X web/mobile
upload-and-recompression proof. None relaxes the Gate 0/Gate 3 public scanner
blockers.
