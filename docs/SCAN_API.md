# Anonymous Scan API Contract

Status: local integration proof v0.1

## Purpose

This contract connects the public viewer to the already-proven destination,
worker-supervision, scan-record, scene, result, and runtime boundaries. It does
not relax any scanner release gate. The local implementation may admit only
seeded fixtures until a production resolver, address-pinned connector,
disposable container, distributed abuse controls, and retention policy exist.

Queue state and scan truth are separate. `queued`, `running`, `ready`,
`rejected`, and `failed` describe orchestration. Only an admitted immutable scan
record may supply `complete`, `partial`, `interstitial`, `blocked`, or `failed`
as `scanStatus`. A valid admitted `failed` scan is therefore a `ready` job with
an honest failed result, not a transport failure.

## HTTP surface

### `POST /api/scans`

Accept exactly one JSON body conforming to `SCAN_SUBMISSION.schema.json`. The
maximum request body is 2,048 bytes and the media type is
`application/json`. Before submission, the browser creates a 256-bit deletion
token and sends only its SHA-256 digest as
`X-Deletion-Token-Digest: sha256=<64 lowercase hex>`. Missing or malformed
digests are rejected. The response is a `SCAN_JOB.schema.json` resource.

- `202 Accepted`: queued or running.
- `200 OK`: an exact immutable result was reused.
- `400 Bad Request`: malformed JSON or submission shape.
- `403 Forbidden`: target rejected by destination policy.
- `413 Content Too Large`: request body exceeds 2,048 bytes.
- `415 Unsupported Media Type`: body is not JSON.
- `429 Too Many Requests`: admission or queue limit; include `Retry-After`.
- `503 Service Unavailable`: scanner disabled by the emergency switch.

The server is authoritative. Browser-side URL parsing is only usability help.
Raw resolver answers and worker errors never cross this response boundary.

### `GET /api/scans/{jobId}`

Return the current `SCAN_JOB.schema.json` resource with `Cache-Control:
no-store`. Unknown or expired IDs return a content-free `404`. Clients poll only
while `pollAfterMs` is non-null and apply a bounded backoff when transport
requests fail.

### `GET /api/results/{resultId}`

Return the immutable `VIEWER_BUNDLE.schema.json` document with a strong ETag.
Once published, the bytes for a result ID cannot change. The viewer validates
all component schemas, identities, versions, source hashes, connection
endpoints, and evidence pointers before rendering. While deletion is supported,
responses use `Cache-Control: no-store`; a public immutable cache is forbidden
until the deployment has a proven purge path. `ARTIFACT_DELIVERY.md` defines the
private-object and `live → retiring → retired` provider contract that must pass
before shared caching can be enabled.

### `GET, HEAD /api/results/{resultId}/poster.png`

Serve the published poster sidecar only when the result is artifact-eligible
and its manifest's poster metadata exactly matches the stored bytes. The route
returns `image/png`, `Cache-Control: no-store`, `X-Content-Type-Options:
nosniff`, a strong ETag equal to the quoted poster SHA-256, and the exact
`Content-Length`. `HEAD` has the same status and headers with no body. A
matching `If-None-Match` returns bodyless `304 Not Modified` with the same
strong ETag and no-store policy.

The server-controlled renderer accepts only a strict 1080 × 1080, 8-bit RGBA,
non-interlaced PNG and publishes the sidecar before committing the JSON result
envelope. `POST`, `PUT`, `PATCH`, `DELETE`, and `OPTIONS` on this exact route
return empty `405 Method Not Allowed` with `Allow: GET, HEAD`.
Missing, ineligible, deleted, expired, or corrupt results/artifacts all return
content-free `404` responses. The API never accepts client pixel uploads.

### `GET, HEAD /api/results/{resultId}/video.mp4`

Serve the published motion sidecar only when the result is artifact-eligible
and its manifest metadata exactly matches the stored bytes. The route returns
`video/mp4`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, a
strong ETag equal to the quoted video SHA-256, and exact `Content-Length`.
`HEAD`, conditional `304`, exact-method `405`, content-free miss, and raw-upload
refusal behavior match the poster route.

The controlled encoder accepts only the validated 1080 × 1080 H.264 (`avc1`)
contract: exactly five seconds, 30 fps, 150 frames, and no more than 8,000,000
bytes. A renderer failure publishes the still-verified poster result rather than
claiming motion exists. Production delivery should add bounded byte-range
streaming without weakening manifest, ETag, or deletion checks.

### `DELETE /api/results/{resultId}`

Require the separate 256-bit `X-Deletion-Token` capability. A correct token
retires the result ID, removes the durable bundle, and returns an empty `204`.
Malformed, wrong, unknown, and rate-limited attempts return empty `400`, `403`,
`404`, and `429` responses respectively, all with `Cache-Control: no-store`;
`429` also includes `Retry-After`. Only a keyed HMAC of the browser-supplied
digest is stored, token comparison is constant-time, repeated failures are
bounded without blocking a correct token, and deletion invalidates in-process
exact-result reuse. Production requires requester-aware distributed throttling.
If shared edge caching is enabled later, origin reachability must be fenced
first and `204` may be returned only after a durable confirmed purge receipt;
pending invalidation requires an explicit non-success/pending response and
provider-independent retry.

### `GET /r/{resultId}`

Serve the viewer shell. It fetches `/api/results/{resultId}` and never rescans.
Target HTML, scripts, images, CSS, and live URLs do not enter this page.

## Lifecycle

```text
POST
  -> queued/admission
  -> queued/queued
  -> running/capturing
  -> running/mapping
  -> running/publishing
  -> ready/complete + immutable result

POST or work may instead end at:
  -> rejected/rejected + allowlisted public error
  -> failed/failed + allowlisted public error
```

Terminal states never transition. A job never exposes a result until transport
admission, scan schema and semantic validation, deterministic mapping, bundle
validation, and immutable publication all succeed.

## Local durable storage and retention

The command-line server writes committed result envelopes beneath
`.dom-xray-data/results` by default and keeps its HMAC key separately at
`.dom-xray-data/store.key`; both paths are ignored by Git. Publication writes
validated poster/video sidecars before a same-directory staged envelope,
flushes it, atomically replaces the final opaque-ID path, and exposes only a
fully validated committed result. Deletion or expiry writes a small durable
tombstone before removing the bundle and sidecars, so an old result ID can
never resolve to different bytes. Startup removes abandoned staging files,
rejects corrupt or symlinked result files, and sweeps expired entries. Bundle
and artifact bytes, deletion authorization, tombstones, and ETags survive
process restart.

The local server defaults to a 24-hour engineering retention window, adjustable
with `--retention-hours`. That is not the public product policy. Durable jobs,
multi-process writers, distributed indexes, a deployed object-store/CDN adapter
with a real purge drill, takedown operations, and the approved production
retention period remain release gates.

## Public error vocabulary

Rejections are `invalid-target`, `rate-limited`, `queue-full`, or
`scanner-disabled`. Execution failures are `scan-timeout`, `worker-crashed`,
`invalid-result`, `capture-failed`, or `internal-error`. Messages are static,
bounded product copy; target content, DNS answers, exception text, worker paths,
and stderr are forbidden.

## Required operational bounds

The API adds bounded request bodies, queue depth, concurrency, per-client
submission rate, per-origin cooling, polling guidance, result size, and
retention to the existing worker limits. Production requires durable distributed
enforcement. The in-process local proof is not that enforcement.

Public arbitrary-URL scanning remains disabled until every release blocker in
`THREAT_MODEL.md` has deployment evidence. Seeded fixture mode must be visibly
named and must never relabel one fixture record as another submitted URL.
