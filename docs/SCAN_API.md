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
`application/json`. The response is a `SCAN_JOB.schema.json` resource.

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
endpoints, and evidence pointers before rendering.

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
