# Durable Result Storage

Status: local single-process proof v0.1

The local filesystem root is a trusted, operator-owned engineering directory.
This proof rejects direct symlink entries but is not a hostile multi-user
filesystem sandbox; production storage must provide no-follow handles or an
object-store transaction boundary.

## Invariants

- A live result ID maps to one byte-identical validated viewer bundle.
- Bundle bytes never contain ownership secrets and never change in place.
- Result IDs are accepted only in the exact `r_` plus 32 lowercase hexadecimal
  form before a filesystem path is constructed.
- Publication is same-directory staged, file-flushed, atomically renamed, and
  directory-flushed where the platform supports it.
- An existing result ID with different bytes is an immutable collision and is
  never overwritten.
- Corrupt, oversized, nonregular, symlinked, incomplete, or expired entries are
  never returned through the API.
- Deletion removes reachability and leaves a private tombstone; it never rewrites
  the public result as “deleted” or allows the result ID to be reused.
- For every ready export, the validated sidecar is committed before the JSON
  result envelope: `{resultId}.poster.png` for the poster and
  `{resultId}.video.mp4` for the video. The JSON envelope is the sole visibility
  marker, so a published result can never point at a missing or partially
  written artifact.
- Manifest artifact metadata is an exact binding: media type, dimensions,
  duration where applicable, byte length, and SHA-256 must match each sidecar.
  Any mismatch makes the entire result unavailable rather than serving
  unverified bytes.

## Private envelope

Each committed file contains the validated bundle plus private storage metadata:

- storage format version;
- result ID;
- publication and optional expiry timestamps;
- SHA-256 of the canonical bundle bytes;
- deletion-key ID; and
- HMAC-SHA-256 of the browser-supplied token digest.

The browser creates the plaintext 256-bit token and keeps it in origin-local
storage. Only its SHA-256 digest crosses the submission request; the server
immediately protects that digest with a keyed HMAC before durable publication.
The plaintext token and its unkeyed digest are absent from public URLs,
manifests, bundles, durable files, ordinary job polls, analytics, and server
error responses. The plaintext crosses the network only in the same-origin
custom header used to request deletion. Key rotation accepts configured previous
keys for deletion while protecting new digests under the first key.

Deletion and retention write a minimal private tombstone before unlinking the
live envelope. Tombstones contain only format version, result ID, and retirement
time. They prevent an expired or deleted share URL from ever identifying new
bytes.

## Cache and restart behavior

The strong ETag remains the exact SHA-256 identity of bundle, poster, and video
bytes across a restart. Their responses are nevertheless `no-store`: immediate
owner deletion cannot coexist honestly with a long-lived public cache until the
selected hosting layer supplies a verified purge mechanism. Static hashed
application assets may remain immutable-cacheable.

`ARTIFACT_DELIVERY.md` defines that separate provider boundary. Its local
filesystem reference uses private deterministic object keys, commits one live
visibility marker only after every exact object exists, fences origin reads
before purge, persists pending retries and confirmed receipts, and lets a
retired tombstone defeat stale restored state. It does not replace this result
store's deletion authority and is not a deployed object-store/CDN adapter.

Completed results, tombstones, the store key, and deletion authorization survive
restart. Jobs, admission cooling, target-to-result reuse indexes, and
deletion-attempt counters remain in process. Production must replace those
pieces with bounded durable/distributed services before arbitrary public
scanning is enabled.

## Verification

`scripts/verify_result_store.py` proves restart identity, staging cleanup,
single publication under concurrency, sidecar-before-envelope ordering, exact
manifest SHA/length binding, HMAC-only durable state, key rotation, deletion,
retention, tombstoned non-reuse, corruption rejection, and traversal-safe
identifiers. `scripts/verify_artifact_delivery.py` proves the provider-neutral
private-object lifecycle and cache-purge state machine. `scripts/verify_local_scan_api.py`
proves the HTTP digest, cache, restart, ownership, throttling, expiry-recovery,
and deletion behavior, poster/video GET/HEAD/304/405 behavior, content-free
misses, and raw-upload refusal through a real local server.
