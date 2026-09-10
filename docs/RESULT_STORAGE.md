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

The strong ETag remains the exact SHA-256 identity of the bundle bytes across a
restart. Bundle responses are nevertheless `no-store`: immediate owner deletion
cannot coexist honestly with a one-year public cache until the selected hosting
layer supplies a verified purge mechanism. Static hashed application assets may
remain immutable-cacheable.

Completed results, tombstones, the store key, and deletion authorization survive
restart. Jobs, admission cooling, target-to-result reuse indexes, and
deletion-attempt counters remain in process. Production must replace those
pieces with bounded durable/distributed services before arbitrary public
scanning is enabled.

## Verification

`scripts/verify_result_store.py` proves restart identity, staging cleanup,
single publication under concurrency, HMAC-only durable state, key rotation,
deletion, retention, tombstoned non-reuse, corruption rejection, and
traversal-safe identifiers. `scripts/verify_local_scan_api.py` proves the HTTP
digest, cache, restart, ownership, throttling, expiry-recovery, and deletion
behavior through a real local server.
