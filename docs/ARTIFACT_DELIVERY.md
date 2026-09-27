# Artifact Delivery and Purge Contract

Status: durable local lifecycle plus credential-free S3 and CloudFront adapter
contracts v0.2; no AWS resource or production provider is deployed.

## Purpose

DOM X-Ray keeps one public URL family:

- `/r/{resultId}` — viewer shell;
- `/api/results/{resultId}` — immutable viewer bundle;
- `/api/results/{resultId}/poster.png` — registered poster, when ready; and
- `/api/results/{resultId}/video.mp4` — registered video, when ready.

The delivery layer must not invent digest URLs, public bucket URLs, alternate
media origins, or provider-specific ETags. The result ID is already an opaque
immutable identity and can never be reused after deletion or expiry. Application
SHA-256 remains the strong ETag even when a provider's multipart-upload ETag has
different semantics.

Private object keys are deterministic and allowlisted:

```text
v1/results/{resultId}/bundle.json
v1/results/{resultId}/poster.png
v1/results/{resultId}/video.mp4
```

The bucket or backing object namespace must remain private. Public requests are
resolved only through the authoritative result lifecycle, so staged objects can
never bypass deletion, expiry, or tombstones.

## Publication lifecycle

The required state machine is:

```text
absent -> staged -> live -> retiring -> retired
```

1. Validate the complete viewer bundle and every ready artifact.
2. Compute exact media type, byte length, SHA-256, strong ETag, private key, and
   same-origin public path.
3. Conditionally create every private object. Existing identical bytes are
   idempotent; any different byte under the same result identity is a collision.
4. Read back and verify all object identities.
5. Atomically commit the live control record as the sole visibility marker.
6. Mark the scan job ready only after that visibility commit succeeds.

An activation failure leaves private staged objects, never a partially public
result. The caller may retry the same stage or abort it and remove its objects.
Production control records require a transactional or conditional multi-writer
store; a process-local lock is not sufficient.

## Retirement and cache purge

Owner deletion and retention expiry use the same ordering:

1. Atomically replace `live` with `retiring`. Origin reads become content-free
   misses before any purge request is sent.
2. Submit one idempotent purge operation covering the shell, bundle, poster, and
   video paths registered for that result.
3. Treat provider acknowledgement as insufficient unless the adapter contract
   defines it as completed invalidation for every configured edge/shield.
4. Persist the confirmed purge receipt, mark the result `retired`, then remove
   private objects. The retired tombstone always wins over stale live markers or
   restored objects and the result ID remains unusable forever.

A timeout, provider error, mismatched operation ID, or merely pending response
leaves the result durably `retiring` and origin-inaccessible. It must be retried
with the same purge operation ID. A production DELETE endpoint may return success
only after this receipt exists; otherwise it must return an explicit pending or
retryable response and keep retrying independently of the browser session.
Receipts bind the operation to a SHA-256 of the exact canonical paths and object
identities, plus the provider request ID and provider-confirmed completion time.
Those fields prevent accidental partial coverage; they do not make a dishonest
or weak provider acknowledgement trustworthy. That semantic guarantee still
requires a provider-specific integration test and operational drill. With
`no-store`, the reference records a retirement receipt marked `purgeRequired:
false`; it does not claim an edge purge occurred.

The delivery component does not run an independent retention clock. The
authoritative result lifecycle owns expiry and must invoke this same `retire`
transition; otherwise cached delivery and durable result state could disagree.

## Cache policy

The only safe default is:

```http
Cache-Control: no-store
```

When—and only when—a deployment adapter passes the purge contract, shared edge
caching may use:

```http
Cache-Control: public, max-age=0, s-maxage=31536000, must-revalidate
```

`max-age=0` keeps private browser caches revalidating; `s-maxage` allows the
shared edge to retain immutable bytes. `immutable` and a year-long browser
`max-age` are forbidden because an edge purge cannot erase a visitor's private
cache. Missing, retiring, retired, corrupt, and ineligible responses remain
`no-store`.

Query variants, alternate hosts, content encodings, range variants, shields,
and any future server-rendered result shell must be included in provider-specific
purge verification. The application contract enumerates canonical paths; the
adapter owns complete provider variant invalidation.

## Reference implementation

`scanner/artifact_delivery.py` provides:

- exact bundle/artifact validation and deterministic delivery bindings;
- a provider-neutral cache-purger protocol and confirmed purge receipt;
- a durable filesystem reference implementing staging, activation, abort,
  retirement, retry, restart recovery, and tombstoned non-reuse; and
- strict policy gating that refuses shared caching without a purger.

This reference is intentionally single-process and stores whole objects. It is
not the production object-store adapter, CDN integration, range/streaming
implementation, multi-region consistency proof, moderation system, or takedown
workflow. Its direct root and state-directory symlink checks assume a trusted
local parent filesystem; a production adapter must use provider-native
conditional operations and equivalent no-follow/path-isolation controls.

## Selected provider slice

`ADR-002-ARTIFACT-DELIVERY-PROVIDER.md` selects private S3 objects,
transactional control state, and a same-origin CloudFront distribution for Gate
5 implementation.

`scanner/s3_object_store.py` supplies the private object slice. It:

- accepts only validated, allowlisted result keys and exact payload identities;
- requires bucket versioning, all four public-access blocks, and
  bucket-owner-enforced ownership before use;
- uses `If-None-Match: *`, SHA-256 checksum headers, `ExpectedBucketOwner`, and
  fixed delivery-version/result/kind/length/digest metadata;
- binds successful writes and all later reads to the exact returned S3
  `VersionId`, with complete byte readback before success;
- treats a 412 as idempotent only after exact existing-object verification and
  retries bounded 409 conditional races without falling back to overwrite; and
- permanently deletes the exact version, then fails closed unless no residual
  version or delete marker remains at that key.

The future transactional control record must persist each returned target and
version binding. The adapter alone does not make an object live, authorize a
route, or own the `live → retiring → retired` transition.

`scanner/cloudfront_purger.py` supplies the purge slice. It:

- derives invalidation coverage only from the already validated result/object
  registry;
- appends a trailing wildcard to every canonical path so the bare path and all
  query-string cache variants plus otherwise invalid route suffixes are
  invalidated;
- uses the durable purge operation ID as CloudFront `CallerReference`, making
  identical retries resolve to one provider invalidation;
- persists and validates the configured distribution as the provider target,
  so a restart cannot confirm an operation against a different distribution;
- rejects provider responses whose caller reference, path set, quantity, or
  invalidation ID drifts; and
- returns `confirmed` only after CloudFront reports `Completed`.

The recorded confirmation time is when DOM X-Ray observed the provider's
`Completed` status. The adapter intentionally returns `pending` for
`InProgress`; the delivery lifecycle owns durable retries.

These credential-free verifiers do not exercise Boto3 credentials, IAM,
deployed S3, bucket policy/OAC enforcement, transactional multi-writer state,
real CloudFront edges, or an in-flight stale origin fill. Shared caching
therefore remains disabled in the HTTP service.

## Verification

Run:

```sh
python scripts/verify_artifact_delivery.py
python scripts/verify_s3_object_store.py
python scripts/verify_cloudfront_purger.py
```

The verifier covers private key/path binding, object-before-live ordering,
failed activation, conditional-create collisions, restart identity, abort
cleanup, concurrent idempotency, origin fencing before purge, durable pending
purge retry and simultaneous retirement convergence with one operation ID,
provider receipts, tombstone precedence,
cache-policy gating, unsafe IDs, and fail-closed byte tampering.

The S3 verifier covers bucket privacy/versioning/ownership preflight,
conditional creation, application and provider checksum metadata,
exact-version readback, identical 412 convergence, bounded 409 retry, provider
target binding, malformed-listing rejection, and permanent exact-version
deletion. It also proves `ExpectedBucketOwner` on bucket preflight and every
object operation, plus checksum-enabled HEAD/GET calls. It uses a deterministic
fake S3 client and creates no AWS resources.

The CloudFront verifier covers exact wildcard path construction, one
`CallerReference` across retries, pending-to-`Completed` status handling,
provider-response identity checks, environment wiring, and integration with the
durable retiring state, including fail-closed distribution drift. It uses a
deterministic fake CloudFront client and creates no AWS resources.

Before production, the provider adapters must be composed behind one
transactional lifecycle authority and pass the same suite against deployed AWS,
plus a drill that warms every CDN variant, deletes/expires the result, waits for
confirmed purge, permanently deletes the bound S3 versions, and proves all old
URLs and stale ETags are unable to return bytes. Public arbitrary-page scanning
remains independently blocked by the scanner containment and egress gates.
