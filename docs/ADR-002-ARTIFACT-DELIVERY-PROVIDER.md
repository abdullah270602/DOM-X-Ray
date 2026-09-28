# ADR-002: Artifact Delivery Provider

Status: **accepted for Gate 5 implementation; no cloud resources deployed**

Date: 2026-09-27

## Decision

Use an AWS delivery shape for production artifact work:

```text
same-origin CloudFront distribution
  ├─ static viewer origin
  └─ /r/* and /api/* → application origin
                          ├─ transactional result/control state
                          └─ private S3 artifact objects
```

The production control store uses one conditionally updated DynamoDB item per
result. The application origin, not a public bucket URL, authorizes every
result read from the durable `staged → live → retiring → retired` state. The
item binds the immutable publication digest, exact S3 target/version registry,
retention boundary, deletion-capability digest, cache policy, purge operation,
and cleanup evidence. Exact retries converge; changed retention, deletion
capability, object version, or publication identity collides instead of
silently transferring authority. The S3 bucket is versioned, blocks all public
access, and uses bucket-owner-enforced ownership. Objects are created with
`If-None-Match: *`, an application SHA-256 checksum, and fixed identity
metadata, then read back by the returned S3 `VersionId` before a live control
record is committed. That exact version binding must be stored in the
transactional object registry; neither an S3 ETag nor an unversioned key is an
accepted durable identity.

CloudFront fronts the stable same-origin routes. Retirement fences the
application origin first, submits one invalidation using the durable purge
operation ID as `CallerReference`, and remains pending until
`GetInvalidation` reports `Completed`. Each registered canonical route gets its
own trailing-wildcard invalidation (`/r/{id}*`, the bundle route, the poster
route, and the video route when registered). This conservatively covers the
canonical URL, query-string variants, and otherwise invalid route suffixes. The
locally observed completion time, CloudFront distribution identity, and
invalidation ID become provider evidence in the receipt.

After confirmed retirement, cleanup permanently deletes every registry-bound
S3 version and checks `ListObjectVersions` for residual versions or delete
markers at the exact key. A delete marker alone is not deletion proof. If
cleanup fails, the control record remains retired and cleanup is retried; no
object failure can restore public visibility.

A sparse DynamoDB GSI discovers live expiry candidates at an exact epoch-
millisecond boundary, followed by a strongly consistent base-table read and a
conditional `live → retiring` fence. Visibility reads independently reject a
live record at or after that exact boundary, and activation conditionally
requires expiry to remain in the future. DynamoDB native TTL remains disabled:
retired items are permanent non-reuse tombstones, not expiring data. Production
uses a dedicated table on which TTL has never been enabled. As defense in
depth, startup rejects any reported TTL attribute, requires an operator-supplied
TTL-disabled timestamp, and applies a conservative one-hour quarantine—twice
AWS's approximate 30-minute post-disable deletion period.

Runtime access uses an IAM role with narrow S3, control-store, and CloudFront
permissions, including exact-version reads/deletes and prefix-bounded version
listing for deletion proof. Only the lifecycle service may write the control
table; the control identity is a consistency digest, not authentication against
a privileged table writer. The runtime role may describe TTL but may not call
`UpdateTimeToLive`; that setting remains infrastructure-owned. Static access
keys are not an accepted deployment configuration. A deployment selecting
SSE-KMS must also grant only the KMS checksum-read permissions required by its
key policy.

## Why this provider shape

- S3 supports conditional writes that reject an existing key, matching the
  immutable create-once object contract.
- S3 version IDs let the control record bind reads and deletion to the exact
  bytes that passed readback, while permanent exact-version deletion avoids
  mistaking a versioning delete marker for erasure.
- CloudFront accepts the caller-supplied `CallerReference` as an idempotency
  key and exposes an inspectable `Completed` state. Repeating the same
  reference and paths returns the prior invalidation instead of creating a new
  one; reusing the reference with different paths is an error.
- The same distribution can preserve the product's same-origin URLs while the
  bucket remains private and application state continues to gate visibility.
- The provider APIs map directly to durable retry rather than requiring a
  browser session to stay open during deletion.
- DynamoDB conditional writes fence every lifecycle transition while strong
  base-table rereads resolve retries without treating the eventually
  consistent expiry index as authority.

Official provider references:

- [S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- [S3 `PutObject` conditional and checksum parameters](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/bucket/put_object.html)
- [S3 version deletion behavior](https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeletingObjectVersions.html)
- [CloudFront `CreateInvalidation` and `CallerReference`](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_CreateInvalidation.html)
- [CloudFront invalidation API](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_GetInvalidation.html)
- [CloudFront invalidation paths and query variants](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/invalidation-specifying-objects.html)
- [CloudFront private S3 origins with OAC](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html)
- [DynamoDB conditional writes](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithItems.html)
- [DynamoDB read consistency](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html)
- [DynamoDB `DescribeTable`](https://docs.aws.amazon.com/boto3/latest/reference/services/dynamodb/client/describe_table.html)
- [DynamoDB `DescribeTimeToLive`](https://docs.aws.amazon.com/boto3/latest/reference/services/dynamodb/client/describe_time_to_live.html)
- [DynamoDB TTL disable drain window](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/time-to-live-ttl-how-to.html)

## Alternatives

### Cloudflare R2 and Cloudflare cache

This remains a viable cost/simplicity alternative, but it is not the selected
Gate 5 implementation. Cloudflare documents that HTTP 200 from its purge API
means the request was received, not that cached content was proven evicted.
That makes a durable confirmed-deletion receipt depend on additional probe and
operational semantics. Cloudflare also requires exact care around custom cache
keys. The project can revisit it if a deployment drill supplies evidence at
least as strong as the selected contract.

### Direct public object URLs

Rejected. They would introduce a second public identity and could bypass the
authoritative result lifecycle, deletion capability, tombstones, and stable
same-origin ETags.

### Browser-immutable caching

Rejected. CDN invalidation cannot remove bytes already held in a visitor's
private browser cache. Result responses retain `max-age=0` even after shared
edge caching is enabled.

## Proof boundary

`scanner/cloudfront_purger.py` and its deterministic verifier prove request
construction, identity validation, idempotent retries, and the rule that only
`Completed` becomes confirmed. `scanner/s3_object_store.py` and its
credential-free verifier prove configuration preflight, conditional
create-once requests, exact-version readback, collision handling, target
binding, and permanent exact-version deletion against an injected client. They
do not prove AWS credentials, IAM policy, deployed S3 behavior, bucket
policy/OAC correctness, routing, a warmed global edge, or deletion during an
in-flight origin fill.

`scanner/dynamodb_control_store.py` and its deterministic verifier prove the
low-level AttributeValue codec, table/GSI/TTL preflight, insert-only staging,
conditional lifecycle fences, strong conflict rereads, expiry and pending-work
pagination, one winning purge operation, confirmed purge evidence, and
permanent tombstones against an injected client. The composite backend and its
fake-provider verifier now compose deletion-HMAC verification, exact-version
object operations, control transitions, and purge/cleanup retries behind the
`ResultBackend` interface. The runtime verifier also covers explicit composite
selection and fail-closed provider preflight, with fixed no-store policy and no
purger. These do not prove Botocore request-model acceptance in the installed
deployment, live DynamoDB contention/consistency, or IAM isolation. A read
authorized before retirement may finish after the fence. Staged publication
abandonment and discovery remain unimplemented.

Before enabling shared caching, a deployed environment must warm every relevant
route/variant, pause an origin fill across retirement, wait for the confirmed
invalidation, release the old fill, and prove neither the old bytes nor stale
ETags can repopulate or escape any tested edge.
