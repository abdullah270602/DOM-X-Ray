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

The production control store is expected to use conditional, multi-writer-safe
transitions (DynamoDB is the default implementation target). The application
origin, not a public bucket URL, authorizes every result read from the durable
`live → retiring → retired` state. The S3 bucket is versioned, blocks all public
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

Runtime access uses an IAM role with narrow S3, control-store, and CloudFront
permissions, including exact-version reads/deletes and prefix-bounded version
listing for deletion proof. Static access keys are not an accepted deployment
configuration. A deployment selecting SSE-KMS must also grant only the KMS
checksum-read permissions required by its key policy.

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

Official provider references:

- [S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- [S3 `PutObject` conditional and checksum parameters](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/bucket/put_object.html)
- [S3 version deletion behavior](https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeletingObjectVersions.html)
- [CloudFront `CreateInvalidation` and `CallerReference`](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_CreateInvalidation.html)
- [CloudFront invalidation API](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_GetInvalidation.html)
- [CloudFront invalidation paths and query variants](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/invalidation-specifying-objects.html)
- [CloudFront private S3 origins with OAC](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html)

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
do not prove AWS credentials, IAM policy, transactional multi-writer control
storage, deployed S3 behavior, bucket policy/OAC correctness, routing, a warmed
global edge, or deletion during an in-flight origin fill.

Before enabling shared caching, a deployed environment must warm every relevant
route/variant, pause an origin fill across retirement, wait for the confirmed
invalidation, release the old fill, and prove neither the old bytes nor stale
ETags can repopulate or escape any tested edge.
