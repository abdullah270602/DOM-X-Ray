# DOM X-Ray

DOM X-Ray is a public, no-login website-exploration toy. A visitor pastes a public URL and receives a cinematic 3D cutaway whose geometry and motion are derived from real page-load measurements, then shares one precise, surprising finding.

## North star

> Paste a public URL → receive a beautiful, truthful 3D X-ray and visible hero fact at p90 within 20 seconds for supported successful scans → export one fact worth sharing.

The first release is deliberately not a full developer dashboard, a Lighthouse replacement, or a generic website roast. The spectacle earns attention; inspectable evidence earns trust.

## Current status

Gate 0's local extraction, policy, supervision, and transport proofs are
implemented, while production egress and containment remain open release gates.
Gate 1 has a shipped React/Three.js viewer for all three immutable fixtures, and
the authored Gate 2 reveal runs through the shared five-stage runtime. The Gate
3 local API adds anonymous pollable jobs, transport-backed seeded scans,
restart-stable immutable result bundles, strong ETags, bounded retention, and a
separate HMAC-backed no-login deletion capability. Published eligible results
have a fail-closed dual-format share preview, stable caption/link controls, and
server-controlled poster and video sidecars: a strict 1080 × 1080 RGBA PNG plus
a deterministic five-stage, five-second 1080 × 1080 H.264 MP4. Their exact
SHA-256 digests, byte lengths, and source-result bindings are committed with the
immutable manifest. The viewer independently verifies each same-origin route,
response status/final URL/type/ETag/length/signature/SHA before preview or
download; video failure falls back safely to the verified poster, while poster
failure retains the bounded local-export path. A durable local delivery
reference proves private immutable keys, object-before-live publication,
origin fencing, `live → retiring → retired`, idempotent purge retries,
confirmed receipts, and tombstoned non-reuse. AWS S3 plus DynamoDB control state
and CloudFront is the selected Gate 5 delivery shape. Credential-free adapters
now prove private conditional S3 creation with exact-version readback/permanent
deletion, DynamoDB full-identity conditional lifecycle state with exact
millisecond visibility and permanent tombstones, and idempotent CloudFront
invalidation accepted only at provider `Completed`. The HTTP runtime can
explicitly select the composite with `--result-backend composite` or
`DOM_XRAY_RESULT_BACKEND=composite`. It owns deletion-HMAC verification,
version-bound S3 reads/writes, and DynamoDB visibility transitions; the DynamoDB
GSI also indexes retiring and retired-but-incomplete cleanup work for restartable
retries. Composite startup requires strict `DOM_XRAY_DELETION_KEYS_B64` and
retention via `--retention-hours` or `DOM_XRAY_RETENTION_HOURS`; provider setup
fails closed without falling back to filesystem storage. The HTTP runtime uses
`no-store` and no CloudFront purger. These local fake-provider/runtime proofs do
not establish live AWS/IAM behavior, multi-writer contention, or warmed-edge and
stale-fill purge behavior. Reads authorized before the retirement fence may
finish afterward. New staged publications have a finite lease and indexed
abandonment/cleanup recovery; objects uploaded before control creation still
need a separate orphan-recovery design.
Partial captures disclose their exact limitation and neutral captures remain
link-only. Arbitrary public scanning remains honestly disabled. This is
executable product progress, not a production-scanner claim: public egress,
distributed queues and abuse controls, an approved retention/takedown policy,
deployed AWS delivery evidence, representative production benchmarks, share
telemetry, and current X upload/recompression testing remain unfinished.

## Project documents

- [PRODUCT.md](PRODUCT.md) — durable product truth and open decisions
- [ROADMAP.md](ROADMAP.md) — goal gates, exit criteria, metrics, and pivot rules
- [docs/TRUTH_CONTRACT.md](docs/TRUTH_CONTRACT.md) — what the experience may visualize and claim
- [docs/SCAN_RECORD.schema.json](docs/SCAN_RECORD.schema.json) — technology-neutral scan record contract
- [docs/CAPTURE_PROTOCOL.md](docs/CAPTURE_PROTOCOL.md) — fixed Chromium observation and measurement rules
- [docs/MAPPING_REGISTRY.md](docs/MAPPING_REGISTRY.md) — semantic-to-scene mapping and reveal behavior
- [docs/MAPPING_REGISTRY.v0.1.json](docs/MAPPING_REGISTRY.v0.1.json) — machine-readable prototype mapping
- [docs/SCENE_MANIFEST.md](docs/SCENE_MANIFEST.md) — executable scan-to-scene contract and renderer obligations
- [docs/SCENE_MANIFEST.schema.json](docs/SCENE_MANIFEST.schema.json) — Draft 2020-12 contract for renderer inputs
- [docs/RESULT_MANIFEST.md](docs/RESULT_MANIFEST.md) — immutable public-result and export binding
- [docs/RESULT_MANIFEST.schema.json](docs/RESULT_MANIFEST.schema.json) — strict result/link/poster/video contract
- [docs/VIEWER_RUNTIME.md](docs/VIEWER_RUNTIME.md) — shared interaction, fallback, and evidence behavior
- [docs/VIEWER_RUNTIME.schema.json](docs/VIEWER_RUNTIME.schema.json) — renderer-neutral runtime contract
- [docs/SCAN_TRANSPORT.md](docs/SCAN_TRANSPORT.md) — destination-grant, worker, and record-admission boundary
- [docs/SCAN_API.md](docs/SCAN_API.md) — anonymous job lifecycle and immutable viewer-bundle boundary
- [docs/RESULT_STORAGE.md](docs/RESULT_STORAGE.md) — durable local publication, retention, and deletion boundary
- [docs/ARTIFACT_DELIVERY.md](docs/ARTIFACT_DELIVERY.md) — private-object publication and verified cache-purge boundary
- [docs/ADR-002-ARTIFACT-DELIVERY-PROVIDER.md](docs/ADR-002-ARTIFACT-DELIVERY-PROVIDER.md) — selected S3/control-state/CloudFront delivery shape
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — release-blocking public-scanner security boundary
- [docs/TELEMETRY.md](docs/TELEMETRY.md) — product event chain, metrics, and data minimization
- [docs/GATE_0_EVIDENCE.md](docs/GATE_0_EVIDENCE.md) — requirement-by-requirement completion evidence and remaining proof
- [docs/GATE_5_EVIDENCE.md](docs/GATE_5_EVIDENCE.md) — local poster/video share evidence and remaining Gate 5 proof

## Project verification

The fixture validator is contract tooling, not a commitment to the eventual application stack. With Python and `jsonschema` available, run:

```sh
python scripts/validate_fixtures.py
python scripts/validate_mapping.py
python scripts/verify_scene_manifest.py
python scripts/verify_result_manifest.py
python scripts/verify_viewer_runtime.py
python scripts/verify_insights.py
python scripts/verify_browser_fixtures.py
python scripts/verify_worker_deadline.py
python scripts/verify_capture_worker.py
python scripts/verify_destination_policy.py
python scripts/verify_scan_transport.py
python scripts/verify_pinned_connector.py
python scripts/verify_scan_api_contract.py
python scripts/verify_result_store.py
python scripts/verify_artifact_delivery.py
python scripts/verify_s3_object_store.py
python scripts/verify_dynamodb_control_store.py
python scripts/verify_cloudfront_purger.py
python scripts/verify_composite_result_backend.py
python scripts/verify_composite_runtime.py
python scripts/verify_local_scan_api.py
python scripts/verify_png_validation.py
python scripts/verify_poster_renderer.py
python scripts/verify_mp4_validation.py
python scripts/verify_video_renderer.py --attempts 15
```

The first command validates the three deterministic scan profiles against JSON Schema Draft 2020-12, then checks cross-record provenance, attribution, party/domain consistency, five distinct node-count meanings, auxiliary-event boundaries, claim wording, and negative controls that JSON Schema alone cannot express. The second checks deterministic geometry/mass rules, monotonicity, registrable-domain hub grouping and placement, version matching, explicit object-budget treatment, unknown states, the exact hero comparator, and the five-second reveal. The third validates the formal scene-manifest schema and committed golden viewer inputs. The fourth validates immutable public-result and export bindings. The fifth validates three byte-identical viewer-runtime models, shared WebGL/reduced-motion/text evidence, replay, scrub, modes, selection, isolation, partial/interstitial/evidence-only behavior, and transfer-state preservation. The sixth exercises hero selection, limitation suppression, known-value coverage, hostile-copy independence, and neutral fallback without launching a browser. The seventh runs thirty-one real fixture pages through pinned Chromium, using a local policy proxy for reserved public-style hosts and two explicitly trusted localhost secure-origin fixtures for service-worker behavior. In addition to the scanner boundaries below, every live result must build a schema-conformant scene manifest. It proves the base DOM candidate filters, hard DOM-inspection, geometry-candidate, request, per-response-byte, total-byte, and popup/download observation boundaries with honest partial results, immediate auxiliary-page/download containment, main-document limit precedence, repeated-URL block provenance, genuine origin-marker and service-worker-marker replay controls, deterministic 650-object aggregation, evidence-free wrapper collapse, evidence-preserving mandatory overflow, ordered redirect-hop identity, final-page party recalculation, three positive and twenty-eight no-standout/interstitial hero outcomes, five redirect rejection cases, four live unsafe-method/private-subresource blocks, one deliberately state-changing GET, exact-scan reuse, per-origin cooling, sensitive-header stripping, sixteen secret canaries, cross-scan storage isolation, exact image attribution, selector redaction, marked geometry, CDP admitted-wire accounting, mixed-cache source classification, page/worker request ownership and target-qualified identities, exact uniquely correlated service-worker bootstrap accounting with conservative ambiguity fallback, active-request settling, bounded DOM-churn timeout, missing-byte preservation, structural login-wall and final-document HTTP-error classification, the subresource-error negative boundary, domain grouping, and the fixture-only request-policy cases. The eighth proves a process-level 15-second ceiling, nonce-scoped bounded transport-envelope eligibility, post-capture timeout, and browser-descendant cleanup on the local operating system. The ninth binds the real Gate 0 probe to that supervisor in a fixture worker, requires exact typed configuration, validates eligible records against both schema and semantic rules, preserves page-timeout partial evidence, and rejects a real post-capture hang before result publication. Production API/queue entry and disposable-container integration remain open. Install `requirements-dev.txt` and the Playwright Chromium binary before running these checks on a fresh machine.

The tenth command is network-free: it exercises the deployment-neutral destination-policy seam against 51 public/forbidden addresses, 29 malformed or unsafe URLs, seven resolver failure modes, and a same-host public-to-private answer sequence. The second resolution is rejected before its connector callback can run. This proves fail-closed policy behavior, not a deployed resolver, HTTPS proxy, or egress firewall.

The eleventh composes that policy with the supervised worker and record-admission boundary. It proves independent initial/redirect/subresource grants, zero launch on 29 target and seven DNS rejections, rebinding denial, strict worker-envelope admission, scan-schema plus semantic validation, and exact initial-target correlation. No record is publishable after launch/setup failure, crash, timeout, stale nonce, oversized/nonregular artifact, malformed envelope, invalid record, or target mismatch. It is connector-contract evidence, not proof of production address-pinned HTTPS, public egress, a queue, or container containment.

The scan-API verifier proves the separate anonymous job lifecycle and immutable
bundle boundary. The result-store verifier proves atomic file publication,
byte-identical restart recovery, HMAC-only digest storage, key rotation,
retention, tombstoned non-reuse, corruption rejection, deletion, concurrency,
and identifier safety. The artifact-delivery verifier separately proves
deterministic private keys, object-before-live activation, exact-byte collision
rejection, abort cleanup, restart validation, origin fencing before purge,
durable pending retries, confirmed receipts, cache-policy gating, and tombstone
precedence. The S3 verifier proves private/versioned/owner-enforced target
preflight, conditional exact-key creation, checksum and immutable metadata,
exact-version readback, idempotent collision handling, and permanent
exact-version deletion against a deterministic client. The DynamoDB verifier
proves table/GSI/TTL plus post-disable-drain preflight, metadata-only
AttributeValue encoding, full-control-identity insert-only staging, exact-
millisecond visibility, conditional lifecycle fences, strong conflict rereads,
bounded expiry cursors, one winning purge operation, persisted
confirmation/cleanup evidence, and permanent tombstones against a deterministic
client. The CloudFront verifier adds exact canonical/query-variant invalidation
coverage, operation-ID idempotency, provider-response validation, and pending-
to-`Completed` retry integration against a deterministic client. The composite
verifier composes fake object, control, and purge providers to prove centralized
HMAC checks, exact-version binding, publication ordering, and retryable
retirement/cleanup. The runtime verifier checks selector/key/retention
validation, injected S3/DynamoDB initialization, fail-closed startup, and the
fixed no-store/no-purger policy. These are local contract proofs, not deployed
AWS/CDN evidence. The local HTTP verifier
then exercises bounded JSON submission, browser-minted deletion digests,
queued/running/ready states, the existing supervised transport,
schema-plus-semantic admission, no-store ETags, restart recovery and owner
deletion, exact-result reuse without ownership transfer, owner-safe guess
throttling, expiry recovery, target correlation, queue and cooling limits, the
stable result shell, and content-free misses. It also proves the poster and
video GET/HEAD routes, strong SHA ETags and conditional 304s, exact-method
405/Allow behavior, content-free 404s for missing, ineligible, deleted, expired,
or corrupt artifacts, poster-only video-failure fallback, and raw-upload
refusal. The viewer tests and Chromium run prove independent same-origin
verification and exact-byte download for both hosted artifacts, with a safe
poster/local fallback when motion is absent or rejected. The PNG and MP4
validators plus their trusted renderers prove the exact 1080 × 1080 media
boundaries, deterministic controlled output, worker supervision, strict
size/duration/cadence limits, and no client pixel upload. An arbitrary public
target remains disabled in this local safety proof.

## Product loop

1. Paste one public desktop URL.
2. Watch a five-second causal reveal: page → structure → weight → external machinery → hero fact.
3. Orbit, isolate, and inspect the source measurement behind any dramatic object.
4. Export a compact poster or video and a stable result link.
5. A viewer of that result can immediately scan another URL.
