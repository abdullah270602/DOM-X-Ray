# DOM X-Ray Telemetry Contract

Status: prototype v0.1

## Purpose

Telemetry answers two product questions:

1. How long does it take a supported visitor to reach a meaningful, truthful reveal?
2. Does a shared result cause another person to begin a scan?

It is not a surveillance layer for target websites or visitors. Page views, orbit gestures, and export counts are diagnostics—not north-star success.

## Core event chain

```text
scan_submitted
  → scan_finished
  → scene_first_frame
  → hero_fact_visible
  → reveal_completed
  → share_intent
  → shared_result_viewed
  → new_scan_started
```

Events can be absent for legitimate reasons. Funnel analysis must distinguish an abandoned visit, rejected URL, blocked scan, partial result, technical failure, and privacy/telemetry opt-out.

## Common envelope

Every event uses the same bounded envelope:

| Field | Meaning |
|---|---|
| `eventVersion` | Telemetry schema version |
| `eventName` | Allowlisted event name |
| `eventId` | Random idempotency identifier, unique for one logical emission |
| `occurredAt` | Server-normalized timestamp |
| `anonymousSessionId` | Random first-party session identifier; no account identity |
| `scanId` | Opaque scan identifier when a scan exists |
| `attemptId` | Opaque identifier for one submitted scan attempt |
| `parentAttemptId` | Previous attempt when this is an explicit retry; otherwise `null` |
| `resultContext` | `owner`, `shared`, `seeded-example`, or `unknown` |
| `entrySource` | Coarse source such as `direct`, `shared-link`, or `unknown` |
| `clientClass` | Coarse `desktop`, `mobile`, or `tablet`; no fingerprint |
| `telemetryMode` | `full`, `essential-only`, or `off` |

Never place a full target URL, URL query, resource URL, DOM selector, page title, screenshot, page text, IP address, user-agent string, referrer path/query, or share caption in product analytics.

If origin-level analysis becomes necessary, use a short-lived keyed hash of the registrable domain with a rotating salt. The analytics system must not be able to reverse it into browsing history. Operational security logs are a separate, access-controlled system with their own retention policy.

## Event definitions

### `scan_submitted`

Emitted after client URL parsing succeeds and the request is accepted into the scanner boundary.

Properties: `inputShape` (`bare-domain` or `absolute-url`), `queueDepthBucket`, `challengeShown`.

Not permitted: the submitted URL or hostname.

### `scan_finished`

Emitted once with `status` (`complete`, `partial`, `interstitial`, `blocked`, `failed`), machine-readable `failureCode`, scanner/schema/mapping versions, and phase durations.

Properties: `queueMs`, `navigationMs`, `settleMs`, `extractMs`, `persistMs`, request/node/byte buckets, limitations count, and caps reached.

Exact resource URLs and selectors stay in the protected scan record, never analytics.

### `scene_first_frame`

Emitted when the result shell has drawn the first usable 3D frame or the accessible non-WebGL equivalent.

Properties: `renderPath` (`webgl`, `static`, `text`), `loadMs`, `sceneObjectBucket`, `reducedMotion`.

### `hero_fact_visible`

Emitted only when the complete hero sentence and primary number are actually visible or announced by the accessible path.

Properties: `heroKind`, `evidenceLevel`, `attributionScope`, `timeFromSubmitMs`, `partialLabelVisible`.

No metric value enters analytics; the immutable scan record owns it.

### `reveal_completed`

Emitted when the five-second reveal finishes or the final reduced-motion step is reached.

Properties: `revealPath` (`motion`, `reduced-motion`), `durationMs`, `droppedFrameBucket`, `skipped`.

### `share_intent`

Emitted for `preview-opened`, `poster-downloaded`, `video-downloaded`, `link-copied`, `caption-copied`, or `native-share-invoked`.

This event means **share intent**, not a published post. Product reporting must never rename it to “shares.”

Properties: `intentType`, `artifactType`, `generationMs`, `sizeBucket`, `generationStatus`.

### `shared_result_viewed`

Emitted once per anonymous session after an immutable shared result becomes usable.

Properties: `renderPath`, `scanAgeBucket`, `artifactAvailable`, `resultStatus`.

### `new_scan_started`

Emitted when a shared-result viewer focuses or activates the new-scan flow and then submits a valid URL. Activation alone is a diagnostic; submission is the conversion numerator.

Properties: `sourceScanId`, `timeFromSharedViewMs`.

## Diagnostic events

These events explain failures without becoming success metrics:

- `url_validation_failed` with allowlisted reason only.
- `scan_progress_phase` sampled for latency diagnostics.
- `evidence_opened` with evidence kind and attribution scope, never selector/value.
- `mode_changed` for Structure, Weight, or Third-party.
- `isolation_changed` with object kind only.
- `reveal_replayed`, `reveal_scrubbed`, and `reveal_skipped`.
- `share_generation_failed` with allowlisted encoder/error category.
- `retry_started` with previous failure category.
- `webgl_unavailable` and `render_recovered`.

Pointer movement, camera coordinates, raw keystrokes, pasted values, and per-object identifiers are not collected.

## Primary metrics

### Time to meaningful reveal

```text
hero_fact_visible.occurredAt − scan_submitted.occurredAt
```

Each attempt may emit at most one `hero_fact_visible`. The latency distribution contains supported attempts that produce a nonfallback hero through WebGL, static, or text rendering; the event timestamp is when the full statement and primary value first become perceivable on that path. A neutral no-standout summary is not a hero and does not enter the latency distribution.

Report p50 and p90 together with **meaningful reveal coverage**:

```text
supported attempts that emit hero_fact_visible
÷ all supported submitted attempts
```

Complete scans with no standout, partial scans without a defensible hero, blocked, failed, and interstitial attempts remain separate counts and stay in the coverage denominator when they were accepted as supported input. This prevents a fast subset from hiding product failures. The conditional latency target is p90 at or below 20 seconds; launch also requires the completion/coverage gates in the roadmap.

### Viral handoff

```text
unique shared-result viewers who submit a new scan
÷ unique shared-result viewers
```

Deduplicate one shared-result view per `anonymousSessionId + scanId` within a rolling 24-hour analysis window. The anonymous session identifier itself expires no later than 24 hours unless the approved consent/retention policy chooses a shorter period. Seeded/internal traffic and automated checks are excluded by an explicit environment/source field—not ad hoc query filtering.

## Gate metrics

- Scan completion and useful-partial rate.
- Reveal completion rate.
- Hero-fact comprehension from explicit study data, not click inference.
- Evidence-inspector success in moderated tests.
- Share-intent rate among successful scans.
- Viewer-to-new-scan conversion.
- Scanner p50/p90 latency and failure taxonomy.
- Viewer frame-time and fallback rate.
- Poster/video generation success, duration, and size bucket.
- Security-policy rejections, cap terminations, queue saturation, and cost per successful scan in operational telemetry.

Unsolicited public posts require link attribution or manual confirmation; product analytics cannot infer publication from an export.

## Privacy and minimization

- Analytics are first party and purpose-limited.
- Use random anonymous IDs with bounded lifetime; never derive identity from target URLs.
- Respect the product's disclosed consent/opt-out model and applicable law before launch.
- Keep product analytics separate from restricted security/abuse logs.
- Do not send scan contents to general analytics vendors.
- Do not record full IP addresses in product analytics.
- Redact or bucket high-cardinality values before emission, not after ingestion.
- The viewer and exporter function when optional telemetry is off.

## Data quality

- Server timestamps anchor cross-surface latency; client durations use monotonic clocks and carry a source label.
- Every scan emits at most one terminal `scan_finished` event.
- Every event is schema-validated and rejects unknown properties.
- Development, seeded, synthetic, and production traffic remain distinct.
- An accepted submission creates one `attemptId`. An explicit retry creates a new ID and sets `parentAttemptId` to the immediately preceding attempt; automatic navigation retries are prohibited.
- `eventId` is stable across delivery retries. The receiver enforces uniqueness for at least the raw-event retention window and treats duplicate IDs as the same logical event.
- At least 95% of successful benchmark sessions must produce a complete core trace before the private launch gate.

## Retention decision still required

Raw analytics retention, aggregate retention, deletion behavior, consent language, and the security-log boundary need user/legal approval before public launch. The provisional engineering target is the shortest period that still supports a two-week launch cohort and incident investigation; no duration is silently committed here.
