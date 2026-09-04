# DOM X-Ray Goal-Gated Roadmap

## North star

> Paste a public URL → receive a beautiful, truthful 3D X-ray and visible hero fact at p90 within 20 seconds for supported successful scans → export one fact worth sharing.

The latency clock begins when a valid visitor clicks **X-Ray** and ends when the first interactive cutaway and hero fact are visible. Queueing, scanning, transformation, storage, delivery, and first rendering are all inside the clock.

This roadmap is gated, not date-driven. Work advances only when the current gate's evidence satisfies its exit criteria. A demo that looks complete but cannot prove a gate remains inside that gate.

## Definition of the first complete release

A public, no-login visitor can submit a supported public desktop URL; receive a valid or honestly partial scan; understand the authored five-second reveal; inspect the source measurement of any emphasized object; explore Structure and Weight; and create a stable share result. The end-to-end path is measured, secured against obvious scanner abuse, and verified on representative pages and target social playback.

## Gate 0 — Truth contract and product boundary

**Question:** What are we allowed to show and say?

Deliverables:

- Durable product record and explicit V1 exclusions.
- Versioned scan-record schema.
- Measurement-to-visual mapping with attribution levels and prohibited claims.
- Fixture plan covering clean, image-heavy, and third-party-heavy pages.
- Initial scanner threat model and operating limits.

Exit criteria:

- Every proposed 3D primitive points to a raw measurement or a named deterministic derivation.
- Observations, derivations, and inferences have distinct claim language.
- Unknown, cached, blocked, unattributed, and partial data have defined representations.
- The schema can encode all three fixture profiles without one-off fields.
- Fixture element rectangles reproduce within 1 CSS pixel and transferred-byte totals within 2% under the declared capture protocol.
- A reviewer cannot mistake “third-party request” for “tracker” or page-level work for element blame.

Current status: **in progress, foundational extraction proof passed but scanner proof incomplete**. Three live deterministic pages now prove base candidate filtering, 23 marked rectangles within 1 CSS pixel, six exact image-element links—including a reused URL—with stylesheets/fonts/scripts/fetches left page-level, selector redaction, stable structural fingerprints, exact CDP-to-wire byte accounting, the quiet-window mutation reset, and third-party domain grouping. Gate 0 still needs mandatory-node aggregation, redirect/cache/service-worker/timeout/interstitial fixtures, production-shaped egress and DNS controls, unsafe-GET/cooling tests, approved scanner identity/robots/opt-out behavior, and a launch retention/deletion decision.

Pivot rule: if the concept requires invented causality to feel dramatic, remove that layer. The minimum honest product is Structure + transferred Weight + external requests.

## Gate 1 — Visual proof with deterministic fixtures

**Question:** Does truthful data produce a legible and desirable physical world?

Build exactly three local, deterministic scan fixtures:

1. **Clean:** shallow structure, modest transfer weight, almost entirely first party.
2. **Image-heavy:** a few visually dominant regions carry most transferred bytes.
3. **Third-party-heavy:** external requests and script weight materially alter the silhouette.

Deliverables:

- One interactive viewer driven only by the shared scan schema.
- Flat-page orientation, 3D cutaway, Structure mode, Weight mode, and evidence inspection.
- A deterministic capture route or script for visual regression checks.
- Frame-time and object-count instrumentation.

Exit criteria:

- A first-time viewer identifies the image-heavy and third-party-heavy scenes within ten seconds, without instruction.
- Every selectable object reveals its metric, value, source, capture status, and mapping rule.
- All three scenes use the same renderer and schema; no fixture-specific visual logic exists.
- The typical target laptop sustains a median of at least 55 FPS and a low-percentile floor of at least 45 FPS after the reveal at the agreed viewport, with 500–700 rendered objects as a hard budget rather than a target.
- Reduced-motion and WebGL-fallback presentations retain the hero fact and evidence.
- At least 7 of 10 target creators call the deterministic poster intentional and share-worthy.

Instrumentation: scene-ready time, median and low-percentile frame rate, draw calls, rendered-object count, aggregation ratio, evidence-panel opens, mode switches, comprehension-test answer, and poster desirability.

Parallel scanner-risk spike: scan ten deliberately difficult public URLs before polishing the visual system. At least seven must yield a useful complete or partial capture, every failure needs a category, and the prototype scanner must already reject private-network and redirect-pivot targets. This does not replace Gate 3; it prevents the largest technical risk from waiting behind visual polish.

Pivot rule: if two bounded visual iterations still require explanation, aggregate the DOM more aggressively and reduce the grammar to fewer, larger regions. Do not add legends to rescue an illegible metaphor.

## Gate 2 — The five-second reveal

**Question:** Can one short sequence teach the causal story and end on a shareable fact?

Required sequence:

- **0.0–0.7 s:** recognizable flat page.
- **0.7–1.7 s:** camera tilts; structural planes separate.
- **1.7–3.2 s:** transferred resource weight pulls or expands the responsible regions.
- **3.2–4.2 s:** third-party connections enter as external machinery.
- **4.2–5.0 s:** camera locks; one precise hero fact becomes readable.
- **After 5.0 s:** free orbit, scrubbing, isolation, and evidence inspection become primary.

Exit criteria:

- The authored sequence completes in `5.0 s ± 0.2 s` on target hardware.
- At least 8 of 10 unprompted test viewers describe the same basic causal story.
- The hero fact remains readable for at least one second and has no more than three support metrics.
- The hero fact remains readable and uncropped in an approximately 360-pixel-wide feed preview.
- Replay and timeline scrubbing are deterministic from the same scan record.
- Reduced-motion mode communicates the same stages without camera-dependent meaning.

Instrumentation: reveal start/completion, skipped reveal, scrub/replay, hero-fact visibility time, fact recall, surprise score, comprehension result, and dropped-frame count.

Before leaving this gate, upload one fixture artifact through the current X media flow and inspect the recompressed result. Current platform behavior must be reverified at test time rather than assumed from this roadmap.

Pivot rule: high completion with low comprehension means simplify the mapping and camera choreography; do not lengthen the film first.

## Gate 3 — Real public-page scanner

**Question:** Can real pages be captured consistently, safely, and fast enough?

Deliverables:

- Controlled Playwright/Chromium scanner using a fixed declared viewport.
- DOM rectangles and hierarchy, stacking-context derivation, sanitized screenshot, resource transfer records, party classification, and recorded layout shifts where supported.
- Fresh isolated context per scan, URL/redirect validation, execution and resource limits, throttling, and actionable failure reasons.
- Immutable scan storage that reproduces the same shared result without rescanning.
- Representative corpus of at least 100 allowed public pages, including difficult and blocked cases.

Exit criteria:

- At least 80 of 100 representative URLs produce a valid complete or explicitly useful partial record.
- Scanner p50 is at most 10 seconds and p90 is at most 18 seconds under the defined test environment, leaving rendering headroom for the product-level p90 submit-to-visible-hero target of 20 seconds.
- Every failure is classified as blocked, invalid target, timeout, resource limit, capture error, or unsupported page—not a generic error.
- Repeated scans of stable fixtures keep headline transfer totals within 5% under identical capture conditions.
- Security tests prove private/loopback/link-local/metadata targets and redirect pivots are rejected.
- No result claims element-level causality from page-level or unattributed measurements.

Instrumentation: queue time, navigation/capture/processing durations, status and limitation codes, request/byte caps, redirect count, block reason, browser crash, and scan-schema version.

Pivot rule: if arbitrary-page reliability or safety misses the gate after bounded remediation, narrow the supported input set—curated domains, user-provided static exports, or seeded examples—before weakening isolation or truthfulness.

## Gate 4 — Public exploration loop

**Question:** Can a newcomer complete the core journey without help?

Deliverables:

- URL entry, scan progress, clear blocked/partial/failure recovery, and no-login result route.
- Orbit/zoom, reveal scrub/replay, isolate, and Structure/Weight/Third-party views.
- Evidence panel containing selector or region, mapped metric, value, capture source, and mapping explanation.
- One-click “scan another URL” from both owned and shared results.
- Responsive shell with keyboard, touch, reduced-motion, and non-WebGL paths.

Exit criteria:

- At least 12 of 15 first-time participants submit a URL, understand the hero fact, inspect one source, and start another scan without facilitation.
- No essential fact or action depends solely on hover, color, camera motion, or WebGL.
- A partial scan explains what is missing while preserving only defensible results.
- The result URL reconstructs the exact versioned scan and visual mapping.

Instrumentation: submit, validation error, scan state, reveal completion, evidence open, mode/isolate interaction, retry, and viewer-to-new-scan conversion.

Pivot rule: if visitors watch but do not inspect or rescan, improve the transition from hero fact to evidence and the shared-result CTA before adding diagnostics.

## Gate 5 — Share engine

**Question:** Does the artifact survive outside the product and invite the next scan?

Deliverables:

- Stable public result URL.
- Designed poster and approximately five-second square video containing the page identity, cinematic reveal, exact hero fact, DOM X-Ray identity, and final-frame CTA.
- Deterministic server-side or controlled encoding path, with H.264 MP4 as the interoperability target unless current platform testing disproves it.
- Share preview that lets the visitor check the artifact before export.

Exit criteria:

- A visitor reaches share preview within 45 seconds of beginning a successful scan.
- Export completes within 10 seconds in the defined environment.
- The video is at most 8 MB and plays correctly in current X web/mobile upload tests.
- Poster generation succeeds in at least 99% and video generation in at least 95% of benchmark attempts.
- p90 successful submit-to-share-ready time is at most 30 seconds.
- The exported claim and numbers exactly match the immutable scan record.
- Opening the stable link reproduces the result and offers a new scan in one action.

Instrumentation: preview open, poster/video export, copy-link, export failure, artifact size/time, shared-result view, and shared-viewer-to-new-scan conversion.

Pivot rule: high reveal completion but low sharing means test the artifact composition, caption, and privacy expectations before changing the core visualization.

## Gate 6 — Private launch and decision

**Question:** Does the complete loop create voluntary sharing and new scans?

Launch with 25–40 design/development creators and six seeded scans spanning clean, heavy, recognizable, and open-source pages.

Provisional two-week exit criteria:

- At least 70% of submitted supported scans complete successfully.
- At least 60% of successful visitors finish the reveal.
- At least 20% of successful visitors create a share artifact or copy a result link.
- At least 8% of shared-result viewers start a new scan.
- At least five people publish results without being individually prompted to post.
- Qualitative interviews show the hero claims were understood and trusted.
- At least 80% of sampled shared-result viewers describe the hero fact correctly.

Decision rules:

- **Proceed:** comprehension and viewer-to-new-scan pass; scale reliability and widen inputs.
- **Fix share layer:** reveal/comprehension pass but artifact creation or posting fails.
- **Simplify visual grammar:** completion passes but comprehension or trust fails.
- **Narrow scanner scope:** demand exists but scan reliability/safety fails.
- **Stop or reposition:** people understand the artifact but neither share nor initiate another scan after two bounded share experiments.

## Cross-gate rules

- Git commits are goal-sized and must identify the gate they advance.
- A gate's status changes only with linked evidence: test output, captured artifact, benchmark, or research notes.
- New scope enters the backlog; it does not enter the current gate unless it is required for that gate's exit criteria.
- “Looks good” never substitutes for comprehension, provenance, performance, or reliability evidence.
- Current open decisions: implementation stack, deployment target, persistent comp-first versus code-first workflow preference, storage/retention policy, and the exact representative URL corpus.

## Core event chain

`scan_submitted → scan_finished → scene_first_frame → hero_fact_visible → reveal_completed → share_intent → shared_result_viewed → new_scan_started`

Primary product metrics:

- **Time to meaningful reveal:** `hero_fact_visible − scan_submitted`, reported at p50 and p90.
- **Viral handoff:** new scans started from shared results ÷ unique shared-result viewers.

Exports, link copies, and native-share invocations are **share intent**, not proof of a published post.
