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

Current status: **in progress, foundational extraction proof passed but scanner proof incomplete**. Thirty-one live deterministic pages now prove base candidate filtering, 57 marked rectangles within 1 CSS pixel, twelve exact image-element links—including reused URLs—with stylesheets/fonts/scripts/fetches left page-level, selector redaction, stable structural fingerprints, exact CDP-to-admitted-wire byte accounting, the quiet-window mutation reset, third-party domain grouping, ordered cross-host redirects classified against the final page, and privacy-safe popup/download containment. One adversarial page records one popup and two downloads—one initiated by the main page and one from the popup—while retaining no URL, window name, filename, or body and leaving no auxiliary page open; a second run lowers the combined observation cap to one, saturates the typed counts, and becomes an explicit partial `resource-limit` record while still denying the later events. The probe stops DOM inspection and retained geometry candidates at explicit deterministic boundaries; two live fixtures reproduce the retained prefix, become partial with `resource-limit`, and disclose every affected interpretation instead of presenting truncation as a complete scene. Network-limit fixtures prove inclusive request, per-response byte, and total received-byte boundaries at local egress, including all three limits on the main document: the triggering request is not contacted or the oversized response is not relayed, admitted bytes stay bounded to the configured allowance plus one detection byte, synthetic 509 responses remain distinct from a genuine target 509, direct origin marker forgery, and a browser-level service-worker replay. Repeated sanitized URLs retain exact blocked-occurrence provenance, affected claims are suppressed, and each evidence fingerprint repeats deterministically. Every block receives an independent random identifier; the first matching CDP occurrence consumes it, origin copies are removed, later browser replays remain page-controlled, and no identifier persists in normalized evidence.

Aggregation evidence covers a deterministic 723-candidate → 650-region reduction with 73 preserved member IDs, two same-footprint evidence-free wrapper collapses with parent rewiring, and a 654-mandatory-candidate fallback that renders exactly 650 objects while retaining all four overflow nodes—including an exact-linked image—as inspectable evidence. The mapping registry defines a complete hero comparator and the live scanner deterministically selects three evidence-backed heroes while leaving twenty-eight no-standout/interstitial fixtures without manufactured claims; a separate pure suite proves threshold, coverage, limitation, exact-attribution, and hostile-copy boundaries. Cache, service-worker, continuous-churn, unfinished-response, login-wall, final-document HTTP-error, storage-isolation, request-policy, anonymous-GET, header-stripping, popup/download, and redirect-rejection fixtures retain the previously recorded evidence and deterministic repeat checks.

A deployment-neutral destination-policy seam now re-parses and independently resolves initial, redirect, and subresource destinations. Its deterministic corpus covers 51 public/forbidden IPv4 and IPv6 addresses, 29 malformed or unsafe URLs, seven resolver failure modes, answer-count limits, same-family and mixed-family public/private answers, and a same-host public-to-private rebinding sequence rejected before connector contact. It returns validated addresses that a future connector can pin; the current callback proof cannot enforce how that connector opens its socket. This is policy proof, not production DNS, HTTPS tunneling, or network-namespace enforcement.

The deployment-neutral public-scan transport now makes initial-target validation a prerequisite for worker construction, carries the ephemeral address grant into the launch seam, runs the worker under the proven process supervisor, and returns a record only after strict envelope, scan-schema, semantic, and requested-target admission. Redirects and subresources use a separate connector seam that receives only a freshly validated destination. Its negative matrix proves no worker launch on all 29 target-policy cases, seven DNS failures, or a rebound private answer, and no admitted result for launch/setup failures, crashes, timeouts, stale nonces, oversized/nonregular artifacts, malformed envelopes, invalid records, or a valid record for the wrong target. It does not prove that a future connector pins its sockets or that deployment egress contains a compromised browser.

Gate 0 still needs the proven destination and request/byte semantics—including transient service-worker bootstrap observations—integrated with a selected production resolver and public-egress boundary, the locally bound supervisor/capture contract adopted by the production API/queue worker and disposable-container kill, defensible consent/challenge handling, an approved published scanner identity/robots/opt-out policy, durable distributed rate enforcement, and a launch retention/deletion decision. The local worker fixture now has complete bootstrap byte coverage when correlation is unique; ambiguity deliberately remains an explicit instrumentation limitation.

Pivot rule: if the concept requires invented causality to feel dramatic, remove that layer. The minimum honest product is Structure + transferred Weight + external requests.

The Gate 0 TCP/TLS origin connector now uses only approved numeric addresses,
checks the connected peer, and preserves hostname/SNI/certificate verification
under one connection/handshake timeout. Its network-free verifier checks pinning,
rejected grants, TLS failures, fallback, and cleanup. One public TLS handshake
succeeded on 2026-10-05. Browser proxy integration, request/byte enforcement,
production resolution, and container egress remain required before public scans.

The bounded origin exchange now applies anonymous header policy, raw HTTP byte
budgets, strict response framing, redirect DNS revalidation, and a socket I/O
deadline over that connector. Its deterministic adversarial suite and one real
HTTPS HEAD smoke test are recorded in `docs/ORIGIN_EXCHANGE.md`. Browser HTTPS
interception, request/block-ledger integration, service-worker coverage, bounded
production DNS, and independent egress enforcement remain open.

The browser HTTPS proxy now terminates CONNECT locally and checks tunnel Host,
TLS SNI, and decrypted request Host before using the bounded origin exchange.
Real Chromium evidence covers document/script/service-worker requests, private
redirect denial, byte caps, authority pivots, and stalled-socket teardown.
See `docs/BROWSER_EGRESS_PROXY.md`. Certificate issuance, capture-probe ledger
integration, bounded resolver/issuer execution, and independent container egress
still block production scanning.

Gate 3 broker checkpoint: `docs/ORIGIN_BROKER_RPC.md` records a bounded per-scan
Unix RPC and actual Chromium process-pair fixture. The broker owns grants, DNS,
pinning and wire budgets; every call checks exact full-grant binding, and initial
binding precedes fetch/tunnel operations. This is still same-UID, same-container,
reserved-origin proof. Separate identities/mount policy, real public egress,
durable recovery, parser and production adoption gates remain open.

The follow-up `docs/CONTAINER_BROKER_BOUNDARY.md` checkpoint demonstrates actual
Chromium capture with different broker/worker container UIDs and a fresh named
volume mounted read-only by the worker. Permission and credential canaries prove
worker mutation/private-file access denial and no origin/DNS activity for denied
clients. This remains reserved-origin fixture evidence: a startup-inclusive
trusted pair supervisor, durable recovery and public broker egress are not yet
implemented or production-adopted.

`docs/PAIR_SUPERVISOR.md` now records that trusted pair-supervisor checkpoint:
the existing transport admits actual fixture capture only after a shared
startup-through-cleanup lease, broker report and exact container/volume teardown.
Four native cases passed within 15 seconds, including live-renderer timeout and
credential rejection. Durable controller-death/orphan recovery, independent
cgroup-empty proof, actual public broker egress and production API adoption still
remain open; fixture timings are not public-corpus latency evidence.

The `docs/LEASE_JOURNAL.md` checkpoint adds content-free durable intent/ID/removal
records to the pair lease, local OS ownership locking, bounded SQLite storage and
fail-closed state dependencies. Journal owner termination/lock handoff and actual
journal fault injection are verified; a replacement Docker reaper, automatic
watchdog and real controller-crash cleanup evidence are still required. Public
scanning remains disabled rather than treating journal persistence as recovery.

The `docs/LEASE_RECOVERY.md` checkpoint implements the operator-only replacement
pass with full runtime readback and 18 actual-journal simulated-daemon cases.
Automatic watchdog deployment and native controller-death proof remain open;
initial Docker capture attempts on 2026-10-08 timed out and are not counted as passes.

`docs/PAIR_LATENCY.md` records the subsequent responsive listener teardown fix
and reuse of the existing broker cleanup engine proof. A fresh four-case native
pair matrix, idle/active listener tests and filesystem canaries pass on a separate
code-overlay image. Containment and measurement limits are unchanged; production
runtime adoption, controller-death recovery and independent emptiness remain open.

`docs/CONTROLLER_CRASH_RECOVERY.md` now proves one actual Chromium/controller-tree
kill and replacement-owner recovery on Windows/Docker Desktop. The host Job is
empty while the owned Linux worker is positively observed running; the replacement
then removes the exact resources and resolves the durable lease without a result.
Automatic watchdog deployment, broader native crash/race coverage and independent
Linux cgroup emptiness remain open. This does not prove the original 15-second
bound under controller death or enable arbitrary public scanning.

`docs/RECOVERY_SCHEDULING.md` verifies multi-lease cursor fairness, mixed eligibility,
outage/budget retention and strict daemon-number parsing with actual journals and
simulated daemons. It establishes a scheduler contract, not a deployed watchdog
or native multi-lease/outage proof. Watchdog ownership, restart/cursor behavior
and native overall controller-death bounds remain required.

`docs/RECOVERY_POLLER.md` adds existing-authority-only, single-journal polling,
typed busy ownership, pinned runtime/file identities, bounded retry health and
an independent-process native fixture. It does not install a service, displace
live owners, persist cursors or establish an overall controller-death deadline.
Final native evidence and the remaining deployment gates are tracked there.

`docs/RECOVERY_CURSOR.md` subsequently persists the poller's runtime-bound cursor
in the existing private journal. Transaction rollback, owner process death and
simulated restart fairness are verified. Native watchdog restart, service/registry
deployment and overall controller-death deadline enforcement remain open.

## Gate 1 — Visual proof with deterministic fixtures

**Question:** Does truthful data produce a legible and desirable physical world?

Current status: **interactive local visual proof implemented and independently reviewed `ship`**. The approved **Instrument Panorama** reference and `docs/VIEWER_CONTRACT.md` define the spatial contract. One React/Three.js renderer consumes all three validated bundles and implements Structure, Weight, Origins, selection, isolation, evidence, replay, scrub, bounded orbit, reduced-motion stepping, text fallback, deterministic capture routes, and frame/object instrumentation. Automated browser checks prove those paths. Target-laptop frame benchmarks and the 10-person comprehension/desirability study remain exit evidence; headless SwiftShader measurements are labeled as software rendering and are not substituted for that hardware proof.

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

Current status: **authored local reveal implemented; human and platform evidence still open**. The viewer reproduces the five deterministic stages, replay and scrubbing, reduced-motion stepping, and exact hero-fact binding across all three fixtures. Automated browser checks cover the timing/state contract. Target-hardware timing, the 10-person comprehension test, the 360-pixel feed-preview check, and a current X recompression test remain required exit evidence.

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

Current status: **local anonymous job/publication proof implemented; arbitrary public scanning remains deliberately disabled**. A transport-backed seeded API now admits three exact HTTPS fixtures, crosses the scanner worker and validation boundaries, exposes bounded queued/running/ready/rejected/failed jobs, publishes immutable ETag-bound viewer bundles, and serves restart-stable result routes from a staged local file store. Eligible results also publish a server-controlled, no-network Chromium poster sidecar before the JSON commit envelope; it is a strict 1080 × 1080 RGBA non-interlaced PNG with exact manifest SHA/length binding and verified GET/HEAD/304 delivery. Browser-minted no-login deletion, keyed-digest storage, tombstoned result-ID retirement, 24-hour engineering retention, exact reuse, expiry recovery, concurrency bounds, target correlation, admission cooling, content-free misses, and honest `scanner-disabled` rejection are verified. Production work still requires address-pinned HTTPS egress, process/container isolation, distributed storage and rate limits, an approved retention/takedown policy, scanner identity and opt-out policy, and the representative 100-URL corpus.

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

Gate 3 containment checkpoint: the guarded Linux capture worker now launches
actual Chromium through the fixed proxy bridge and user/network/PID namespace
wrapper. Native integration evidence covers normal HTTPS/service-worker capture
(3,694 / 3,477 ms), live-browser timeout (14,518 / 14,504 ms), distinct browser network namespace,
and parent-owned relay/scan-file cleanup. See `docs/EGRESS_CAPTURE_WORKER.md` and
`docs/BROWSER_NAMESPACE.md`. Deployment identity/runtime integrity, whole-worker resource
bounds, patched deployment images, API/queue adoption and public-corpus evidence
remain open; arbitrary public scanning is still disabled.

The subsequent Gate 3 checkpoint adopts an explicit private browser filesystem root:
read-only runtime mounts, detached old root, a bounded private NSS snapshot,
private IPC, only the fixed proxy socket, and scoped browser profile/data paths.
Native canaries deny host files and unrelated Unix sockets, including a deeper
user-namespace attempt to unlock runtime mounts. Actual Chromium capture,
timeout/profile cleanup and six direct-network bypass denials pass; see
`docs/BROWSER_FILESYSTEM.md`. Immutable patched images, separate broker/worker
identities, whole-worker cgroup/disk bounds and public-corpus/deployment evidence
remain required. This is not public-scan enablement.

The local Docker resource checkpoint now exercises seven disposable Python probes
under Docker Desktop's Linux/cgroup-v2 engine: configured limits, actual CPU
throttling, fork rejection, tmpfs saturation, and kernel OOM kill, plus stopped
container observations after detached normal/forced exits. It uses no networking,
host mounts or privileges and removes only invocation-owned test containers.
See `docs/CONTAINER_RESOURCE_PROOF.md`. This is native quota evidence, not scanner
adoption or independent detached-descendant/cgroup-empty proof; those boundaries
and actual Chromium budgets remain open. Arbitrary public scanning stays disabled.

The next Gate 3 checkpoint runs actual sandboxed Chromium capture in a baked,
non-root, read-only Docker fixture with no network/host mounts, one CPU, 1 GiB/no
swap and 128 tasks. Complete capture, live-renderer filter observations, timeout
without admission, six direct-network bypass denials and scoped cleanup pass.
A read-only launcher allows non-executable scratch, including the inner mounts;
an empty browser sbin directory avoids Docker's locked init submount without a
recursive fallback. See `docs/CONTAINER_CAPTURE_FIXTURE.md`. The historical
browser and broad inherited fixture filter are not production-approved; trusted
engine-side launcher/result transfer, independent teardown, patched image,
identity/egress/API adoption and public-corpus proof remain open.

A trusted Docker launch/result checkpoint now transfers a bounded grant and
fresh nonce over stdin and accepts capped stdout only after exact owned-container
stop/removal checks. Native actual capture, live-renderer timeout, crash,
wrong-nonce, trailing/duplicate JSON, oversized output and stderr-flood cases
exercise the explicit transport provider. No process fallback or public API
enablement is introduced. See `docs/DOCKER_WORKER_TRANSPORT.md`. This closes the
fixture-only engine launch/result seam; production image/filter review,
restricted broker connectivity, durable orphan recovery, independent
descendant/cgroup-empty teardown, and public scanner adoption remain open.

The next runtime candidate pins Playwright 1.63.0 / Chromium 153.0.8010.12 in a
separate image, with official PyPI-verified hash locks and an immutable runtime
manifest that checks package/browser versions before page contact. The old 140
fixture remains for comparison; no visitor can select a runtime or disable its
pin. See `docs/RUNTIME_CANDIDATE.md`. Current-image testing does not replace
vulnerability/kernel review, reproducible OS locking, patch maintenance,
production syscall-policy review or public scanner adoption.
Seven native suites (including 31 sandboxed measurement fixtures) and twelve
transport cases pass on the current candidate; historical transport compatibility
also passes. An incorrect browser pin is rejected before origin connector contact.

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

Current status: **trusted local poster/video publication and truthful dual-format
share preview implemented; Gate 5 remains open**.
`result-manifest-v0.1.0` deterministically binds an opaque result path, scan
record, mapping registry, scene manifest, exact hero sentence and numeric
evidence, limitation disclosure, and bounded poster/video targets. The seeded
API exposes immutable ETag-bound bundles and restart-stable `/r/{resultId}`
routes consumed by the viewer; the creating browser can delete through a
separate unshared capability, while retired IDs are tombstoned. Published
artifact-eligible results offer a protected still/motion preview, product-owned
caption and link controls, a server-controlled no-network Chromium 1080 × 1080
RGBA PNG, and a deterministic five-stage 1080 × 1080 H.264 MP4 with exactly five
seconds, 30 fps, 150 frames, and an 8 MB ceiling. The manifest binds each
artifact's exact SHA-256, byte length, and source hashes; the browser
independently verifies same-origin route,
status/final URL/type/ETag/length/signature/SHA before preview or download.
Motion failure falls back to the verified poster, and reduced-motion visitors
are never forced into autoplay. A durable provider-neutral delivery reference
proves private object keys, object-before-live activation, origin fencing,
pending purge recovery, exact coverage receipts, and tombstoned non-reuse while
refusing shared caching without a purger. AWS S3 plus DynamoDB control state and
CloudFront is the selected delivery shape. Credential-free adapters prove
private conditional S3 creation with exact-version readback/permanent deletion,
DynamoDB table/TTL preflight and full-identity conditional lifecycle state with
exact-millisecond visibility/permanent tombstones, and exact CloudFront variant
coverage with idempotent `Completed`-only confirmation. The composite
`ResultBackend` now coordinates deletion HMACs, exact-version S3 objects, and
DynamoDB control transitions; the DynamoDB GSI also discovers retiring and
retired cleanup work for retries after restart. Its fake-provider verifier is
local contract evidence. The live API remains honestly `no-store`, and the
composite is now selectable with `--result-backend composite` or
`DOM_XRAY_RESULT_BACKEND=composite`. Startup requires the strict deletion
keyring and explicit retention, and fails closed rather than falling back to
filesystem storage. The runtime fixes cache policy to `no-store` and configures
no CloudFront purger. These proofs do not establish deployed AWS/IAM behavior,
live multi-writer contention, or warmed-edge and in-flight stale-fill purge
behavior. A read authorized before the retirement fence may finish after it;
new staged publications now have indexed abandonment and cleanup recovery.
Pre-control upload orphans and legacy staged-record recovery remain operational
gaps. Local
validators, renderer
supervision, a 15/15 deterministic video run (5.317 s p50, 6.723 s max), and
real-browser exact-byte downloads prove the current controlled path. The
deployed S3/DynamoDB behavior,
a warmed-cache and in-flight-fill purge drill, current X web/mobile upload and
recompression, representative production benchmarks, and share instrumentation
remain unfinished.

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
- Current open decisions: production deployment and isolation target, distributed storage plus public retention/takedown policy, scanner identity and opt-out policy, and the exact representative URL corpus. The implementation stack is React, TypeScript, Vite, Three.js, and React Three Fiber; **Instrument Panorama** is the approved implementation reference.

## Core event chain

`scan_submitted → scan_finished → scene_first_frame → hero_fact_visible → reveal_completed → share_intent → shared_result_viewed → new_scan_started`

Primary product metrics:

- **Time to meaningful reveal:** `hero_fact_visible − scan_submitted`, reported at p50 and p90.
- **Viral handoff:** new scans started from shared results ÷ unique shared-result viewers.

Exports, link copies, and native-share invocations are **share intent**, not proof of a published post.
