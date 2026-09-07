# Gate 0 Evidence Ledger

Last updated: 2026-09-07

Gate status: **in progress**

This ledger prevents documentation volume from being mistaken for completion. A row passes only when its named evidence exists and is verifiable in the current Git state.

| Requirement | Authoritative evidence | Status |
|---|---|---|
| Public/no-login exploration scope and V1 exclusions | `PRODUCT.md` | Pass |
| Goal gates, metrics, and pivot rules | `ROADMAP.md` | Pass |
| Allowed measurements, claims, attribution, and missing-data behavior | `docs/TRUTH_CONTRACT.md` | Pass as contract; implementation unproven |
| Versioned scan record encodes the three target archetypes | `docs/SCAN_RECORD.schema.json`, `fixtures/scan/*.json` | Pass |
| Cross-record provenance, five distinct node-count meanings, parent acyclicity, party/domain consistency, auxiliary-event bounds, hero rules, and negative mutations | `python scripts/validate_fixtures.py` | Pass: 3 fixtures + 15 negative controls |
| Versioned semantic-to-scene formulas and reveal timing | `docs/MAPPING_REGISTRY.md`, `docs/MAPPING_REGISTRY.v0.1.json` | Pass as prototype contract |
| Mapping monotonicity, deterministic fixture transforms, object cap, explicit bus/hub placement, unknown states, and five-second duration | `python scripts/validate_mapping.py` | Pass: 3 fixtures + 7 negative controls |
| Executable renderer-neutral scene topology and evidence handoff | `scanner/scene_manifest.py`, `docs/SCENE_MANIFEST.md`, `python scripts/verify_scene_manifest.py` | Pass for the deterministic handoff: all 3 fixtures use one mapper; stable fingerprints cover exact geometry, mass, page-bus and sorted right-arc hub endpoints, evidence-only exclusion, hero binding, and distinct known/cache/worker/unknown/blocked transfer states; 7 negative controls fail closed. The static fixture audit also removed four wholly off-viewport nodes that had contradicted the viewport-candidate contract. |
| Deterministic hero selection and claim suppression | `scanner/insights.py`, `python scripts/verify_insights.py`, live browser assertions | Pass: complete comparator, four enabled evidence candidates, neutral fallback, exact-attribution and 90% known-value boundaries, limitation suppression, hostile-copy independence, 3 positive browser outcomes, and 28 no-standout/interstitial outcomes |
| Fixed browser/capture protocol | `docs/CAPTURE_PROTOCOL.md`, `scanner/browser_probe.py` | Partial implementation proven on local deterministic pages |
| Public-destination URL/DNS policy seam | `scanner/destination_policy.py`, `python scripts/verify_destination_policy.py` | Pass as a deployment-neutral policy primitive: 51 public/forbidden addresses, 29 malformed or unsafe URLs, 7 resolver failure modes, independent initial/redirect/subresource resolution, same-family and mixed-family answer rejection, bounded answer collection, content-free errors, validated address sets available for future connector pinning, and same-host public-to-private rebinding rejection before connector contact. The seam is not wired into the fixture browser/proxy because neither can provide address-pinned public HTTPS; production parser/resolver selection, connector integration, HTTPS forwarding, and network-namespace enforcement remain open. |
| Scanner threat model and release-blocking controls | `docs/THREAT_MODEL.md` | Pass as model; automated controls unproven |
| Privacy-minimized product telemetry and primary metric formulas | `docs/TELEMETRY.md` | Pass as contract; instrumentation unproven |
| Geometry captured within 1 CSS pixel from deterministic pages | `fixtures/browser/`, `python scripts/verify_browser_fixtures.py` | Pass: 57 hand-marked rectangles in the 31-fixture live-browser suite |
| Received-byte totals captured within 2% from deterministic resources | Fixture server/proxy wire ledgers + CDP extraction in `python scripts/verify_browser_fixtures.py` | Pass for resources with canonical byte evidence: exact wire-byte equality and declared payload within 2%; uniquely correlated service-worker bootstraps use the named CDP-plus-egress rule, while ambiguous observations remain unknown |
| Browser base candidate selection and exact element/resource attribution | `scanner/browser_probe.py`, deterministic inclusion/exclusion, redaction, duplicate-link, and page-level assertions | Pass for Gate 0 fixtures: all elements inspected on uncapped pages, a separately proven bounded prefix on the capped page, 5 base exclusion controls, 1 partial-viewport control, and 12 exact element links; stylesheets/fonts/scripts/fetches remain page-level, including a worker fetch sharing a URL with an exactly linked page image |
| Browser-driven `perceptual-region-v1` aggregation | `scanner/aggregation.py`, three live browser aggregation fixtures, and `python scripts/verify_browser_fixtures.py` | Pass: 723 candidates → 650 regions with 73 unique members and deterministic cutoff; two evidence-free wrappers collapse with correct parent rewiring; 654 mandatory candidates → 650 scene objects plus 4 complete evidence-only records, preserving an omitted exact image link under an explicit partial/resource-limit state |
| Redirect hop identity and final-page party basis | Cross-host browser fixture, CDP chain extraction, and schema/semantic assertions | Pass for fixture: ordered 302 → 307 → 200 document resources, predecessor links, exact wire bytes, party recalculation against `final.test`, and query-canary absence from stored and fixture-ledger evidence |
| Cache source behavior | Mixed-cache browser fixture + server ledger | Pass: sequential fetches classify network then cache, cache bytes remain measured zero, and the asset reaches the origin once |
| Service-worker source and accounting boundary | Secure-origin browser fixture + page/worker CDP sessions + egress observation ledger | Pass for the deterministic boundary: worker-produced client response classifies as service-worker and never reaches origin; the worker-owned origin fetch is captured once with exact bytes and target-qualified identity; same-URL page/worker requests stay distinct and only the page image is element-attributed; a uniquely matched `serviceworker` egress observation supplies the bootstrap's exact delivered wire bytes, producing a complete five-request record with zero missing values; ambiguous, missing, pending, blocked, and malformed observations remain unknown |
| Bounded settling and unknown-byte behavior | Never-settling and unfinished-response browser fixtures | Pass: DOM churn and active qualifying requests independently reach the two-second fixture hard stop; both preserve partial geometry, while the unfinished response remains unknown/`null`, receives a resource-scoped limitation, and is never retried |
| Bounded DOM inspection and geometry-candidate collection | DOM-limit and candidate-limit browser fixtures, repeated deterministic fingerprints, and schema limit vocabulary | Pass: first 40 of a larger DOM are inspected while the exact raw count remains visible; first 12 of a larger qualifying set are retained independently; both become explicit partial `resource-limit` records and enumerate the interpretations made incomplete |
| Bounded request and response transfer at local egress | Subresource and main-document request-limit, response-byte-limit, and total-byte-limit fixtures; proxy admitted-byte ledger; repeated fingerprints | Pass for the deterministic proxy: the inclusive triggering request never reaches origin; oversized responses are read only through one detection byte and are not relayed; total admitted wire bytes are exact; independently random per-block IDs preserve exact limited occurrences even when sanitized URLs repeat; origin marker headers are stripped; first-use consumption defeats a live same-origin service-worker replay; and no ID persists in normalized evidence. All limits emit partial `resource-limit` records, disclose configured boundaries, suppress affected claims, and reproduce on repeat. Production egress remains unproven. |
| Whole-worker deadline and transport eligibility | `scanner/worker_supervisor.py`, Chromium-owning post-capture hang fixture, `fixtures/worker/capture_worker_fixture.py`, `python scripts/verify_worker_deadline.py`, `python scripts/verify_capture_worker.py` | Partial but materially advanced: a 15-second outer ceiling includes a reserved termination tail; only a fresh regular ≤4 MB nonce-scoped JSON envelope after zero exit proceeds to schema validation; Windows workers are contained before resume; two timed-out process fixtures commit no result and leave no recorded Chromium descendants. The real Gate 0 probe now runs inside a fixture worker with exact typed configuration. Eligible complete, byte-limited, service-worker, and never-settling records pass schema plus semantic validation at the caller, a clean record repeats deterministically, malformed config is rejected, and a real post-capture hang publishes no result. The local capture boundary passes; production API/queue and disposable-container integration remain open. |
| Interstitial behavior | HTTP 200 login wall, terminal 404/503/509 pages, forged-marker origin 509, synthetic main-document 509 limits, 200 + subresource-404 negative fixture, and 13 classifier guards | Pass for structural login and direct HTTP error classes: preserves measured orientation geometry, emits no insight for interstitials, makes no form submission, retains no form values, ignores subresource-only errors, distinguishes genuine and forged-marker target 509s from instrument-generated limit responses, and reproduces the same status/limitation; consent and challenge remain intentionally open because current structural signals are ambiguous |
| Cross-scan storage isolation | Repeated fresh-context fixture with local/session/cookie sentinels | Pass: the later scan sees none of the earlier scan's local storage, session storage, or cookie state and reproduces the same evidence fingerprint |
| Popup and download containment | Normal and one-event-limit auxiliary fixtures; content-bearing canaries; repeated fingerprints | Pass for the deterministic browser harness: one popup is synchronously closed, handlers cover every created page, and downloads initiated by both the main page and popup are synchronously cancelled. No auxiliary page remains at capture, and popup URL/window-name plus download URL/filename canaries do not enter normalized or fixture-ledger evidence. A lowered combined cap saturates typed counts, remains content-free, produces an explicit partial `resource-limit` record, and repeats deterministically. Production browser/container isolation remains a separate gate. |
| Private-network, DNS-rebinding, redirect-pivot, method, limit, and secret rejection | Automated scanner security suite | Partial: the resolver-injected policy covers 51 public/forbidden addresses, 29 malformed or unsafe URLs, 7 DNS failure modes, mixed answers, and public-to-private rebinding before connector contact; 20 request-policy cases, 5 fixture-boundary cases, 5 browser-enforced redirect rejections, 4 live unsafe-method/literal-private-subresource blocks, deterministic DOM/candidate/request/byte caps, and 10 unsafe-GET canaries also pass. Private URLs stay out of normalized evidence, sensitive outbound headers are stripped at egress, request-cap targets are not contacted, and oversized responses are not relayed. The live fixture scanner still has no hostname-resolution boundary; production resolver/egress integration, address-pinned HTTPS, production quota integration, production-container deadline enforcement, and remaining cases are missing. |
| Residual anonymous-GET risk, honest scanner identity, robots/owner opt-out, scan dedupe, and per-origin cooling | `scanner/admission_policy.py`, unsafe-GET browser fixture, fixture ledgers | Partial: one state-changing GET reaches origin once under an explicit fixture user-agent; exact-result reuse and same-origin cooling make no second contact under an injectable clock. Production durations, durable/distributed enforcement, published identity, robots policy, and owner opt-out remain open decisions |
| Retention, deletion, consent, moderation, and takedown policy | Approved product/legal decision and implementation test | Open decision |

## Reproduce current passing evidence

```sh
python scripts/validate_fixtures.py
python scripts/validate_mapping.py
python scripts/verify_scene_manifest.py
python scripts/verify_insights.py
python scripts/verify_browser_fixtures.py
python scripts/verify_worker_deadline.py
python scripts/verify_capture_worker.py
python scripts/verify_destination_policy.py
```

Expected output:

```text
Validated 3 fixtures and 15 negative controls against Gate 0.
Validated mapping-v0.1.0 against 3 fixtures and 7 negative controls; reveal duration is 5.0 seconds.
Verified scene-manifest-v0.1.0 across 3 fixtures, one transfer/endpoint matrix, and 7 negative controls; fingerprints: {'fixture-clean': '264c19fe87d40ace', 'fixture-image-heavy': 'b79c3f7b136df4e4', 'fixture-third-party-heavy': 'f209bed602212d37'}.
Validated deterministic hero selection across 3 scan fixtures and 7 boundary cases.
Validated controlled Chromium 140.0.7339.16 against 31 deterministic browser fixtures.
  clean: 11 candidates -> 11 regions (0 aggregated), 2 exact element links, 5 requests, 180770 known CDP/wire bytes, 0 missing-byte requests
  image-heavy: 11 candidates -> 11 regions (0 aggregated), 3 exact element links, 7 requests, 5201071 known CDP/wire bytes, 0 missing-byte requests
  third-party: 9 candidates -> 9 regions (0 aggregated), 1 exact element links, 8 requests, 1161260 known CDP/wire bytes, 0 missing-byte requests
  aggregation: 723 candidates -> 650 regions (73 aggregated), 0 exact element links, 2 requests, 100315 known CDP/wire bytes, 0 missing-byte requests
  redirect: 5 candidates -> 5 regions (0 aggregated), 2 exact element links, 6 requests, 81073 known CDP/wire bytes, 0 missing-byte requests
  cache: 3 candidates -> 3 regions (0 aggregated), 0 exact element links, 3 requests, 130340 known CDP/wire bytes, 0 missing-byte requests
  service-worker: 4 candidates -> 4 regions (0 aggregated), 1 exact element links, 5 requests, 85616 known CDP/wire bytes, 0 missing-byte requests
  service-worker-marker-replay: 5 candidates -> 5 regions (0 aggregated), 0 exact element links, 5 requests, 18767 known CDP/wire bytes, 0 missing-byte requests
  never-settling: 3 candidates -> 3 regions (0 aggregated), 0 exact element links, 1 requests, 25158 known CDP/wire bytes, 0 missing-byte requests
  unknown-byte: 3 candidates -> 3 regions (0 aggregated), 0 exact element links, 2 requests, 25158 known CDP/wire bytes, 1 missing-byte requests
  interstitial: 9 candidates -> 9 regions (0 aggregated), 0 exact element links, 1 requests, 28158 known CDP/wire bytes, 0 missing-byte requests
  http-error-404: 5 candidates -> 5 regions (0 aggregated), 0 exact element links, 1 requests, 24165 known CDP/wire bytes, 0 missing-byte requests
  http-error-503: 5 candidates -> 5 regions (0 aggregated), 0 exact element links, 1 requests, 24175 known CDP/wire bytes, 0 missing-byte requests
  http-error-509: 5 candidates -> 5 regions (0 aggregated), 0 exact element links, 1 requests, 24180 known CDP/wire bytes, 0 missing-byte requests
  spoofed-block-header-509: 5 candidates -> 5 regions (0 aggregated), 0 exact element links, 1 requests, 24180 known CDP/wire bytes, 0 missing-byte requests
  subresource-error: 5 candidates -> 5 regions (0 aggregated), 1 exact element links, 2 requests, 24329 known CDP/wire bytes, 0 missing-byte requests
  storage-isolation: 5 candidates -> 5 regions (0 aggregated), 0 exact element links, 1 requests, 20213 known CDP/wire bytes, 0 missing-byte requests
  policy-boundary: 4 candidates -> 4 regions (0 aggregated), 0 exact element links, 3 requests, 32552 known CDP/wire bytes, 0 missing-byte requests
  unsafe-get: 5 candidates -> 5 regions (0 aggregated), 0 exact element links, 2 requests, 34504 known CDP/wire bytes, 0 missing-byte requests
  auxiliary-events: 5 candidates -> 5 regions (0 aggregated), 0 exact element links, 1 requests, 26158 known CDP/wire bytes, 0 missing-byte requests
  auxiliary-event-limit: 5 candidates -> 5 regions (0 aggregated), 0 exact element links, 1 requests, 26158 known CDP/wire bytes, 0 missing-byte requests
  wrapper-collapse: 7 candidates -> 5 regions (2 aggregated), 1 exact element links, 2 requests, 50305 known CDP/wire bytes, 0 missing-byte requests
  dom-limit: 35 candidates -> 35 regions (0 aggregated), 0 exact element links, 2 requests, 100315 known CDP/wire bytes, 0 missing-byte requests
  candidate-limit: 12 candidates -> 12 regions (0 aggregated), 0 exact element links, 2 requests, 100315 known CDP/wire bytes, 0 missing-byte requests
  request-limit: 5 candidates -> 5 regions (0 aggregated), 0 exact element links, 3 requests, 18538 known CDP/wire bytes, 0 missing-byte requests
  response-byte-limit: 5 candidates -> 5 regions (0 aggregated), 0 exact element links, 3 requests, 18538 known CDP/wire bytes, 0 missing-byte requests
  total-byte-limit: 5 candidates -> 5 regions (0 aggregated), 0 exact element links, 3 requests, 18538 known CDP/wire bytes, 0 missing-byte requests
  request-navigation-limit: 3 candidates -> 3 regions (0 aggregated), 0 exact element links, 1 requests, 223 known CDP/wire bytes, 0 missing-byte requests
  response-navigation-limit: 3 candidates -> 3 regions (0 aggregated), 0 exact element links, 1 requests, 223 known CDP/wire bytes, 0 missing-byte requests
  total-navigation-limit: 3 candidates -> 3 regions (0 aggregated), 0 exact element links, 1 requests, 223 known CDP/wire bytes, 0 missing-byte requests
  mandatory-overflow: 654 candidates -> 650 regions (4 aggregated), 1 exact element links, 2 requests, 90305 known CDP/wire bytes, 0 missing-byte requests
Validated deterministic node, aggregation, redirect, attribution, source, interstitial, and policy fingerprints across repeated captures.
Validated deterministic hero selection on 3 positive and 28 no-standout/interstitial browser fixtures.
Validated bounded DOM inspection and geometry-candidate collection.
Validated enforced request, per-response byte, and total-byte capture boundaries.
Validated 20 request-policy cases and 5 fixture-boundary cases.
Validated 4 transfer-source priority cases.
Validated bounded popup/download observation and immediate containment.
Validated 13 interstitial-classifier safety guards.
Validated 4 aggregation safety guards.
Validated scan reuse and per-origin cooling with an injectable policy clock.
Validated 5 browser-enforced redirect rejection cases.
Validated 4 live unsafe-method/private-subresource blocks.
Validated one unsafe GET, sensitive-header stripping, and ten secret canaries.
Validated 1 redirect-chain negative control.
Validated a 15-second-ceiling worker supervisor, bounded nonce-scoped transport eligibility, repeatable post-capture timeout, and Chromium descendant cleanup.
Validated complete, resource-limited, service-worker, and page-timeout scan records through the supervised capture-worker transport; strict config parsing, deterministic clean evidence, and a real post-capture worker timeout also hold.
Validated 51 public/forbidden addresses, 29 malformed or unsafe URLs, 7 DNS failure modes, and public-to-private rebinding rejection before contact.
```

## Next proof-producing slice

After the application stack is approved, adopt the destination-policy seam in the production API/queue worker, select and pin the shared WHATWG/UTS #46 parser and resolver, and make the HTTPS connector use only each grant's validated addresses behind an independently enforced public-egress boundary. Carry the proven request/byte semantics and transient service-worker bootstrap observations into that same boundary; neither the pure resolver test nor the loopback proxy is deployment containment. Adopt the proven supervisor/capture envelope and make the deployment kill the whole disposable container without relabeling the local OS proof as production containment. Keep consent and challenge handling open until a provider-independent, non-text structural proof can distinguish them from ordinary application modals and iframes; do not ship a guessed classifier. The in-memory admission primitive is not durable rate enforcement. The schema distinguishes inspectable evidence-only nodes from scene-instantiated nodes for mandatory overflow; the eventual viewer must honor `sceneIncluded` rather than rendering every record entry.
