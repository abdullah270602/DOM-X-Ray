# Gate 0 Evidence Ledger

Last updated: 2026-09-05

Gate status: **in progress**

This ledger prevents documentation volume from being mistaken for completion. A row passes only when its named evidence exists and is verifiable in the current Git state.

| Requirement | Authoritative evidence | Status |
|---|---|---|
| Public/no-login exploration scope and V1 exclusions | `PRODUCT.md` | Pass |
| Goal gates, metrics, and pivot rules | `ROADMAP.md` | Pass |
| Allowed measurements, claims, attribution, and missing-data behavior | `docs/TRUTH_CONTRACT.md` | Pass as contract; implementation unproven |
| Versioned scan record encodes the three target archetypes | `docs/SCAN_RECORD.schema.json`, `fixtures/scan/*.json` | Pass |
| Cross-record provenance, five distinct node-count meanings, parent acyclicity, party/domain consistency, hero rules, and negative mutations | `python scripts/validate_fixtures.py` | Pass: 3 fixtures + 12 negative controls |
| Versioned semantic-to-scene formulas and reveal timing | `docs/MAPPING_REGISTRY.md`, `docs/MAPPING_REGISTRY.v0.1.json` | Pass as prototype contract |
| Mapping monotonicity, deterministic fixture transforms, object cap, unknown states, and five-second duration | `python scripts/validate_mapping.py` | Pass: 3 fixtures + 6 negative controls |
| Fixed browser/capture protocol | `docs/CAPTURE_PROTOCOL.md`, `scanner/browser_probe.py` | Partial implementation proven on local deterministic pages |
| Scanner threat model and release-blocking controls | `docs/THREAT_MODEL.md` | Pass as model; automated controls unproven |
| Privacy-minimized product telemetry and primary metric formulas | `docs/TELEMETRY.md` | Pass as contract; instrumentation unproven |
| Geometry captured within 1 CSS pixel from deterministic pages | `fixtures/browser/`, `python scripts/verify_browser_fixtures.py` | Pass: 44 hand-marked rectangles across 14 live pages |
| Received-byte totals captured within 2% from deterministic resources | Fixture server wire ledger + CDP extraction in `python scripts/verify_browser_fixtures.py` | Pass for resources with canonical byte evidence: exact wire-byte equality and declared payload within 2%; the worker bootstrap remains explicit unknown data |
| Browser base candidate selection and exact element/resource attribution | `scanner/browser_probe.py`, deterministic inclusion/exclusion, redaction, duplicate-link, and page-level assertions | Pass for Gate 0 fixtures: all elements inspected, 5 exclusion controls, 1 partial-viewport control, 11 exact element links; stylesheets/fonts/scripts/fetches page-level, including a worker fetch sharing a URL with an exactly linked page image |
| Browser-driven `perceptual-region-v1` aggregation | `scanner/aggregation.py`, three live browser aggregation fixtures, and `python scripts/verify_browser_fixtures.py` | Pass: 723 candidates → 650 regions with 73 unique members and deterministic cutoff; two evidence-free wrappers collapse with correct parent rewiring; 654 mandatory candidates → 650 scene objects plus 4 complete evidence-only records, preserving an omitted exact image link under an explicit partial/resource-limit state |
| Redirect hop identity and final-page party basis | Cross-host browser fixture, CDP chain extraction, and schema/semantic assertions | Pass for fixture: ordered 302 → 307 → 200 document resources, predecessor links, exact wire bytes, party recalculation against `final.test`, and query-canary absence from stored and fixture-ledger evidence |
| Cache source behavior | Mixed-cache browser fixture + server ledger | Pass: sequential fetches classify network then cache, cache bytes remain measured zero, and the asset reaches the origin once |
| Service-worker source and accounting boundary | Secure-origin browser fixture + page/worker CDP sessions + partial-record assertions | Partial but materially advanced: worker-produced client response classifies as service-worker and never reaches origin; the worker-owned origin fetch is captured once with exact bytes and target-qualified identity; same-URL page/worker requests stay distinct and only the page image is element-attributed; bootstrap URL/ownership are recorded but bootstrap bytes remain unknown, invalidating request-count and total-byte claims |
| Bounded settling and unknown-byte behavior | Never-settling and unfinished-response browser fixtures | Pass: DOM churn and active qualifying requests independently reach the two-second fixture hard stop; both preserve partial geometry, while the unfinished response remains unknown/`null`, receives a resource-scoped limitation, and is never retried |
| Interstitial behavior | HTTP 200 login-wall browser fixture + classifier guards | Pass for structural login wall: preserves measured orientation geometry, emits no insight, makes no form submission, retains no form values, and reproduces the same status/limitation; consent, challenge, and error classes remain open |
| Private-network, DNS-rebinding, redirect-pivot, method, limit, and secret rejection | Automated scanner security suite | Partial: 10 request-policy cases, 5 fixture-boundary cases, 5 browser-enforced redirect rejections, 4 live unsafe-method/literal-private-subresource blocks, and 10 unsafe-GET canaries pass; private URLs stay out of normalized evidence, sensitive outbound headers are stripped at egress, and blocked origins are not reached; production DNS/egress, rebinding, and remaining cases are missing |
| Residual anonymous-GET risk, honest scanner identity, robots/owner opt-out, scan dedupe, and per-origin cooling | `scanner/admission_policy.py`, unsafe-GET browser fixture, fixture ledgers | Partial: one state-changing GET reaches origin once under an explicit fixture user-agent; exact-result reuse and same-origin cooling make no second contact under an injectable clock. Production durations, durable/distributed enforcement, published identity, robots policy, and owner opt-out remain open decisions |
| Retention, deletion, consent, moderation, and takedown policy | Approved product/legal decision and implementation test | Open decision |

## Reproduce current passing evidence

```sh
python scripts/validate_fixtures.py
python scripts/validate_mapping.py
python scripts/verify_browser_fixtures.py
```

Expected output:

```text
Validated 3 fixtures and 12 negative controls against Gate 0.
Validated mapping-v0.1.0 against 3 fixtures and 6 negative controls; reveal duration is 5.0 seconds.
Validated controlled Chromium 140.0.7339.16 against 14 deterministic browser fixtures.
  clean: 11 candidates -> 11 regions (0 aggregated), 2 exact element links, 5 requests, 180770 known CDP/wire bytes, 0 missing-byte requests
  image-heavy: 11 candidates -> 11 regions (0 aggregated), 3 exact element links, 7 requests, 5201071 known CDP/wire bytes, 0 missing-byte requests
  third-party: 9 candidates -> 9 regions (0 aggregated), 1 exact element links, 8 requests, 1161260 known CDP/wire bytes, 0 missing-byte requests
  aggregation: 723 candidates -> 650 regions (73 aggregated), 0 exact element links, 2 requests, 100315 known CDP/wire bytes, 0 missing-byte requests
  redirect: 5 candidates -> 5 regions (0 aggregated), 2 exact element links, 6 requests, 81073 known CDP/wire bytes, 0 missing-byte requests
  cache: 3 candidates -> 3 regions (0 aggregated), 0 exact element links, 3 requests, 130340 known CDP/wire bytes, 0 missing-byte requests
  service-worker: 4 candidates -> 4 regions (0 aggregated), 1 exact element links, 5 requests, 75452 known CDP/wire bytes, 1 missing-byte requests
  never-settling: 3 candidates -> 3 regions (0 aggregated), 0 exact element links, 1 requests, 25158 known CDP/wire bytes, 0 missing-byte requests
  unknown-byte: 3 candidates -> 3 regions (0 aggregated), 0 exact element links, 2 requests, 25158 known CDP/wire bytes, 1 missing-byte requests
  interstitial: 9 candidates -> 9 regions (0 aggregated), 0 exact element links, 1 requests, 28158 known CDP/wire bytes, 0 missing-byte requests
  policy-boundary: 4 candidates -> 4 regions (0 aggregated), 0 exact element links, 3 requests, 32440 known CDP/wire bytes, 0 missing-byte requests
  unsafe-get: 5 candidates -> 5 regions (0 aggregated), 0 exact element links, 2 requests, 34504 known CDP/wire bytes, 0 missing-byte requests
  wrapper-collapse: 7 candidates -> 5 regions (2 aggregated), 1 exact element links, 2 requests, 50305 known CDP/wire bytes, 0 missing-byte requests
  mandatory-overflow: 654 candidates -> 650 regions (4 aggregated), 1 exact element links, 2 requests, 90305 known CDP/wire bytes, 0 missing-byte requests
Validated deterministic node, aggregation, redirect, attribution, source, interstitial, and policy fingerprints across repeated captures.
Validated 10 request-policy cases and 5 fixture-boundary cases.
Validated 4 transfer-source priority cases.
Validated 6 interstitial-classifier safety guards.
Validated 4 aggregation safety guards.
Validated scan reuse and per-origin cooling with an injectable policy clock.
Validated 5 browser-enforced redirect rejection cases.
Validated 4 live unsafe-method/private-subresource blocks.
Validated one unsafe GET, sensitive-header stripping, and ten secret canaries.
Validated 1 redirect-chain negative control.
```

## Next proof-producing slice

Extend the browser suite with conservative consent, challenge, and error interstitial classes plus cross-scan storage isolation. Keep investigating a protocol-supported service-worker bootstrap byte signal, but never replace the current unknown with a second fetch or a body-size guess. Add a production public-DNS/egress boundary only after the implementation stack is explicitly selected or delegated; the loopback fixture proxy and in-memory admission primitive are not that deployment boundary. The schema now distinguishes inspectable evidence-only nodes from scene-instantiated nodes for mandatory overflow; the eventual viewer must honor `sceneIncluded` rather than rendering every record entry.
