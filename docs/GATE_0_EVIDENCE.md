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
| Geometry captured within 1 CSS pixel from deterministic pages | `fixtures/browser/`, `python scripts/verify_browser_fixtures.py` | Pass: 31 hand-marked rectangles across 7 live pages |
| Received-byte totals captured within 2% from deterministic resources | Fixture server wire ledger + CDP extraction in `python scripts/verify_browser_fixtures.py` | Pass: exact wire-byte equality; declared payload within 2% |
| Browser base candidate selection and exact element/resource attribution | `scanner/browser_probe.py`, deterministic inclusion/exclusion, redaction, duplicate-link, and page-level assertions | Pass for Gate 0 fixtures: all elements inspected, 5 exclusion controls, 1 partial-viewport control, 8 exact element links; stylesheets/fonts/scripts/fetches page-level |
| Browser-driven `perceptual-region-v1` aggregation | `scanner/aggregation.py`, 720-tile live browser fixture, and `python scripts/verify_browser_fixtures.py` | Pass for budget reduction: 723 candidates → 650 regions, 73 unique aggregate members, deterministic preorder cutoff; remaining aggregation edge cases stay open |
| Redirect hop identity and final-page party basis | Cross-host browser fixture, CDP chain extraction, and schema/semantic assertions | Pass for fixture: ordered 302 → 307 → 200 document resources, predecessor links, exact wire bytes, party recalculation against `final.test`, and query-canary absence from stored and fixture-ledger evidence |
| Cache source behavior | Mixed-cache browser fixture + server ledger | Pass: sequential fetches classify network then cache, cache bytes remain measured zero, and the asset reaches the origin once |
| Service-worker source and accounting boundary | Secure-origin browser fixture + partial-record assertions | Partial: worker response classifies as service-worker and never reaches origin; page-session CDP omits the separately fetched worker script, so request-count and total-byte claims are invalidated until worker-target capture exists |
| Interstitial, timeout, and unknown-byte behavior | Browser integration fixtures | Missing |
| Private-network, DNS-rebinding, redirect-pivot, method, limit, and secret rejection | Automated scanner security suite | Partial: 10 request-policy cases, 5 fixture-boundary cases, and 5 browser-enforced redirect rejections pass; production DNS/egress, rebinding, private subresources, and remaining cases missing |
| Residual anonymous-GET risk, honest scanner identity, robots/owner opt-out, scan dedupe, and per-origin cooling | Approved policy + unsafe-GET integration fixture | Open decision and missing test |
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
Validated controlled Chromium 140.0.7339.16 against 7 deterministic browser fixtures.
  clean: 11 candidates -> 11 regions (0 aggregated), 2 exact element links, 5 requests, 180770 exact CDP/wire bytes
  image-heavy: 11 candidates -> 11 regions (0 aggregated), 3 exact element links, 7 requests, 5201071 exact CDP/wire bytes
  third-party: 9 candidates -> 9 regions (0 aggregated), 1 exact element links, 8 requests, 1161260 exact CDP/wire bytes
  aggregation: 723 candidates -> 650 regions (73 aggregated), 0 exact element links, 2 requests, 100315 exact CDP/wire bytes
  redirect: 5 candidates -> 5 regions (0 aggregated), 2 exact element links, 6 requests, 81073 exact CDP/wire bytes
  cache: 3 candidates -> 3 regions (0 aggregated), 0 exact element links, 3 requests, 130340 exact CDP/wire bytes
  service-worker: 3 candidates -> 3 regions (0 aggregated), 0 exact element links, 2 requests, 35158 exact CDP/wire bytes
Validated deterministic node, redirect, and attribution fingerprints across repeated captures.
Validated 10 request-policy cases and 5 fixture-boundary cases.
Validated 4 transfer-source priority cases.
Validated 3 aggregation safety guards.
Validated 5 browser-enforced redirect rejection cases.
Validated 1 redirect-chain negative control.
```

## Next proof-producing slice

Attach and deduplicate service-worker targets so their requests can be counted, then extend the browser suite with a never-settling page, unknown-byte response, blocked unsafe methods, private subresources, interstitials, broader secret canaries, and aggregation edge cases such as wrapper collapse and a truthful mandatory-overflow fallback. The reducer currently refuses mandatory overflow rather than emitting an over-budget record. Add a production public-DNS/egress boundary only after the implementation stack is explicitly selected or delegated; the loopback fixture proxy is not that deployment boundary.
