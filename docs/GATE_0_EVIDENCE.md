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
| Geometry captured within 1 CSS pixel from deterministic pages | `fixtures/browser/`, `python scripts/verify_browser_fixtures.py` | Pass: 23 hand-marked rectangles across 3 live pages |
| Received-byte totals captured within 2% from deterministic resources | Fixture server wire ledger + CDP extraction in `python scripts/verify_browser_fixtures.py` | Pass: exact wire-byte equality; declared payload within 2% |
| Browser base candidate selection and exact element/resource attribution | `scanner/browser_probe.py`, deterministic inclusion/exclusion, redaction, duplicate-link, and page-level assertions | Pass for Gate 0 fixtures: all elements inspected, 5 exclusion controls, 1 partial-viewport control, 6 exact element links; stylesheets/fonts/scripts/fetches page-level |
| Browser-driven `perceptual-region-v1` aggregation | High-candidate-count browser fixture | Missing |
| Redirect, cache, service-worker, interstitial, and unknown-byte behavior | Browser integration fixtures | Missing |
| Private-network, DNS-rebinding, redirect-pivot, method, limit, and secret rejection | Automated scanner security suite | Partial: 10 method/scheme/credential/literal-host policy cases and 5 fixture-boundary cases pass; browser egress and remaining cases missing |
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
Validated controlled Chromium 140.0.7339.16 against 3 deterministic browser fixtures.
  clean: 11/23 candidates, 2 exact element links, 5 requests, 180770 exact CDP/wire bytes
  image-heavy: 11/18 candidates, 3 exact element links, 7 requests, 5201071 exact CDP/wire bytes
  third-party: 9/19 candidates, 1 exact element links, 8 requests, 1161260 exact CDP/wire bytes
Validated deterministic node and attribution fingerprints across a repeated capture.
Validated 10 request-policy cases and 5 fixture-boundary cases.
```

## Next proof-producing slice

Extend the browser suite with `perceptual-region-v1` aggregation, redirect hops/pivots, cold-cache and service-worker accounting, a never-settling page, blocked unsafe methods, private subresources, interstitials, and broader secret canaries. Add a production-shaped URL/DNS/egress boundary only after the implementation stack is explicitly selected or delegated; the loopback host mapping in the current proof is not that boundary.
