# DOM X-Ray

DOM X-Ray is a public, no-login website-exploration toy. A visitor pastes a public URL and receives a cinematic 3D cutaway whose geometry and motion are derived from real page-load measurements, then shares one precise, surprising finding.

## North star

> Paste a public URL → receive a beautiful, truthful 3D X-ray and visible hero fact at p90 within 20 seconds for supported successful scans → export one fact worth sharing.

The first release is deliberately not a full developer dashboard, a Lighthouse replacement, or a generic website roast. The spectacle earns attention; inspectable evidence earns trust.

## Current status

Gate 0 is in progress. Product truth, the gated roadmap, and the measurement-to-visual contract are documented, with thirty-one deterministic browser fixtures covering geometry, bounded DOM/candidate collection, transfer evidence, bounded aggregation, policy behavior, popup/download containment, storage isolation, and conservative login/error interstitials. A separate resolver-injected destination-policy proof now covers malformed targets, public/special-use IPv4 and IPv6 answers, mixed DNS sets, and public-to-private rebinding before connector contact. The implementation stack and deployment target remain open decisions, so no application scaffold has been selected yet.

## Project documents

- [PRODUCT.md](PRODUCT.md) — durable product truth and open decisions
- [ROADMAP.md](ROADMAP.md) — goal gates, exit criteria, metrics, and pivot rules
- [docs/TRUTH_CONTRACT.md](docs/TRUTH_CONTRACT.md) — what the experience may visualize and claim
- [docs/SCAN_RECORD.schema.json](docs/SCAN_RECORD.schema.json) — technology-neutral scan record contract
- [docs/CAPTURE_PROTOCOL.md](docs/CAPTURE_PROTOCOL.md) — fixed Chromium observation and measurement rules
- [docs/MAPPING_REGISTRY.md](docs/MAPPING_REGISTRY.md) — semantic-to-scene mapping and reveal behavior
- [docs/MAPPING_REGISTRY.v0.1.json](docs/MAPPING_REGISTRY.v0.1.json) — machine-readable prototype mapping
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — release-blocking public-scanner security boundary
- [docs/TELEMETRY.md](docs/TELEMETRY.md) — product event chain, metrics, and data minimization
- [docs/GATE_0_EVIDENCE.md](docs/GATE_0_EVIDENCE.md) — requirement-by-requirement completion evidence and remaining proof

## Gate 0 verification

The fixture validator is contract tooling, not a commitment to the eventual application stack. With Python and `jsonschema` available, run:

```sh
python scripts/validate_fixtures.py
python scripts/validate_mapping.py
python scripts/verify_insights.py
python scripts/verify_browser_fixtures.py
python scripts/verify_worker_deadline.py
python scripts/verify_capture_worker.py
python scripts/verify_destination_policy.py
```

The first command validates the three deterministic scan profiles against JSON Schema Draft 2020-12, then checks cross-record provenance, attribution, party/domain consistency, five distinct node-count meanings, auxiliary-event boundaries, claim wording, and negative controls that JSON Schema alone cannot express. The second checks deterministic geometry/mass rules, monotonicity, registrable-domain hub grouping, version matching, object budgets, unknown states, the exact hero comparator, and the five-second reveal. The third exercises hero selection, limitation suppression, known-value coverage, hostile-copy independence, and neutral fallback without launching a browser. The fourth runs thirty-one real fixture pages through pinned Chromium, using a local policy proxy for reserved public-style hosts and two explicitly trusted localhost secure-origin fixtures for service-worker behavior. It proves the base DOM candidate filters, hard DOM-inspection, geometry-candidate, request, per-response-byte, total-byte, and popup/download observation boundaries with honest partial results, immediate auxiliary-page/download containment, main-document limit precedence, repeated-URL block provenance, genuine origin-marker and service-worker-marker replay controls, deterministic 650-object aggregation, evidence-free wrapper collapse, evidence-preserving mandatory overflow, ordered redirect-hop identity, final-page party recalculation, three positive and twenty-eight no-standout/interstitial hero outcomes, five redirect rejection cases, four live unsafe-method/private-subresource blocks, one deliberately state-changing GET, exact-scan reuse, per-origin cooling, sensitive-header stripping, sixteen secret canaries, cross-scan storage isolation, exact image attribution, selector redaction, marked geometry, CDP admitted-wire accounting, mixed-cache source classification, page/worker request ownership and target-qualified identities, exact uniquely correlated service-worker bootstrap accounting with conservative ambiguity fallback, active-request settling, bounded DOM-churn timeout, missing-byte preservation, structural login-wall and final-document HTTP-error classification, the subresource-error negative boundary, domain grouping, and the fixture-only request-policy cases. The fifth proves a process-level 15-second ceiling, nonce-scoped bounded transport-envelope eligibility, post-capture timeout, and browser-descendant cleanup on the local operating system. The sixth binds the real Gate 0 probe to that supervisor in a fixture worker, requires exact typed configuration, validates eligible records against both schema and semantic rules, preserves page-timeout partial evidence, and rejects a real post-capture hang before result publication. Production API/queue entry and disposable-container integration remain open. Install `requirements-dev.txt` and the Playwright Chromium binary before running these checks on a fresh machine.

The seventh command is network-free: it exercises the deployment-neutral destination-policy seam against 51 public/forbidden addresses, 29 malformed or unsafe URLs, seven resolver failure modes, and a same-host public-to-private answer sequence. The second resolution is rejected before its connector callback can run. This proves fail-closed policy behavior, not a deployed resolver, HTTPS proxy, or egress firewall.

## Product loop

1. Paste one public desktop URL.
2. Watch a five-second causal reveal: page → structure → weight → external machinery → hero fact.
3. Orbit, isolate, and inspect the source measurement behind any dramatic object.
4. Export a compact poster or video and a stable result link.
5. A viewer of that result can immediately scan another URL.
