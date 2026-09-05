# DOM X-Ray

DOM X-Ray is a public, no-login website-exploration toy. A visitor pastes a public URL and receives a cinematic 3D cutaway whose geometry and motion are derived from real page-load measurements, then shares one precise, surprising finding.

## North star

> Paste a public URL → receive a beautiful, truthful 3D X-ray and visible hero fact at p90 within 20 seconds for supported successful scans → export one fact worth sharing.

The first release is deliberately not a full developer dashboard, a Lighthouse replacement, or a generic website roast. The spectacle earns attention; inspectable evidence earns trust.

## Current status

Gate 0 is in progress. Product truth, the gated roadmap, and the measurement-to-visual contract are now documented. The implementation stack and deployment target remain open decisions, so no application scaffold has been selected yet.

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
python scripts/verify_browser_fixtures.py
```

The first command validates the three deterministic scan profiles against JSON Schema Draft 2020-12, then checks cross-record provenance, attribution, party/domain consistency, five distinct node-count meanings, claim wording, and negative controls that JSON Schema alone cannot express. The second checks deterministic geometry/mass rules, monotonicity, registrable-domain hub grouping, version matching, object budgets, unknown states, and the exact five-second reveal. The third runs five real fixture pages through pinned Chromium and a local policy proxy. It proves the base DOM candidate filters, deterministic 650-object aggregation, ordered redirect-hop identity, final-page party recalculation, five redirect rejection cases, exact image attribution, selector redaction, marked geometry, CDP wire-byte accounting, settling, domain grouping, and the first fixture-only request-policy cases. Install `requirements-dev.txt` and the Playwright Chromium binary before running it on a fresh machine.

## Product loop

1. Paste one public desktop URL.
2. Watch a five-second causal reveal: page → structure → weight → external machinery → hero fact.
3. Orbit, isolate, and inspect the source measurement behind any dramatic object.
4. Export a compact poster or video and a stable result link.
5. A viewer of that result can immediately scan another URL.
