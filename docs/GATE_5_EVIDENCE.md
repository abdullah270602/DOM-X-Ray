# Gate 5 Local Share Evidence

Status: partial gate evidence; Gate 5 remains open.

## Proven locally

Implementation baseline: `d309200` (`feat(results): publish trusted poster
artifacts`) plus the viewer trust-boundary integration documented here.

- Only immutable published results can expose public share controls. Fixture
  previews expose none.
- A complete or honestly partial result with one defensible hero opens a modal
  preview and receives a server-controlled Chromium poster: strict 1080 × 1080,
  8-bit RGBA, non-interlaced PNG, no larger than 5,000,000 bytes. The exact
  manifest SHA-256 and byte length bind the published sidecar, which is written
  before the JSON commit envelope.
- A partial poster carries `PARTIAL CAPTURE` and the exact product-authored
  limitation message bound to the admitted scan. A complete neutral result stays
  link-only and cannot manufacture a poster claim.
- The headline is recomputed from structured scan evidence. Aggregate forms
  require the exact complete set of typed source references and must reproduce
  numerically from the record; exact-resource and request-count forms likewise
  fail closed on provenance drift.
- The preview and PNG source are product-owned. Target URLs, page titles,
  selectors, resource URLs, raw scene/record identifiers, scripts, fonts, live
  assets, and deletion authority are not accepted as poster inputs; client pixel
  uploads are not accepted.
- `GET`/`HEAD /api/results/{resultId}/poster.png` is same-origin and returns
  `image/png`, strong SHA ETag, exact length, `no-store`, and `nosniff`; matching
  `If-None-Match` returns `304`. Unsupported exact-route methods return `405`
  with `Allow: GET, HEAD`, while missing, ineligible, deleted, expired, and
  corrupt artifacts are content-free `404`s.
- The browser verifies route, status, final URL, type, ETag, length, and SHA
  before preview/copy/download and falls back safely to local export.
- The share dialog traps focus, closes with Escape, restores the initiating
  control, announces clipboard failures, and routes directly to a selected new
  scan task.

## Reproducible evidence

From `viewer/`, with the local API and Vite viewer running:

```powershell
npm run typecheck
npm test
npm run build
python scripts/verify-ui.py http://127.0.0.1:5173/
python ../scripts/verify_png_validation.py
python ../scripts/verify_poster_renderer.py
```

The unit suite proves deterministic poster source, exact result/record/scene
binding, trusted-origin stable links, partial disclosure, link-only gating, and
hostile provenance rejection. It also exercises URL/status/type/ETag/length/SHA
verification, stale-result isolation, bounded body handling, and local fallback.
The Chromium verifier then opens actual published complete, partial, and neutral
results; waits for the manifest-verified hosted preview; compares it with the
registered server bytes; downloads those exact bytes twice; checks dimensions
and the byte envelope; and compares repeated rendered-pixel digests.

One recorded local run on 2026-09-14 with Chromium `140.0.7339.16` produced:

- image-heavy: two 260,258-byte PNGs in 0.355 s and 0.089 s, both decoding to
  pixel digest `9feca4d2b6d0f5c089bee2ce49a8a2ea5a3819e8902a1d95f9fa77e0cdc28ef7`;
- third-party-heavy: two 272,768-byte PNGs in 0.209 s and 0.201 s, both decoding
  to pixel digest `f192b0f97295e2f1cf8aa31a01ba70f6cd3d4bc38bfdd894f8c5e458abfddaa6`.

These timings and digests are a reproducible single-environment proof, not the
Gate 5 success-rate or p90 benchmark.

The reviewed desktop and mobile surfaces are committed at
`.impeccable/review/gate5-hosted-share-desktop.png` and
`.impeccable/review/gate5-hosted-share-mobile.png`.

Independent finish reviews for the implementation baseline returned `PASS` for
the responsive/accessibility surface and `PASS` for the share-boundary security
contract. The production build completes; its existing large-chunk warning is a
performance backlog item, not Gate 5 evidence.

## Not yet proven

- durable public poster storage, publication, cache purge, moderation, or
  takedown;
- an approximately five-second H.264 MP4 and its 8 MB envelope;
- current X web/mobile upload, playback, and recompression behavior;
- the 99% poster / 95% video benchmark success thresholds;
- p90 submit-to-share-ready and export-time measurements under the defined
  production environment;
- share-intent and viral-handoff instrumentation; or
- public arbitrary-page scanning, which remains blocked by the separate scanner
  containment and policy gates.

The next Gate 5 implementation decision is between production artifact
hosting/cache purge and the bounded video encoder. Neither decision relaxes the
Gate 0/Gate 3 public scanner blockers.
