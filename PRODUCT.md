# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

The viewer uses React, TypeScript, Vite, Three.js, and React Three Fiber. The user approved this stack on 2026-09-07. The existing Python controlled Playwright/Chromium scanner stays a separate runtime. The current local API proves anonymous jobs, restart-stable immutable result routes, bounded engineering retention, and browser-held no-login deletion with seeded records only; hosting, distributed storage/abuse controls, and production public-scanner deployment remain later decisions.

## Users

The primary visitor is a design- or technology-curious person who encounters DOM X-Ray through a shared result, has a public website in mind, and wants an immediate, understandable look beneath its visible surface.

Web designers, developers, and creators are an important early audience because they can recognize the measurements, choose interesting URLs, and publish results to X. The product must remain legible to people who do not know browser internals.

## Product Purpose

DOM X-Ray turns a truthful snapshot of one public page load into an understandable cinematic 3D cutaway. Success means a visitor can paste a URL without an account, understand one consequential fact about that page in seconds, verify where the fact came from, and create a shareable result that invites another scan.

The north-star journey is:

> Paste a public URL → receive a beautiful, truthful 3D X-ray and visible hero fact at p90 within 20 seconds for supported successful scans → export one fact worth sharing.

## Positioning

DOM X-Ray is an explorable physical metaphor for measured web behavior, not a scorecard with 3D decoration. A visible region's position comes from the captured layout; structural separation comes from DOM and stacking information; mass comes from transferred resources; external machinery comes from third-party requests; and any attributed motion comes from recorded layout displacement.

Every dramatic object must reveal its source measurement. When attribution is weak, the product must say so or move the effect to page level rather than imply a false cause.

## Operating Context

- A visitor arrives from a shared result or the public home page.
- They paste one public HTTP(S) URL and do not sign in.
- A controlled browser loads the page at a declared desktop viewport and records a bounded snapshot.
- The result first plays as a five-second authored reveal, then becomes freely explorable.
- The visitor can inspect evidence, replay the reveal, and produce a poster, short video, or stable result link.
- A shared-result viewer can launch a new scan in one action.

## Capabilities and Constraints

The first version includes:

- One public desktop page per scan.
- A recognizable flat-page opening that becomes a 3D architectural cutaway.
- Structure and Weight as the primary exploration modes.
- First-party versus third-party resource distinction without equating “third party” with “tracker.”
- A single hero insight, supported by at most three secondary measurements.
- Inspectable provenance for rendered objects and claims.
- Replay, orbit/zoom, isolation, a share poster or short video, and a stable scan URL.
- Explicit loading, blocked, partial, timeout, and failure states.

The first version excludes:

- Accounts, personal history, teams, and comparisons.
- Crawling whole sites or scanning authenticated/private pages.
- A general Lighthouse-style grade, SEO audit, or accessibility audit.
- AI-generated commentary presented as measurement.
- Element-level JavaScript blame without defensible attribution.
- A dedicated Motion diagnostic mode until source attribution is reliable.

Operational constraints:

- The scanner must use a fresh, isolated context with no user cookies or credentials.
- Only public HTTP(S) destinations are in scope; private, loopback, link-local, and cloud-metadata targets must be rejected and redirects revalidated.
- Capture time, requests, transferred bytes, execution, and rendered-object count must be bounded.
- Headless blocking, consent walls, regional variance, and unstable pages are expected realities. Partial results must never masquerade as complete scans.
- Shared results must be reconstructable from an immutable, versioned scan record rather than a new live page load.

## Brand Commitments

The product name is **DOM X-Ray**.

Its character is a serious scientific instrument with a slightly mischievous reveal. It should feel like an architectural museum model or physical inspection table, not a generic analytics dashboard, neon cyberpunk scene, decorative particle field, or “roast my site” gimmick.

The Three.js Concept Atlas established the visual world. The user has now approved the implementation-specific **Instrument Panorama** composition. Its spatial relationships are the first-viewport contract; the detailed responsive, data-binding, interaction, and accessibility rules live in `docs/VIEWER_CONTRACT.md`.

## Evidence on Hand

- Approved interactive concept atlas: `C:\Users\Abdullah Naseem\.codex\visualizations\2026\09\04\01a06e25-99f2-77a3-a31c-f0ab8fd7e502\threejs-concept-atlas.html`
- Approved first-viewport composition: `C:\Users\Abdullah Naseem\Documents\ChatGPT\DOM-X-Ray\.impeccable\mocks\decision\architectural-section.png` (**Instrument Panorama**, approved 2026-09-06).
- Approved viewer contract: `C:\Users\Abdullah Naseem\Documents\ChatGPT\DOM-X-Ray\docs\VIEWER_CONTRACT.md`.
- Confirmed product choice: a public website-exploration toy, not a developer-first diagnostic workspace.
- Confirmed interaction preference: an interactive viewer rather than static boards alone.
- No production scanner, representative scan dataset, usability findings, performance benchmark, testimonials, or public traction evidence exists yet. Future work must not fabricate them.

## Product Principles

1. **Truth before spectacle.** A beautiful effect is allowed only when its measurement and transformation are inspectable.
2. **One causal story first.** The reveal should teach the page → structure → weight → external-dependency story before exposing controls.
3. **Surprise without humiliation.** Surface consequential facts with wit and precision; do not manufacture a roast.
4. **Progressive depth.** A newcomer gets one clear finding, while an expert can trace it to raw evidence.
5. **Share the artifact, preserve the evidence.** The exported result should be native to social feeds while the stable link retains context and provenance.

## Accessibility & Inclusion

Implementation baseline: the non-3D shell and all evidence must meet WCAG 2.2 AA; core exploration must have keyboard and touch alternatives; color cannot carry meaning alone; and `prefers-reduced-motion` must replace the cinematic reveal with an understandable stepped or static presentation. The hero fact and evidence must remain available as text even when WebGL is unavailable.
