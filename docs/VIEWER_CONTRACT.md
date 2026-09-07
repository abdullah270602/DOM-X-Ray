# DOM X-Ray Viewer Contract

Status: approved composition contract for Gate 1

## Approved reference

- Composition: **Instrument Panorama**
- Artifact: `C:\Users\Abdullah Naseem\Documents\ChatGPT\DOM-X-Ray\.impeccable\mocks\decision\architectural-section.png`
- Approval date: 2026-09-06
- Reference viewport: 1440 × 900 CSS pixels
- Mapping version: `mapping-v0.1.0`

The approved image is the spatial contract for the first viewport. Its hierarchy, approximate proportions, grouping, visual weight, and physical-material direction are binding. The literal fixture URL, numbers, labels, and synthetic page content are examples, not constants.

## Surface brief

DOM X-Ray is a public, no-login exploration toy. A visitor pastes one public URL, watches a five-second measured reveal, and then inspects the resulting architectural cutaway. The first viewport must explain the product before interaction: a recognizable page becomes layered structure, transferred resources acquire physical weight, and third-party domains sit outside the page boundary. The experience feels like an exact museum-model inspection table with one mischievous red finding—not a monitoring dashboard or a decorative 3D scene.

## First-viewport inventory

| Zone | Purpose | Required content | Spatial rule |
|---|---|---|---|
| Left instrument column | Identity, input, and the result's single causal statement | DOM X-RAY wordmark; URL field; X-RAY action; dynamic hero or neutral fallback; View evidence | Roughly the left third; quiet and readable; never covered by the canvas |
| Central model stage | Recognizable page and its truthful 3D cutaway | Captured-page orientation; scene-included regions; structure planes; exact-linked weight; selection reticle | Dominant object; begins near the center and owns most of the right two-thirds |
| External edge | Page-level or third-party topology | One teal machinery zone containing every retained registrable-domain hub; exact or page-level connections; unknown-state treatment | Beyond the page plinth on the right; must not compete with the page model |
| Bottom instrument rail | Mode and playback controls | Structure; Weight; Origins; Replay; orbit/drag hint | One continuous physical rail near the bottom edge, not a row of floating cards |
| Evidence drawer | Provenance for the selected object or hero | Metric; raw value and unit; evidence level; attribution; source; mapping rule; limitations | Opens from the model/evidence edge without shrinking the primary scene into a dashboard |
| Capture status | Honesty about the result | Complete, partial, interstitial, blocked, or failed state; affected limitations | Visible near the identity/hero evidence; never hidden only inside the drawer |

## Composition rules

At 1440 × 900:

- The 3D model is the visual subject and occupies approximately 60–66% of the viewport width.
- The left column occupies approximately 24–30%, with a generous gutter before the model.
- The title is the strongest typographic object; the dynamic hero statement is second.
- The external machinery is one supporting zone at the far right, not a second hero. It may contain multiple hubs when the scan record requires them.
- The bottom rail is visually attached to the inspection table and remains inside the first viewport.
- Empty warm-paper space is intentional. Do not fill it with metrics, navigation, cards, or decorative labels.

The implementation may adjust exact coordinates to satisfy real text and responsive constraints, but a 1440 × 900 screenshot must preserve these relationships. If a layout change solves a technical problem by making the model materially smaller or the shell materially denser, it violates the contract.

## Data-binding contract

- Every visual path consumes `scene-manifest-v0.1.0`, conforming to `SCENE_MANIFEST.schema.json` and derived from the immutable scan record by the reference mapper. WebGL, reduced-motion, no-WebGL, export, and regression routes may not independently recalculate geometry, topology, mass, or endpoints.
- Public result, poster, and video surfaces additionally consume `result-manifest-v0.1.0`; its source hashes, hero evidence, limitation disclosure, required layers, route identity, and artifact eligibility may not be independently reconstructed by a renderer.
- WebGL, reduced-motion, and text-only paths consume `viewer-runtime-v0.1.0` for playback, modes, selection, isolation, status/finding presentation, and evidence pointers. They may not maintain separate behavioral truths.
- The hero statement is rendered from the single `record.insights` entry whose `hero` value is `true`. Fixture phrases and percentages in the comp are never hard-coded.
- If no eligible hero exists, show the neutral no-standout capture summary. Do not manufacture a superlative and do not make that fallback share-eligible by default.
- Instantiate 3D region objects only for nodes with `sceneIncluded !== false`. Evidence-only nodes remain reachable through aggregate membership and the non-3D evidence path.
- Element geometry, DOM depth, stacking seams, resource mass, party topology, unknown values, and aggregation use `mapping-v0.1.0`; visual styling may not reinterpret those formulas.
- Exact resource links may terminate at the responsible region. Probable, page-level, and unknown attribution must terminate at a page-level bus or external machine.
- `null` is unknown, not zero. Cache, service-worker, network, failed, and missing transfer states require distinct material and text treatments.
- Every emphasized scene object resolves to raw evidence and its mapping rule. Selection must never reveal invented metadata.

## Interaction contract

- The deterministic five-second reveal follows Flat → Structure → Weight → Party → Hero, then yields to free exploration.
- Orbit is bounded so the page remains recognizable; zoom cannot move all evidence or controls off-screen.
- Structure, Weight, and Origins change emphasis, not the underlying measurements or object membership.
- Selecting a plate, mass, hub, cable, or aggregate opens the same evidence in pointer, keyboard, touch, and text-only paths.
- Replay returns to the same timeline for the same scan record. It never triggers a rescan.
- A stable result reconstructs from its immutable, versioned record; shared-result viewing never silently refreshes the page measurement.

## Responsive and fallback behavior

- At narrow desktop and tablet widths, keep the hero statement and model visible together; compress annotations and external machinery before shrinking the model below legibility.
- On phone widths, use a staged vertical composition: identity and hero first, a bounded touch model second, modes third, and the evidence sheet last. Preserve a one-action path to scan another URL.
- With `prefers-reduced-motion`, replace automatic camera travel and continuous separation with user-advanced Flat, Structure, Weight, Party, and Hero steps.
- Without WebGL, present the captured page, hero or neutral statement, modes as textual groups, and the complete evidence path. No essential fact may depend on the canvas.

## Visual direction

- Palette: warm paper `#E9E1D2`, graphite `#20251F`, inspection red `#D9492F`, external teal `#2D6571`, model board `#B8AA8B`.
- Materials: paper, board, translucent drafting film, graphite lines, brass registration details, engraved labels.
- Geometry: flat or lightly chamfered instrument parts; restrained mechanical joins; no inflated pills or soft floating cards.
- Motion: deliberate sectional separation, measured camera tilt, and crisp inspection marks. No ambient particles, liquid blobs, perpetual bobbing, or decorative wire motion.
- Exclusions: generic dashboard, bento grid, glassmorphism, gradients, neon cyberpunk, code-editor theater, globe, speed score, or roast framing.

## Implementation acceptance

Before Gate 1 visual review, provide evidence for all of the following:

1. A 1440 × 900 screenshot whose primary spatial relationships match the approved reference.
2. The clean, image-heavy, and third-party-heavy fixtures rendered by the same schema-driven scene mapper with no fixture-specific component branches.
3. Dynamic hero and evidence binding verified against fixture records.
4. Rendered-object count at or below 650, with evidence-only nodes absent from the scene.
5. Keyboard, touch, reduced-motion, and no-WebGL paths that retain the hero and evidence.
6. Deterministic reveal/replay and a screenshot route suitable for regression comparison.
7. Frame-time, draw-call, rendered-object, and aggregation instrumentation at the agreed viewport.

When application HTML is created, its first `<body>` comment must summarize this direction contract, name the approved comp path, and list the required data-binding, accessibility, performance, and visual exclusions above.
