# DOM X-Ray Mapping Registry

Status: prototype `mapping-v0.1.0` for Gate 1

Machine-readable values live in [MAPPING_REGISTRY.v0.1.json](MAPPING_REGISTRY.v0.1.json). This document explains what they mean and which product claims they are allowed to carry.

This is a falsifiable prototype mapping, not the final `DESIGN.md`. Gate 1 comprehension and performance testing may replace it under a new mapping version. Existing shared scans retain the version they were created with.

## Scene thesis

The captured viewport begins as a flat, recognizable page on an architectural inspection table. It separates into DOM-derived strata; known transferred bytes acquire physical mass; third-party registrable domains arrive as machinery outside the page plinth; one exact fact closes the authored reveal. The visitor can then orbit, isolate, and inspect the evidence.

The world inherits the approved concept atlas: warm paper, graphite, translucent drafting film, red inspection marks, and teal external machinery. Color is never the only carrier of meaning. Topology, line style, fill, labels, and material state provide redundant encodings.

## Coordinate mapping

The captured viewport maps to a plane 12 world units wide. Let `s = 12 / viewport.width`.

For each viewport-intersecting rectangle, first clip the raw observed rectangle to the capture viewport. The scene rectangle is:

```text
x = (clipped.x + clipped.width / 2 - viewport.width / 2) × s
y = -(clipped.y + clipped.height / 2 - viewport.height / 2) × s
width = clipped.width × s
height = clipped.height × s
```

Raw geometry remains in the inspector. Clipping changes the scene footprint, not the recorded evidence.

## Structure mapping

DOM ancestry becomes monotonic structural separation:

```text
z = min(2.4, 0.42 × log2(1 + domDepth))
```

The logarithm prevents deeply nested utility wrappers from turning the scene into an unreadable tower. The cap preserves non-decreasing order but intentionally stops increasing visual distance after the cap. The inspector always shows the uncapped raw depth.

An inferred stacking context adds a visible 0.08-world-unit seam and a drafting-film plane. That seam says only “this node met `stacking-context-v1`”; it does not represent browser compositor layers, GPU work, or simple z-index order.

## Weight mapping

For a resource with known `transferredBytes = b`:

```text
mass = clamp(log2(1 + b / 1024) / 12, 0, 1)
plateThickness = 0.035 + mass × 0.48 world units
```

The global logarithmic scale makes ordinary assets legible while preventing a single enormous response from consuming the whole composition. It is monotonic and shared across pages. The visual cap never caps the displayed raw byte value.

States are deliberately distinct:

- Known positive bytes: solid mass using the resource material.
- Measured zero from cache: hollow cached shell.
- Unknown/missing bytes: hatched hollow shell with an unknown label.
- Failed or blocked response: broken outline; no mass value.

Multiple exactly linked resources sum only their known received bytes for the region's mass. Unknown resources remain separate markers and never become zero inside the sum.

Unattributed scripts, styles, fonts, fetches, and other requests feed a page-level counterweight bank outside the DOM layers. They do not attach to a visually convenient region.

## First- and third-party topology

Party is derived from the final page's registrable domain under `registrable-domain-v1`.

- First-party resources remain inside the page plinth.
- Each unique stored `resource.registrableDomain` classified as third party becomes one external hub on a 7.5-world-unit ring. Subdomains and ports that resolve to the same registrable domain share a hub.
- Requests connect to their exact region only when attribution is exact; otherwise they terminate at the page-level bus.
- Known cable thickness uses the same monotonic byte mapping as mass.
- Unknown transfer uses a dashed, hollow connection.

External topology means “different registrable domain in this captured load.” It never means tracker, advertising, ownership, surveillance, necessity, or harm.

## Perceptual aggregation

The renderer has a hard budget of 650 scene objects, including external hubs. `perceptual-region-v1` runs deterministically in document order:

1. Create candidates from the capture protocol's viewport-intersecting nodes.
2. Mark mandatory nodes: root/body, semantic landmarks, replaced media, exact resource-link targets, shift sources, inferred stacking contexts, canvas, SVG roots, and iframes.
3. Collapse a wrapper into its nearest represented ancestor when its clipped rectangle matches the ancestor within 1 CSS pixel, it has no exact resource, no stacking-context trigger, no semantic role, and contributes no distinct painted region known to the DOM evidence.
4. If the result still exceeds the available budget, rank nonmandatory candidates by clipped viewport area, exact-resource weight, semantic distinctness, and DOM order as the final tie-breaker.
5. Preserve all mandatory nodes. Fill the remaining budget by rank.
6. Attach every omitted candidate to its nearest represented ancestor as a member ID. An aggregate exposes its member count and rule.

The algorithm never describes omitted candidates as nonexistent. `rawDomNodeCount`, `inspectedNodeCount`, `aggregatedNodeCount`, and `renderedRegionCount` remain separate.

If mandatory objects alone exceed the budget, the scan is partial and the viewer uses a region-level fallback. It does not silently discard exact evidence.

## Hero selection

The result contains zero or one hero insight. A hero has exactly one numeric primary metric and at most three support metrics. Its primary evidence is observed or deterministically derived; classified/probable evidence cannot drive it.

Prototype candidate thresholds:

- A resource type owns at least 60% and 500,000 known received bytes.
- Third-party requests own at least 50% of all party-classified requests.
- Third-party bytes own at least 50% when known-byte coverage is at least 90%.
- One exactly linked resource owns at least 35% and 500,000 known received bytes.

Candidates are ranked by normalized effect strength, measurement coverage, attribution scope, and visual consequence. Exact element attribution wins a tie over page-level evidence; observed wins a tie over derived; DOM order provides the final deterministic tie-breaker.

If no candidate crosses a threshold, the result says no standout finding was captured and shows a neutral capture summary. That fallback is not automatically share-eligible.

Every hero sentence names its comparison domain and is scoped to “this captured load.”

## Five-second reveal

| Time | Stage | Viewer learns |
|---:|---|---|
| 0.0–0.7 s | Flat | This is the captured page, not an abstract sculpture |
| 0.7–1.7 s | Structure | The page is nested and layered |
| 1.7–3.2 s | Weight | Received resources alter physical mass |
| 3.2–4.2 s | Party | Different registrable domains sit outside the page boundary |
| 4.2–5.0 s | Hero | One exact fact explains the strongest visual consequence |

Animation exposes evidence; it does not depict the page literally moving. After five seconds, authored camera motion stops and exploration takes over.

Reduced-motion mode presents the same five stages as user-advanced steps with no automatic camera or continuous geometry motion. It preserves the hero fact, evidence, and limitations.

## Inspector contract

Selecting a plate, weight, hub, cable, scar, or aggregate reveals:

- Semantic object name and mapping version.
- Raw metric, numeric value, and unit.
- Observed/derived/classified evidence level.
- Exact/probable/page-level attribution scope.
- Sanitized DOM selector, resource URL, or registrable domain when available.
- Transformation formula and mapped value.
- Aggregation members and rule.
- Cache/worker/network source, capture timestamp, and limitations.

The same information must exist in keyboard, touch, and non-WebGL paths.

## Gate 1 falsification tests

The mapping is rejected or versioned when any of these are true:

- Fewer than 8 of 10 first-time viewers distinguish clean, image-heavy, and third-party-heavy fixtures within ten seconds.
- Viewers consistently interpret DOM depth as slowness, third-party as tracking, or mass as decoded memory.
- A scene object cannot resolve to raw evidence and a mapping rule.
- Unknown and measured-zero bytes are confused.
- The renderer cannot sustain the Gate 1 frame-rate floor within the 650-object budget.
- A truthful page needs invented motion, causality, or judgment to feel interesting.

The first response to low comprehension is fewer simultaneous encodings and stronger aggregation—not a larger legend.
