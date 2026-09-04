# DOM X-Ray Truth Contract

Status: draft v0.1 for Gate 0

## Purpose

DOM X-Ray may dramatize measurements, but it may not dramatize causality. This contract defines the evidence each visual primitive and written claim needs, how uncertainty is shown, and what the first version must refuse to imply.

The versioned scan record is the source of truth. The cinematic sequence, interactive viewer, poster, video, and text fallback are different renderings of that same record.

## Evidence levels

Every displayed metric or claim carries one of these levels:

1. **Observed** — emitted directly by a declared browser API or capture instrument during this scan.
2. **Derived** — calculated deterministically from observed values using a named, versioned rule.
3. **Classified** — assigned by a versioned lookup or heuristic, with its basis and confidence retained.
4. **Unavailable** — not captured reliably; the raw field is `null` and a limitation explains the gap. It is omitted from an insight's evidence array rather than converted into claim evidence.

The V1 hero fact may use only observed or deterministically derived evidence. Classified evidence may appear as clearly labelled supporting context but may not determine the headline. The product uses categorical attribution labels and never fabricates percentage-confidence scores. Unavailable evidence never becomes a zero.

## Attribution scope

Evidence quality and attribution scope are separate. An observed network value can still lack an exact element owner.

- **Exact element** — the measurement belongs directly to the captured DOM node.
- **Exact resource link** — a captured element URL matches an observed request after deterministic canonicalization.
- **Probable link** — browser initiator or stylesheet evidence suggests a relationship but does not prove element-level causation.
- **Page level** — the measurement is real but no defensible element relationship exists.
- **Unknown** — attribution is unavailable.

Probable links can be explored as qualified context but cannot drive a hero fact or terminate a dramatic effect at an element.

## Capture envelope

Every scan records enough context to bound its claims:

- Requested URL, final URL, capture timestamp, scanner/schema version, browser identity, locale, and viewport.
- Navigation, capture, and stabilization timing.
- Complete, partial, interstitial, blocked, or failed status plus machine-readable limitation codes.
- Whether each resource value came from network transfer, cache, service worker, or an unknown path.
- Limits reached for time, request count, bytes, DOM nodes, or rendered regions.
- Fresh-context and cache policy, capture point, observation-window duration, timezone, scanner region when known, inspected/rendered/aggregated node counts, and requests missing byte data.

The product describes “this captured load,” never the permanent nature of a site. Repeated loads can differ by geography, personalization, experiments, cache, consent, and time.

## Measurement-to-visual mapping

| Evidence | Capture basis | Permitted visual mapping | Permitted language | Required caveat |
|---|---|---|---|---|
| Element rectangle | `getBoundingClientRect()` at the declared capture moment | X/Y footprint and relative width/height | “occupied this region at capture” | Viewport and capture moment are visible |
| DOM ancestry/depth | Captured parent relationships | Structural elevation, grouping, or exploded separation | “nested N levels” / “structural layer” | Z is a metaphor, not a browser-rendered physical depth |
| Stacking context | Versioned derivation from relevant computed-style triggers | Separate translucent plane or seam | “creates a stacking context” | Do not equate context order with simple DOM depth |
| Transferred resource bytes | CDP network totals and/or Resource Timing with source recorded | Mass, volume, sag, or counterweight assigned to a defensible resource/region | “transferred X during this load” | Cached/worker/unknown transfer is labelled; missing is not zero |
| Decoded resource size | Browser timing/CDP value where available | Secondary internal volume, never network mass | “decoded size X” | Keep distinct from transferred bytes |
| First/third party | Registrable-domain comparison against final page URL using a versioned public-suffix rule | External cable, off-board machine, or boundary crossing | “third-party request/origin” | Never call it a tracker without separate evidence |
| Resource initiator | Browser initiator metadata where available | A connection from the initiating region or page-level bus | “requested by…” only at captured confidence | Fall back to page-level when a DOM element is not defensibly identified |
| Layout-shift entry | `PerformanceObserver` layout-shift value and source rectangles where available | Recorded displacement vector, scar, or ghosted before/after position | “shifted by this recorded displacement” | Omit fabricated motion; exclude or label recent-input shifts as appropriate |
| DOM node/region count | Captured and aggregation-qualified nodes | Density, layer count, or section label | “N captured nodes / M rendered regions” | Never present an aggregated region count as raw DOM count |
| Script transfer weight | Resource record for script responses | Page-level machinery or mass; region attachment only with evidence | “scripts transferred X” | Transfer weight is not execution time |
| Screenshot | Sanitized captured page image | Orientation texture on the flat opening | “captured appearance” | It is not analysis and must not generate claims by itself |

An inferred CSS stacking context is never called a compositor or GPU layer. Transferred bytes are never presented as decoded memory, speed, energy, carbon, or overall site quality. Main-thread or long-task claims are outside scan-schema v0.1 and cannot appear until a later schema adds their raw evidence.

All transformation formulas—normalization, clamping, aggregation, mass scale, separation, and camera emphasis—must be versioned. A viewer inspecting an object can see the raw value and the transformation name.

## Attribution rules

- A measurement belongs to a DOM region only when the capture record contains a defensible link to that region.
- Resource timing by URL does not automatically identify the element that caused or consumed the resource.
- JavaScript transfer weight, JavaScript execution time, and layout movement are separate facts.
- A third-party origin is not automatically advertising, surveillance, malicious, unnecessary, or slow.
- DOM depth is not z-index. Stacking context is not visual importance. Transferred bytes are not decoded size.
- A screenshot match or visual proximity may help orientation but cannot establish causality.
- Aggregated regions must retain the member node IDs and aggregation rule.
- Cinematic peeling, camera motion, pulses, and transitions are staging. They may reveal a measurement but may not imply that the page itself moved, vibrated, collapsed, overheated, or became unstable.

When attribution stops at the page or origin level, the visual must stop there too: use a page-level bus, engine, counterweight, or external machine rather than attaching blame to a nearby element.

## Hero-fact contract

Each scan produces zero or one hero fact. It contains:

- A precise statement scoped to this captured load.
- One primary numeric value and unit.
- Exactly one `primary` evidence item and at most three `support` items.
- An observed or derived primary evidence level; classified context is support-only and carries classifier metadata.
- References to the underlying scan fields.
- The rule that selected it and any relevant limitation.
- At most three supporting metrics.

Acceptable examples:

- “Images accounted for 71% of the 5.8 MB transferred in this captured load.”
- “18 of 27 contacted origins were third party.”
- “One hero image contributed 2.4 MB of recorded transfer weight.” — only when resource-to-element attribution is defensible.

Prohibited examples without additional evidence:

- “This hero image made the page slow.”
- “These 18 trackers are spying on visitors.”
- “This component caused the layout shift.”
- “Your DOM is bad.”
- “The page always weighs 5.8 MB.”

If no candidate has sufficient evidence or consequence, the product says that no standout finding was captured. It must not manufacture a superlative.

Comparatives such as “largest” or “heaviest” must name their comparison domain—for example, “the largest completed response observed in this scan.”

## Missing and partial data

- `null` means unknown or unavailable; zero means a measured zero.
- A partial scan retains valid observed data and lists exactly what is missing.
- A blocked page gets no simulated cutaway presented as its scan.
- Consent screens, login walls, CAPTCHAs, bot challenges, and error documents are `interstitial` captures. The result may describe that captured state but must not imply it reached the intended destination.
- Cached or service-worker responses use their own source label and are not silently mixed with network transfer totals.
- Cross-origin restrictions, browser omissions, node caps, and aggregation are disclosed at the affected metric and scan level.
- The share artifact visibly labels partial results and cannot omit a limitation that changes the hero fact's interpretation.

## Privacy, safety, and retention boundary

- Public HTTP(S) pages only; never accept credentials, cookies, request headers, file URLs, browser-extension URLs, or private-network targets from a visitor.
- Validate the initial URL, DNS resolution, every redirect, and the final destination against the network policy.
- Use a fresh, nonprivileged browser context; do not sign in, submit forms, grant permissions, start downloads, or persist page storage into another scan.
- Persist no page HTML, body text, form values, cookies, storage, authorization headers, `Set-Cookie` headers, or response bodies. Store only normalized evidence, a capture image, and sanitized metadata required by the result.
- Strip URL fragments and redact query values from user-visible provenance by default. Preserve only the minimum internal data required to reproduce a safe result.
- Sanitize selectors so high-entropy IDs or attribute values cannot leak through evidence panels or logs.
- Screenshots and page text can contain personal or copyrighted public content. Retention, deletion, abuse-reporting, and sharing policies are open product decisions and must be settled before a public launch.
- Enforce bounded navigation time, total time, requests, bytes, redirects, DOM nodes, and browser processes. Rate-limit public submissions and isolate scanner egress.

## Required provenance interaction

Selecting any emphasized object must reveal:

- What the object represents.
- Raw metric, value, and unit.
- Evidence level and capture source.
- Sanitized source URL/origin or DOM selector/region when available.
- Mapping/aggregation rule and mapping version.
- Limitations or uncertainty that affect interpretation.

The same evidence must be reachable without hover and in the non-WebGL fallback.

## Gate 0 acceptance tests

1. **Schema validity:** clean, image-heavy, and third-party-heavy fixtures validate against the same scan-record schema.
2. **Provenance coverage:** every emphasized fixture object resolves to existing evidence references; no orphan visuals exist.
3. **Measurement integrity:** fixture rectangles reproduce within 1 CSS pixel and transferred-byte totals within 2% under the declared capture protocol.
4. **Math integrity:** rendered totals and hero-fact values reproduce from raw fixture values within exact integer arithmetic or a declared rounding rule.
5. **Unknown integrity:** replacing any optional metric with `null` removes or labels the dependent effect; it never turns into zero.
6. **Party language:** third-party fixtures never emit “tracker,” “ad,” or “surveillance” unless a separate versioned classifier supplies that categorical label and basis.
7. **Attribution boundary:** removing an exact element link moves resource/CPU representation to page level rather than attaching it to the nearest visible node.
8. **Partial integrity:** every limitation that invalidates a hero candidate prevents that candidate from being selected.
9. **Determinism:** the same schema version, mapping version, and scan record produce the same measurements, insight selection, and reveal timeline.
10. **Claim snapshot:** automated snapshots cover every hero-fact template and its required caveat.
11. **Secret audit:** fixtures containing cookies, authorization values, query secrets, form data, and high-entropy identifiers leave none of those values in stored artifacts or logs.
12. **Security boundary:** tests reject private and special-use destinations, including redirect and DNS-rebinding attempts, before public scanning is enabled.

## Open decisions before Gate 0 closes

- Exact browser instrumentation and reconciliation rule when CDP and Resource Timing differ.
- URL-redaction and immutable-record retention policies.
- Public-suffix library and any optional tracker/category classifier.
- Layout-shift stabilization window and treatment of recent user input.
- Region-aggregation algorithm and the minimum evidence required to link a resource to a DOM region.
- Versioned visual transformation formulas and hero-candidate thresholds.
