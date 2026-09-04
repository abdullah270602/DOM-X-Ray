# DOM X-Ray Capture Protocol

Status: prototype v0.1 for Gate 0 and the Gate 1 scanner-risk spike

## Claim boundary

One scan is one bounded observation of the initial state of one public top-level page in a fresh desktop Chromium context. It is not a crawl, field data, a logged-in experience, a mobile result, or a permanent judgment about the website.

The target product clock begins when a valid visitor submits a URL and ends when the interactive cutaway and hero fact are visible. Supported successful scans target p90 at or below 20 seconds. Protocol limits therefore favor an honest partial record over waiting indefinitely.

## Fixed capture profile

Any change to these values requires a scanner-version bump and must remain visible on the result.

| Setting | v0.1 value | Reason |
|---|---:|---|
| Browser | Container-pinned Chromium build | One declared instrument for reproducibility |
| Viewport | 1440 × 900 CSS pixels | Stable desktop composition and fixture baseline |
| Device scale factor | 1 | Keeps geometry and screenshots in one declared scale |
| Locale | `en-US` | Avoids host-dependent defaults |
| Timezone | `UTC` | Avoids host-dependent date rendering |
| Color scheme | light | One deterministic first state; not a claim about user preference |
| Reduced motion | no preference | Capture the page's default state; DOM X-Ray itself supplies a separate reduced-motion viewer |
| Browser context | Fresh, non-persistent, no imported storage state | No visitor cookies, credentials, or cross-scan state |
| Cache | Disabled for the capture context | Defines a repeatable clean-load observation |
| Service workers | Allowed and explicitly recorded | Avoid silently changing service-worker-dependent pages; worker-served responses remain distinct |
| Scroll/input | None | V1 captures the initial viewport without manufacturing lazy-load or interaction state |
| Frames | Top-level document only | Cross-origin and nested frame DOM stays opaque; the iframe element may appear as one region |
| Screenshot | Initial viewport only | Orientation reference, not full-page analysis |

Playwright non-persistent browser contexts do not write browsing data to disk. The scanner still destroys every context after one scan and never reuses its storage state.

## Bounded timeline

1. Parse and normalize the requested URL, reject embedded credentials, resolve DNS, and apply the network policy before Chromium sees it.
2. Create a fresh context and page. Deny permissions, downloads, additional pages, and access to local or private networks.
3. Install the layout-shift observer before navigation and enable the Chrome DevTools Protocol Network domain.
4. Navigate toward `DOMContentLoaded` with a 10-second navigation ceiling.
5. After `DOMContentLoaded`, start a 750 ms quiet timer no earlier than 500 ms after that event. Check the timer every 50 ms and reset it on any qualifying request completion/failure, qualifying DOM mutation, or layout-shift entry defined below.
6. Capture only after `document.readyState === "complete"` and the quiet timer expires. Stop waiting at 12 seconds from navigation start even if that never occurs. A usable document that misses either condition becomes partial with `document-not-complete` or `settle-timeout`; an unevaluable document fails with `timeout`.
7. In one bounded capture window, read DOM geometry and styles, take the viewport screenshot, close the observation window, and finalize network records.
8. Finish transformation and record persistence inside a 15-second scanner hard limit. The remaining product budget is reserved for delivery and first render.

Qualifying network resets are `loadingFinished` or `loadingFailed` events for Document, Stylesheet, Image, Media, Font, Script, XHR, and Fetch requests owned by the page or its service worker. WebSocket, EventSource, Ping/beacon, Preflight, and other intentionally open streams do not reset the quiet timer; their presence and unfinished byte values are recorded as limitations.

The DOM observer watches the top-level document body with `{subtree: true, childList: true, characterData: true, attributes: true}`. It resets the timer for child-list or character-data changes outside `script`/`style`, and for changes to `class`, `style`, `hidden`, `open`, `width`, `height`, `src`, `srcset`, `sizes`, or `href`. Other attribute churn is ignored. Any recorded layout-shift entry resets the timer. The hard stop remains authoritative when animation or application churn never becomes quiet.

## Resource and execution limits

These are initial safety values for the 10-site risk spike, not timeless product claims:

- 500 observed requests.
- 50 MB total received bytes.
- 20 MB for any single response.
- 10 redirects across the main navigation.
- 20,000 top-level document elements counted or inspected.
- 5,000 geometry candidates before aggregation.
- 650 rendered scene objects, including external domain hubs.
- One top-level page; popups are closed and recorded.
- 15 seconds total scanner wall time.

When a cap is reached, the scanner stops the affected collection, records the exact limit, marks the scan partial when interpretation is materially incomplete, and suppresses any invalidated hero candidate.

## Network measurement

### Canonical transfer value

For a completed request, `Network.loadingFinished.encodedDataLength` is the canonical v0.1 value and is described to visitors as **bytes received during this captured load**. Chrome documents it as the total number of bytes received for that request. It is not decoded size, memory use, execution cost, energy, carbon, or a speed verdict.

The Gate 0 browser fixtures compare that value with the exact HTTP status-line, header, and body bytes emitted by a deterministic local server. They also require the total to remain within 2% of the separately declared response-body payload. The wire-byte equality proves the instrument; the body-payload tolerance keeps the fixture expectations understandable. Production claims always use the CDP value, never the body-only reference.

The scanner listens to:

- `Network.requestWillBeSent` and redirect response data.
- `Network.responseReceived` for response type and cache/service-worker flags.
- `Network.dataReceived` for optional decoded-data accumulation.
- `Network.loadingFinished` for canonical received bytes.
- `Network.loadingFailed` and `Network.requestServedFromCache` for outcome/source state.

Performance Resource Timing may be retained temporarily for diagnostics, but it never silently overwrites the CDP canonical value. If reconciliation is later required, it becomes a new named transfer-accounting rule.

### Request identity and redirects

Each stored resource uses a scanner-generated ID. Redirect hops use `requestId + hopIndex` internally so one reused protocol request ID cannot collapse multiple responses. A hop receives a byte value only when the protocol supplies defensible response data; otherwise its value is `null`.

HTTP error responses such as 404 or 503 remain completed responses when the network lifecycle completes. A network failure and an HTTP error are different states.

### Cache and service-worker state

Network, cache, service-worker, and unknown are mutually exclusive stored transfer sources. A zero or missing transfer for a cached/worker response never becomes ordinary zero-mass content. Service-worker-owned and frame-owned observations are deduplicated by protocol request identity and ownership; ambiguous duplicates remain unknown rather than being counted twice.

### Method and residual side-effect boundary

V1 allows page-initiated `GET`, `HEAD`, and required `OPTIONS` requests. It aborts `POST`, `PUT`, `PATCH`, `DELETE`, downloads, external-protocol launches, and other methods. Any blocked method produces a limitation because this can change the page's behavior.

This does **not** prove the scan is side-effect free. HTTP defines GET/HEAD as safe intent, but real servers can misuse them. A public page can also trigger anonymous side effects through subresource GETs. The scanner therefore sends no cookies, authorization, referrer, user-provided headers, or URL query parameters; identifies itself honestly; honors the approved robots/opt-out policy; deduplicates recent identical scans; applies a strict per-origin cooling window; and never retries a navigation automatically. These controls limit identity, repetition, and amplification rather than pretending to eliminate target-side risk.

Public launch remains blocked until the acceptable-use/robots policy, target-owner opt-out, per-origin limits, and abuse response are approved and tested. The integration suite includes a deliberately unsafe GET endpoint and proves the scanner supplies no credentials, does not retry it, and cannot invoke it repeatedly inside the cooling window. The product never claims “no requests changed server state.”

## DOM and geometry measurement

### What a rectangle means

`getBoundingClientRect()` supplies a fractional-pixel border-box union positioned relative to the viewport. Transforms and current scroll state affect the result. DOM X-Ray stores that observed rectangle and capture time, then clips a copy to the captured viewport for scene geometry. It never calls the rectangle an exact painted-pixel mask.

### Candidate rule

The scanner counts top-level document elements, then considers an element for scene representation when all are true:

- Its captured rectangle intersects the viewport.
- The intersection area is at least 16 CSS px².
- Computed `display` is not `none`.
- Computed `visibility` is neither `hidden` nor `collapse`.
- Computed opacity is greater than `0.01`.
- The element is not a nonvisual metadata/script/style node.

This is named **viewport-intersecting**, not “visible.” The scanner does not prove occlusion, clipping by every ancestor, pixel opacity, or user attention.

Mandatory candidates are the root/body, semantic landmarks, replaced media (`img`, `video`, `canvas`, `iframe`, SVG roots), exact resource-link targets, recorded layout-shift sources, and nodes that create an inferred stacking context.

### DOM boundaries

- Text content, form values, HTML, event listeners, and page storage are not persisted.
- Pseudo-elements are not separate DOM nodes and do not become independent evidence objects.
- Shadow DOM may be counted and inspected only when open and reachable; closed roots remain opaque and are disclosed.
- Descendant frame DOM is excluded in V1 even when same-origin, preserving one consistent boundary.
- Canvas and iframe contents appear only through the orientation screenshot; the element region itself may be represented.

### Selector sanitization

Selectors are display aids, not stable identity. The scanner keeps tag names and low-entropy IDs/classes, removes attribute values, truncates each selector, and replaces high-entropy tokens with a redaction marker. Exact element/resource matching happens in memory before redaction.

## Exact element-to-resource links

V1 may create an exact resource link from captured `currentSrc`, `src`, `poster`, stylesheet URL, or computed CSS image URL when its fully resolved URL exactly matches the observed request URL after deterministic canonicalization. Query values may participate in the in-memory match but are never published; only a hash and redacted display URL remain.

Browser initiator data without an exact element URL is `probable-link` or page-level. Scripts, fonts, stylesheets, fetches, XHR, beacons, and unattributed work remain page-level unless a later protocol proves a stronger relationship.

## Stacking-context derivation

`stacking-context-v1` is an explicit heuristic over captured computed styles. It marks the document root and known CSS triggers such as positioned elements with non-auto z-index, fixed/sticky positioning, opacity below one, transforms, filters, perspective, blend mode, isolation, containment, and declared change hints.

The result is called an **inferred CSS stacking context**. It is never called a paint order, compositor layer, GPU layer, or performance cost. The raw trigger is stored as the rule.

## Layout shifts

The observer is installed before navigation and uses `{ type: "layout-shift", buffered: true }` when available. Each entry stores timestamp, score value, `hadRecentInput`, and up to the browser-supplied source nodes with previous/current rectangles.

Source rectangles identify elements that moved; they do not identify the root cause. Entries with recent input remain in evidence but are excluded from default headline candidates. V1 can show recorded displacement as a secondary inspection detail, but Motion remains outside the primary experience.

The API and its source-attribution rectangles are not uniformly supported across browsers. That is acceptable for a pinned Chromium instrument but must remain a limitation of the claim.

## Aggregation handoff

The capture record preserves raw candidate IDs and exact links. `perceptual-region-v1`, defined in the mapping registry, reduces candidates to the 650-object budget. Every aggregate retains all member IDs and its aggregation rule; the viewer reports inspected nodes and rendered regions separately.

## Screenshot boundary

The screenshot is a same-scan, 1440 × 900 orientation image captured as close as practical to geometry extraction. It is not used to infer DOM, weight, causality, or visibility. Capture and geometry timestamps are stored so the viewer can disclose a material gap.

The page is not scrolled, clicked, animated by DOM X-Ray, or restyled before the screenshot. If the screenshot fails, metric evidence can remain valid, but the missing orientation image is explicit.

## Result status

- **complete:** all evidence required by the selected hero is complete under this protocol; nonmaterial limitations may remain.
- **partial:** usable evidence exists, but a limit or missing measurement materially narrows possible claims.
- **interstitial:** the captured page is a login wall, consent screen, CAPTCHA, bot challenge, or error document rather than the intended destination.
- **blocked:** policy rejected the target before a scene could be created.
- **failed:** no useful, safe record could be completed.

Blocked and failed records contain no simulated cutaway. Interstitial records can show the captured orientation state but cannot emit a hero insight about the intended page.

## Reproducibility

A shared result always renders the immutable scan record with its recorded schema, scanner, and mapping versions. Opening a shared link never silently rescans the target. A protocol change produces a new version; old results keep their original interpretation.

## Primary references

- [MDN: `getBoundingClientRect()`](https://developer.mozilla.org/en-US/docs/Web/API/Element/getBoundingClientRect)
- [Chrome DevTools Protocol: Network domain](https://chromedevtools.github.io/devtools-protocol/tot/Network/)
- [Playwright: BrowserContext](https://playwright.dev/docs/api/class-browsercontext)
- [Playwright: service workers](https://playwright.dev/docs/service-workers)
- [WICG: Layout Instability](https://wicg.github.io/layout-instability/)
- [Public Suffix List](https://publicsuffix.org/)
