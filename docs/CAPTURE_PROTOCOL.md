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

Playwright non-persistent browser contexts do not write browsing data to disk. The scanner still destroys every context after one scan and never reuses its storage state. The Gate 0 isolation fixture performs repeated captures and fails if the later context sees the earlier context's local storage, session storage, or cookie.

## Bounded timeline

1. Parse and normalize the requested URL, reject embedded credentials, resolve DNS, and apply the network policy before Chromium sees it.
2. Create a fresh context and page. Deny permissions and access to local or private networks; observe and immediately cancel downloads and close additional pages without retaining their content-bearing fields.
3. Install the layout-shift observer before navigation and enable the Chrome DevTools Protocol Network domain.
4. Navigate toward `DOMContentLoaded` with a 10-second navigation ceiling.
5. After `DOMContentLoaded`, start a 750 ms quiet timer no earlier than 500 ms after that event. Check the timer every 50 ms and reset it on any qualifying request completion/failure, qualifying DOM mutation, or layout-shift entry defined below. The timer cannot expire while a qualifying request remains active.
6. Capture only after `document.readyState === "complete"` and the quiet timer expires. Stop waiting at 12 seconds from navigation start even if that never occurs. A usable document that misses either condition becomes partial with `document-not-complete` or `settle-timeout`; an unevaluable document fails with `timeout`.
7. In one bounded capture window, read DOM geometry and styles, take the viewport screenshot, close the observation window, and finalize network records.
8. Finish transformation and record persistence inside a 15-second scanner hard limit. The remaining product budget is reserved for delivery and first render.

The process-level clock begins immediately before the disposable worker is spawned and ends only after that worker exits. At the default ceiling, the supervisor reserves the final 500 ms for process-tree termination, so a result must be committed before the 14.5-second acceptance boundary and the whole call must return by 15 seconds. Queue time precedes this worker clock but remains part of the product's 20-second submit-to-cutaway latency metric; delivery and first render follow it.

Workers receive a fresh result destination and an unpredictable supervisor nonce. Standard streams are discarded. A transport envelope is eligible for schema validation only when the worker exits zero and leaves one regular UTF-8 JSON file of at most 4 MB containing the matching nonce and a `result` member. Missing, stale, symlinked, malformed, wrong-nonce, oversized, crashed, or timed-out artifacts are ineligible. This boundary does not itself prove that `result` is a valid scan record; the caller must run the JSON Schema and cross-record semantic validators before persistence or rendering. The worker contract uses a same-directory temporary file and atomic replace; the parent never treats post-timeout partial geometry as a scan record. Injectable proof deadlines are restricted to 1–15 seconds so cleanup always retains a nonzero reserved budget.

Helper callers can lower `max_result_bytes` while the scan-record default stays
4,000,000 bytes. Values above that hard ceiling or nonpositive/noninteger values
are rejected before launch; size is checked before supervisor JSON parsing. The
bounded DNS adapter uses a 2,048-byte envelope (`BOUNDED_RESOLVER.md`).

The local supervisor starts a new POSIX session and kills its process group. On Windows it creates the worker suspended, assigns it to a kill-on-close Job Object, and resumes it only after containment is active. Its deterministic process proof launches pinned Chromium, reaches a post-capture hang, fires the outer deadline twice, and verifies the recorded Chromium descendants are gone. A separate fixture worker owns Playwright, Chromium, and the local egress proxy; runs the real probe for complete, byte-limited, service-worker, and never-settling captures; atomically publishes a nonce-scoped envelope; and leaves schema plus semantic validation to the caller after transport eligibility. Its exact-type config parser rejects coercible booleans and numbers, and a real post-capture delay proves the supervisor withholds the result at timeout. This binds the reusable local process boundary to the actual Gate 0 capture path without claiming a production service. The eventual API/queue worker and disposable-container kill still have to adopt it; a page timeout or `Process.terminate()` alone does not satisfy this requirement.

`scanner/destination_policy.py` is the stack-independent URL/DNS seam for that eventual worker boundary. Each initial, redirect, or subresource call is parsed and resolved independently through an injected resolver; missing, malformed, excessive, mixed public/private, non-global, multicast, mapped, and transition-mechanism answers fail closed. Successful validation returns an in-memory address grant for a connector to pin rather than re-resolve. Initial targets reject credentials and query/fragment delimiters. Until the application stack selects and pins the shared WHATWG/UTS #46 implementation, non-ASCII hostnames fail closed. The deterministic verifier uses no network and proves a public first answer followed by a private answer cannot invoke the connector twice. It does not select a resolver, implement HTTPS tunneling, or enforce the deployment network namespace.

Qualifying network resets are `loadingFinished` or `loadingFailed` events for Document, Stylesheet, Image, Media, Font, Script, XHR, and Fetch requests owned by the page or its service worker. Any such request remains active from `requestWillBeSent`—or from a later qualifying response classification—until its finish/failure event. WebSocket, EventSource, Ping/beacon, Preflight, and other intentionally open streams do not reset the quiet timer; their presence and unfinished byte values are recorded as limitations.

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
- 100 combined popup/download observations; every popup is closed and every download is cancelled. Later events remain denied, but per-type counts saturate and make the scan explicitly partial.
- 15 seconds total scanner wall time.

When a cap is reached, the scanner stops the affected collection, records the exact limit, marks the scan partial when interpretation is materially incomplete, and suppresses any invalidated hero candidate.

The local Gate 0 egress proxy now enforces the three network budgets rather than calculating them only after capture. The request boundary is inclusive: the request that reaches the configured observed-request count becomes a local 509 limit response and is not forwarded to the origin. The per-response and whole-capture byte boundaries count upstream HTTP wire bytes. The proxy reads at most the active boundary plus one detection byte, closes the upstream response, and does not relay the oversized response to Chromium. The small local 509 response remains visible as a resource record but is excluded from page-byte and resource-mass claims by an explicit limitation. Every admitted request also receives a privacy-minimized transient observation containing its query-free URL, scan-scoped opaque full-URL identity, method, Fetch Metadata destination, outcome, status, exact completed wire-byte counts, and only the names—not values—of sensitive header classes seen before stripping; oversized rejects retain the bounded upstream prefix read and leave the completed upstream length unknown. It contains no header values or body and is never published. Browser-delivered bytes become exact only after the socket write succeeds. Every block receives an independent random 128-bit identifier, correlating proxy enforcement with the exact CDP response when sanitized method/URL pairs repeat. The first matching CDP occurrence consumes that identifier; later page or service-worker replays remain ordinary page-controlled responses. The proxy strips the same header name from all origin responses, and identifiers are never persisted in the public scan record. This instrument-scoped provenance prevents synthetic main-document 509s, origin forgery, and browser-level marker replay from being misclassified; an origin's own 509 remains an `http-error-status-v1` interstitial.

Browser records disclose `requestLimit`, `perResponseByteLimit`, `totalByteLimit`, and `auxiliaryEventLimit`. Tests may lower them, but the probe rejects zero, booleans, and values above the production ceilings. A fired request boundary adds `limitsReached: ["requests"]`; either byte boundary adds `limitsReached: ["bytes"]`; and overflow of the combined popup/download counter adds `limitsReached: ["auxiliary-events"]`. Each produces an honest partial `resource-limit` result with the dependent interpretations identified. The deterministic proxy proves request/byte enforcement semantics and exact admitted-byte accounting, but it remains local proof infrastructure—not the production public-DNS or egress boundary.

`popupAttemptCount` and `downloadAttemptCount` contain only saturated event counts. The scanner installs a download handler on every created page, closes each popup and cancels each download synchronously, fails the capture if either containment action fails, and requires that no auxiliary page remain at the capture point. It never reads or retains popup URLs, window names, suggested filenames, download bodies, or response headers. The adversarial fixture seeds the popup URL/window name and both main-page and popup-page download URL/filename pairs with six canaries; none reaches the scan record, proxy ledger, or server ledger. The normal event fingerprint and the one-event truncation fingerprint both repeat under pinned Chromium.

For the DOM boundary, the scanner reads the top-level document's element count once, then evaluates at most the first 20,000 elements in deterministic document order. If more exist, `rawDomNodeCount` remains the exact observed collection length, `inspectedNodeCount` records the bounded prefix, `limitsReached` includes `dom-nodes`, and a scan limitation invalidates complete geometry, candidate-count, maximum-depth, login-gate, scene-completeness, and visual-region interpretations. The probe never silently calls that prefix the whole page.

Within the inspected prefix, at most 5,000 qualifying geometry candidates are retained, again in deterministic document order. Discovering another qualifying element sets `limitsReached: ["candidates"]`, produces a partial `resource-limit` record, and invalidates complete geometry, candidate-count, scene-completeness, and visual-region interpretations. This boundary precedes perceptual aggregation and is distinct from the 650 rendered-scene budget. Tests may lower either boundary, but the probe rejects values above the production hard ceilings. The two boundaries are exercised at smaller injected values in deterministic fixtures so the production defaults remain testable without a 20,000-node test artifact.

## Network measurement

### Canonical transfer value

For an ordinary completed request, `Network.loadingFinished.encodedDataLength` is the canonical v0.1 value and is described to visitors as **bytes received during this captured load**. Chrome documents it as the total number of bytes received for that request. The named `cdp-plus-egress-service-worker-bootstrap-v1` rule has one narrow exception: an attached worker bootstrap may use the enforcing proxy's exact bytes delivered to Chromium when a single relayed `Sec-Fetch-Dest: serviceworker` observation uniquely matches a single bootstrap by method and scan-scoped opaque full-URL identity. It is not decoded size, memory use, execution cost, energy, carbon, or a speed verdict.

The Gate 0 browser fixtures compare each canonical value with the exact HTTP status-line, header, and body bytes emitted by a deterministic local server. They also require the total to remain within 2% of the separately declared response-body payload. The wire-byte equality proves the instrument; the body-payload tolerance keeps the fixture expectations understandable. Production claims use only the record's named transfer-accounting rule, never the body-only reference.

The scanner listens to:

- `Network.requestWillBeSent` and redirect response data.
- `Network.responseReceived` for response type and cache/service-worker flags.
- `Network.dataReceived` for optional decoded-data accumulation.
- `Network.loadingFinished` for canonical received bytes.
- `Network.loadingFailed` and `Network.requestServedFromCache` for outcome/source state.

Performance Resource Timing may be retained temporarily for diagnostics, but it never silently overwrites the CDP canonical value. If reconciliation is later required, it becomes a new named transfer-accounting rule.

### Request identity and redirects

Each stored resource uses a scanner-generated ID. Redirect hops use `requestId + hopIndex` internally so one reused protocol request ID cannot collapse multiple responses. A hop receives a byte value only when the protocol supplies defensible response data; otherwise its value is `null`.

The normalized record stores `requestChainId`, `redirectHopIndex`, `redirectedFromResourceId`, and `responseStatus` on instrumented resources. Capture-level redirect evidence stores ordered sanitized source/target URLs, status, whether the hop was followed, and any rejection code. `redirectCount` counts followed top-level navigation hops against `redirectLimit`; subresource redirects remain resource evidence but do not consume that main-navigation counter.

The Gate 0 fixture browser sends traffic through a single-scan local policy proxy. The proxy inspects each redirect target before returning its `Location` header, rejects unsafe targets without connecting to them, and relays allowed response bytes after removing the proxy's reserved marker header from origin responses. A Playwright route callback alone is not accepted as redirect enforcement because continuing the initial request can allow Chromium to follow later hops without re-entering that callback. Production still requires the selected stack's independently enforced DNS and public-egress boundary.

HTTP error responses such as 404 or 503 remain completed responses when the network lifecycle completes. A network failure and an HTTP error are different states. The versioned `http-error-status-v1` interstitial classifier uses only the terminal final-hop main-document status and classifies 400–599; it never uses title or body text. A 200 main document with a 404 subresource remains a normal capture, and redirects ending in 200 are classified from that final response rather than an earlier hop.

If a qualifying request has no completed canonical byte value at capture, its transfer source is `unknown` and `transferredBytes` remains `null`; it is never coerced to zero. The record receives a resource-scoped limitation that invalidates that resource's mass plus request-count and whole-load byte claims. The Gate 0 unfinished-response fixture proves this state while the active request holds settlement open until the hard stop.

### Cache and service-worker state

Network, cache, service-worker, and unknown are mutually exclusive stored transfer sources. Source classification gives a service-worker response priority over cache flags, then uses cache, a supplied canonical byte value as network, and otherwise unknown. A zero or missing transfer for a cached/worker response never becomes ordinary zero-mass content.

The Gate 0 mixed-cache fixture deliberately enables cache in one fresh context and fetches the same immutable resource twice. It proves network-then-cache order, an exact measured-zero cache transfer, and one origin hit. Normal capture fixtures and the production profile remain cold-cache observations.

The scanner auto-attaches related service-worker targets before worker execution. Page and worker requests use `(owner target, protocol request ID, redirect hop)` internally; URL equality never deduplicates requests. The normalized `requestOwner` distinguishes page from service-worker initiation. The worker-produced client response remains page-owned and service-worker-sourced, while a worker's own origin fetch is a separate worker-owned network request. This preserves both causal roles without counting the zero-transfer client response as a second network transfer.

Chromium fetches the bootstrap worker script before its target Network domain can emit a trustworthy full-response `loadingFinished` value. In the pinned build, the late worker event exposes only 164 response-header bytes for the 10,164-byte fixture response; Playwright context request events omit that bootstrap. The scanner therefore never uses the late event, refetches the script, or substitutes declared body size. Instead, the required single-scan egress boundary can supply exact delivered wire bytes under `cdp-plus-egress-service-worker-bootstrap-v1`. The proxy derives an opaque keyed identity from the exact in-memory URL, so query-distinct scripts do not collide without retaining the query. Correlation is accepted only for a one-to-one method/opaque-identity group whose proxy destination is `serviceworker`; repeated identical requests remain ambiguous rather than being paired by timing. Missing, pending, blocked, malformed, write-failed, or ambiguous observations preserve `null` bytes and `service-worker-bootstrap-bytes-unavailable`.

The Gate 0 fixture proves exact bootstrap and worker-owned fetch bytes against the origin and proxy wire ledgers, separation from the service-worker-produced client response, stable ownership/source fingerprints across fresh contexts, and conservative rejection of ambiguous or noncanonical proxy observations. The successful five-request capture is complete with zero missing byte values. A missing worker target or unfinished worker request retains its own partial-record limitation.

### Method and residual side-effect boundary

V1 allows page-initiated `GET`, `HEAD`, and required `OPTIONS` requests. It aborts `POST`, `PUT`, `PATCH`, `DELETE`, external-protocol launches, and other methods. Download events are cancelled without accepting or retaining the file. Any blocked method produces a limitation because this can change the page's behavior.

Any observed policy block makes the capture partial and invalidates whole-load byte interpretation plus the page-behavior claim. A blocked unsafe method to an otherwise allowed public URL may remain as a resource-scoped record of the proxy's completed 403 response, but its policy-response bytes are not usable as that resource's mass. A private, credentialed, disallowed-scheme, or otherwise forbidden target is never normalized into `resources`; it receives a scan-scoped limitation that also invalidates request count. The fixture-only proxy block log is required whenever that proxy is used so these events cannot disappear between enforcement and normalization.

This does **not** prove the scan is side-effect free. HTTP defines GET/HEAD as safe intent, but real servers can misuse them. A public page can also trigger anonymous side effects through subresource GETs. The scanner therefore accepts no target query parameters or user-provided headers; strips Cookie, Authorization, Proxy-Authorization, and Referer at egress; never publishes page-generated query values; identifies itself honestly; honors the approved robots/opt-out policy; deduplicates recent identical scans; applies a strict per-origin cooling window; and never retries a navigation automatically. These controls limit identity, repetition, and amplification rather than pretending to eliminate target-side risk.

Public launch remains blocked until the acceptable-use/robots policy, target-owner opt-out, production per-origin limits, and abuse response are approved and tested. The integration suite includes a deliberately unsafe GET endpoint and proves the scanner reaches it once, does not retry it, strips browser-produced credential/referrer headers before origin contact, reuses a recent identical result, and rejects a different same-origin reservation inside an injected cooling window. The admission primitive requires callers to supply both durations; this fixture does not approve launch values or prove distributed enforcement. The product never claims “no requests changed server state.”

The Gate 0 policy-boundary fixture separately proves that page-initiated `POST` and `DELETE` requests plus literal-private fetch/image requests receive bounded proxy blocks before origin contact. The proxy stores no request body, private target URLs stay outside the normalized record, public block responses receive one-to-one resource limitations, and repeated captures preserve the same policy fingerprint. This is local proof infrastructure, not the production DNS/egress or cooling boundary.

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

Among elements that pass this candidate rule, mandatory candidates are the document root and body, semantic landmarks, replaced media (`img`, `video`, `canvas`, `iframe`, SVG roots), exact resource-link targets, recorded layout-shift sources, and nodes that create an inferred stacking context. “Mandatory” means the element must survive aggregation; it does not turn a hidden, zero-area, or off-viewport element into scene geometry.

### DOM boundaries

- Text content, form values, HTML, event listeners, and page storage are not persisted.
- Pseudo-elements are not separate DOM nodes and do not become independent evidence objects.
- Shadow DOM may be counted and inspected only when open and reachable; closed roots remain opaque and are disclosed.
- Descendant frame DOM is excluded in V1 even when same-origin, preserving one consistent boundary.
- Canvas and iframe contents appear only through the orientation screenshot; the element region itself may be represented.

### Selector sanitization

Selectors are display aids, not stable identity. Under `selector-sanitization-v1`, the scanner keeps the tag name and at most one ID plus two class tokens. A token must be an ASCII identifier no longer than 18 characters; 13–18 character mixed alphanumeric tokens with at least 75% distinct characters are also treated as high entropy. Invalid or high-entropy tokens become the inert `xray-redacted` token, attribute values are never included, and the final display string is truncated to 96 characters. Exact element/resource matching happens in memory before redaction.

`node.parentId` names the nearest represented ancestor after filtering and aggregation, not necessarily the element's direct raw DOM parent. Raw `domDepth` remains the evidence for original ancestry depth; the relationship is never described as a lossless DOM tree.

## Exact element-to-resource links

V1 may create an exact resource link from a replaced element's captured `currentSrc`, `src`, or `poster`, an iframe/source URL, or a computed CSS image URL when its fully resolved URL exactly matches the observed request URL after deterministic canonicalization. Query values may participate in the in-memory match but are never published; only a hash and redacted display URL remain.

Browser initiator data without an exact element URL is `probable-link` or page-level. Scripts, fonts, stylesheets, fetches, XHR, beacons, and unattributed work remain page-level unless a later protocol proves a stronger relationship.

## Stacking-context derivation

`stacking-context-v1` is an explicit heuristic over captured computed styles. It marks the document root and known CSS triggers such as positioned elements with non-auto z-index, fixed/sticky positioning, opacity below one, transforms, filters, perspective, blend mode, isolation, containment, and declared change hints.

The result is called an **inferred CSS stacking context**. It is never called a paint order, compositor layer, GPU layer, or performance cost. The raw trigger is stored as the rule.

## Layout shifts

The observer is installed before navigation and uses `{ type: "layout-shift", buffered: true }` when available. Each entry stores timestamp, score value, `hadRecentInput`, and up to the browser-supplied source nodes with previous/current rectangles.

Source rectangles identify elements that moved; they do not identify the root cause. Entries with recent input remain in evidence but are excluded from default headline candidates. V1 can show recorded displacement as a secondary inspection detail, but Motion remains outside the primary experience.

The API and its source-attribution rectangles are not uniformly supported across browsers. That is acceptable for a pinned Chromium instrument but must remain a limitation of the claim.

## Aggregation handoff

The capture record preserves raw candidate IDs and exact links. `rawDomNodeCount` is every observed top-level-document element; `inspectedNodeCount` is every element actually tested before a cap; `candidateNodeCount` is the qualifying pre-aggregation set; `aggregatedNodeCount` is the number omitted into aggregate membership; and `renderedRegionCount` is the final scene-instantiated set. `perceptual-region-v1`, defined in the mapping registry, reduces candidates to the 650-object budget. Every aggregate retains all member IDs and its aggregation rule.

Ordinary records contain only represented nodes; an absent `sceneIncluded` value therefore means true. When mandatory candidates alone exceed the available scene slots, `mandatory-overflow-v1` keeps all candidate records so exact rectangles, selectors, ancestry, and resource links remain inspectable, marks only bounded representatives with `sceneIncluded: true`, and marks the remainder false while attaching each ID once to its nearest scene ancestor. The capture becomes partial with `failureCode: resource-limit`, `limitsReached: ["regions"]`, and a limitation that forbids a complete-scene claim. Evidence-only nodes are never instantiated by the renderer or counted in `renderedRegionCount`.

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

The versioned `login-gate-structural-v1` classifier requires exactly one visible form containing a visible identity input, password input, and submit control, with no competing visible text, media, or content landmark outside that form and its ancestors. It does not classify from title or body text, never submits the form, and does not persist field values. The Gate 0 HTTP 200 login-wall fixture proves the positive case plus negative guards for missing credential controls, a second form, and competing content. The separate `http-error-status-v1` classifier takes precedence when the final main document itself returned 400–599. False negatives are preferred to labeling ordinary page content as an interstitial. Consent screens and challenges remain named classes but are not emitted yet: current dialog/iframe structure cannot distinguish them safely from ordinary application UI without trusting attacker-controlled copy or provider markers.

## Reproducibility

A shared result always renders the immutable scan record with its recorded schema, scanner, and mapping versions. Opening a shared link never silently rescans the target. A protocol change produces a new version; old results keep their original interpretation.

## Primary references

- [MDN: `getBoundingClientRect()`](https://developer.mozilla.org/en-US/docs/Web/API/Element/getBoundingClientRect)
- [Chrome DevTools Protocol: Network domain](https://chromedevtools.github.io/devtools-protocol/tot/Network/)
- [Playwright: BrowserContext](https://playwright.dev/docs/api/class-browsercontext)
- [Playwright: service workers](https://playwright.dev/docs/service-workers)
- [WICG: Layout Instability](https://wicg.github.io/layout-instability/)
- [Public Suffix List](https://publicsuffix.org/)
