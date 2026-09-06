# Deterministic Browser Fixtures

These pages are Gate 0 instrumentation evidence, not the public application stack. A loopback-only Python server emits response bodies with exact declared sizes. A local policy proxy maps reserved `.test` hosts to that server, relays admitted response bytes while removing its reserved marker header from origin responses, validates redirect targets, and enforces injected request and byte budgets before Chromium receives them. The verifier then compares:

- every document element on uncapped fixtures—and only the declared deterministic prefix on the capped fixture—evaluated against the area, viewport, display, visibility, opacity, and nonvisual-tag candidate rules;
- five explicit hidden/tiny/offscreen exclusions, one partially clipped inclusion retaining its raw rectangle, and every hand-marked geometry expectation within 1 CSS pixel;
- deterministic preorder IDs, nearest-represented parent links, sanitized selectors, and a high-entropy selector canary;
- exact image URL-to-element links—including one URL reused by two elements—while stylesheets, fonts, scripts, and fetches remain page-level;
- identical node, nearest-candidate parent, raw depth, stacking-context, geometry, selector, count, redirect-chain, attribution, and retained-limit fingerprints across repeated clean, redirect, DOM-limit, candidate-limit, request-limit, response-byte-limit, and total-byte-limit captures;
- every `Network.loadingFinished.encodedDataLength` total against the exact HTTP bytes emitted by the server;
- the same CDP total against declared body payload within the product's 2% tolerance;
- an inclusive request boundary whose triggering request is never forwarded to the origin;
- a per-response boundary that reads only the configured wire-byte allowance plus one detection byte and never relays the oversized upstream response;
- a whole-capture boundary that counts exact previously relayed upstream bytes, reads only the remaining allowance plus one detection byte, and preserves the local limit response only as claim-invalidating evidence;
- all three boundaries firing on the main document without a synthetic 509 being mistaken for a target error page, plus genuine and forged-marker target 509s that remain error-document interstitials;
- two requests whose query-stripped display URLs are identical, with an independently random internal block ID attaching the response limit to the exact second occurrence while remaining absent from normalized evidence;
- a hostile same-origin service worker reading a real block marker and replaying it on a later 509; first-occurrence consumption keeps two subsequent real proxy blocks correctly targeted and leaves the replay page-controlled;
- the fixed 1440 × 900, DPR 1, `en-US`, UTC profile, cold cache by default plus one explicit mixed-cache source fixture;
- the post-DOMContentLoaded quiet window, including the image-heavy fixture's mutation reset;
- four external requests collapsing into three registrable-domain fixture hubs;
- a deterministic first-40-element inspection boundary on a larger document, retaining the exact raw count while producing an explicit partial result that invalidates complete geometry, depth, candidate, scene, and login-gate interpretations;
- a deterministic first-12-geometry-candidate boundary on a fully inspected document, distinct from the later 650-object aggregation budget and reproduced byte-for-byte on repeat;
- a 723-candidate page reducing to exactly 650 rendered regions, with 73 omitted candidate IDs retained once as aggregate members and preorder order deciding an otherwise tied cutoff;
- two same-footprint, evidence-free wrappers collapsing into their represented ancestor while exact image attribution and represented parent links remain intact;
- 654 mandatory candidates producing a partial 650-object overview while four evidence-only nodes—including an exact-linked image with its raw rectangle and symmetric resource link—remain inspectable under `mandatory-overflow-v1`;
- a cross-host 302 → 307 → 200 navigation retaining all three document responses, ordered hop/predecessor identity, exact wire bytes, first/third-party classification against the final page domain, and no redirect-query canary in the scan or fixture ledgers;
- two sequential fetches of one cacheable asset stored as network then cache, with a measured-zero cache transfer and exactly one origin hit;
- a worker-produced client response stored as service-worker rather than network, with zero page-session transfer bytes and no origin hit, plus its worker-owned origin fetch captured once with exact CDP wire bytes and target-qualified identity;
- one URL requested independently as a page image and worker fetch, preserved as two records while only the page-owned image receives exact element attribution;
- the worker bootstrap represented once as service-worker-owned with unknown bytes because its transfer precedes target attachment, forcing a partial record and suppressing request-count and whole-load byte claims;
- an active qualifying fetch preventing quiet-window settlement, retaining `null` bytes and unknown source at the hard stop, and producing a resource-scoped limitation without a retry;
- continuous DOM mutation independently reaching the bounded hard stop while retaining useful but explicitly partial geometry;
- a stable HTTP 200 credential gate classified structurally as an interstitial, retaining orientation geometry while emitting no insight, making no form submission, and storing no form values;
- terminal main-document 404 and 503 responses classified as error-document interstitials from status alone, plus a 200 page with a 404 image proving subresource failures do not trigger the classifier;
- repeated fresh contexts proving that local storage, session storage, and cookies do not cross the scan boundary;
- two unsafe methods and two literal-private subresources rejected by the policy proxy before origin contact, with public block responses retained as targeted evidence and private URLs omitted from the normalized record;
- one deliberately state-changing GET reaching origin exactly once, with recent identical-result reuse and same-origin cooling producing no second contact under an injectable policy clock;
- Cookie, Authorization, Proxy-Authorization, and Referer stripped before origin forwarding, ten cookie/header/query/form/storage/selector canaries absent from normalized and fixture evidence, and an explicit fixture-only scanner user-agent at origin;
- private-literal, credentialed, disallowed-scheme, cyclic, and over-ten-hop redirects rejected at the proxy before the forbidden target reaches the server;
- ten local request-policy cases for allowed methods, blocked methods, credentials, schemes, and literal private hosts;
- five fixture-target boundary cases that keep normal proof traffic restricted to credential-free, query-free reserved HTTP `.test` pages; only the service-worker secure-origin fixture can opt into exact-host `localhost` trust;
- the exact Chromium version expected from the pinned Playwright dependency.

The fixture-only registrable-domain helper understands reserved `.test` names. It is deliberately not a substitute for the production Public Suffix List implementation.

## Run

```sh
python -m pip install -r requirements-dev.txt
python -m playwright install chromium
python scripts/verify_browser_fixtures.py
```

The loopback policy proxy and in-memory admission gate exist only inside this deterministic proof. Passing them proves the named redirect, unsafe-method, literal-private-subresource, sensitive-header, exact-result reuse, and same-origin cooling behavior, but not production public-IP resolution, an enforceable deployment egress boundary, DNS-rebinding resistance, service-worker bootstrap byte accounting, durable distributed rate enforcement, or approved launch durations. The localhost service-worker exception and scanner identity are fixture-scoped and do not weaken or decide the public-target boundary. Those remaining controls are explicit Gate 0 work.
