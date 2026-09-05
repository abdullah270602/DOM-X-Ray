# Deterministic Browser Fixtures

These pages are Gate 0 instrumentation evidence, not the public application stack. A loopback-only Python server emits response bodies with exact declared sizes. A local policy proxy maps reserved `.test` hosts to that server, relays response bytes unchanged, and validates redirect targets before Chromium receives them. The verifier then compares:

- every document element evaluated against the area, viewport, display, visibility, opacity, and nonvisual-tag candidate rules;
- five explicit hidden/tiny/offscreen exclusions, one partially clipped inclusion retaining its raw rectangle, and every hand-marked geometry expectation within 1 CSS pixel;
- deterministic preorder IDs, nearest-represented parent links, sanitized selectors, and a high-entropy selector canary;
- exact image URL-to-element links—including one URL reused by two elements—while stylesheets, fonts, scripts, and fetches remain page-level;
- identical node, nearest-candidate parent, raw depth, stacking-context, geometry, selector, count, redirect-chain, and attribution fingerprints across repeated clean and redirect captures;
- every `Network.loadingFinished.encodedDataLength` total against the exact HTTP bytes emitted by the server;
- the same CDP total against declared body payload within the product's 2% tolerance;
- the fixed 1440 × 900, DPR 1, `en-US`, UTC profile, cold cache by default plus one explicit mixed-cache source fixture;
- the post-DOMContentLoaded quiet window, including the image-heavy fixture's mutation reset;
- four external requests collapsing into three registrable-domain fixture hubs;
- a 723-candidate page reducing to exactly 650 rendered regions, with 73 omitted candidate IDs retained once as aggregate members and preorder order deciding an otherwise tied cutoff;
- a cross-host 302 → 307 → 200 navigation retaining all three document responses, ordered hop/predecessor identity, exact wire bytes, first/third-party classification against the final page domain, and no redirect-query canary in the scan or fixture ledgers;
- two sequential fetches of one cacheable asset stored as network then cache, with a measured-zero cache transfer and exactly one origin hit;
- a worker-produced fetch stored as service-worker rather than network, with zero page-session transfer bytes and no origin hit, while the separately fetched worker script is disclosed as unobserved worker-target traffic that makes the scan partial;
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

The loopback policy proxy exists only inside this deterministic proof. Passing it proves the named redirect behavior but not production public-IP resolution, an enforceable deployment egress boundary, DNS-rebinding resistance, full worker-target accounting, cooling-window enforcement, or unsafe-GET containment. The localhost service-worker exception is scoped to the test harness and does not weaken the public-target boundary. Those remaining controls are explicit Gate 0 work.
