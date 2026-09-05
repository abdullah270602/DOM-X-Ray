# Deterministic Browser Fixtures

These pages are Gate 0 instrumentation evidence, not the public application stack. A loopback-only Python server gives Chromium reserved `.test` hostnames and emits response bodies with exact declared sizes. The verifier then compares:

- every document element evaluated against the area, viewport, display, visibility, opacity, and nonvisual-tag candidate rules;
- five explicit hidden/tiny/offscreen exclusions, one partially clipped inclusion retaining its raw rectangle, and every hand-marked geometry expectation within 1 CSS pixel;
- deterministic preorder IDs, nearest-represented parent links, sanitized selectors, and a high-entropy selector canary;
- exact image URL-to-element links—including one URL reused by two elements—while stylesheets, fonts, scripts, and fetches remain page-level;
- identical node, nearest-candidate parent, raw depth, stacking-context, geometry, selector, count, and attribution fingerprints across a repeated clean capture;
- every `Network.loadingFinished.encodedDataLength` total against the exact HTTP bytes emitted by the server;
- the same CDP total against declared body payload within the product's 2% tolerance;
- the fixed 1440 × 900, DPR 1, `en-US`, UTC, cold-cache profile;
- the post-DOMContentLoaded quiet window, including the image-heavy fixture's mutation reset;
- four external requests collapsing into three registrable-domain fixture hubs;
- a 723-candidate page reducing to exactly 650 rendered regions, with 73 omitted candidate IDs retained once as aggregate members and preorder order deciding an otherwise tied cutoff;
- ten local request-policy cases for allowed methods, blocked methods, credentials, schemes, and literal private hosts;
- five fixture-target boundary cases that keep this proof restricted to credential-free, query-free reserved HTTP `.test` pages;
- the exact Chromium version expected from the pinned Playwright dependency.

The fixture-only registrable-domain helper understands reserved `.test` names. It is deliberately not a substitute for the production Public Suffix List implementation.

## Run

```sh
python -m pip install -r requirements-dev.txt
python -m playwright install chromium
python scripts/verify_browser_fixtures.py
```

The host-resolver mapping to loopback exists only inside this proof. Passing it does not prove a public egress firewall, redirect validation, DNS-rebinding resistance, service-worker accounting, cooling-window enforcement, or unsafe-GET containment. Those remain explicit Gate 0 work.
