# DOM X-Ray Scanner Threat Model

Status: release-blocking baseline v0.1

## Security objective

An anonymous visitor may ask DOM X-Ray to observe one public page, but that request must not turn the scanner into a private-network browser, credential relay, state-changing bot, denial-of-service amplifier, or script-delivery path to shared-result viewers.

The scanner is hostile-input infrastructure. The submitted URL, every redirect, DNS answer, response, page script, title, selector, screenshot, and generated share field is untrusted.

## Trust boundaries

1. **Public client → scan API:** anonymous and abuse-prone.
2. **Scan API → URL/DNS policy:** all names and addresses are untrusted until proven public and allowed.
3. **Policy → browser worker:** the target page is actively hostile.
4. **Browser worker → normalized scan record:** only allowlisted evidence fields cross this boundary.
5. **Scan record → viewer/exporter:** stored strings and images remain untrusted content.
6. **Public result → shared viewer:** no live target code or implicit rescanning crosses this boundary.

## Protected assets

- Host and cloud metadata services.
- Private, loopback, link-local, carrier-grade NAT, multicast, and internal networks reachable from the scanner.
- Scanner secrets, filesystem, process namespace, browser profile, and neighboring workloads.
- Service availability and scan/media-generation budget.
- Cross-scan isolation and visitor privacy.
- Integrity of measurements and public claims.
- Shared viewers who open a result.
- Public sites whose content appears in a screenshot or result.

## Release-blocking threats and controls

| Threat | Consequence | Required controls | Verification |
|---|---|---|---|
| Direct SSRF | Access to localhost, private services, or metadata endpoints | Strict HTTP(S) parser; approved ports; A/AAAA resolution; reject special-use ranges; public-only egress firewall/proxy | Unit corpus for IPv4/IPv6 forms and live integration tests against denied ranges |
| Redirect SSRF | Public URL redirects into a forbidden network | Re-parse, re-resolve, and revalidate every redirect before following | Public-to-private redirect fixture is blocked |
| DNS rebinding | Host resolves public during validation and private during navigation | Resolve through controlled resolver; bind requests to validated public addresses where possible; enforce the same policy again at network egress | Rebinding fixture cannot reach a private listener |
| Subresource SSRF | Public page requests private or metadata resources | Apply destination policy to every browser request, not only main navigation | Malicious page with private image/fetch/iframe requests records blocks and cannot connect |
| Browser escape | Malicious page exploits the browser or host | Current pinned Chromium; browser sandbox plus non-root container; no host mounts/secrets; restricted syscalls/capabilities; disposable worker; patched runtime | Image/dependency scanning and documented patch SLA; container escape review before launch |
| State-changing requests | Scanner submits forms, triggers APIs, or generates side effects | No user input or credentials; reject target query parameters; allow only `GET`/`HEAD`/required `OPTIONS`; abort other methods, downloads, external protocols, permissions, and popups; no automatic navigation retry; per-origin cooling/deduplication; honest crawler identity; robots/opt-out policy; explicitly accept that hostile GET endpoints can still mutate state | Fixtures attempt each blocked method; an unsafe GET fixture proves no credentials, no retry, and cooling-window enforcement |
| Credential or state leakage | One scan inherits another scan's identity | Fresh non-persistent context; no imported storage; no proxy credentials visible to page; destroy context and temporary files after scan | Canary cookies/storage never appear in a later scan |
| Secret capture | Query tokens, headers, form data, or high-entropy selectors enter storage/logs | Reject URL credentials; redact query values/fragments; never persist bodies, headers, HTML, page text, form values, cookies, or storage; sanitize selectors | Secret-seeded fixture leaves no canary in record, logs, screenshot metadata, or analytics |
| Resource exhaustion | Infinite page, decompression bomb, huge media, request flood, browser fork, long script | Wall-time, request, response, total-byte, redirect, DOM, page, process, concurrency, and output-size caps; worker termination; global queue backpressure | Each cap has a deterministic fixture and observable termination code |
| Scan amplification/abuse | Anonymous API becomes a traffic or cost weapon | IP/network and anonymous-session rate limits; per-origin cooling; challenge after threshold; queue quotas; reject repeated identical work through safe caching | Load test verifies caps and no unbounded origin fan-out |
| Stored XSS / injection | Target strings execute in viewer, captions, Open Graph, or export pipeline | Treat all text as text nodes; schema validation; output encoding; restrictive CSP; no target HTML; safe image content types; bounded fonts; no SVG from target | Payload corpus remains inert in viewer, metadata, and rendered poster/video |
| Live target execution in results | Shared viewers run target code or reveal their IP to target | Results render immutable normalized data and stored raster only; never embed the live page or load target resources client-side | Network assertion: result page contacts no target origin |
| Screenshot privacy/copyright abuse | Public-but-sensitive material is reshared without context | Results are unlisted until explicit publish/share; preview before export; target/final host visible; deletion capability; report/takedown path; short documented retention | Publish flow and takedown drill before private launch |
| Claim manipulation | Target page changes behavior for the scanner or injects misleading strings | Hero facts compute only from normalized measurements; page copy cannot become a claim; capture conditions and interstitial status visible | Hostile title/text cannot alter metrics or hero templates |
| Artifact mismatch | Poster/video claims differ from stored scan | Generate all surfaces from immutable scan ID and mapping version; assert numeric/text equivalence | Golden test compares viewer, poster, video metadata, and record |

## URL policy

The scan API accepts a single absolute URL and applies all of these rules before enqueueing:

- Scheme is `http` or `https`; normalize bare domains in the client before submission.
- Reject leading/trailing ASCII whitespace, raw backslashes, a percent sign in the authority, username/password, target query parameters, fragments, and a trailing-dot hostname.
- Ports are 80 or 443 in V1.
- Parse with one pinned WHATWG URL/UTS #46 implementation shared by the API and worker. Lowercase scheme/host, apply nontransitional IDNA processing, normalize default ports and dot segments, serialize, reparse, and require the same host/port result.
- Reject ambiguous numeric IPv4 forms. An IPv4 literal must be four decimal octets; an IPv6 literal must be bracketed and survive canonical round-trip parsing.
- Resolve every A and AAAA answer. Reject the request if any usable answer is forbidden; do not select only the public answer.
- Reject unspecified, loopback, private, link-local, shared-address, multicast, reserved/documentation, unique-local, mapped, and cloud-metadata destinations.
- Reapply the policy to redirects and subresources.
- Limit redirect count and detect loops.
- Keep the original requested host and final host in sanitized evidence.

Redirects and subresources may contain queries required by the site, but query values are never stored or logged. Their scheme/authority/IDNA/IP/port validation is identical to the initial target and is independently enforced at egress. The exact parser and IDNA package versions plus a cross-layer conformance corpus must be committed when the stack is selected.

Application validation is defense in depth; the worker's network namespace or egress proxy must independently prevent access to forbidden ranges.

Gate 0 fixture evidence now proves a local egress proxy can preserve an allowed cross-host 302 → 307 → 200 chain while refusing private-literal, credentialed, disallowed-scheme, cyclic, and over-limit redirect targets before those targets reach the fixture server. This is deliberately narrower than production SSRF proof: public DNS resolution, all special-use ranges, rebinding, HTTPS tunneling, and deployment-level egress enforcement remain release blockers.

The same local proxy now proves inclusive request admission, per-response wire-byte, and cumulative wire-byte limits. The triggering request is rejected before origin contact; an oversized response is read only through one boundary-detection byte and is never relayed to Chromium; and the resulting local limit response cannot become resource-mass or whole-load evidence. Synthetic responses use independently random 128-bit markers, origin responses have that marker header stripped, only the first observed match is trusted, and no marker persists in normalized evidence. A hostile origin therefore cannot convert its own 509 into a trusted boundary event, while a page or service worker that learns and replays a used marker cannot retarget later evidence. These are deterministic enforcement semantics, not a production control: the deployment egress layer must reproduce them under concurrent workers and hostile public origins.

## Worker isolation profile

- One disposable non-root browser context per scan; prefer one disposable worker/container per small bounded batch.
- Browser sandbox remains enabled. Containerization is not treated as a replacement for it.
- No cloud credentials, source-control credentials, developer tokens, SSH agents, or host browser profile in the worker.
- Read-only runtime filesystem plus a bounded temporary directory.
- No host network mode, Docker socket, device access, clipboard, microphone, camera, geolocation, notifications, USB, Bluetooth, serial, or filesystem permissions.
- Public egress only through the enforcement layer.
- CPU, memory, process, file-size, and wall-time limits with a supervisor capable of terminating the full process tree.
- Scan record is sent through a narrow, schema-validated channel; temporary browser data is destroyed.

## Viewer and exporter controls

- Render target strings as inert text and cap length before layout.
- Apply a CSP that disallows target-origin scripts, frames, connections, fonts, and media.
- Store screenshots in a non-executable raster format with server-controlled content type and attachment behavior where appropriate.
- Do not proxy arbitrary target assets through the viewer.
- Poster/video renderers receive normalized JSON and stored raster references only.
- Open Graph titles/descriptions use product-owned templates and bounded sanitized fields.
- Shared links use opaque, unguessable IDs and never contain the original URL's query string.
- No-login deletion uses a separate high-entropy deletion token that is never embedded in the public result URL.

## Abuse, retention, and incident requirements

Before any public launch, the project needs:

- A documented raw scan/screenshot retention period and automated deletion job.
- A user-visible deletion path for no-login scans.
- A report/takedown path and response target.
- A published scanner user-agent, robots/acceptable-use policy, target-owner opt-out mechanism, and per-origin cooling window.
- An emergency scanner kill switch that preserves existing safe result viewing.
- Per-scan audit fields for policy decisions without retaining sensitive request data.
- A patched-browser policy and owner.
- Queue, resource, and cost alarms.
- An incident runbook for SSRF, browser compromise, harmful content, secret leakage, and abusive scanning.

Retention duration, moderation, robots/acceptable-use, opt-out, and residual GET-side-effect policy remain product/legal/security decisions. Public scanning cannot launch while they are unspecified.

## Security gate

The public URL field remains disabled outside local/allowlisted environments until all release-blocking rows have automated evidence. A visually complete demo is not authority to expose the scanner.

The fallback release is a fixture-only or tightly allowlisted experience. If public URL scanning cannot pass the network-policy and isolation suite, public scanning stops; safety is not traded for scan coverage.
