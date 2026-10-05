# Browser HTTPS egress proxy

Status: real Chromium integration evidence; production capture and containment open.

`scanner/browser_egress_proxy.py` is a per-scan loopback listener in front of
`OriginExchange`. HTTP requests use absolute targets. HTTPS CONNECT is checked
against `DestinationPolicy`, then browser TLS is terminated with a certificate
from a trusted host-specific context factory. The decrypted origin-form request
is passed through the same anonymous header, pinning, framing, and byte-budget
path. The proxy does not relay an opaque CONNECT tunnel to the origin.

CONNECT authority, its Host, TLS SNI, and the decrypted request's Host must agree.
Malformed authority delimiters, duplicate/missing Host, request bodies,
Transfer-Encoding, Expect, Upgrade, and unsupported methods are rejected before
origin contact. Each connection carries one request and then closes. Incoming
headers are bounded to 64 KiB/100 fields. Sixteen handler slots and a 15-second
socket deadline bound browser parsing and TLS handshakes.

TLS contexts must be fresh, configured for server use, and contain a leaf bound
to the requested host. The proxy forces TLS 1.2+ and HTTP/1.1 ALPN. Browser trust
must be restricted to the disposable browser; never install its signing key in
system trust or disable upstream HTTPS verification. Upstream connections still
use `connect_pinned` with the origin's real hostname and normal certificate
verification. The fixture's Chromium key allowlist is test-only configuration.

The transient ledger contains outcome/status/counts and random block IDs, with
no URLs, request headers, or bodies. Oversized responses retain exact numeric
received-byte evidence. A 1,000-event cap sets `events_truncated`; capture
integration must disclose that limit instead of claiming complete observations.
This ledger is not yet the probe's correlated request/response ledger.

Shutdown stops acceptance, closes active browser sockets, and waits up to five
seconds for handlers. It reports failure if a handler remains. Trusted
synchronous DNS or certificate factories can still block: deployment must bound
both and destroy the entire disposable worker after its hard deadline. An open
origin exchange is bounded by its own socket deadline. A loopback listener and
Chromium proxy setting are not independent network containment.

## Reproducible evidence

Run `python scripts/verify_browser_egress_proxy.py` with pinned Playwright
Chromium and OpenSSL installed. On Windows the verifier also recognizes Git's
bundled OpenSSL. It generates a one-day temporary leaf/key, removes them at
completion, and scopes browser certificate-error allowance to that key's SPKI.
No system trust is changed.

The verifier opens real Chromium HTTPS and proves document, script, service-worker
bootstrap, and worker activation requests reach the exchange. It rejects a
private redirect and a 10,001-byte response under a 10,000-byte cap, inspects
block receipts, and tests decrypted Host and TLS SNI pivots plus body framing.
An incomplete browser request left open is closed during teardown.

Origin sockets are deterministic fixtures in this test. Real pinned origin TLS
and an anonymous public HEAD have separate evidence in `SCAN_TRANSPORT.md` and
`ORIGIN_EXCHANGE.md`. This combination has not yet been exercised with the full
capture probe, deployed resolver, certificate issuer, or independent firewall.

Chromium source for its scoped test trust:
[IgnoreErrorsCertVerifier](https://chromium.googlesource.com/chromium/src/+/main/services/network/ignore_errors_cert_verifier.h).

Next: integrate the policy-block and transient wire ledger with the capture probe,
issue fresh host-bound certificates in the disposable worker, select a bounded
resolver, verify browser bypass attempts in the container network, then run
representative public-page capture. Public arbitrary scanning remains disabled.
