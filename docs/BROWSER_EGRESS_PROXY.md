# Browser HTTPS egress proxy

Status: real Chromium and full fixture-capture integration evidence; public capture and containment open.

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
`ScanCertificateIssuer` now provides independent per-scan roots and host keys,
fresh contexts, and bounded issuance; see `SCAN_CERTIFICATES.md`. Installing its
root only in the deployed disposable browser remains required evidence.

The content-free diagnostic events contain outcome/status/counts and random
block IDs. A separate scan-local capture ledger retains redacted URL paths
(no credentials/query/fragment), method, fetch destination, a scan-keyed
query-sensitive opaque identity, status, and wire evidence. Neither ledger
retains headers or bodies; neither is a public artifact. CONNECT itself is
not an origin fetch. Keys cannot correlate across scans.

`snapshot_observations`, `correlation_key`, and `blocked` implement the probe's
correlation interface. Block authority is recorded before sending its random
receipt. Rejected redirects are attributed to the source request; the
content-free exchange error does not expose the rejected target. Bootstrap bytes
are used only for a unique method/opaque-key match to a successful serviceworker
response. Ambiguous matches stay unknown. Browser wire bytes mean serialized
decrypted HTTP headers plus body, not TLS overhead or upstream bytes. Failed
browser writes retain upstream evidence but leave browser wire bytes unknown.

Observations and block authority are independently capped at 1,000 rows; tests
may lower the bound. Overflow rejects origin contact with a 509 receipt, retains
block authority while capacity remains, and sets `ledger.truncated`. Diagnostic
overflow sets `events_truncated`. Pass a callback combining both to the probe's
`egress_observations_truncated`: truncation invalidates request counts/total bytes
and forces a partial resource-limit result. The opt-in HTTPS fixture path
requires this callback and the proxy/ledger. Use fresh proxy/exchange instances
for each scan. Public targets are still rejected by the fixture capture guard.

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
An incomplete browser request left open is closed during teardown. Fresh proxy
instances also drive the full capture probe: a complete HTTPS document with
service-worker bootstrap evidence, a real one-row ledger overflow with no extra
origin contact, and an oversized HTTPS main document producing a partial
resource-limit result rather than an origin-error interstitial. All three
records pass JSON Schema and cross-record semantic validation. The original
31 controlled browser fixtures remain regression coverage. A deterministic
browser-write failure proves upstream evidence survives without inventing
delivered bytes or an additional policy block. Ledger tests cover query
separation, canonical identities, secret redaction, caps, and detached snapshots.

Origin sockets are deterministic fixtures in this test. Real pinned origin TLS
and an anonymous public HEAD have separate evidence in `SCAN_TRANSPORT.md` and
`ORIGIN_EXCHANGE.md`. This combination has not yet been exercised with public
page capture, a deployed resolver, certificate issuer, or independent firewall.

Chromium source for its scoped test trust:
[IgnoreErrorsCertVerifier](https://chromium.googlesource.com/chromium/src/+/main/services/network/ignore_errors_cert_verifier.h).

Next: integrate disposable-browser root trust and a bounded resolver, verify
browser bypass attempts in the container network, then run
representative public-page capture. Public arbitrary scanning remains disabled.
