# Bounded origin exchange

Status: origin-side integration evidence; browser proxy and deployment proof open.

`scanner/origin_exchange.py` composes `DestinationPolicy` and `connect_pinned`
for one scan's anonymous HTTP origin requests. It is intended behind an enforcing
browser proxy that can inspect HTTPS. It has no listener or browser TLS
interception and is not wired to the public API.

## Request and response contract

The exchange accepts only bodyless GET, HEAD, and OPTIONS. It constructs Host
from the validated grant and sends the original path/query over a pinned socket.
Only a small request-header allowlist is forwarded. Cookies, authorization,
proxy credentials, referrers, browser identity, and caller-provided Host do not
reach the origin. A caller supplies the scanner User-Agent explicitly; the
published production identity/robots/opt-out decision remains open.

Responses are buffered before release and parsed with Python's
[HTTPResponse](https://docs.python.org/3/library/http.client.html). Ambiguous
Content-Length/Transfer-Encoding, duplicate Location, folded/invalid headers,
unsupported transfer coding, and bytes beyond one framed response are rejected.
Chunked framing is decoded and rebuilt with a single length. Content-encoded
payload bytes remain encoded; this layer does not decompress. Hop-by-hop fields,
connection-nominated fields, Set-Cookie, and the reserved policy block marker
are stripped. Trailer fields are never forwarded. HEAD keeps the representation
length without emitting a body. Interim/upgrade responses are currently rejected;
the eventual browser must disclose unsupported captures honestly.

A redirect Location is independently resolved and checked before the response
is returned. The exchange does not follow it or cache the resulting grant.
The browser's subsequent request is checked again, so a public-to-private DNS
change is rejected before the next origin connection. Redirect-chain count,
loop handling, and policy block ID correlation belong to the browser proxy.

## Limits and deadline

The defaults match the existing fixture ceilings: 500 observed requests,
20,000,000 raw HTTP response bytes, and 50,000,000 received bytes per scan.
The inclusive request fence rejects the triggering request before contact.
The raw HTTP byte count includes headers, chunk framing, and trailers, not TLS
record overhead. A read beyond either byte ceiling stops after at most one
detection byte. Every received byte is charged, including rejected, malformed,
and interrupted responses. Exhausted scan budgets forbid later origin contact.
Requests are serialized within one scan to make budget reservation exact.

One monotonic deadline includes lock waiting, connection/handshake, send, and
every receive. It is rechecked before admitting the result. Synchronous injected
DNS cannot be interrupted here: deployment must use a bounded resolver and the
whole disposable-worker supervisor. A resolver returning after the deadline
causes rejection without connecting. Socket I/O timeouts and slow-drip traffic
close the socket and return a content-free timeout. No untrusted URL/header/body
is placed in an exception or response representation.
Failures carry only the numeric `upstream_bytes_read` alongside their category,
so the browser proxy can record exact rejected-response byte evidence without
retaining response content.

## Evidence

`python scripts/verify_origin_exchange.py` uses deterministic sockets and DNS.
It covers Host/target binding, credential/cookie/reserved-marker stripping,
redirect checks and rebinding, framing failures and trailing messages, chunked
reconstruction, HEAD semantics, request quota, per-response and aggregate wire
caps, detection-byte boundaries, delayed DNS, slow-drip timeout, and cleanup.

On 2026-10-05, one real anonymous HTTPS HEAD to `www.python.org` through this
exchange returned HTTP 200, 1,209 raw HTTP wire bytes, and zero body bytes.
The system resolver was used only for this smoke test. This is one-machine
evidence, not a production resolver choice or a representative browser benchmark.

The next integration must terminate browser HTTPS with trust scoped to the
disposable browser, preserve Host/SNI identity across both sides, apply the same
path to redirects/subresources/service-worker traffic, bound incoming request
framing, correlate block receipts, and deny every browser route that can bypass
the proxy. Independent container egress enforcement is still required.
Arbitrary public scanning remains disabled.
