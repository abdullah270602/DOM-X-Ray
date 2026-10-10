# Local HTTP request framing checkpoint

The local API is a fixed-length endpoint using the standard handler's HTTP/1.0
response protocol. This checkpoint is not general HTTP/1.1 transfer-coding
support, request-smuggling protection for every parser, or deployed proxy-chain
interoperability evidence.

## Policy

Scan POSTs require exactly one Content-Length field. Every Transfer-Encoding
field is rejected, including empty or duplicated fields. Duplicate lengths are
rejected even when equal; comma lists, signs, non-ASCII digits, internal spaces
and non-decimal forms are rejected. Space/tab edge whitespace and leading zeroes
are accepted. Leading zeroes are removed before checking digit count, so huge
decimal values produce an oversize response without unbounded integer parsing.

Malformed framing returns 400; oversize bodies return 413. Both close the
connection and use no-store before scan admission or executor contact. An
EOF-short body also returns 400 before JSON admission, even if its received
prefix is valid JSON. Unsupported media returns 415 and unknown POST paths
return 404 with explicit closure because their bodies remain unread. Artifact
upload refusal remains an empty 405 and does not drain ambiguous framing.

The policy deliberately rejects ambiguous lengths rather than collapsing them,
an option permitted by [RFC 9110 Content-Length](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6).
Incomplete fixed-length bodies and invalid framing must not be treated as
complete messages; see [RFC 9112 message body length](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3).

## Evidence

`scripts/verify_api_request_framing.py` passed in normal and optimized Python
modes on the final source. Owned raw loopback sockets cover 17 invalid/oversize
framing cases, EOF-short valid JSON, unsupported media, unknown POST paths,
three artifact refusal cases, and valid decimal/zero/whitespace controls.
Invalid scan framing creates fixed rejected-job metadata but never calls scan
submission or the executor. Responses are complete, no-store, and do not echo
the private canary; appended requests receive no second response. Valid controls
reach the disabled scanner path exactly once each, not actual public capture.

The standard HTTP/1.0 handler normally closes connections already. Explicit
closure is future-proofing, not evidence of a reproduced live keep-alive exploit.
Final normal/optimized absolute-ingress controls and a full normal seeded API
regression also passed, including real poster/video, restart and deletion.
That single renderer success does not establish export reliability.

Header grammar/size beyond standard parser limits, buffered parsing costs,
whole-request/backend/response deadlines, aggregate memory, reverse-proxy and
HTTP/2 translation, and distributed enforcement remain open. Rejected-job
metadata remains subject to the independent terminal-history cap. Arbitrary
public URL scanning remains disabled.
