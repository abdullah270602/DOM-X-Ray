# Public Scan Transport Contract

Status: deployment-neutral proof v0.1

## Purpose

The public-scan transport is the narrow boundary between an anonymous target URL
and a scan record that an API may publish. It composes destination validation,
worker supervision, and record admission without selecting an API framework,
queue, resolver, HTTPS client, container runtime, or hosting provider.

The reference seam is `scanner/scan_transport.py`.
`scanner/pinned_connector.py` supplies the TCP/TLS origin connection step.

## Required flow

```text
untrusted initial target URL
  → DestinationPolicy.validate(initial)
  → ephemeral PublicScanGrant(target + validated address set)
  → launch adapter
  → supervised disposable worker
  → nonce/size/regular-file/zero-exit eligibility
  → strict { supervisorNonce, result: { record } } envelope
  → scan-record JSON Schema validation
  → cross-record semantic validation
  → requested-target correlation
  → admitted immutable record or no record
```

The launch adapter is not called when destination validation fails. Only an
initial-target transport may publish a scan record, and its normalized
`requestedUrl` must equal that target. A valid record for a different target is
rejected. Redirect and subresource connections use `authorize_connection`; each
requires a separate grant and cannot reuse the initial grant. Connectors receive
only `ValidatedDestination`, never the raw URL. Grants are ephemeral and their
representations omit resolver answers.

The supervisor owns a fresh private result path. A launch/setup failure, worker
crash, timeout, stale nonce, oversized/nonregular artifact, malformed envelope,
schema failure, semantic failure, or target mismatch returns only an allowlisted
outcome and no record. Temporary artifacts are removed before the transport call
returns.

## Integration obligations

The launcher receives both the requested target and `ValidatedDestination`.
Production integration must use the grant's exact address tuple for connection
pinning while preserving the validated hostname for Host/TLS SNI and the target's
path/query request semantics. It must not resolve the hostname again. Every
redirect and subresource needs a newly validated grant.

The two required validator callbacks allow the eventual API runtime to use its
pinned schema package and semantic validator without making this proof select an
application stack. Both must succeed before the caller receives a record.

## What this proves

`python scripts/verify_scan_transport.py` proves:

- independent initial, redirect, and subresource resolution;
- zero worker-launch calls for the existing 29 malformed/unsafe target cases,
  seven DNS failure modes, and a public-to-private rebinding attempt;
- delivery of the normalized, sorted validated address set to the launch adapter;
- no resolver address in the grant representation;
- rejection of a schema-valid and semantically valid record for another target;
- fail-closed launch, supervisor, crash, timeout, nonce, size, nonregular,
  envelope, schema, and semantic cases;
- no admitted record and no surviving temporary artifact for every failed case.

## What this does not prove

The transport seam alone does not prove socket pinning or HTTPS; the separate
connector evidence below covers those steps. Neither proves that deployment
egress stops a compromised browser. It also does not select a production resolver, shared URL
parser/IDNA implementation, queue, durable store, rate limiter, or disposable
container. Those remain release-blocking deployment proofs. The local fixture
proxy and the injected fake resolver must not be relabeled as production
containment.

## Pinned origin connector evidence

`connect_pinned` can be passed directly to `authorize_connection`. It rechecks
the complete canonical grant before creating a socket, connects only to numeric
addresses in that grant, checks the connected peer, and preserves the validated
hostname for TLS SNI and certificate verification. TCP failures can try another
approved address; TLS failures end the call. Connection attempts and handshake
share one monotonic timeout, capped at 15 seconds.

The caller owns the returned socket and must close it, preserve the hostname
in HTTP Host, and enforce method/header/byte limits and a lifetime deadline on
subsequent I/O. The connector sends no HTTP and follows no redirects. Each new
origin connection needs a newly authorized grant; grants must not be retained
as a connection pool or DNS cache.

`python scripts/verify_pinned_connector.py` is network-free. It proves numeric
IPv4/IPv6 endpoint selection without DNS, validation of all answers before
contact, approved TCP fallback, SNI/trust/hostname/TLS-minimum configuration,
no fallback after certificate failure, peer verification, deadline exhaustion,
socket cleanup, and content-free errors.

A public handshake on 2026-10-05 independently resolved `www.python.org` with
the system resolver, passed the answers through `DestinationPolicy`, and called
`connect_pinned` with a five-second budget. It negotiated TLS 1.3 and HTTP/1.1,
with default CA and hostname validation. No HTTP request was sent. This is
one-machine TLS evidence, not a scanner benchmark or deployment egress proof.

Python API references: [socket](https://docs.python.org/3/library/socket.html)
and [TLS context/socket](https://docs.python.org/3/library/ssl.html).

Browser proxy integration, request/byte admission, service-worker coverage,
grant lifetime, production resolution, and container egress still need tests.
Arbitrary scanning remains disabled.

The origin-side HTTP integration is now in `scanner/origin_exchange.py`.
It enforces anonymous requests, strict response framing, scan-wide wire-byte
limits, and redirect revalidation over the pinned connector. See
`docs/ORIGIN_EXCHANGE.md` for its verifier and real HTTPS HEAD evidence.
It still needs the browser-facing TLS interception proxy and containment.
