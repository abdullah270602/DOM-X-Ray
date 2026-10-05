# Per-scan browser TLS certificates

Status: real issuer and proxy integration evidence; deployed browser trust open.

`scanner/scan_certificates.py` supplies `ScanCertificateIssuer`, a callable for
`BrowserEgressProxy.tls_context`. It creates a new P-256 CA key and root for each
scan, then independent P-256 keys and server-only leaves for each canonical
public hostname/IP. DNS and IP subject alternatives are distinct; one leaf has
exactly one requested identity. A fixed Common Name avoids the shorter CN limit
for valid long DNS names. Wildcards, noncanonical/Unicode hostnames, private
literals, credentials, delimiters, controls, and extension injection are rejected
before certificate commands. This syntax check does not resolve DNS or grant
origin access; the proxy's `DestinationPolicy` still performs destination checks.

The factory caches host key/chain files, not `SSLContext` instances. Each call
returns a fresh server context with TLS 1.2+ and HTTP/1.1 ALPN; the proxy adds its
CONNECT-bound SNI check. Leaves are not valid for client authentication or CA
issuance. Certificates have one-day cryptographic validity, but the issuer has
a maximum fifteen-second monotonic lifetime and belongs to a disposable worker.
Closing the issuer removes files; destroying the worker releases retained TLS
contexts and in-memory keys. Disk deletion is not a secure-erasure guarantee.

The root and leaf material live in a new private temporary directory. Generated
file names contain no host material. POSIX mode intent is directory 0700 and keys
0600; Windows ACL isolation still requires deployment proof. `trust_certificate`
exposes only the root certificate path for the browser-profile trust adapter.
It never installs trust in the OS, changes origin CA trust, or publishes keys.
Do not share the issuer or trust root between scans.

## Bounds and failures

Setup and each factory call share a five-second operation budget, including lock
waits and OpenSSL commands. All operations also consume the issuer's monotonic
scan lifetime. Distinct successful hosts default to a cap of 128 (configurable
downward or up to the 500-request hard ceiling); cache hits do not consume another
slot. OpenSSL is an explicit absolute trusted executable, invoked without a
shell. Its output is discarded except for internal bounded SAN inspection;
relevant ambient OpenSSL configuration is
replaced with the private minimal config, and errors use content-free reasons.
Timeouts kill and wait for the command; partial issuance files are removed and
failed CA setup (including early permission/config setup failures) removes the
directory. Before caching, a bounded internal SAN inspection requires exactly
the requested DNS or IP identity; an unexpected extra identity is rejected and
the files removed. No failed leaf enters the cache. Root-path access also ends
at the monotonic lifetime. Teardown waits at most five seconds for issuance;
if the lock remains owned, it reports failure rather than removing active files,
and worker destruction is required.

These are application-level bounds, not a replacement for the worker
supervisor. Synchronous filesystem/OS operations can stall; the entire worker
and descendants must still be destroyed at the hard deadline. The issuer's
context factory is called before CONNECT establishment, so issuance failure
does not create an opaque tunnel or contact the origin.

OpenSSL 3.2.4 is the verified executable on this machine. Deployment must supply
its reviewed OpenSSL binary and private runtime filesystem. Certificate extension
construction follows the official [req documentation](https://docs.openssl.org/3.2/man1/openssl-req/)
and [x509 documentation](https://docs.openssl.org/3.3/man1/openssl-x509/).

## Reproducible evidence

Run `python scripts/verify_scan_certificates.py` with pinned Playwright Chromium
and OpenSSL. The verifier checks:

- independent roots, private leaf keys, fresh TLS contexts, and scan-owned cleanup;
- normal CA/purpose/hostname verification, wrong-root/hostname/client-purpose rejection;
- DNS, IPv4, IPv6, and a valid 253-character DNS name;
- malformed-name rejection before commands and distinct-host cap rejection;
- real proxy TLS with normal Python CA and hostname verification;
- real Chromium chain acceptance with a test-only scan-root SPKI exception;
- lock, actual subprocess, lifetime, and contended-teardown timeout failures;
- setup/leaf cleanup and unexpected-extra-SAN postcondition rejection.

POSIX permission assertions run only on POSIX. They were not executed on this
Windows machine. The verifier changes neither system nor browser-profile trust.
Origin sockets are deterministic fixtures; upstream normal CA validation has
separate evidence in `SCAN_TRANSPORT.md` and `ORIGIN_EXCHANGE.md`.

## Remaining release obligations

Install the root only in the disposable browser's isolated trust/profile, verify
negative trust tests without certificate-error switches, remove that profile and
worker after every scan, and prove independent egress/firewall containment.
Select a bounded resolver, wire the public worker/grant path, and run the public
corpus/latency tests. Arbitrary public scanning remains disabled. The Chromium
SPKI exception in this verifier is not the production trust configuration.
