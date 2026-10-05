# Per-scan origin broker RPC checkpoint

This is a Linux Unix-socket protocol and a reserved-origin process-pair fixture,
not production public scanning. The stock `.test` capture guard and public API
`scanner-disabled` response remain unchanged.

## Boundary

The trusted broker owns one validated grant, DNS policy, pinned connector,
redirect validation and request/wire-byte budgets. The client cannot supply
addresses, grants, purpose, limits, runtime or connectors. It has no local DNS
or origin-connection fallback. Capture accepts this exchange only as trusted
operator injection, not visitor input.

Each connection checks Linux `SO_PEERCRED` UID and a random per-scan 256-bit
capability. Every RPC also carries a capability-keyed HMAC over the exact target,
purpose, scheme, hostname, port and ordered address tuple. A valid `bind` must
complete before tunnel/fetch operations. Same-URL/different-address grants fail
before DNS or origin contact, including after another client has bound. No
resolver addresses are returned by the protocol. Equivalent differently spelled
grants are not normalized into a matching HMAC: this is conservative exact
identity, not the still-open shared WHATWG parser.

`bind` and tunnel validation return authority only; neither consumes the initial
pin. The first fetch must match the host's initial target and consumes that pin
once. Subsequent fetches resolve independently on the broker. Purpose is inferred
server-side. Anonymous header stripping and existing OriginExchange budgets
remain authoritative. A separate trusted control-call budget (at most 1,000)
limits bind/tunnel validation before DNS, including calls that later fail policy.

Requests are one length-prefixed strict JSON frame (64 KiB maximum), followed by
write EOF. No request body, pipelining, arbitrary TCP tunnel or descriptor-transfer
API is provided. Responses have a bounded strict JSON head, bounded raw body,
correlated request nonce and final EOF. Duplicate keys, nonfinite values,
unknown fields, malformed counts, truncated/trailing data and unapproved error
reasons fail closed. Active handlers, unauthenticated reads and broker lifetime
are bounded. Socket creation requires a canonical private owner directory and
cleanup checks the socket inode before unlinking it. Failed cleanup requires
whole-container teardown, not an assumption that work stopped.

Linux peer credentials are documented in [unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html).

## Fixture and verification

`broker_capture_fixture.py` forks the broker before browser/proxy threads start.
The two processes share a UID and container but communicate through the RPC
socket. The capability is not in argv or environment. A private owner pipe and
bounded report prove broker exit/socket removal before admitting a record.
Actual sandboxed Chromium captures through the pair; the hang fixture keeps a
real renderer alive until the trusted Docker supervisor rejects and tears down
the whole owned container.

```powershell
python scripts/verify_origin_exchange.py
python scripts/verify_scan_transport.py
python scripts/verify_docker_supervisor_contract.py
python scripts/verify_container_capture.py --image dom-x-ray-runtime-candidate:gate3 --origin-broker
python scripts/verify_docker_transport.py --image dom-x-ray-runtime-candidate:gate3 --origin-broker
```

Build the candidate first as described in `RUNTIME_CANDIDATE.md`. Run native suites
sequentially to avoid obscuring engine latency with simultaneous builds/tests.
The protocol suite checks framing, actual peer UID, wrong capability, exact grant
mismatch, pre-bind rejection, one-shot pin/fresh DNS, private destinations and
redirects/rebinding, stripped credentials, server-owned byte/request/control
limits and 16 forged-response canaries. The transport matrix adds broker capture
and live-renderer timeout to the twelve existing cases. Native evidence and local
image identity are recorded with the current checkpoint, not release guarantees.

Local 2026-10-06 verification used Docker Desktop Linux engine 28.3.2, cgroup v2,
Playwright 1.63.0 and Chromium 153.0.8010.12. The tested immutable local image ID
was `sha256:f4c0acfa1d2a9ba67e56976ea3f18f64fd40bb4eea875b4d8c37fa5e86e8701b`;
the reviewed broad fixture seccomp hash remains
`242cbd13aa6babf1f163ffa712ee00b0ce95e48c8bb3675d82eb213230b4ff48`.
All five native capture/protocol cases and all fourteen sequential transport
cases passed. Broker capture was admitted at 7,567 ms; the live broker/renderer
hang was rejected at 14,382 ms with engine-reported exact-container teardown.
The capture suite observed 222,777,344-byte cgroup memory peak and 92-process
peak, within the fixture's 1 GiB/128-process limits. Origin exchange, scan
transport and ten mocked supervisor cases also passed; the latter passed under
Python optimization. Smaller-model review found no remaining material blocker
within this protocol/fixture scope.

An earlier transport run on the preceding image returned `supervisor-failed`
instead of `invalid-record` for the wrong-target case while builds/native suites
overlapped. It admitted no result. The sequential final-image run passed that
case at 2,951 ms. Overlap was observed, not proven to be the cause; one clean
rerun is not engine reliability evidence.

## Still required before public scanning

Follow-up evidence: `CONTAINER_BROKER_BOUNDARY.md` now records separate-UID,
cross-container socket access and permission-denial fixtures. That does not
replace production pair supervision, recovery or real public egress proof.

- Different worker/broker identities and cross-container socket mount policy;
  same-UID peer checks do not prove identity isolation.
- Actual public TLS with broker egress/firewall policy and bounded production DNS.
- Minimal reviewed seccomp, vulnerability/patch policy and immutable release image.
- Durable controller-death/orphan recovery and independent cgroup-empty evidence.
- Shared URL/parser semantics, production API/queue adoption, abuse controls,
  approved scanner/retention/opt-out policy and representative URL performance.

The private browser root does not expose this broker socket to Chromium. This
fixture proves protocol composition with the existing proxy bridge; it does not
yet prove a separately deployed broker cannot be bypassed by a compromised worker.
