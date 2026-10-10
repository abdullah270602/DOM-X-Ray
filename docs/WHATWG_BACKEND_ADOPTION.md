# Opt-in shared parser backend integration

This Gate 0 checkpoint advances the [shared structural policy](SHARED_URL_POLICY.md)
from a standalone helper to trusted destination-policy, transport and origin
exchange paths. It does not select it in the public API, native broker fixture or
production image. Arbitrary public scanning remains disabled.

## Data path

Trusted operator code can construct `WhatwgDestinationPolicy(resolver,
parser=pinned_parser)`. The parser must be a configured `WhatwgUrlParser`, not a
visitor-selected executable, callback or pin. Each invocation canonicalizes with
the fixed helper before the independent address policy validates the serialized
URL. Private/special literals, forbidden hostnames, unsafe resolver answers and
rebinding checks remain authoritative. The base `DestinationPolicy` retains its
existing behavior through an identity `canonical_url` seam.

The public-scan transport canonicalizes before making the ephemeral launch grant;
the worker receives that exact canonical target. Existing complete-grant checks
and schema/semantic/target-bound admission remain required. Records that report a
raw Unicode or unnormalized path rather than the canonical launch identity are
not silently accepted by the record identity check.

`OriginExchange` canonicalizes bind, purpose, tunnel and fetch input before grant
matching or request serialization. The first matching initial GET consumes the
pin once. Setup never consumes or freshly resolves it; repeat requests resolve
independently. Host comes from the address grant and path/query from the canonical
href; fragments do not enter the wire request. Parser faults cannot borrow even
an existing pending initial pin. The proxy now recomputes its remaining budget
after purpose parsing rather than passing a stale timeout into fetch.

## Evidence on 2026-10-09

`python scripts/verify_whatwg_backend.py` and its optimized Python invocation pass:

- Actual pinned local Node parsing and actual supervised fixture subprocess
  admission agree on Unicode host, default port, dot segment and emoji path.
  Existing scan schema and semantic validators run, not a substitute permissive
  admission callback.
- Canonical bind/tunnel/purpose handling leaves the initial pin intact; first GET
  consumes it without extra DNS, repeat GET resolves again, and wire Host/path
  and subresource query/fragment handling match the canonical identity.
- Empty initial query, credentials and normalized private IPv4 produce no DNS,
  connector or worker launch. An injected parser configuration fault fails before a
  pending pin is consumed.
- Unicode redirect preflight resolves the punycode hostname; a private literal
  redirect is rejected before destination DNS. Origin responses/sockets and DNS
  answers are deterministic fixtures, not public network proof.
- Actual parsing plus a bounded artificial delay expires the exchange budget
  without DNS/connector contact. A fake-clock proxy-handler test verifies purpose
  parsing cannot refresh the outer 15-second budget. Neither is a hard native
  process/cgroup deadline or general resolver preemption proof.

Existing destination-policy (51 address/29 URL/seven DNS cases), origin-exchange
and supervised transport regressions pass. The real local Chromium proxy suite
passes with ephemeral key-scoped TLS trust; public origin sockets are not used.
Its initial run found a service-worker observation race: registration readiness
was not sufficient evidence that the activation fetch had reached the fixture.
The test now waits at most five seconds for that exact request through a private
test callback, retaining both bootstrap/activation assertions. Normal and
optimized checks passed after this change.

## Remaining boundaries

The subsequent [API admission checkpoint](WHATWG_API_ADMISSION.md) adds an
explicitly configured pinned parser to the job service. Real loopback rejection,
canonical queue/deduplication and helper identity checks pass. Its subsequent
configured-parser seeded HTTP publication test passes actual supervised fixture
execution, exports, reuse and no-publication controls. Explicit CLI pin wiring
now has fail-before-startup configuration proof with mocked hosting; deployed
CLI/image/broker adoption and public egress remain open.

- At this checkpoint relative `Location` resolution used Python `urljoin`.
  [The subsequent relative-resolution checkpoint](RELATIVE_URL_RESOLUTION.md)
  adds opt-in native resolution with bounded Node/Chromium comparison evidence;
  full standards conformance is still unproven.
- Canonicalization can be invoked more than once along a request path. Every
  invocation checks pins and starts a disposable helper. Throughput, hash I/O and
  representative submit-to-reveal performance are unmeasured; no latency gate is
  closed by this fixture.
- Synchronous hash/metadata reads and resolver calls are not hard-preemptible.
  The helper's own deadline is not a caller-bound process-tree or cgroup budget.
  Connector contact is deadline-checked, but this is not an overall hard bound.
- Native broker RPC's conservative raw pre-bind identity and its image/API
  configuration still require explicit adoption and Linux native evidence.
  Worker clients must not acquire local DNS/origin fallback while adopting it.
- Docker startup repair, independent cgroup emptiness, native orphan recovery,
  reviewed release image/egress, bounded production resolver, published scanner
  policy and end-to-end launch proof remain open. No Docker resources or settings
  were changed by this checkpoint.
