# Shared relative redirect resolution checkpoint

This Gate 0 checkpoint completes the local opt-in relative-resolution seam left
open by [backend parser adoption](WHATWG_BACKEND_ADOPTION.md). It does not enable
public scanning, select a production parser runtime, or prove all URL standards
cases.

`resolvePublicUrl(reference, base)` validates the base using the same structural
policy before handling any reference, including an absolute one. Relative path,
query and fragment references are resolved by the runtime's native `URL`
constructor and the result is admitted through `parsePublicUrl` again. Raw
absolute and network-path authorities are checked before serialization can
discard empty userinfo or normalize an ambiguous numeric/escaped hostname.

The strict policy intentionally rejects scheme-bearing references without the
explicit `://` form, triple-slash/empty authorities, controls, whitespace,
backslashes, unpaired surrogates and raw credential authorities. An empty
reference is allowed with a valid base; an empty absolute target remains invalid.
Input/base/output length limits remain 2,048 UTF-16 code units, with the helper's
combined JSON envelope capped at 16,384 bytes. Some long escaped input pairs can
exceed that envelope and are rejected rather than relaxing the pipe bound.

The pinned helper now accepts either the original exact three-field request or
an exact four-field request containing `base`. A base is allowed only for a
redirect operation. `WhatwgUrlParser.resolve` retains pin checks, bounded pipes,
nonce/schema checks, fixed errors, sanitized environment and owned-process
cleanup. New helper/module bytes require new trusted operator pins.

`WhatwgDestinationPolicy.resolve_redirect` returns the canonical resolved href.
`OriginExchange` uses that resolver, checks its remaining budget, then applies
independent destination authorization before returning an admitted redirect
response. It does not itself follow the redirect or treat structural acceptance
as public-address authorization. The default legacy policy preserves its Python
`urljoin` behavior; production adoption must explicitly select the pinned policy.

## Evidence on 2026-10-09

`python scripts/verify_whatwg_resolution.py` and its optimized invocation verify:

- Actual Node and Chromium 140.0.7339.16 agree on 13 admitted references, and each
  admitted href equals the browser's native `new URL(reference, base).href`.
  Cases include Unicode authorities/paths, empty references/query/fragment,
  encoded dot segments, parent paths, scheme changes and encoded path separators.
- Thirteen strict rejection cases agree across the same shared source in both
  runtimes. Invalid bases are rejected even for otherwise valid absolute refs.
- Resolved loopback IPv4 (including fullwidth input), loopback IPv6 and metadata
  hostname destinations are denied before resolver contact.
- Actual pinned parsing through `OriginExchange` revalidates relative redirects
  with query data, rejects a private redirect without destination DNS contact,
  and closes the deterministic origin socket in both cases.

The existing 26-case Node/Chromium absolute-policy corpus and backend supervised
fixture admission remain valid. Destination-policy and origin-exchange
regressions pass. Frontend tests/build check the shared module's unchanged
initial-target use; no visual interface changed in this checkpoint.

## Still open

The selected corpus is not universal WHATWG/UTS #46 conformance. Parser throughput,
hash I/O, synchronous resolver/hash preemption, process-tree/cgroup containment,
native broker RPC pre-bind adoption, immutable release image and public API
selection remain open. Docker repair/native orphan recovery evidence is still
pending. Independent public egress, representative latency and the complete
public scan-to-share flow remain release gates, not conclusions from this test.
