# Remove redundant backend parser work

This Gate 0 checkpoint reduces duplicate pinned-helper invocations on already
canonicalized URLs. It does not cache URL results or DNS grants, remove pin checks
from parser invocations, or enable public scanning.

Trusted backend code performs two phases: `canonical_url` (or `resolve_redirect`)
then `_validate_canonical`. The second phase retains the independent legacy
serialized-authority/address checks and fresh DNS authorization, without starting
the same helper again. General callers still use `validate`, which performs both
phases. The internal underscore method is a callsite convention, not a security
boundary or visitor-exposed API. Its inputs must come from the trusted policy's
canonicalization in that operation. No arbitrary executable/policy configuration
is accepted from visitors.

The default policy's internal method delegates to `self.validate`, preserving
existing subclass checks. The WHATWG policy's internal method uses the base
address validator. Transport and OriginExchange callsites explicitly canonicalize
before using it. Initial grant matching still precedes pin consumption; repeat
requests and redirects freshly authorize DNS. With an initial grant, request
purpose no longer reparses the unused `initial_url` argument: the checked grant
target is authoritative, as it was before the shared-parser integration.

## Actual local evidence on 2026-10-09

`scripts/verify_parser_work.py` uses actual pinned local Node invocations with
deterministic DNS and HTTP sockets. It counts calls, not an assumed optimization:

| Selected phase | Before | After |
| --- | ---: | ---: |
| Initial purpose with grant | 2 | 1 |
| First initial GET | 1 | 1 |
| Repeated initial GET | 2 | 1 |
| Subresource GET | 2 | 1 |
| Fetch plus redirect preflight | 4 | 2 |

The observed total is 11 → 6 helper invocations. Both runs retain exactly five
DNS calls, four connector calls and all four closed origin sockets. The first
normal observation had approximately 498/263/502/510/1,034 ms per phase; the
first optimized-code observation had approximately 256/269/250/265/514 ms.
These are single local fixture observations, not a statistically controlled
benchmark or public-corpus latency result. A helper still costs roughly 250 ms
here; this runtime strategy is not established as meeting supported-page latency
requirements. Hash I/O, serialized work and production containment need further
design and representative measurements.

The count/fresh-authorization verifier and actual supervised backend admission
pass normally and with optimized Python. Independent destination policy, origin
exchange, supervised transport, relative Node/Chromium resolution and actual local
Chromium proxy regressions pass. Smaller-model callsite review found no bypass;
the internal-phase convention remains explicitly documented.

Docker's read-only server-version check still reports the missing Linux-engine
pipe; no Docker resources/settings were changed. Native recovery proof, parser
containment/throughput, production broker/image/API selection and the complete
public scan-to-share loop remain open.
