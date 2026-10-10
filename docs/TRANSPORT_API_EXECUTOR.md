# Shared supervised transport to API mapping seam

`TransportScanExecutor` now accepts operator-owned exact target configuration,
per-scan destination-policy factory, launch callback, optional worker supervisor and a 1–15 second
scan deadline. It forwards both schema and semantic validators to
`run_public_scan_transport`, then uses the existing shared scene/result/runtime
and artifact pipeline only after admitted transport output. Visitor submission
does not select commands, images, runtime paths, policy or supervisor providers.
The factory is called only for supported execution, so bounded resolver lifetime
and lookup budgets can start per scan rather than at API startup. Bad factory
results/faults fail with fixed internal-error before worker contact; the operator
remains responsible for actually returning fresh scan-scoped state.

`FixtureScanExecutor` is its default seed-only specialization: the same three
HTTPS targets, fixed fixture worker, resolver and three-second transport budget.
Its constructor and renderer injection seams are preserved. Empty query/fragment
delimiters are now explicitly rejected by the local exact-target helper rather
than normalized away. This helper is not WHATWG conformance; the existing pinned
parser configuration remains independent.

There is **no public executor CLI option or public scan enablement**. The generic
adapter does not attest supplied callbacks or prove deployment containment. A
production operator configuration still requires reviewed runtime/parser/resolver
pins, independently enforced egress/isolation, durable supervision, abuse controls
and operating policy before it can be installed in the public API.

## Portable and default-path evidence

```powershell
python scripts/verify_transport_executor.py
python -O scripts/verify_transport_executor.py
python scripts/verify_local_scan_api.py
```

Final normal/optimized adapter controls passed exact target refusal before any
transport contact, explicit provider/policy/deadline forwarding, empty-record
refusal by each forwarded validator, fixed transport outcome mapping, real
private DNS-answer refusal before launch, and invalid operator configuration.
Most transport outcomes here are controlled, not actual capture evidence.

The full normal seeded HTTP regression passed after the initial source refactor,
including real poster/video publication, immutable restart recovery and owner
deletion. A full optimized API-process run failed the required video GET with
the unchanged worker timeout and correct not-generated/poster-only fallback.
It is not a full optimized pass. After the final per-scan policy-factory correction,
a further normal full regression also failed the required video route on the same
timeout/fallback. The intermediate success is not a final-version full-suite pass.
Optimization of child processes is not claimed. These failures reinforce the
still-open renderer reliability gate.

## Native reserved-origin integration: failed closed

```powershell
python scripts/verify_pair_api_publication.py --image sha256:d495bf5f6e49090faf092e80d04d3b3dc180ba189a3fbe18f93e8809468b4f15 --trace
```

This verifier uses the existing network-none Docker pair and unchanged reviewed
seccomp policy, exact reserved `https://xray.test/`, real HTTP admission/polling,
and a persistent per-invocation lease journal. Its intended assertions include
validated scene/runtime publication, byte-exact storage, reuse, owner deletion
and scoped inventory restoration. **They have not passed natively.** Neither of
the two attempts on 2026-10-11 published a result; both returned capture-failed.

The traced attempt used about 6.906 seconds before broker readiness; the worker
attach then reached the execution cutoff near 10.122 seconds. Container cleanup
completed, but volume inspection exhausted the overall lease near 15.129 seconds.
These instrumented control observations identify lease pressure, not public-page
latency, exact kernel timings or a cause of every earlier failure. No timeout,
reserve, isolation or artifact admission rule was relaxed.

Its exact expired journal `pair-api-journal-26c4fdd0cff93a57af30dcbc0da452e2`
was subsequently recovered with the existing identity-bound recovery code:
resolved=1, retained=0, and scoped volume inventory empty. The first journal,
`pair-api-journal-d9888a01b7f6e3ffa692fec73163ef59`, remains preserved: all
containers are recorded removed, but its volume is only recorded created while
the scoped engine inventory is empty. Exact recovery retained this obligation
rather than inventing a missing durable removal proof. It must not be cleared
manually or treated as independent cgroup emptiness.

The verifier's explicit `--recover-journal` mode accepts only one existing
invocation-owned journal beneath the local data root and never submits a scan.
Final failure-path inventory logging and per-scan policy-factory wiring were
added afterward; they have not been rerun natively. Stock recovery semantics
are unchanged.

Native API publication, independently bound cgroup observation, installed
supervision, real public egress, deployed storage and representative end-to-end
reliability remain open. Default health still reports arbitrary scanning false.
