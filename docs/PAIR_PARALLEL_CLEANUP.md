# Bounded parallel role cleanup

The pair controller now overlaps its three independent container cleanup
sequences after attach-client stop attempts. The fixed pool has at most three
threads per active pair; only attempted worker/broker/initializer roles are
submitted. No visitor field controls concurrency or cleanup targets.

Each role retains the same exact name/token/immutable-ID ownership inspection,
kill-if-running and fresh stopped/PID-zero proof, removal, and absence check.
All tasks use the original absolute lease deadline. Returned states and durable
`removed` notes are collected only on the controller thread. The pool joins its
submitted tasks before the shared volume can be removed.

Any role exception, missing state, journal-note failure, unavailable pool or
failed submission makes cleanup unproven: the controller does not remove the
shared volume, no artifact is
admitted, and existing journal recovery obligations remain. Collection continues
after one role fails. An ambiguous submission is not destructively retried.
The controller still preserves an earlier control/pipe-stop failure even when
role cleanup succeeds. The 15-second lease and five-second cleanup reserve are
unchanged, as are image, seccomp, identity, namespaces and resource policy.

Threads overlap blocking Docker control work; they do not make filesystem,
scheduler, thread creation/join or engine stalls independently preemptible.
This is not a hard-real-time guarantee, a cross-scan/global host-process cap or
independent cgroup emptiness. Existing daemon pipe-reader/writer uncertainty on
failed client teardown is not replaced by joining the role-control pool.

## Evidence on 2026-10-11

```powershell
python scripts/verify_pair_parallel_cleanup.py
python -O scripts/verify_pair_parallel_cleanup.py
python scripts/verify_pair_supervisor_contract.py
python -O scripts/verify_pair_supervisor_contract.py
python scripts/verify_journal_pair_contract.py
python -O scripts/verify_journal_pair_contract.py
```

All six final control suites passed. The new suite uses real threads and a
three-way barrier to require actual overlap, checks role ownership arguments,
shared deadlines, controller-only journal callbacks and terminated thread
objects before volume handling/return. It rejects role, journal, pool and
partial-submission faults without retrying the failed submission or skipping
later submissions. Existing mocked outcome/identity/kill-race controls and
actual-journal fault injection retain coverage. Mock states are now keyed by
role instead of assuming thread completion order.

Initial restricted-shell runs could not write their temporary artifacts and
failed; explicit runs with usable private test storage passed. Those initial
filesystem failures are not test passes or Docker behavior evidence.

Two selected native runs used the existing immutable image
`sha256:d495bf5f6e49090faf092e80d04d3b3dc180ba189a3fbe18f93e8809468b4f15`
and unchanged seccomp hash
`242cbd13aa6babf1f163ffa712ee00b0ce95e48c8bb3675d82eb213230b4ff48`:

- A traced reserved-origin pair-to-HTTP attempt still failed publication with
  `scan-timeout`. Broker readiness arrived near 8.732 seconds and the worker
  reached the execution cutoff near 10.230 seconds. Overlapping role cleanup
  finished near 12.836 seconds; volume removal/absence finished near 14.555
  seconds. Scoped container and volume inventories matched their baselines.
  A separate exact journal inspection confirmed zero retained leases in
  `pair-api-journal-2ea778227db21791a83a6a714e9f92e6`. No result was published.
- The journaled native wrong-capability transport case passed the expected
  `worker-invalid-result`, no admitted record, empty lease journal and unchanged
  inventories, with startup-through-cleanup duration 13,542 ms.

These are selected fixture observations, not a paired speedup distribution or
successful public capture. Trace instrumentation affects timing; aggregate host
load/runtime variability was not controlled. The full native case/race matrix,
live-renderer timeout witness under this final controller, API publication,
installed supervision, independent host identity binding and public egress
remain unproven. The earlier unresolved missing-volume journal documented in
`TRANSPORT_API_EXECUTOR.md` remains preserved and is not cleared by this change.
Public scanning remains disabled.
