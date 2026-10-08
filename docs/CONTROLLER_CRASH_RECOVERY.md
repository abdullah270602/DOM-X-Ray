# Gate 3 — Native controller-crash recovery

## What this proves

`scripts/verify_pair_controller_crash.py` exercises the actual Docker pair,
actual private lease journal and actual replacement recovery pass on Windows
with Docker Desktop. It does not deploy a watchdog, enable public scanning or
prove independent Linux cgroup emptiness.

The fixture uses immutable image
`sha256:d495bf5f6e49090faf092e80d04d3b3dc180ba189a3fbe18f93e8809468b4f15`,
engine 28.3.2 and the existing reviewed fixture seccomp JSON. Worker/broker
network-none, non-root identities, readonly roots, limits and socket-volume
policy remain unchanged. The only target is the reserved HTTPS fixture.

1. Create a fresh persistent journal outside temporary results.
2. Spawn the controller suspended, assign a dedicated kill-on-close Windows Job,
   then resume it. Docker CLI descendants inherit that Job; Docker Desktop and
   its Linux engine are not members.
3. Observe the worker's fixed `renderer-live` line, emitted only after the fixture
   has opened an actual Chromium page and successfully evaluated JavaScript.
   A shared lock serializes notification against controller cleanup. The parent
   also requires the controller to be alive when it receives the witness.
4. Terminate the Job, wait for controller exit and query zero active Job processes
   before closing the Job handle. This proves the host controller/CLI subtree
   died, not that its Linux workload died. The accounting field and API follow
   [Microsoft's structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information)
   and [query definition](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject).
5. Reopen the private journal under the replacement owner. Require all four
   recorded resources created, matching runtime fingerprint, exact immutable
   worker ID/name/token and full runtime-policy readback. Positively inspect that
   this owned worker is still running with a nonzero engine PID after Job death.
6. Verify pre-expiry recovery skips the lease with zero Docker control calls.
   Wait for real wall-clock expiry plus the unchanged five-second grace; do not
   inject a future clock or shorten eligibility to get a pass.
7. Recover with the normal 15-second pass budget. Require one resolved lease,
   no retained obligations, empty journal, no result artifact and unchanged scoped
   container/volume inventory. Failed journals remain persistent. Inventory
   observations also run when the test fails; unrelated resources are never removed.

## Evidence — 2026-10-08

Native normal and optimized-Python runs proved the live orphan and resolved it in
5,524 ms and 5,702 ms respectively. A repeat after extracting the observer helper
resolved in 5,956 ms. Those durations cover only the replacement recovery pass,
not original setup, the eligibility wait or the entire orphan lifetime.

The final lock-guarded witness version passed natively with a 5,615 ms recovery
pass; its forced-interleaving contract test also passes in normal/optimized Python.
The final optimized native run resolved its live orphan in 5,548 ms with both
scoped inventories unchanged.

The first two attempts failed before engine contact because the fixture's pipe
observer omitted optional arguments used by control calls. Their unrequested
journal rows were safely finished after expiry; they do not count as native
crash-cleanup evidence. A portable normal/optimized regression now covers those
arguments, worker-only signaling, cleanup-phase suppression, a forced interleaving
between marker observation and notification, and failure-path inventory auditing.
Existing recovery and pair-admission regressions also pass.

```powershell
python scripts/verify_crash_fixture_contract.py
python -O scripts/verify_crash_fixture_contract.py
python scripts/verify_pair_controller_crash.py
python -O scripts/verify_pair_controller_crash.py
```

The image tag is resolved to its immutable ID once before spawning the controller;
both owners use that exact ID. Persistent test journal paths are printed for
operator recovery. No grants, capabilities, worker nonces, page content or raw
provider errors are forwarded. Private result directories belong only to this test.

## Still unproven

This is one real-renderer controller-crash scenario, not the full crash/race matrix.
The fixture deliberately allows the orphan to outlive its original 15-second
lease while waiting for expiry/grace and replacement cleanup. It therefore does
**not** establish a 15-second overall bound when a controller dies. Independent
automatic watchdog scheduling, admission/lease integration, delayed creates,
partial-removal crashes, daemon outages, cursor fairness and backward-clock cases
still require implementation or native evidence. Windows Job emptiness is not
Linux cgroup emptiness. Production image/egress/parser/API, policy and product
gates remain open; arbitrary public scanning stays disabled.
