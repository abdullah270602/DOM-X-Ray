# Bounded local admission records

`ScanAdmissionGate` now accepts positive-integer `max_target_reservations` and
`max_origin_reservations` (engineering defaults 4096 each). Under one lock, it
prunes expired completed-target records and origin cooling timestamps, checks
both capacities, then either inserts both records or neither. Saturation never
evicts an active scan, reusable result mapping or unexpired cooling timestamp.

Existing exact-target reuse, in-flight duplicate and same-origin cooling checks
take precedence over capacity. A new target at capacity receives the gate's
`reject/admission-capacity` decision. The API uses its existing empty-of-private-
detail 429 `rejected/rate-limited` job response with no-store and Retry-After;
the scan executor is not invoked and no target/origin record is inserted.

Retry-After accounts for the earliest potentially freeing expiry in each full
map and takes the maximum necessary wait. If target capacity is entirely active,
one second is a polling hint, **not** a promise that a worker will finish or
capacity become available. Reuse may still succeed while new targets are blocked.

## Active lifecycle correction

Previously duplicate-window pruning also removed unfinished reservations. A
long-running/queued scan could then be duplicated or fail `complete()` after
another submission pruned its record. Unfinished reservations now remain until
explicit completion/abandonment. The API already abandons them on terminal
execution/admission failure. Old active records cannot be displaced by churn.

This intentionally changes active expiry behavior. Callers outside the API must
release failed/cancelled work; lost work can occupy capacity indefinitely until
authoritative recovery. Blind TTL eviction is not a substitute for proving that
an old worker stopped. Durable orchestration, installed supervision and bounded
total-death recovery remain open production requirements.

Completed-result reuse still uses the original submission-based duplicate
window; completion does not reset it. A late result can be stored successfully
but have no remaining reuse window. Deletion/expiry forgets result mappings,
never cooling timestamps, and never changes backend result/deletion authority.
Windows now reject boolean, nonfinite/nonpositive or nonnumeric configuration
before reservations are created, keeping cap/retry calculations well defined
for the supported local engineering configuration.

## Evidence and scope

```powershell
python scripts/verify_admission_capacity.py
python -O scripts/verify_admission_capacity.py
python scripts/verify_api_admission_capacity.py
python -O scripts/verify_api_admission_capacity.py
```

Final normal/optimized primitive tests passed cold-target/origin floods, no
eviction, existing reuse/cooling, exact completed/origin expiry, preservation of
active work past the duplicate window, late completion, release recovery,
strict configuration controls and 20 simultaneous reservations limited to two.

The separate real HTTP/HMAC-memory-backend tests passed 429/no-store responses
without executor calls, reuse at saturation, active TTL survival and late
publication, byte-identical stored bundle retrieval, original owner deletion,
cooling retained after deletion, and new admission after release/exact expiry.
Their executor supplies validated fixture bundles; it does **not** prove real
capture, rendering, public egress or distributed storage. Initial HTTP harness
runs failed because a service-only polling helper received a URL string; they
are not passes. The final harness polls through actual HTTP instead. Existing
`assert_admission_policy_guards` also passed independently.
The full existing seeded API suite separately passed real supervised capture,
poster/video publication and routes, restart recovery, deletion/reuse/expiry,
active-job and target-correlation controls. The optimized cap harnesses cover
their own processes, not optimization propagation into render/capture children.

The caps bound retained record counts, not URL-byte allocation, whole heap,
pruning copies, origin fairness, request/scan cost or cross-instance load. Keys
are canonicalized before map access, so upstream byte/URL policy remains required.
The full API safety/latency and representative export reliability gates remain
open. Public scanning stays disabled.
