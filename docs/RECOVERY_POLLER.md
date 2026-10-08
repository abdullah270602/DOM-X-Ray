# Gate 3 — Independent recovery polling component

## Scope

`LeaseRecoveryPoller` watches one operator-registered, existing private journal
and trusted pair-supervisor runtime. It starts no scan and publishes no result.
It is a reusable component, not an installed service or a live-owner lease enforcer.

Registration pins root, database and lock-file device/inode identities and the
configured runtime fingerprint. Every pass rechecks those identities, opens the
journal with `create=False`, and checks the acquired lock descriptor identity
before recovery. Missing authority is a fault, never a reason to create a new,
empty database. A different factory runtime cannot inherit old cleanup authority.
The recovery pass still independently binds the recorded Docker daemon and exact
resource identity/policy before contacting or removing resources.

`LeaseJournalBusy` distinguishes nonblocking ownership-lock contention from
other constructor failures. Only contention during this journal acquisition is
reported as `busy`; a factory failure is `fault`. A busy owner is not displaced,
and its database is not treated as empty or healthy. Schema inspection waits for
ownership. Existing file/ACL safety checks remain fail-closed.

One local mutex serializes passes. The lexical cursor now persists in the same
private journal; see the [restart checkpoint](RECOVERY_CURSOR.md).
The default interval is 0.5 seconds, configurable
from 0.25 to 5 seconds. Faults or retained obligations increase exponential delay,
capped at 30 seconds and a failure counter of 10. Busy ownership uses the regular
interval without clearing failure history; a validated non-retained pass resets
it. The stop event interrupts inter-pass waits. Health contains only a fixed
status, delay and per-pass counts: no paths, tokens or raw errors. Zero counts do
not prove an empty queue, particularly on a busy or failed pass.

## Local evidence — 2026-10-08

`verify_recovery_poller.py` uses real private journals and OS locks with simulated
Docker. Normal and optimized Python cover busy ownership, future eligibility,
runtime drift, factory faults, handoff, content-free health, interruptible stop,
missing-root/database no-bootstrap behavior, damaged schema and validated repair,
and a forced lock replacement between metadata inspection and acquisition.
An outage preserves two leases/resources, caps retry delay, and resolves both
after the simulated daemon resumes. This does not prove native daemon outages.

The schema fixture explicitly closes its SQLite connection; leaving it open
previously caused Windows temporary-directory cleanup to fail. No journal safety
check was weakened to avoid that failure.

## Native fixture

`verify_native_recovery_poller.py` starts the real renderer/controller and poller
in separate Windows Jobs, assigning each suspended process before resume. It
requires the poller to observe the busy controller, terminates only the controller
Job, verifies its active process count is zero, and positively observes the exact
owned Linux worker still running while the separate poller remains alive.
The success path invokes no manual recovery: the poller waits for real expiry and
grace, cleans the eligible orphan, and exits after its verified recovery receipt.
The journal must be empty, no result may exist, and both scoped Docker container
and volume inventories must match their initial values.

Both process trees are stopped on fixture failure. A journal-authorized manual
fallback can retain unresolved obligations; it never counts as automatic proof.
Persistent test journals remain available for operator inspection/recovery.

A first native run passed before the final acquired-lock identity check was
added. The later optimized run's session handle was unavailable on continuation;
its terminal result is unverified. Docker Desktop was stopped at revalidation,
and its engine remained unavailable after attempting to start the installed app.
Final-version native verification is therefore open at this checkpoint; the
local normal/optimized contracts do not substitute for it.

Startup diagnosis on 2026-10-08: the last backend log reports failure while
initializing the inference manager's `dockerInference` Unix socket: removal
fails with "The file cannot be accessed by the system." The corresponding
zero-length entry in Docker's local `run` directory is a reparse point, not an
ordinary file. The Linux-engine named pipe is absent and no Desktop/backend
process was found; disk free space is ample. This identifies a startup failure,
not proof that the socket is safe to delete. No Docker data/settings, sockets,
images or volumes were removed. Host-runtime repair requires user direction;
factory reset, broad cleanup and weakening scanner isolation are not alternatives.

```powershell
python scripts/verify_recovery_poller.py
python -O scripts/verify_recovery_poller.py
python scripts/verify_native_recovery_poller.py
python -O scripts/verify_native_recovery_poller.py
```

## Remaining release gates

The fixture poller survives only the producer Job's death; it is not a deployed,
self-supervised watchdog. No durable runtime/journal registry,
native watchdog restart proof, native multi-lease/crash/race matrix, or service health
integration is established. A continuously busy hung owner is never reclaimed
by this component. Independent controller deadline enforcement is still needed.
Local filesystem, factory and SQLite operations are not forcibly preemptible.

The orphan intentionally outlives its original 15-second lease during expiry,
grace and cleanup. This is not an overall controller-death bound. Windows Job
emptiness is not Linux cgroup emptiness. Production runtime/egress/parser/API,
policy and product gates remain open; arbitrary public-URL scanning stays disabled.

The subsequent [bounded registry](RECOVERY_REGISTRY.md) schedules up to eight
explicitly registered pollers. It is not filesystem discovery, durable operator
configuration, service installation or hard-real-time isolation between entries.
