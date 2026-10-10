# Native foreground watchdog restart and orphan recovery

This Gate 3 fixture extends the [process restart proof](WATCHDOG_PROCESS_RESTART.md)
to an actual Docker worker that survives controller and watchdog death. It does
not install a service, prove an automatic service restart, or enable public scans.

## Sequence and authority

The harness provisions a fresh private parent, journal and configuration directory.
One exact hash-pinned registry binds existing journal identities and a fixed
runtime fingerprint, immutable image, canonical seccomp policy and Docker CLI
path. Both launcher processes receive the same file and separately supplied
digest; the configuration is never rewritten during the sequence.

An expired, unrequested fixture lease commits cursor zero before Docker work.
Only this synthetic resource-free lease's expiry is adjusted; the real worker's
expiry, grace and host clock are untouched. The first foreground launcher runs
the production entrypoint, with a test-only pause after its committed recovery
receipt, outside the journal transaction/ownership lock. Recovery logic is not
replaced. The pause removes a parent-kill scheduling race.

The real controller then starts the pinned renderer fixture. After its live
renderer witness, the harness kills only the controller's and first launcher's
separate Windows Jobs. Each process was assigned suspended-before-resume;
successful stop requires process exit and positive Job emptiness. The saved
cursor must remain zero, while the journal retains the real lease. Exact worker
name, token label, immutable ID and role isolation are checked before positively
observing `Running=True` and `Pid>0` on the surviving orphan.

A replacement unmodified foreground launcher reloads the same registry, waits
for real eligibility and automatically resolves the orphan. Its committed
receipt must resolve one lease with no retained/deferred obligations. The
replacement is then stopped through its own Job. The journal must be empty,
the final cursor must match the real orphan token, no result artifact may exist,
and scoped container/volume inventories must equal their starting state.

This preserves and updates a real cursor but does not independently distinguish
lexical restart ordering with multiple native leases. The older resource-free
25-record restart fixture remains the evidence for that ordering distinction.

## Failure safety

All owned Job stops are attempted even if another reports an ordinary exception. Pipe readers must be
ended before their stream is closed, avoiding a close against a live reader's
lock. If Jobs are not proven stopped, exact-journal manual recovery is withheld
and the persistent authority is retained. Otherwise failure fallback may attempt
only journal-authorized replacement cleanup; it never counts as automatic proof.
Private journals/configuration remain as local evidence and are not erased.
An additional forced interrupt during teardown can still interrupt cleanup;
this fixture does not establish interruption-proof teardown, and surviving
durable authority must be retained for recovery.

Portable helper checks verify continued Job-stop attempts after an injected
failure, fixed error categories and refusal to close a live reader. They are
not native Docker or full failure-matrix evidence.

## Evidence — 2026-10-10

Normal and optimized native invocations pass on Docker Desktop 4.44.3 / Linux
Engine 28.3.2 and image
`sha256:d495bf5f6e49090faf092e80d04d3b3dc180ba189a3fbe18f93e8809468b4f15`.
The canonical seccomp JSON pin is
`242cbd13aa6babf1f163ffa712ee00b0ce95e48c8bb3675d82eb213230b4ff48`.
Both report positive old-Job emptiness, cursor preservation and a live owned
orphan, followed by automatic replacement cleanup and unchanged scoped
container/volume inventories. Optimization is explicitly propagated to the host
controller and both launcher/poller children. The container's fixed Python
command remains unoptimized; no all-process-tree optimization claim is made.

The first attempt failed before Docker resource creation because the private
parent directory was absent. The harness now explicitly provisions it using
the existing private journal policy. An initial passing normal run preceded the
all-path cleanup helper refinement; final-version normal and optimized runs and
portable helper checks provide the current evidence.

```powershell
python scripts/verify_native_watchdog_restart_contract.py
python -O scripts/verify_native_watchdog_restart_contract.py
python scripts/verify_native_watchdog_restart.py
python -O scripts/verify_native_watchdog_restart.py
```

No Docker settings, pre-existing workload, runtime socket or Windows service was
changed. Installed restart supervision, native multi-root/outage/crash-race
coverage, an overall controller-death deadline and independent Linux cgroup
emptiness remain open. Production egress/resolver/parser/image/API and the full
public scan-to-share release gates remain open as well.
