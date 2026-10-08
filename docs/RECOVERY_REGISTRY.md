# Gate 3 — Bounded operator recovery registry

`LeaseRecoveryRegistry` accepts a fixed tuple of one to eight existing
`LeaseRecoveryPoller` instances. It rejects duplicate journal paths and root
device/inode identities. There is no filesystem discovery, visitor input,
wildcard Docker lookup, implicit bootstrap or dynamic enrollment. Each poller
retains its own pinned journal/runtime and durable scheduling cursor.

A local mutex serializes visits. Each tick selects at most one due entry, rotating
round-robin from the prior completed visit. Busy ownership or authority faults
therefore yield to other due entries. The retry deadline for an entry starts
after its pass completes and does not postpone another entry's due time. When
all entries are waiting, the registry returns the next monotonic delay, capped
at 30 seconds; the run loop waits interruptibly on the caller's stop event.
When more work is immediately due, that delay is zero. An idle outcome means
only that no registered entry is due, not that every journal is empty or healthy.

Health contains the registration index, the existing content-free per-pass
outcome and the next delay. No root path, runtime fingerprint, cleanup token or
raw provider error crosses this boundary. Indices are local operator positions,
not visitor-selected resource identifiers. The trusted registration program must
not mutate/reconfigure pollers or run their loops concurrently with this registry.

## Evidence — 2026-10-08

Normal and optimized `verify_recovery_registry.py` runs use real private journals
and Windows ownership locks. Engine calls are simulated and unexpected contact
is checked during empty-intent recovery. They prove:

- Empty, over-eight, mutable-list, wrong-type and duplicate registrations reject;
  exactly eight entries are accepted and receive a full ordered rotation.
- A held owner returns busy while the next two registered journals resolve.
- Due intervals and round-robin order are respected; the released owner can then
  recover normally without being displaced while live.
- A missing fixture database faults without recreation, and its backoff does not
  suppress another journal's due work.
- A completed slow pass starts its retry interval at completion, while another
  due entry is immediately available.
- Health stays content-free, stop requests end the loop, an external stop wakes
  an actual timed wait, pre-stopped loops do no work, and invalid run bounds reject.

The first fixture attempt used a rejection helper that expected journal exceptions
instead of the registry's containment exception; the helper was corrected. No
production rejection was relaxed.

```powershell
python scripts/verify_recovery_registry.py
python -O scripts/verify_recovery_registry.py
```

## Not established

This implements bounded registration and fair scheduling across completed visits,
not a durable configuration file, registry restart loader or installed service.
Entry order, due times and retry counters are volatile; each journal's cursor is
durable separately. One non-preemptible filesystem/SQLite/factory operation can
delay other entries: serial scheduling is not independent per-entry process
isolation, a starvation guarantee under hung visits, or a hard overall deadline.
Callback failures belong to the trusted caller and are not swallowed.

Native multi-root/outage/race evidence, independent watchdog supervision and
controller-death deadline enforcement remain open. Docker's diagnosed startup
failure still prevents the final native verification. No host Docker files were
changed. Public arbitrary-URL scanning and all other production/product gates
remain disabled or open as previously documented.
