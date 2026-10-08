# Gate 3 — Journal-backed recovery cursor

## Implemented contract

The poller reads its scheduling cursor from its acquired private journal before
calling the Docker reaper, then commits the returned position before reporting a
completed pass. A newly constructed poller resumes the durable position. Its
in-memory `cursor` is only a receipt for the last successfully saved pass.

The journal accepts exactly its original schema or that schema plus one exact
`recovery_cursor` table with one validated singleton. This table contains only
the runtime fingerprint and nullable 32-hex token. No new file, visitor input,
target, capability or resource authority is introduced. Reading a legacy cursor
returns `None` without changing schema. The first save creates the table and row
atomically under the existing OS ownership lock and SQLite transaction.
Existing file/ACL/inode/schema checks and storage caps still apply. Older code
versions reject an extended journal; a downgrade must not delete or reset the
database to get past that error.

The singleton is bound to one runtime fingerprint. A different runtime faults
before engine contact; no automatic reset or reassignment occurs. Operator
runtime migration remains a future workflow. Malformed tokens/fingerprints,
schema or a missing singleton fault rather than resetting scheduling position.
Active scan/recovery holds cannot save scheduling state.

The cursor is a fairness hint, not ownership evidence. Deleted tokens remain
lexical positions and wrap through retained records. Cleanup retains its exact
resource/runtime/daemon checks. Retained passes also save the returned position
so later work can proceed.

Cleanup changes and cursor updates are separate transactions. A crash or failed
cursor write after proven cleanup can leave the old cursor while keeping cleanup
proofs. A failed save reports `fault`, not a successful checkpoint. Restart may
repeat a page: this is not exactly-once scheduling or guaranteed progress under
termination before every cursor commit. Retry delays/fault counts are volatile.

## Evidence — 2026-10-08

`verify_recovery_cursor.py` uses actual private journals, OS ownership, SQLite
transactions and a forcibly terminated child process. Docker is simulated.
Normal and optimized runs verify:

- Legacy reads do not alter schema; failed first insertion rolls back both table
  and row creation without changing lease records.
- Failure before SQLite commit rolls an update back to the previous cursor.
- Invalid tokens, runtime reassignment and saves during active holds reject.
- Reopened journals preserve their position and support a bound null cursor.
- Fresh pollers move past a retained first lease, clean later leases, reject
  runtime drift before engine contact and wrap around a deleted cursor.
- A failed cursor save faults without erasing retained obligations or undoing
  cleanup already proven by the reaper.
- A child commits its cursor, announces the commit and is forcibly terminated;
  a replacement owner reads that same committed value.
- Malformed tokens/fingerprints or a deleted singleton reject journal opening
  and poller ticks without engine contact or silent reset.

```powershell
python scripts/verify_recovery_cursor.py
python -O scripts/verify_recovery_cursor.py
```

Existing polling, journal safety/admission fault injection, recovery, multi-lease
scheduling, pair-supervisor and crash-fixture contracts are regression checks.
This does not prove power-loss durability or a deployed watchdog restart on real
Docker. Docker Desktop's engine is currently unavailable; final native poller
verification remains open. Registry/service supervision, overall controller-death
deadline enforcement, native crash/outage coverage, independent Linux cgroup
emptiness and production/public product gates remain open.
