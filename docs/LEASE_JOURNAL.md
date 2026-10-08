# Content-free durable lease journal

This checkpoint adds local journal authority to the trusted pair launcher. It
does **not** yet implement automatic Docker recovery or a deployed watchdog.
The product goal and public-scanning gates remain open.

## What survives controller process death

The journal stores only a random lease token, runtime fingerprint, actual Docker
daemon ID, expiry and four resource states/immutable container IDs. It stores no
URL, resolved addresses, grants, capability, supervisor nonce, measurement,
output, stderr or exception text. Resource names are derivable from the token.
The runtime fingerprint includes immutable image, Docker executable/context,
exact role commands, seccomp content and a versioned pair policy.

Before any Docker work the launcher reserves a bounded row. After engine
inspection it commits the daemon identity. Every volume/container create has a
committed intent first; returned IDs are committed before preflight/start.
Removal marks follow exact ownership/stop/removal/absence proof, never precede
it. Volume removal marks require every container role to be unrequested or
removed. Container intents require a created volume, and broker/worker setup
dependencies are enforced by the journal API. Only fully resolved leases may be
deleted before artifact admission. Failed writes do not admit a result.

An unresolved intent remains recorded. Absence does not imply removal or prove
that a delayed create cannot appear. Crashes between Docker removal and journal
commit can therefore retain tombstones even when resources are already gone.
There is no automatic age-out or tombstone eviction; a full journal fails closed
before engine/resource work. A future reaper must handle these cases explicitly.

## Local authority and storage bounds

One non-inherited OS file lock is held until the journal closes/process exits:
Windows byte-range locking or POSIX `flock`. A second process opening the same
journal is refused, even before expiry. An active launcher holds a journal-use
reference so another thread cannot close/release it mid-run. Expiry alone is not
proof of controller death and is not recovery authority.

The operator supplies a canonical private local directory, never a visitor path.
Windows creation removes inherited ACL entries and grants the current user,
SYSTEM and Administrators; ACL validation permits OWNER RIGHTS only after the
owner is independently validated against that trusted set. POSIX requires owner
UID and exact directory/file modes 0700/0600. Static reparse/symlink, hardlink,
inode replacement, unexpected sidecar and schema checks fail closed. A hostile
same-UID process racing filesystem path checks is **outside this checkpoint's
threat model**; this is not handle-relative filesystem containment. The trusted
parent namespace, local administrator and service account must be protected at
deployment. It is not shared/network-filesystem or multi-host coordination.

SQLite uses one mutex-serialized connection with DELETE rollback journaling and
verified `synchronous=EXTRA`; mode and schema are rechecked for transactions.
There are at most 1,000 leases, 8 KiB per encoded record, 1,024 4-KiB database
pages (4 MiB) and a separately bounded rollback sidecar (4 MiB). Lock files are
non-inherited, regular, singly linked and permission checked. The configured
sync/page semantics are documented in [SQLite's PRAGMA reference](https://www.sqlite.org/pragma.html).
These settings do not prove power-loss durability on every filesystem/storage
device; that remains deployment evidence.

The journal is explicitly operator supplied through `lease_journal=`. Existing
fixture callers may omit it; such calls are not durable recovery candidates. The
production scanner must not adopt the nonjournaled mode. Every journal operation
is charged to the same pair lease with deadline checks before/after; synchronous
filesystem stalls can cause a fail-closed deadline overrun, not safe admission.

## Verification

```powershell
python scripts/verify_lease_journal.py
python -O scripts/verify_lease_journal.py
python scripts/verify_journal_pair_contract.py
python -O scripts/verify_journal_pair_contract.py
python scripts/verify_pair_transport.py --journal
```

The native host journal test forcibly terminates its owner process, verifies a
competing process could not obtain its lock while alive, then opens from a
replacement process and verifies committed IDs plus unresolved intent survived.
Those IDs are synthetic: this test is **not** a killed-Docker-controller/reaper
proof. It also checks transition ordering, content exclusion, capacity backpressure,
hardlink/size/schema rejection, active-use close denial and retained tombstones.
The fault suite uses actual journal commits with mocked Docker, testing failures
at capacity, intent, ID, removal and completion boundaries; all failed cases have
no artifact and preserve the appropriate unresolved state.

Native pair tests use persistent private journal directories under ignored
`.dom-xray-data/pair-lease-journal-*`, not temporary result directories. On a
failed test they close the owner lock but retain authority for inspection; they
do not erase unresolved leases with temporary-directory cleanup. Known-ID Docker
cleanup now inspects that exact ID directly, verifies its name/token/ID before
kill/removal and still checks exact-name absence afterward. This avoids redundant
CLI lookups without accepting disappearance as teardown proof.

Local 2026-10-06 evidence: journal tests passed normally and under Python
optimization, including forced process termination/ownership handoff. Six actual
journal + mocked-Docker fault cases passed normally and under optimization;
pair-supervisor contracts, the new failed-kill/still-running canaries and the
independent scan-transport matrix passed. A journal-backed native matrix on
Docker Desktop Linux 28.3.2 / cgroup v2 and immutable worker image
`sha256:6f898cbcaa93d174ed62795ef10187009777d2b2f8c7580bcde7bc83fe5fc408`
recorded capture admission at 12,658 ms, real-renderer timeout rejection at
13,370 ms, wrong-capability rejection at 9,328 ms and wrong-UID rejection at
9,041 ms. All four leases and resources were resolved in that run.

Development exposed failures rather than hiding them: an initial temporary test
journal could be deleted during harness failure, so journal roots were moved
outside temporary result directories. Later an exited worker and volume were
retained with their journal obligations; exact manual recovery checked runtime
fingerprint, daemon ID, token and immutable ID, then committed positive removal
proofs. Cleanup now reconciles a failed kill only after fresh ownership-checked
stopped/PID-zero evidence; absent or still-running resources remain failures.
The original failure's cause was not independently proven to be that race.

C: subsequently filled, invalidating oversized-file setup and preventing further
writes. After space became available, host tests were rerun successfully. The
last file-guard hardening also checks opened-file metadata in addition to path
metadata. That final guard change has host/contract evidence but no fresh Docker
matrix: a bounded Docker health query did not complete. No images were rebuilt,
no public scanning was enabled, and no automatic-recovery proof is claimed.

## Next evidence required

See [LEASE_RECOVERY.md](LEASE_RECOVERY.md) for the 2026-10-08 operator-only reaper
implementation and its explicitly limited evidence. The requirements below
remain release gates, not claims of completion.

[CONTROLLER_CRASH_RECOVERY.md](CONTROLLER_CRASH_RECOVERY.md) adds one native
live-renderer/controller-tree death and replacement recovery proof. Automatic
scheduling, the broader crash matrix and independent Linux emptiness remain open.

Implement the replacement-controller reaper and watchdog scheduling. It must
acquire local ownership first, bind the actual daemon/runtime, respect eligibility,
derive only exact recorded names, validate labels/image/IDs, attempt remaining
role cleanup after failures, and preserve ambiguous/absent intents. Volume
removal requires durable positive container-removal proof. Test real controller
termination with a live Chromium witness, delayed creates after an empty lookup,
partial removal crashes, engine outages, ownership mismatches and concurrency.
Independent cgroup-empty proof, public broker egress, production adoption and all
remaining product/human/platform gates are still unproven.

The later [polling checkpoint](RECOVERY_POLLER.md) adds a single-journal polling
component, not a deployed watchdog. Its [cursor checkpoint](RECOVERY_CURSOR.md)
extends the exact schema with an optional, transactionally created singleton
scheduling table. Legacy journals remain readable; unexpected schema still
rejects. Cursor persistence does not confer cleanup ownership or close the
remaining native/deployment gates above.
