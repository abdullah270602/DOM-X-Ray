# Gate 3 — Foreground launcher process-death/restart proof

`verify_watchdog_process_restart.py` runs the foreground launcher in actual,
separate Windows Jobs assigned before each suspended child resumes. It uses one
private hash-pinned configuration, one real journal and 25 expired fixture leases
whose resources are all unrequested. No Docker resource exists or needs removal;
the runtime executable is a fixture and must not be contacted for engine work.
Expiry is adjusted only inside this ephemeral fixture journal, not the host clock.

The first launcher runs the production entrypoint with a test-only pause after
emitting its committed 20-record recovery receipt. At that point its journal
transaction and ownership context have closed. The pause avoids relying on the
parent receiving output and killing within the normal 500ms retry interval; no
recovery algorithm, binding or commit path is replaced. The parent forcibly
terminates only that launcher's dedicated Job, waits for its exact termination exit code 1 and
positively observes active-process count zero. It then opens the journal and
requires cursor 20 with exactly the five later obligations remaining.

The fixture inserts one new unrequested record before the saved lexical position.
The replacement runs the unmodified foreground launcher with the same config and
digest for one tick. It resolves six records and finishes at cursor zero: later
records were visited before wrapping to the newly inserted lower token. Starting
from the beginning would instead end at token 25, so this checks durable cursor
use rather than merely rediscovering the remaining records.

The replacement must exit zero, its Job must become empty, the lease snapshot
must be empty and the cursor must remain zero. Fixed registration/recovery/stop
receipts contain no private paths and no result artifact is admitted. Both Job
trees and bounded pipe readers are stopped/closed on all fixture paths.

## Evidence — 2026-10-08

Normal and optimized Python pass the actual-process fixture. The original first
attempt failed a combined immediate exit/Job-emptiness assertion; that output did
not independently distinguish the two conditions. The fixture now checks the
exit code separately and waits up to five seconds for positive Job emptiness,
rather than assuming process exit and accounting updates are simultaneous.

The private configuration verifier is rerun after extracting its shared fixture
builder. Configuration/runtime identity checks are not weakened.

```powershell
python scripts/verify_watchdog_process_restart.py
python -O scripts/verify_watchdog_process_restart.py
python scripts/verify_recovery_configuration.py
```

## Limits

This proves local process death, OS ownership release, configuration reload and
cursor paging through the foreground entrypoint. It does not install an OS
service, test automatic supervisor restart, contain a hung owner, prove an overall
controller-death deadline, establish power-loss durability, or remove a real
Docker orphan. Windows Job emptiness is not Linux cgroup emptiness. Native Docker
restart/cleanup remains gated by the unresolved Docker startup failure. No Docker
host file was changed; public scanning and other production/product gates remain
open.
