# Gate 3 — Multi-lease recovery scheduling contract

## Implemented behavior

The existing recovery pass operates under one private journal owner, one configured
runtime fingerprint and one bounded monotonic pass deadline. It rotates the sorted
snapshot after a caller-supplied 32-hex token cursor, filters mismatched/future
leases, and attempts at most 20 eligible leases. Each attempted lease advances the
returned cursor whether it resolves or remains ambiguous. The next caller must
carry `next_after`; always starting from the beginning can starve later leases.

Deleted or nonexistent cursors remain useful lexical positions. Reaching the end
wraps to the beginning. Ineligible rows are not mutation targets and do not consume
the eligible-attempt ceiling. Expiry eligibility is inclusive at expiry plus the
configured grace. A backward wall clock delays eligibility; it grants no ownership.
A monotonic deadline exhausted before the first attempt leaves the cursor unchanged.

This is fairness across completed passes with a carried cursor, not a durable
completeness receipt, a fair global multi-runtime scheduler, or a guarantee under
repeated watchdog restarts. A future watchdog must maintain cursor state per
configured journal/runtime and distinguish ownership contention from corrupted
or inaccessible authority. It must never treat an unreadable journal as empty.
The cursor is content-free operator state, never visitor-supplied configuration.

## Decoder hardening

Daemon info now rejects duplicate keys at every decoded object level, literal
NaN/Infinity, and finite-JSON exponent overflow such as `1e999`. The root must be
an object; Linux/cgroup-v2 identity and the nonempty daemon ID remain required
before resource contact. Legitimate extra Docker metadata is allowed; it is not
a closed three-field schema. Nonfinite decoded floats are rejected even in extra
metadata. Replies still have the existing bounded control-byte and deadline limits.

## Evidence — 2026-10-08

`scripts/verify_recovery_paging.py` uses actual private `LeaseJournal` instances,
unique per-lease immutable IDs and a simulated daemon pool. Normal and optimized
Python verify:

- A missing first worker retains authority but yields to later valid leases.
- Deleted/missing cursors wrap; an owned late resource subsequently resolves.
- A 25-row journal is processed in 20- and 5-row pages with no engine contact
  when every resource is unrequested.
- Sparse eligible rows interleaved with mismatched fingerprints and future leases
  preserve exact skipped records/resources while wrapping across the lexical end.
- Simulated outage retains every obligation and advances to deferred work on retry.
- Backward clock, just-before-grace and exact-grace eligibility have the expected
  no-contact/eligible behavior.
- Budget exhaustion during daemon info permits no subsequent action; exhaustion
  before the first attempt does not advance the cursor or contact Docker.
- Eleven malformed/ambiguous/nonfinite daemon replies retain two leases each
  without resource removal or journal mutation.
- Eleven invalid scheduling configurations reject before engine/journal mutation.

The original 18 recovery cases still pass after parameterizing their fixture
daemon for unique tokens/IDs. The [native crash verifier](CONTROLLER_CRASH_RECOVERY.md)
is rerun to check real Docker reply compatibility; it does not establish native
multi-lease fairness, outages, delayed creates or backward-clock recovery.
The final optimized native run with finite-exponent checks resolved one live
orphan in 6,538 ms, with empty controller Job, empty lease journal, no result
artifact and unchanged scoped container/volume inventories.

```powershell
python scripts/verify_recovery_paging.py
python -O scripts/verify_recovery_paging.py
python scripts/verify_lease_recovery.py
python -O scripts/verify_pair_controller_crash.py
```

## Remaining watchdog work

No autonomous scheduler is deployed by this checkpoint. The watchdog still needs
an independently supervised lifetime, bounded private runtime/journal registry,
busy-owner versus damaged-authority handling, cursor persistence/restart behavior,
backoff and health reporting, native multi-lease/crash/race tests, and a demonstrated
overall controller-death bound. Independent Linux cgroup emptiness and all public
scanner deployment, policy and product gates remain open. Public arbitrary-URL
scanning stays disabled.

The subsequent [polling component](RECOVERY_POLLER.md) carries this cursor in
memory, distinguishes busy acquisition from authority faults and backs off on
retained obligations. Durable cursor/restart behavior and service deployment
remain open; it does not supersede the limitations above.
