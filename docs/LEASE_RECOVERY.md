# Gate 3 — Replacement-controller recovery checkpoint

## Operator-only API

`scanner.lease_recovery.recover_expired_leases` takes a trusted, configured pair
supervisor with its private `LeaseJournal`. It never launches scans, creates
Docker resources or admits artifacts. No public endpoint invokes it.

The pass holds the journal mutex and OS ownership lock, excluding local active
controllers. It selects expired leases only when the runtime fingerprint matches,
then binds the recorded Docker daemon ID before touching resources. Expiry plus
the default five-second grace is scheduling eligibility, not ownership proof.

Exact token-derived names, labels, immutable IDs, image, commands and the full
role-specific isolation policy are checked before removal. Recovery accepts a
running container for teardown; launch preflight still requires an unstarted
container. Unknown intents are adopted only after positive matching inspections.
Missing resources remain unresolved, including an empty lookup after a create
intent. Reappeared resources previously marked removed are retained, not deleted.

Worker, broker and initializer cleanup are attempted independently. Volume removal
requires durable container-removal proofs. Final exact-name absence is rechecked
before deleting the lease row. Failure preserves remaining authority; no result
is published. An owned late create can resolve an earlier retained intent on a
subsequent pass.

The default pass has a 15-second scheduling budget, at most 20 eligible leases,
and a caller-carried token cursor. Checks surround control calls and journal
transitions. Local SQLite commits/lock waits are not forcibly preemptible: an
already committed finish is reported resolved even if its transaction crosses
the deadline. This is not a hard-real-time watchdog guarantee. The cursor is a
fairness hint, not a durable completeness marker; multi-lease paging remains an
evidence gap. Clock changes affect eligibility only. The operator must keep its
Docker context stable during a pass.

## Evidence — 2026-10-08

- `python scripts/verify_lease_recovery.py` and optimized Python verify 18 cases
  with an actual private journal and simulated daemon: running/stopped cleanup,
  network/mount/runtime/ownership mismatch, daemon mismatch, eligibility,
  missing and late intents, partial removal, reappearance, active-controller
  exclusion and deadline exhaustion with no subsequent control actions.
- Pair-supervisor contract regressions pass after sharing full policy readback.
- Docker Desktop 28.3.2 is running. The runtime candidate remains immutable image
  `sha256:6f898cbcaa93d174ed62795ef10187009777d2b2f8c7580bcde7bc83fe5fc408`.
- Two fresh native capture attempts failed with `worker-timeout`, not admission.
  Their durable journal snapshots were empty after cleanup. The cause is not yet
  established; neither attempt counts as successful native recovery evidence.

## Open release gates

The later [native controller-crash checkpoint](CONTROLLER_CRASH_RECOVERY.md)
proves one actual renderer/controller-tree termination and replacement-owner
cleanup scenario. It is not automatic scheduling, a complete crash/race matrix
or independent Linux cgroup-empty evidence.

Deploy an independent automatic watchdog; extend the native crash proof to
delayed creates, daemon outages,
partial-removal crashes and cursor paging natively. Independently prove cgroup
emptiness. The later [latency checkpoint](PAIR_LATENCY.md) resolves fresh fixture
capture timeouts on a separate code-overlay candidate, not the stock runtime tag.
Production egress, parser, API
adoption, security/policy and product gates remain open. Public arbitrary-URL
scanning stays disabled.
