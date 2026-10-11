# Startup investigation and intent-ambiguity guard

## Production change: preserve ambiguous intent obligations

The controller now marks each resource attempted **before** invoking its durable
intent write. A journal operation can commit and then raise; omitting that role
from cleanup could otherwise allow shared-volume removal while the journal still
records an unresolved role intent. Attempt bookkeeping is not launch permission:
the actual create still requires a successful durable intent return.

Container roles with an ambiguous intent enter exact-name cleanup with no assumed
ID. An absent/unproven result or failed removal note keeps volume handling blocked
and prevents artifact admission. An ambiguous volume intent triggers only the
existing ownership-bound volume cleanup path; missing ownership is not invented.
Journal schema, transition dependencies and recovery semantics are unchanged.

Consumer preparation is extracted into `_prepare_consumers`, but production
still creates and preflights broker then worker serially, overlapping only the
already-running initializer. The 15-second lease, five-second cleanup reserve,
parallel cleanup proofs, image, seccomp and namespace/resource policy are unchanged.

Final normal/optimized `verify_journal_pair_contract.py` covers committed-then-
raised intent writes for worker, broker, initializer and volume, as well as ID,
removal, completion and capacity faults. It verifies ambiguous container intents
are included in cleanup, shared volume removal is blocked, a missing volume is
looked up but not removed, and no failed artifact is admitted. Existing full pair
and parallel-cleanup controls also pass normally and optimized. These are real
journal/controlled-Docker proofs, not native crash injection.

## Startup candidate: isolated, not adopted

A proposed parallel broker/worker creation was rejected because the actual
journal requires broker-created before worker-intent. No journal rule was relaxed
and no such dual-create native test was run. A revised candidate instead overlaps
read-only broker inspection with stopped worker creation **after** the broker's
durable ID commit. Both preflights, joined tasks and successful initializer exit
must precede any consumer start. Journal writes/preflight decisions stay on the
controller thread; the original absolute deadline passes through both tasks.

The candidate is now test-only in `scripts/verify_pair_startup_pipeline.py`.
`verify_pair_api_publication.py --startup-pipeline-experiment` explicitly opts
only that reserved-origin verifier into it; default controller/API/CLI do not.

```powershell
python scripts/verify_pair_startup_pipeline.py
python -O scripts/verify_pair_startup_pipeline.py
python scripts/verify_journal_pair_contract.py
python -O scripts/verify_journal_pair_contract.py
python scripts/verify_pair_supervisor_contract.py
python -O scripts/verify_pair_supervisor_contract.py
python scripts/verify_pair_parallel_cleanup.py
python -O scripts/verify_pair_parallel_cleanup.py
```

All eight final suites passed. Candidate controls use actual journal states and
real barrier-synchronized threads to check dependency order, overlap, joins,
retained IDs and refused execution after create/ID/inspection/preflight faults.
Its initial new test had an invalid fixed expiry and failed; using a valid current
lease corrected the harness, not production deadlines.

## Native trial, 2026-10-11: no latency improvement demonstrated

One preliminary revised-candidate API attempt used immutable image
`sha256:d495bf5f6e49090faf092e80d04d3b3dc180ba189a3fbe18f93e8809468b4f15`
and the unchanged fixture seccomp policy. It reached broker readiness near
9.406 seconds, worker cutoff near 10.229 seconds, and failed final volume absence
verification near 15.233 seconds. It returned capture-failed and published nothing;
scoped container/volume inventories matched their baselines afterward. This is a
failed integration run, not a speedup, successful capture or cleanup-within-lease
pass. Host/load variability and instrumentation were not controlled.

Its persistent journal `pair-api-journal-537995e5893f59f05a22c9196045a96d`
records all containers removed but volume only created. One exact expired recovery
pass retained it (resolved=0, retained=1) rather than manufacturing a durable
removal proof from current absence. The journal remains preserved, along with the
earlier unresolved journal in `TRANSPORT_API_EXECUTOR.md`. The native trial
predated the final intent bookkeeping guard and candidate isolation; there is no
final-version native candidate or injected journal-crash proof.

The candidate was removed from production because this trial did not demonstrate
improvement. Future investigation needs to measure control-channel overhead and
achieve successful capture/publication under unchanged limits, plus a durable
removal-boundary recovery design. Independent host cgroup binding, installed
supervision, public egress, export reliability and release gates remain open.
Public scanning stays disabled.
