# Startup-inclusive Docker broker-pair lease

`DockerBrokerPairSupervisor` now plugs into the existing public-scan transport
as a trusted worker-supervisor provider. This is a network-none reserved-origin
checkpoint, not public API adoption or production approval.

## Admission contract

The operator selects an immutable image ID, exact reviewed seccomp JSON/hash,
Docker executable/context and fixed initializer/broker/worker commands. Launch
input is only a strictly validated grant. Visitor fields cannot select images,
commands, runtime, containers, volumes, credentials or permissions.

One monotonic lease (at most 15 seconds) starts before engine inspection. Volume
creation, container creation/readback, initialization, broker readiness, actual
worker capture, broker exit/report, exact-resource cleanup and artifact admission
all consume that lease. Five seconds are reserved for teardown at the 15-second
limit; shorter leases reserve at most 45%. No phase receives a fresh timeout.

The per-scan initializer, broker and worker use the identities and permission
layout in `CONTAINER_BROKER_BOUNDARY.md`. All common isolation/resource/security
checks from `DockerWorkerSupervisor` remain, plus exact role UID, no supplementary
group additions, CHOWN-only initializer, exact local named volume and mount access
mode. All three are inspected stopped before start. The initializer receives no
grant, nonce or capability; its zero exit is required before broker startup.

Broker stdin carries the same grant, random per-scan capability and nonce as the
worker and stays open as an ownership pipe during worker execution. Its bounded
stdout must begin with exactly `ready\n` while the attach client remains alive.
After the worker is engine-reported stopped, the controller closes broker stdin
and requires zero attach/engine exits, no OOM and one strictly framed report.
Duplicate/nonfinite fields, extra lines, wrong UID, malformed counts and false
cleanup/pin assertions reject the result. The report is trusted-image evidence,
not independent kernel attestation or a public-facing diagnostic.

Worker stdout is capped at 4 MB plus one detection byte. It remains in memory.
No result file is written until exact cleanup has succeeded: every attempted
container is found by exact name and verified ID/token, killed if running,
verified stopped/PID zero, removed, then checked absent. Cleanup attempts all
remaining roles even when one fails. The exact owned volume is removed only when
all attempted container teardowns are proven. Missing or mismatched resources,
engine/control failures and cleanup deadline exhaustion remain containment
failures; they never become successful scans. An ambiguous create found by exact
ownership lookup can be torn down, but cannot produce an artifact. An empty
lookup after an ambiguous create is not proof that no late container can appear.

Only a zero worker attach/engine exit, no OOM, nonce-bound strict envelope,
validated broker report and successful cleanup can create the exclusive mode-0600
artifact. Existing scan schema, semantic and requested-target validation still
run afterward in the transport. Timeout, malformed stdout and credential-denial
cases do not publish records.

## Verified evidence

Run sequentially:

```powershell
python scripts/verify_held_docker_pipe.py
python scripts/verify_pair_supervisor_contract.py
python -O scripts/verify_pair_supervisor_contract.py
python scripts/verify_pair_transport.py
python scripts/verify_docker_supervisor_contract.py
python scripts/verify_scan_transport.py
```

On 2026-10-06, the native pair matrix passed on Docker Desktop Linux engine
28.3.2 / cgroup v2 with the prior immutable worker image
`sha256:6f898cbcaa93d174ed62795ef10187009777d2b2f8c7580bcde7bc83fe5fc408`
(Playwright 1.63.0 / Chromium 153.0.8010.12). The controller runs from the current
host checkout; worker/broker fixture code in that image is unchanged by this
controller checkpoint. The fixture profile hash remains
`242cbd13aa6babf1f163ffa712ee00b0ce95e48c8bb3675d82eb213230b4ff48`.

Startup-through-cleanup observations: capture admitted at 13,870 ms; live-renderer
hang rejected at 14,367 ms; wrong capability rejected at 10,318 ms; wrong UID
rejected at 10,484 ms. The timeout passed only with a real renderer witness.
Before/after owned-container and volume inventories matched. These four fixtures
do not establish public-page success rate, p90 latency or deployment reliability.

The contract suite passed normally and under Python optimization. It covers
broker report framing/types, attach failures, stale nonce, late execution,
partial cleanup and retained volume, failed volume removal, both ambiguous-create
lookup outcomes, exhausted cleanup deadline and zero engine contact for invalid
input, plus 18 role identity/mount/group/network/start-state canaries. Native host
pipe tests verify held stdin readiness, explicit EOF release, noisy readiness
rejection and bounded stdout overflow. The original ten single-container mocked
contract cases and independent scan-transport matrix also passed.

The first native timeout run with a 3.5-second reserve was **not** successful:
containers were removed but the deadline expired before volume removal, causing
`supervisor-failed` with no admitted record. Read-only inventory identified the
single remaining owned volume. Its token/driver and absence of container users
were verified before exact manual removal. The final five-second-reserve matrix
passed without manual cleanup. This is evidence for the chosen split, not a
guarantee that engine stalls can always be recovered inside a lease.

## Remaining gates

Engine-reported stopped/PID-zero/absence checks are not independent host cgroup
`populated=0` proof. Durable lease journaling/watchdog recovery, controller death,
late engine creates/outages, concurrency and userns/rootless variants still need
tests and adoption. This checkpoint deliberately fails closed on unproven cleanup
rather than claiming an orphan is gone. The three commands are still operator
selected reserved-origin fixtures; public entrypoints are unchanged.

Real public TLS through a broker with independently enforced egress policy,
production resolver/parser semantics, minimized reviewed seccomp, patched runtime
release policy, public API/queue integration, approved scanner/retention/opt-out
policy, distributed abuse controls and representative corpus/human/platform
evidence remain required. The full product goal is still active.
