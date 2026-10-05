# Separate-container origin broker fixture

This checkpoint moves actual sandboxed Chromium capture through a broker in a
different Docker container and UID. It remains a reserved-origin fixture, not a
production pair supervisor or public scanning enablement.

## Tested boundary

- Broker runs as `10002:10001`; worker runs as `10001:10001`. Both have read-only
  roots, dropped capabilities, no-new-privileges, private IPC/cgroup namespaces,
  no host PID/user namespace mode, no network, and bounded CPU/memory/processes.
- Each case creates a fresh, labeled Docker `local` named volume, without host
  bind mounts or driver options. A fixed initializer runs as root with only
  `CAP_CHOWN`, sets the empty volume root to owner `10002:10001`, mode `0710`,
  then exits before either broker or worker starts. It receives no job secrets.
- Broker mounts that volume read-write; worker mounts it read-only. The broker
  creates `origin.sock` owned by `10002:10001`, mode `0620`. The shared group has
  directory traversal and socket connection permission, but no directory listing
  or mutation permission. Group permission does not replace peer UID checks.
- `OriginBroker(socket_gid=...)` explicitly enables this strict layout. The
  client verifies exact directory/socket UID/GID/mode and the connected broker's
  kernel peer UID. Broker verifies the worker's peer UID, per-scan capability and
  full-grant HMAC on every request. Default private mode remains available; its
  directory check now requires exactly `0700` rather than merely no group/other
  permission bits. No visitor field can select socket permissions or identities.
- Capabilities and job grants travel only through stdin, not argv/environment,
  browser arguments, Docker metadata or logging. Broker/worker logging is off.
  Runtime checks read `/proc/self/status`: broker/worker effective capabilities
  must be zero, initializer's must be exactly CHOWN, with no-new-privileges and
  seccomp filtering active for all three.

Docker volumes can be shared across containers and mounted read-only, as described
in the [Docker volume documentation](https://docs.docker.com/engine/storage/volumes/).
The ability to connect to this socket through the read-only mount is tested on
the selected Linux engine, not inferred from that documentation.

## Verification

Build the candidate image using `RUNTIME_CANDIDATE.md`, then run sequentially:

```powershell
python scripts/verify_container_broker_pair.py
python scripts/verify_container_capture.py --image dom-x-ray-runtime-candidate:gate3 --origin-broker
python scripts/verify_origin_exchange.py
python scripts/verify_scan_transport.py
python scripts/verify_docker_supervisor_contract.py
```

The six pair cases cover actual schema/semantically valid Chromium capture;
wrong capability; broker-side wrong expected worker UID; worker without the
shared GID; worker without the volume; and a real live-renderer hang. Every
unauthorized case must have zero broker DNS lookups and origin contacts.
The permitted worker also proves directory listing, broker-private file read,
socket chmod/unlink/chown and file creation are denied. Broker reports first-pin
and later fresh-resolution behavior. On normal exit its socket and private
canary file must be removed before the result is considered. On timeout the
host kills the exact worker container and admits no record.

Every created container has isolation/mount/resource policy read back before
start. Cleanup verifies the case token and exact container ID, kills if needed,
checks engine-reported stopped/PID-zero state, removes that container, then
removes only the exact labeled volume after containers are gone. It never
prunes, deletes host data, changes host certificates/kernel settings, or enables
privileged/unconfined execution. Removed volumes contain only fixture sockets
and the empty private-file canary, not visitor data.

Local evidence on 2026-10-06: Docker Desktop Linux engine 28.3.2 / cgroup v2;
Playwright 1.63.0 / Chromium 153.0.8010.12; immutable tested image
`sha256:6f898cbcaa93d174ed62795ef10187009777d2b2f8c7580bcde7bc83fe5fc408`.
All six final-image cases passed: capture 5,886 ms; wrong capability 1,604 ms;
wrong UID 1,676 ms; wrong GID 1,497 ms; absent volume 1,614 ms; hang 10,718 ms.
These intervals start at worker attachment and exclude setup/container creation,
so they are not end-to-end product latency. The hang passed only after proving
a live renderer witness and rejecting its output. A separate label-filtered
inventory found no fixture-owned containers or volumes remaining. Origin
exchange, scan transport and ten mocked supervisor contract tests passed, and
smaller-model review found no material defect within this fixture scope.
All five existing native capture/protocol regression cases also passed on this
image, including six real Chromium direct-network bypass denials and the sixteen
forged-response canaries. The native supervised baseline capture was 4,219 ms;
its live-renderer timeout was rejected at 14,508 ms. Its maximum observed cgroup
memory peak was 222,375,936 bytes and process peak was 89, not public-corpus bounds.

## Remaining release gates

Follow-up: `PAIR_SUPERVISOR.md` records a trusted startup-inclusive pair launcher
and native 15-second lease tests. The fixture limitations below describe this
verifier specifically; durable recovery and real public egress remain open for
the new launcher too.

The existing `DockerWorkerSupervisor` still forbids mounts and does not launch
this pair. The new verifier is deliberately not its replacement: volume setup
and container creation precede the measured worker interval; cleanup calls have
their own bounded timeouts rather than one production startup-inclusive lease.
It does not cover controller death, late ambiguous creates, engine outages,
independent host cgroup-empty proof, concurrent cross-job attacks, or userns /
rootless mapping variants. These require a trusted pair supervisor and recovery
mechanism before API adoption.

Both containers use `network=none`, and the broker uses baked reserved origin/DNS
fixtures. Actual public TLS, broker firewall/egress policy, minimal production
seccomp/runtime audit, shared URL semantics, policy approval, distributed abuse
controls and representative performance remain open. Public API scanning still
returns `scanner-disabled`; the stock capture worker retains its `.test` guard.
