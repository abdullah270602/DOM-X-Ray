# Gate 3 — local Docker resource proof

On 2026-10-06, the user selected Docker Desktop on this computer for native
resource-limit tests. The installed Desktop CLI started the Linux engine
(Docker Engine 28.3.2, cgroup v2). No WSL controller delegation, host cgroup
policy changes, privileged containers, host-network mode, Docker socket mounts,
host directories, or device mounts were used.

## Reproduce

Start the installed Docker Desktop and pull the official test image:

```powershell
docker desktop start
docker --context desktop-linux pull python:3.12-slim-bookworm
python scripts/verify_container_resources.py
```

The harness resolves the selected image to a local immutable image ID before
creating any containers and requires an official `python@sha256:` repository
digest. This run used
`sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3`.
This is local engine/image metadata, not signed provenance or a vulnerability
audit. Future pulls can change the tag; the report records the tested digest.

Every probe uses UID/GID 65534, no capabilities, no-new-privileges, default Docker
seccomp, no networking, a read-only root, 64 MiB memory with no swap, 32 processes,
0.25 CPU, 16 MiB `/tmp` tmpfs, and 8 MiB shared memory. The harness reads back
Docker configuration before starting the container. In-container checks read
the actual cgroup limits; the disk probe checks mount type and filesystem size.
Local logs are bounded to one 1 MiB file with compression disabled.

## Observed evidence

| Probe | Native observation |
| --- | --- |
| Configuration | cgroup v2 memory/swap/PID/CPU limits match; capabilities zero; no-new-privileges set; root write denied |
| CPU | three-second busy loop increases throttled periods and throttled time |
| Processes | 31 lightweight children are created; next fork fails with EAGAIN and increments `pids.events max` |
| Temporary disk | `/tmp` is a 16 MiB tmpfs; writing reaches 16,777,216 bytes then ENOSPC |
| Memory | 128 MiB allocation child is SIGKILLed and `memory.events oom_kill` increases |
| Detached normal exit | fixture forks a setsid child; root exits zero; Docker reports stopped with host root PID zero |
| Detached forced exit | fixture forks a setsid child; harness kills the container; Docker reports exit 137, stopped, host root PID zero |

Every test container is removed by exact ID only after its random name and
invocation ownership label match. The harness checks no container with that exact
name remains. Cleanup also runs on failed probes and ambiguous create timeouts.
No image, unrelated container, volume, or engine-wide resource is deleted.
Both verifier and fixture reject optimized Python (`-O`) before any checks can
be skipped; those negative invocations were verified.

## Deliberate limitations and next boundary

This checkpoint proves quota behavior for disposable Python fixtures under this
local Docker engine. It does not adopt Docker into the scanner, test Chromium's
memory needs, or prove the existing namespace wrapper works under default Docker
seccomp. The 64 MiB test allocation is intentionally small, not a production
browser budget. Disk evidence covers `/tmp`; shared-memory and log limits are
configuration readbacks, not saturation tests.

Stopped-container/PID-zero observations are not an independent host-side
descendant-liveness check or a `cgroup.events populated=0` observation. Do not
promote them to a whole-tree teardown proof. Scanner adoption still needs a
trusted engine-side launcher, result admission only after independently verified
teardown, bounded output transfer, reviewed broker/browser networking and
identities, a patched immutable runtime, and CPU/memory/PID/disk tests with actual
capture. No visitor URL enters these fixtures. Arbitrary public scanning remains
disabled and the public capture `.test` guard is unchanged.

Reference semantics: [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/)
and [container run options](https://docs.docker.com/reference/cli/docker/container/run/).
