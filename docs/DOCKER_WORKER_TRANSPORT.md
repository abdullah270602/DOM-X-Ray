# Gate 3 — trusted Docker launch and result transport

This checkpoint adopts a host-side Docker supervisor for **reserved-origin
fixtures only**. It does not enable arbitrary public scans, wire the public API
to Docker, or approve the historical Chromium image for untrusted public pages.

## Contract

`run_public_scan_transport` accepts an explicit operator-selected supervisor.
The process supervisor remains the default; it rejects stdin payloads rather
than silently ignoring them. There is no Docker-to-process fallback on error.

The Docker adapter selects a trusted absolute CLI path, named context, immutable
local image ID, fixed baked entrypoint, and hash-checked fixture syscall profile.
These choices never come from visitor JSON. Both the host and the image recheck
the grant shape. Only the grant and a fresh result nonce cross stdin; targets,
resolved addresses and nonce are not placed in arguments or environment values.
Input is bounded to 16 KiB and rejects duplicate keys and extra fields.

Each container is created but not started until readback verifies identity,
entrypoint/arguments, disabled healthcheck, resource limits, exact security
options, private namespaces, read-only root, no host mounts/devices, and disabled
networking. Policy is one CPU, 1 GiB memory with no swap, 128 tasks, no
capabilities, no-new-privileges, non-root UID/GID 10001, private 128 MiB noexec
scratch and 64 MiB shared memory. Docker's init process is enabled.

The image emits one JSON envelope on stdout. The host retains at most 4,000,001
bytes, drains/discards excess while stopping the client, and refuses oversized,
duplicate-key, nonfinite, trailing, malformed or wrong-nonce results. Stderr is
discarded and the container log driver is `none`; there is no accumulating
engine log or unbounded `communicate()` buffer. A valid envelope still needs
schema, semantic and target-bound admission in the transport.

The 15-second worker deadline includes engine setup, execution, teardown and
envelope admission, reserving two seconds for teardown. It is not a nested
15-second container timeout or an end-to-end promise including DNS/queue time.
Slow or unavailable engine control fails closed; it cannot make output eligible.

## Teardown before admission

Every invocation uses a random name plus an ownership label. The host stops the
attached CLI independently, looks up only that exact name, checks the label and
ID, kills the owned container if running, checks stopped state and PID zero,
removes that exact stopped container, then checks name absence. It never uses
broad prune or force-removes an unverified container. Create-time ambiguity uses
the same scoped lookup; an empty lookup after an ambiguous create is unresolved,
not proof that no container can appear later. A failed attachment client also
prevents admission even if the engine reports the container's exit as zero.
Any failed ownership/control/teardown check prevents
artifact creation/admission. An external disappearance is not accepted as proof
of teardown for a previously identified container.

These are **engine-reported observations**, not independent evidence that a host
cgroup has `populated=0`. A late create after an engine timeout, controller crash,
or engine outage can leave an orphan; durable lease recovery/watchdog and
independent descendant/cgroup-empty evidence remain release gates. Rejecting a
result is not a claim of successful cleanup when the engine is unavailable.

## Verification

Prepare/build the fixture image as described in `CONTAINER_CAPTURE_FIXTURE.md`,
then run:

```powershell
python scripts/verify_scan_transport.py
python scripts/verify_docker_supervisor_contract.py
python scripts/verify_docker_transport.py
```

The native verifier covers valid fixture output, actual sandboxed Chromium
capture, a live post-capture renderer hang, crash, wrong nonce, trailing JSON,
duplicate keys, output overflow, stderr flood, target mismatch and the stock
entrypoint's public-target rejection. It resolves the fixture tag to
an immutable local ID before invocation and verifies no new owned containers or
host result directories remain after the matrix. Fixture origin/DNS injection
is baked trusted test code, never a stdin option. The stock image entrypoint
retains the `.test` guard.

The Docker Desktop Linux engine was selected by the user. Local 2026-10-06
verification recorded actual capture at 7,021 ms and live-renderer timeout with
no admission at 14,303 ms. All eleven native cases and ten mocked contract cases
passed; the contract suite also passed with Python optimization enabled.
These timings are fixture observations, not public
corpus or production reliability evidence.

Before public adoption: update/audit the immutable browser/runtime, minimize and
review the broad fixture filter, build a restricted egress-broker path (network
`none` currently prevents real public origin contact), establish durable cleanup
recovery and independent teardown evidence, and complete parser, identity,
API/queue, abuse and representative-corpus gates in `ROADMAP.md`.
