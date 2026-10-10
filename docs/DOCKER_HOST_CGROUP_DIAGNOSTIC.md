# Docker Desktop host cgroup diagnostic

This is a fixture-only investigation. It is **not** a production
observer, adversarial identity binding, or proof of complete worker/broker teardown.
Arbitrary public scanning remains disabled.

## Selected host observations

On the selected Docker Desktop 4.44.3 / Engine 28.3.2 host, the
`docker-desktop` WSL distribution exposes `/sys/fs/cgroup/docker` and cgroup-v2
controllers. Its `/proc` cannot read the exact orphan worker's engine-reported
PID. An initial PID-membership probe therefore failed closed with
`cgroup-fixture-pid-unavailable`. Its manual journal-authorized fallback left
zero retained leases and unchanged scoped container/volume inventories. This
failed attempt is not native proof.

BusyBox `stat -fc %T` reports `UNKNOWN` for this filesystem; `%t` reports
`63677270`, matching the kernel's
[CGROUP2_SUPER_MAGIC constant](https://github.com/torvalds/linux/blob/master/include/uapi/linux/magic.h).
The candidate diagnostic uses the numeric magic rather than its rendered name.

## Candidate probe

```powershell
python scripts/verify_docker_host_cgroup_fixture.py
python -O scripts/verify_docker_host_cgroup_fixture.py
python -u scripts/verify_native_recovery_poller.py --image sha256:d495bf5f6e49090faf092e80d04d3b3dc180ba189a3fbe18f93e8809468b4f15 --probe-host-cgroup
```

The native fixture first validates the journal-authorized immutable worker ID,
ownership, isolation readback, and running engine state. The optional diagnostic
passes only that validated 64-hex ID as a positional argument to a fixed hidden
WSL shell program. It reads only `/sys/fs/cgroup/docker/<ID>/cgroup.events`,
rejects symlinks, checks filesystem magic, and requires a conservative parse
with `populated=1`. It neither enumerates unrelated workloads nor changes
Docker/WSL configuration, resources, or cgroup controls. The five-second command
timeout is not a process-tree containment or whole-fixture deadline guarantee.

Portable mock protocol tests passed normally and under `-O`. These test invalid
IDs, exact output acceptance, separate arguments, fixed input, and timeout;
they are not native kernel evidence. The sandbox printed a Python executable
location warning, but both tests exited zero.

The first candidate native run passed: a populated path matching the exact
owned ID was observed, the separate poller automatically recovered the orphan,
the journal emptied, no result was admitted, and scoped inventories were
unchanged. Its fresh persistent evidence journal suffix was
`0b808d26ebcd631fb8bffb94dcf58e01`. This preceded the additional events-file
symlink check; final-version evidence is recorded below after its own run.

The final version passed a separate fresh native run with journal suffix
`66ba0058c7540cee0ad410628ae646d1`: candidate populated, automatic recovery,
empty journal, no admitted result, and unchanged scoped inventories. No manual
fallback was used by either passing candidate run. No pre-existing journal or
Docker workload was deleted. The container runs the pinned fixture image;
this does not establish production image or broker safety.

## What remains

### Trusted-fixture cross-view corroboration

An additional opt-in command was tested with the same immutable image:

```powershell
python -u scripts/verify_native_recovery_poller.py --image sha256:d495bf5f6e49090faf092e80d04d3b3dc180ba189a3fbe18f93e8809468b4f15 --probe-host-cgroup --probe-cgroup-root-identity
```

This validates the owned running worker as above, checks cgroup-v2 magic on the
host path, and compares its decimal device/inode to the private cgroup root
inside the container. A fixed `docker exec --user 10001:10001` Python `-I`
diagnostic requires `/proc/self/cgroup` to be exactly `0::/` and reads root
metadata. No privilege, mount, image, or isolation-policy change is requested.
The [kernel namespace documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#namespace)
explains the private view rooted at the namespace's cgroup. The matching
device/inode is corroboration for this trusted fixture, not evidence against a
compromised renderer that could interfere with the in-container diagnostic.

The native run passed with fresh persistent journal suffix
`f4895d35ccfef3d57c26c5cf01daabc8`: host/container root match, populated
candidate, live owned orphan, automatic recovery, empty journal, no admitted
result, and unchanged scoped inventories. No manual fallback was used.
Portable tests passed normal and `-O` for matching roots, mismatched roots,
nonzero exits, malformed/extra/oversized metadata, invalid IDs, fixed arguments,
and per-command timeouts. These mocks are protocol evidence only.

Unlike the host-only read, the cross-view probe creates a transient process
inside the worker's existing resource limits. Its two sequential commands each
have a five-second timeout; while setup owns the journal it can delay recovery.
This is neither deadline evidence nor a forced process-tree bound. It does not
establish the engine PID's kernel membership, broker identity, retained-handle
observation, a transition to zero, or production-safe independent binding.

### Retained worker events observation

```powershell
python -u scripts/verify_native_recovery_poller.py --image sha256:d495bf5f6e49090faf092e80d04d3b3dc180ba189a3fbe18f93e8809468b4f15 --probe-cgroup-root-identity --observe-worker-cgroup-transition
```

The host shell opens the candidate `cgroup.events` file on descriptor 3 and
compares its device/inode to the original file path. Each subsequent read
reopens `/proc/$$/fd/3`, referencing that retained object rather than resolving
the container-ID pathname again. The loop uses shell builtins to parse the
complete known events fields, requires an initial `populated=1`, and accepts
only a later literal `populated=0`. EOF, missing fields, removal, read errors,
changed output, and nonzero process exit are not success. A fixed Linux
`timeout -s KILL 40` bounds the diagnostic shell; the Windows side also waits
with timeouts. This is not a proven Windows/WSL/Linux process-tree containment
or overall scan deadline. Killing a WSL proxy is not proof of host shell exit.

Two earlier attempts failed closed. The initial `sh -c` delivery failed before
readiness (journal suffix `a3cb3a08ff5505b9d3ae84b7c63e2b68`). Stdin delivery
then observed one but not zero with a slower stat/cat loop (suffix
`f8b3aa10481e52509eeef7ea0cf6716c`). Both used exact journal-authorized manual
fallback, retained zero leases, and restored scoped inventories. Neither is
empty-cgroup evidence.

The final lower-overhead builtin-read loop passed a fresh native run (suffix
`9fa49bfb01af1a3d3e069ec2545b7940`): retained events handle populated=1,
trusted private-root match, live orphan, automatic cleanup, direct populated=0,
empty journal, no result, unchanged scoped inventories. No manual fallback was
used in this passing run. No stop/remove delay or lease/grace override was
introduced. Portable mock protocols passed normal and optimized runs for
ordered markers, CRLF, missing markers, initial-zero rejection, overlong and
extra output rejection, fixed stdin/arguments, and pipe closure after reader
termination. They do not test kernel semantics or provide native repeatability.

This is selected worker-only kernel observation, not the full release gate.
The events object is pinned, but adversarial host/runtime identity binding is
not demonstrated; root matching still uses a trusted fixture diagnostic. The
broker is not observed before controller death. Setup holds the journal lock
and may delay recovery. Polling can miss a brief zero before removal; failures
must remain failures, never be replaced with engine or disappearance evidence.
Installed supervision, race/repetition coverage and independent total-deadline
enforcement remain open.

### Remaining binding and teardown requirements

A matching directory name is not a demonstrated host/runtime identity binding.
The diagnostic reads once while the fixture owns the journal lock, potentially
delaying recovery during setup; it provides no overall controller-death bound.
The basic candidate probe does not observe a transition to zero; the opt-in
observer does, but lacks independent binding. Disappearance and Docker stopped/PID-zero reports must not be
treated as kernel emptiness.

The [kernel cgroup-v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#cgroup-events)
defines `populated=0` as no live processes in the cgroup or descendants. A future
observer must establish identity and directly capture that condition for both
worker and broker without weakening isolation. Installed supervision, complete
native race/crash coverage, production egress, and public release gates remain
open.
