# Docker Desktop host cgroup diagnostic

This is a fixture-only, read-only investigation. It is **not** a production
observer, independent identity binding, or proof of worker/broker cgroup emptiness.
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

### Remaining binding and teardown requirements

A matching directory name is not a demonstrated host/runtime identity binding.
The diagnostic reads once while the fixture owns the journal lock, potentially
delaying recovery during setup; it provides no overall controller-death bound.
It does not observe a transition to zero or retain an independently bound
cgroup handle. Disappearance and Docker stopped/PID-zero reports must not be
treated as kernel emptiness.

The [kernel cgroup-v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#cgroup-events)
defines `populated=0` as no live processes in the cgroup or descendants. A future
observer must establish identity and directly capture that condition for both
worker and broker without weakening isolation. Installed supervision, complete
native race/crash coverage, production egress, and public release gates remain
open.
