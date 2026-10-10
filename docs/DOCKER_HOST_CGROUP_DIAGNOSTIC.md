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

### Pre-crash pair observation checkpoint

```powershell
python scripts/verify_pair_cgroup_witness.py
python -O scripts/verify_pair_cgroup_witness.py
python -u scripts/verify_native_recovery_poller.py --image sha256:d495bf5f6e49090faf092e80d04d3b3dc180ba189a3fbe18f93e8809468b4f15 --observe-pair-cgroup-transitions --probe-cgroup-root-identity
```

The opt-in trusted controller emits its fully committed resource record before
the renderer-live marker. The parent caps the line at 8192 bytes, rejects
duplicate/nonfinite JSON keys and invalid record schema, validates the runtime
fingerprint, and independently inspects exact worker and broker IDs for
ownership, isolation and live engine state. No new journal reader lock is
taken while the original controller owns it. Both external host observers
retain their events objects before controller termination; the optional fixed
unprivileged root diagnostics corroborate each path. After death, the actual
exclusive journal snapshot must equal the announced record exactly. The
announcement is fixture metadata, not a visitor artifact or production API.

Two preliminary pair runs passed before the ordering guard was added (journal
suffixes `54c7eeec019a901e73777f081d464b92` and
`aabe1b0edbbb6a960668f0c1da3c697b`). They are not evidence for the new ordering
guard. Review identified that a broker could exit during observer setup; the
fixture now rejects an observer already empty/exited at the end of setup and
records the parent receive time of each zero marker before waiting for EOF.
It requires these times to be at or after controller termination initiation.
These are not kernel transition timestamps: pipe buffering/scheduling can
delay receipt. The fixture makes no causal claim that automatic recovery,
rather than stdin EOF or the broker's own timeout, caused the broker to exit.

The final guarded version passed with fresh persistent journal suffix
`284852dde0ee0d1647203fe07d045c8e`: both pre-crash populated handles, trusted
root corroboration, controller Job empty, surviving separate poller and live
worker orphan, both zero markers received after termination began, automatic
recovery, empty journal, no admitted result, and unchanged scoped inventories.
No manual fallback, shortened lease/grace, extra stop/remove pause, or runtime
configuration change was used. Portable witness framing/schema and observer
protocol tests passed normal and `-O`; timing tests reject a supplied boundary
later than the receive time. The native host children do not inherit `-O`
from an optimized parent; no optimized pair-child run is claimed.

This addresses the missing broker observation for the selected trusted native
fixture. It does not establish adversarial host identity binding, kernel-exact
crash causality, production integration, independent process-tree deadline
enforcement, or broad native race/repetition coverage. Existing worker-only
evidence above is retained as history, not substituted for pair scope.

### WSL PID-number probe: failed closed

```powershell
python -u scripts/verify_native_recovery_poller.py --image sha256:d495bf5f6e49090faf092e80d04d3b3dc180ba189a3fbe18f93e8809468b4f15 --probe-host-pid-membership
```

The opt-in read-only diagnostic takes only the validated immutable ID and the
engine-reported positive integer PID, passed separately to a fixed shell script.
It checks cgroup-v2 magic and nonsymlink directory/file metadata, reads at most
256 one-token decimal lines from the selected candidate's `cgroup.procs`, and
requires a literal PID-number match. Empty, zero-only, mismatching, malformed,
over-limit and nonzero command results never imply identity or emptiness.

The selected native run failed with `cgroup-fixture-membership-mismatched`
(fresh persistent journal suffix `f76159f47afc958d7651453c67542279`). The view
contained nonzero numbers but not the engine-reported value. Exact-resource
manual fallback left zero retained leases and unchanged scoped inventories.
This is diagnostic failure evidence, not an automatic-recovery or binding pass.
The earlier inaccessible `/proc/<engine-PID>` observation and this mismatch
mean the current WSL route does not establish independent process identity.
They do not, by themselves, identify the namespace offset or prove its cause.

Portable protocols passed normal and optimized runs for exact output, CRLF,
mismatch/not-visible/nonzero/extra-output rejection and invalid PID types/ranges.
Mocks do not prove kernel membership. Even a matching number would be too weak
without reader/engine PID namespace alignment: number equality is not process
identity. No production observer or release gate consumes this diagnostic.

A next experiment would use a separate trusted, disposable diagnostic container
with host PID and cgroup namespace visibility, network disabled, read-only root,
non-root user, dropped capabilities and the existing seccomp policy. It would
read only exact owned fixture PIDs/cgroups and retain independently bound events
handles. Host namespace visibility exposes host process metadata and is a
meaningful expansion beyond the current isolated worker policy. It requires
explicit user approval before implementation/execution; it must not be added
to renderer or broker configuration. No such container, host service, privileged
mode, writable host mount or namespace-setting change has been launched.

### Open production requirements

A matching directory name is not a demonstrated host/runtime identity binding.
The diagnostic reads once while the fixture owns the journal lock, potentially
delaying recovery during setup; it provides no overall controller-death bound.
The basic candidate probe does not observe a transition to zero; the opt-in
observer does, but lacks independent binding. Disappearance and Docker stopped/PID-zero reports must not be
treated as kernel emptiness.

The [kernel cgroup-v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#cgroup-events)
defines `populated=0` as no live processes in the cgroup or descendants. A future
observer must establish identity and directly capture that condition for both
worker and broker without weakening isolation. The selected pair fixture now
captures the condition, but independent binding is still unproven.
Installed supervision, complete
native race/crash coverage, production egress, and public release gates remain
open.
