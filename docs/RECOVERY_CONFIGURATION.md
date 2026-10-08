# Gate 3 — Private recovery configuration and foreground launcher

## Boundary

`load_recovery_registry` reconstructs the bounded operator registry from a
private JSON file plus a separately supplied SHA-256 digest. The expected digest
must come from trusted operator/supervisor configuration, not be calculated from
an untrusted file at each start. This is deployment metadata, never a visitor
API payload. No directory scan, wildcard enrollment, config hot reload, scan
launch or result publication occurs.

The file and its containing directory use the existing journal's exact private
ACL/mode policy. The loader rejects symlink/reparse/canonical-path violations,
nonregular files, hardlinks, replaced file identities and files over 32 KiB.
It compares the exact bytes to the operator digest and rejects duplicate JSON
keys, nonfinite constants, unknown fields and wrong types.

The version-1 root object has exactly `version` (integer 1) and `entries` (one
through eight entries). Each entry has exactly:

- `root`: canonical absolute existing journal path.
- `identities`: three two-integer lists, in root/owner-lock/database order,
  containing the registered device/inode identities.
- `runtimeFingerprint`: the registered 64-lowercase-hex pair-runtime fingerprint.
- `runtime`: exactly `docker_executable`, `context`, immutable `image_id`,
  `seccomp_path`, `seccomp_sha256`, `command`, `initializer_command`, and
  `broker_command`, matching the trusted supervisor constructor configuration.

Executable/profile paths must be canonical and absolute. Commands are bounded
argument arrays, never shell strings. The existing supervisor independently
checks immutable image syntax, context syntax, profile hash/default-deny policy
and command shape. The loader reconstructs each trusted supervisor and rejects
any journal identity or runtime fingerprint mismatch before registry use.
Duplicate registered journals also reject. The executable is trusted operator
code: an image/profile pin is not an executable-signature or production audit.

No automatic enrollment, reset or identity migration occurs on replacement or
reboot. If filesystem identities legitimately change, fail closed and investigate
before an operator explicitly registers new bindings. Do not delete the journal
or ignore old obligations to make a new configuration load.

## Foreground launcher

`scripts/run_recovery_watchdog.py` accepts `--configuration` and
`--configuration-sha256`. `--check` validates file/runtime/metadata bindings only;
it does not acquire journal ownership, inspect schema, contact Docker or prove
cleanup/daemon health. Without `--check`, the foreground process runs the registry.
Optional `--max-ticks` bounds a fixture/operator run to 1–1000 registry ticks.

SIGINT/SIGTERM request an interruptible inter-pass stop; they do not preempt an
in-progress filesystem/SQLite/factory operation. Signal handlers are restored
when the launcher exits. A successful stop/finite-run exit means the loop ended,
not that all leases resolved. Per-entry outcomes are the cleanup status source.

Output is fixed JSON status plus index/count-only recovery health. Unchanged idle
health is suppressed; state transitions and resolved work are emitted. Startup
failure exits 2 with `configuration-fault`; loop failure exits 3 with
`watchdog-fault`. Raw config/provider exception text, paths and tokens are not
forwarded. Output sink limits and independent restart supervision belong to the
deployment supervisor, which is not installed by this command.

## Evidence — 2026-10-08

`verify_recovery_configuration.py` uses actual private files/Windows ACLs, journal
metadata and isolated foreground launcher processes. It reconstructs two entries
after reload and tests strict entry counts/shapes, absent/copied roots, wrong
identities, valid-but-drifted runtime and mutable image rejection, changed profile,
invalid commands, unknown fields, duplicate entries/JSON keys, nonfinite JSON,
invalid UTF-8, oversized files, wrong hashes, hardlinks and nonprivate files or
directories. A fixture-only Everyone-read ACE is removed after the Windows ACL
test; no user-file permission is changed. Native symlink rejection is tested when
the host permits creating a fixture symlink; otherwise the verifier explicitly
reports that missing evidence. Same-inode content mutation after a completed read
does not change the hash-pinned bytes used for this load; a later load must pass
the hash check again. Malicious same-owner filesystem races are not established
as contained by these metadata checks.

On the current Windows normal/optimized runs, fixture symlink creation was
unavailable. Native config symlink evidence remains open; permissions were not
broadened to obtain it.

Actual `--check` and one-tick child runs produce content-free output and clean
exits using empty journals and a fixture executable that must never be invoked
for engine contact. Invalid run bounds and a changed file fail without a raw
error. This is actual process/configuration evidence, not a native Docker
watchdog restart or real cleanup test.

```powershell
python scripts/verify_recovery_configuration.py
python -O scripts/verify_recovery_configuration.py
```

Independent service installation/restart proof, deployed configuration/key
management, native multi-root/crash/outage evidence, controller-death deadline
enforcement, Linux cgroup emptiness and production/public product gates remain
open. Docker startup repair still awaits user approval; no Docker host files,
images or volumes were changed by this checkpoint.

The subsequent [process-restart fixture](WATCHDOG_PROCESS_RESTART.md) proves
forced launcher death, same-configuration reload and durable paging with real
Windows processes and unrequested leases. Native Docker restart and installed
independent supervision remain distinct, unfinished requirements.
