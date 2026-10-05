# Supervised browser-egress capture lifecycle

Status: native Linux namespaced controlled capture and timeout proof; arbitrary public capture remains disabled.

`scanner/egress_capture_worker.py` integrates the real scanner components into
one worker lifecycle. `create_capture_launch` implements the
`PublicScanGrant + result path → WorkerLaunch` seam consumed by
`run_public_scan_transport`. It creates a bounded 16,384-byte config file in
the transport-owned private directory, with mode 0600 and exclusive creation.
The target and complete address grant are in that private file, never argv or
environment. Only config/result paths and trusted code/dependency paths are
process arguments. Config, browser, trust, and issuer files are temporary, not
public artifacts.

The child starts with Python `-I`, an optional explicit trusted package directory,
and a minimal PATH/locale/private HOME/TMPDIR environment. The supervisor adds
its fresh nonce. Application secrets, ambient PYTHONPATH, and operator HOME are
not inherited. Trusted binaries, packages, entrypoint, and library directories
are deployment configuration; production must review and make them immutable.
Path existence checks alone do not establish code integrity or ownership.

The worker rejects oversized, nonregular, symlink, duplicate-key, unknown-field,
wrong-type, private-address, and noncanonical grant inputs before browser setup.
The nonce must have the supervisor's exact shape. The stock entrypoint accepts
no fake resolver, origin connector, certificate-error option, or hang switch.
The optional entrypoint argument is trusted program configuration for fixtures
or deployment packaging, not an API/visitor setting.

## Worker flow and cleanup

1. Read the bounded config and recheck the launch grant without DNS.
2. Apply the existing reserved `.test` target guard. Public URLs fail closed.
3. Create the bounded system resolver, one destination policy, and origin
   exchange with the one-shot initial grant and normal pinned TLS connector.
4. Create a fresh scan CA, private Linux NSS browser trust, and enforcing HTTPS
   proxy using that same policy instance.
5. Create a fixed Unix-socket proxy bridge under the worker's parent-owned
   private TMPDIR. Launch pinned Chromium 140.0.7339.16 through the trusted
   user/network/PID namespace wrapper, with sandboxing, normal certificate
   verification, private trust environment, and the namespace-local proxy relay.
6. Run the real browser probe with its ledger/block/truncation evidence.
7. Close Chromium, Playwright, bridge/proxy handlers, trust profile, and certificate
   issuer before writing the atomic, bounded nonce result envelope.
8. The parent admits only a zero-exit eligible artifact that passes schema,
   semantic, and target correlation checks. The transport removes all owned
   config/result/runtime-temp files before returning, including after timeout.

The outer supervisor reserves a termination tail within its fifteen-second
clock. A timeout or cleanup failure never publishes a record. Linux
process-group termination is not a container, cgroup, PID namespace, or network
firewall. The adopted browser wrapper independently creates a loopback-only
network namespace and a PID namespace whose destruction kills browser children,
including detached sessions (see `BROWSER_NAMESPACE.md`). The host-side worker
and broker are outside that namespace. Whole-worker containment and
filesystem/disk/process limits still remain required.

## Reproducible native proof

Prepare the project-local Linux runtime described in `BROWSER_TRUST.md`, then
from the repository in Linux run:

```bash
env PYTHONPATH="$PWD/.dom-xray-data/linux-trust/python" \
    python3 scripts/verify_egress_capture_worker.py
```

For WSL, native Linux storage avoids the observed Windows-mounted runtime
startup penalty. The verifier accepts an explicit trusted `--runtime-root`:

```bash
task_native=$(mktemp -d /tmp/dom-xray-native-runtime-XXXXXX)
task_source="$PWD/.dom-xray-data/linux-trust"
cp -a "$task_source/python" "$task_source/root" "$task_source/browsers" "$task_native/"
env PYTHONPATH="$task_native/python" \
    python3 scripts/verify_egress_capture_worker.py --runtime-root "$task_native"
```

Run preparation and verification in the same Linux session if its temporary
storage does not persist between invocations. This copies dependencies only;
it does not install OS packages, modify trust stores, or alter source code.

The separate fixture entrypoint injects deterministic origin sockets and DNS;
the stock worker does not. The verifier passes the real grant file through the
launch adapter, subprocess supervisor, real sandboxed Chromium/private NSS/HTTPS
capture, and schema-plus-semantic transport admission. Its page includes
subresources and service-worker bootstrap traffic. Initial addresses survive
the config roundtrip; later requests independently validate. A secret canary
and environment checks prove no ambient application credential inheritance.

One Windows-mounted-runtime run completed in 9,936 ms; subsequent normal runs
also timed out and were correctly withheld. With those same dependencies copied
to native Linux temporary storage, complete capture took 3,825 ms. This supports
startup filesystem I/O as a contributor, not a production reliability claim.
Two further native-storage verifier runs completed their normal captures in
3,686 ms and 3,525 ms; both also passed explicit service-worker bootstrap-byte,
stock public-target rejection, strict config, and timeout/cleanup assertions.
A second native-storage run captured that same page, recorded live
Chromium descendants by PID plus Linux start ticks, then deliberately hung
before publication. The supervisor timed out at 14,508 ms without an eligible
artifact. Those exact observed descendants stopped within a maximum 400 ms
follow-up observation, and scan trust/config directories no longer existed.
This is a controlled local fixture measurement, not a public p90 benchmark or
a proof against detached descendants. Initial shorter-budget and one-tick exit
checks were insufficient evidence; the verifier explicitly requires reaching
the live-browser post-capture phase and bounded process-identity observation.

Additional checks reject malformed config, oversized/symlink files, forged
private answers and boolean ports, and ensure the stock entrypoint cannot
admit an arbitrary public target. Schema/nonce/crash/target-mismatch negative
admission cases retain coverage in `verify_scan_transport.py`.

In the initial, pre-parent-death-fix namespace adoption run, the native-storage integration verifier completed a
normal HTTPS/service-worker capture in 3,572 ms and the deliberately hung live
browser timed out at 14,504 ms. Both used actual Chromium in a network namespace
different from the worker's host namespace. The verifier observed exact live
browser descendants before exit and confirmed they stopped, and the parent
transport removed the relay socket **and its directory**, including after hard
worker termination. Schema/semantic admission, initial-grant pinning, strict
config rejection, secret-free environment and stock public-target rejection
also passed in that run. These are local fixture measurements, not production
latency or full containment evidence.
That first pass did not establish reliable detached-launch cleanup, as the
repeat failure below demonstrates; the repaired topology is verified separately.

A repeat completed capture in 4,901 ms but failed the existing 400 ms timeout
descendant check: two non-Chromium host-network descendants remained alive.
The pinned Playwright launcher explicitly uses a detached process group, so
worker group termination alone does not cover that executable. The trusted
wrapper now sets SIGKILL parent-death before exec and checks the parent race;
`unshare --kill-child` carries teardown into namespace PID 1. A separate native
fixture now reproduces detached launch and verifies namespace destruction after
its parent is killed. This addresses the launch topology, not arbitrary
whole-worker process escape or a replacement for cgroups.

With that parent-death fix, two consecutive complete/timeout verifier runs
passed without extending the 400 ms cleanup observation. Complete captures
took 3,694 ms and 3,477 ms; forced timeouts took 14,518 ms and 14,504 ms. Both
also passed the missing-TMPDIR fail-closed regression and parent-owned socket
directory removal. Reliability on the production image still requires its own
benchmark and hostile cleanup tests.

The Linux pathname socket is limited to 107 encoded bytes. Deployment must use
short private runtime paths. Capture rejects a missing/empty TMPDIR rather than
using standalone storage. Unsafe, symlink, non-private or overlong bridge
parents fail closed; there is no fallback outside parent-owned cleanup storage.

## Remaining work

Adopt this launcher in the API/queue only behind independently verified
deployment containment, with shared URL/parser and registrable-domain rules,
published scanner identity/robots/opt-out policy, durable distributed abuse
controls, and retention decisions. Then lift the public probe guard and run
representative successful/partial/error captures and end-to-end latency tests.
Neither the seeded API nor the public probe gate was relaxed by this checkpoint.

The network/PID namespace wrapper has independent native kernel and actual
Chromium bypass evidence in `BROWSER_NAMESPACE.md` and is now adopted by this
stock lifecycle. Filesystem/other Unix sockets, same-UID sibling
access, whole-worker quotas and deployment containment remain open.
