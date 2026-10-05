# Browser network/PID namespace proof

Status: native kernel and actual Chromium network-bypass proof; not complete deployment containment.

`scanner/browser_namespace.py` generates a trusted executable wrapper around
pinned Chromium. `unshare` creates new user, network, PID, and private-proc mount
namespaces, mapping the current non-root UID/GID to itself. A trusted Python
host launcher first sets a SIGKILL parent-death signal and rechecks its parent
PID to close the setup race, then execs `unshare`. This is needed because
Playwright launches the executable in a detached process group; worker group
termination alone cannot reliably reach it. The non-privileged exec must
preserve this signal, while `unshare --kill-child` links namespace PID 1 to the
outer launcher. See the [parent-death signal rules](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html).
Namespace PID 1 enables only loopback. Before starting the relay or browser it
drops effective, permitted, inheritable, ambient, and bounding capabilities and
sets no-new-privs. The helper verifies its own postcondition and fails closed on
setup errors. There is no veth, external interface, default route, host-network
mode, or direct DNS path. No host network configuration is changed.

The browser receives only standard streams and Playwright's explicit debugging
pipes (FDs 3/4); other inherited descriptors are closed on its subprocess launch.
The trusted setup uses `--keep-caps`, but the browser never inherits those setup
privileges. Chromium's own sandbox can create deeper user namespaces, whose
capabilities are scoped there. The verifier requires zero capabilities on the
observed Chromium process in the relay-owned namespace, not an incorrect
global zero-capability assertion across every nested sandbox namespace.
See the official [unshare manual](https://man7.org/linux/man-pages/man1/unshare.1.html)
and [user namespace rules](https://man7.org/linux/man-pages/man7/user_namespaces.7.html).

## Fixed proxy bridge

`scanner/namespace_bridge.py` exposes a private 0600 pathname Unix socket under
a new 0700 `dxr-net-*` directory. Standalone proofs use `/tmp`; the supervised
capture lifecycle explicitly uses its parent-owned private worker TMPDIR, so
the transport also removes socket files after hard worker termination. Unsafe
parents and paths exceeding 107 encoded bytes fail closed without an external
storage fallback. Its host-side handler checks Linux peer UID
and can connect only to a fixed `127.0.0.1` enforcing-proxy port. It never accepts
an upstream address, proxy credentials, shell command, or passed descriptor.
The namespace-local TCP relay listens on loopback at that same port, so existing
proxy URLs refer to the isolated relay rather than the host listener.

Both sides cap concurrent handlers at sixteen, use two buffers of at most
65,536 bytes per connection pair, handle partial writes/half-closes, and impose
a fifteen-second relay deadline. Relay byte *volume* is not a quota: the
enforcing HTTP proxy owns method/header/response/scan-byte admission. Shutdown
closes active sockets, requires stopped listener threads, and waits at most five
seconds for handlers. Peer process IDs are bounded, scan-local verification
metadata, not public scan evidence or authorization decisions.

The namespace helper waits for the browser, then shuts down the relay and exits.
Destruction of namespace PID 1 also destroys children that escaped the ordinary
process group with `setsid()`. The outer killable `unshare` process uses
`--kill-child`; both normal exit and supervised timeout are exercised below.
This does not replace cgroup resource limits or all worker-level cleanup.

## Exact native evidence

Tested on Ubuntu under WSL2 kernel `6.6.87.2-microsoft-standard-WSL2`, util-linux
2.39.3, with the prepared Playwright 1.55.0 / Chromium 140.0.7339.16 fixture runtime.

`python3 scripts/verify_network_namespace.py` checks:

- exact large-payload relay delivery with constrained socket buffers, partial
  writes, and half-closes in both directions;
- explicit parent-owned bridge placement and orderly cleanup, rejection of
  non-private/symlink parents, and overlong-path rejection without leaked files;
- distinct user/network/PID namespaces, exact single UID/GID mappings, non-root
  execution, loopback UP as the only interface, and empty main IPv4/IPv6 routes;
- zero capability sets plus no-new-privs in the adversarial child;
- nine failed direct TCP attempts: outside IPv4/IPv6 loopback listeners, public
  IPv4/IPv6, private IPv4/IPv6, metadata IPv4, TCP DNS (53), and DoT (853);
- denied raw IPv4 ICMP and packet sockets;
- zero outside-loopback UDP datagrams and failed external IPv4 UDP DNS send;
- a successful HTTP fixture through the fixed bridge, followed by a private
  target denied without another origin contact;
- a live `setsid()` descendant destroyed on normal exit and timeout, with no
  remaining members of its exact PID namespace after bounded observation;
- a trusted parent that launches the wrapper with `start_new_session=True`,
  matching Playwright's detached group, then waits for it; supervisor timeout
  kills that parent and the parent-death chain destroys the browser namespace;
- no eligible artifact after timeout and removal of the bridge socket on close.

`scripts/verify_namespaced_chromium.py` additionally launches the *actual*
Chromium executable through this wrapper, preserving Playwright's pipes and
browser sandbox. It proves normal private NSS certificate verification,
complete schema/semantic HTTPS capture, exact initial-grant pinning, independent
later destination validation, and relayed service-worker bootstrap bytes. A
second context explicitly bypasses the proxy for six URLs: IPv4/IPv6 loopback,
private IPv4, metadata IPv4, and public IPv4/IPv6. All navigations fail, proxy observation counts do not
change, and host loopback listeners receive no connections. Accessible actual
Chromium process metadata confirms distinct network/user namespaces, no-new-
privs, and zero setup capabilities in the relay-owned user namespace. Protected
or inaccessible processes are not claimed as directly inspected.

For the Chromium check, prepare dependencies as in `BROWSER_TRUST.md`. In WSL,
use native Linux storage to avoid the observed mounted-runtime startup penalty:

```bash
task_native=$(mktemp -d /tmp/dom-xray-native-runtime-XXXXXX)
task_source="$PWD/.dom-xray-data/linux-trust"
cp -a "$task_source/python" "$task_source/root" "$task_source/browsers" "$task_native/"
env PYTHONPATH="$task_native/python" \
    python3 scripts/verify_namespaced_chromium.py --runtime-root "$task_native"
```

## Still required before public capture

This is a direct-IP network boundary for the tested topology, **not** a complete
container or browser-escape boundary. The stock capture lifecycle now also opts
into the explicit filesystem root documented in `BROWSER_FILESYSTEM.md`; the
standalone network-only fixture mode still shares its filesystem. Same-UID
sibling processes, mutable runtime sources, and scanner broker/signing-key
processes need independent deployment identity/integrity protection. Same-UID
peers can reach the fixed bridge; UID checks do not authenticate a particular
scan. No private-key confidentiality or cross-worker isolation claim follows
from this proof. The kernel, binaries, packages and mount layout also require
reviewed patched deployment images, quotas, and runtime integrity controls.

The stock supervised capture lifecycle now uses this wrapper; its integrated
normal-capture and live-browser timeout evidence is in `EGRESS_CAPTURE_WORKER.md`.
Next: enforce runtime-image integrity and whole-worker resource/identity
bounds, then repeat hostile network, file, sibling, teardown and public-corpus
tests. The seeded API was not switched to arbitrary public capture, and the
reserved-target guard remains enforced. Arbitrary public scans remain disabled.
