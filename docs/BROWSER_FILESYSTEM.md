# Explicit browser filesystem root

Status: native arbitrary-code canaries and actual Chromium capture/timeout proof;
not a sealed deployment image or complete worker containment.

The guarded Linux capture worker now opts into `scanner/browser_filesystem.py`
through the trusted namespace wrapper. Visitor inputs cannot select mounts.
The standalone wrapper API still supports the older network-only fixture mode;
only callers supplying `filesystem_runtime_directories` get this root.

## Mount policy and order

Setup runs in the fresh user/mount/PID/network/IPC namespaces, before dropping
capabilities or starting the relay/browser. It makes propagation private,
mounts a new tmpfs root, installs explicit non-recursive bind mounts, pivots the
root, detaches the old root, changes cwd to `/`, removes the old-root mountpoint,
and remounts the root read-only. All setup directory descriptors are closed;
only standard streams and the explicit Playwright pipes can survive into the
browser. The existing zero-capability/no-new-privs postcondition remains required.
This does not rely on `chroot` alone: [chroot caveats](https://man7.org/linux/man-pages/man2/chroot.2.html),
[mount propagation](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html).

| Visible surface | Access / source |
| --- | --- |
| `/usr/bin`, x86-64 libraries, Python 3.12 | Required, non-recursive read-only runtime mounts |
| `/usr/sbin` | Empty directory; setup uses networking tools before pivot, avoiding Docker's locked init child mount |
| Locale, font, fontconfig and timezone directories | Read-only when present; no whole-`/usr` mount |
| Chromium executable directory and explicit custom libraries | Read-only, canonical trusted runtime paths |
| Browser HOME config/data/cache/tmp | Only these private per-scan directories, read-write |
| Playwright profile | Exactly one canonical, owned, private, empty fresh profile with the expected prefix and parent |
| Browser HOME `.pki/nssdb` | Bounded copy into private writable tmpfs, not a writable host-trust mount |
| `/run/proxy.sock` | Only the fixed enforcing-proxy socket; no directory containing other sockets |
| `/proc` | Fresh PID-namespace procfs, nosuid/nodev/noexec |
| `/dev` | Only null/zero/random/urandom plus private shm; no host device tree |
| `/etc` | Synthetic user/group/hosts/NSS lookup files, empty resolver file; only explicit read-only ld cache and font configuration |
| `/tmp`, `/dev/shm` | Fresh 64 MiB tmpfs each; namespace root 16 MiB, NSS copy 8 MiB |

Ancestors such as private `/tmp` are mounted before runtime/profile/data paths
under them, so later ancestor mounts cannot hide earlier bind mounts. Host
`/home`, `/root`, `/mnt`, unrelated `/run` sockets, scanner issuer keys, and the
transport grant/result directory are not exposed by the stock mount policy.
The exact allowed runtime sources must themselves contain no secrets.

Chromium opens its Linux NSS database for writing. An initial read-only bind
launched Chromium but caused `ERR_CERT_AUTHORITY_INVALID`; no certificate-error
override was added. The current setup copies only regular `cert9.db`, `key4.db`
and `pkcs11.txt` files (at most 1 MiB combined) from the fresh scan NSS database.
The browser can write its private copy without changing the host database;
the scan CA issuer's signing key is never copied. Current upstream behavior is
visible in [Chromium's NSS initialization](https://chromium.googlesource.com/chromium/src/+/HEAD/crypto/nss_util.cc).
The actual pinned Chromium fixture verifies this compatibility independently.

## Exact tested environment and evidence

This implementation is deliberately image-specific: x86-64 Linux syscall 155
for `pivot_root`, Ubuntu's usr-merged layout, Python 3.12, and the prepared
Playwright 1.55.0 / Chromium 140.0.7339.16 fixture runtime. Required runtime
directories and usr-merged links fail closed if absent or incompatible.
Native tests ran under Ubuntu/WSL2 kernel 6.6.87.2-microsoft-standard-WSL2.
This fixture browser version is not a claim of current production patching.

`python3 scripts/verify_browser_filesystem.py` verifies:

- inaccessible host key/home canaries through direct paths, symlinks, and both
  `/proc/1/root` and `/proc/self/root` paths;
- old-root removal, distinct mount/IPC namespaces, and unchanged host mounts;
- real read-only runtime/root write failures and scoped browser-data writes;
- private NSS copy writes leaving the host database unchanged;
- denial of unrelated pathname and abstract Unix sockets, with zero host
  listener contacts, while the single proxy socket succeeds;
- a deliberately inherited host directory descriptor is not available in the
  browser or trusted namespace PID 1;
- a *successfully created* deeper user/mount namespace gains scoped SYS_ADMIN
  but cannot remount the inherited runtime writable (`EPERM`), in both normal
  and timeout cases;
- non-empty, wrong-name and symlink Chromium profiles fail at the intended
  setup guard, not merely at Python's unknown-option parser;
- oversized, symlink and unknown-name NSS source files fail at the bounded-copy
  guard without producing an eligible worker result;
- parent-death/detached-launch teardown on normal exit and timeout, with no
  remaining members after the same bounded 400 ms observation;
- no eligible result after timeout and no filesystem mounts leaking into the
  host namespace. A trusted fixture-only entrypoint records local diagnostics;
  the stock capture worker has no diagnostic environment switch.

`scripts/verify_egress_capture_worker.py` additionally crosses the real grant,
supervisor, browser, TLS proxy, probe, schema and semantic admission boundaries.
The final run completed HTTPS/service-worker capture in 3,884 ms and deliberately
timed out a live capture at 14,509 ms. It observes actual Chromium's distinct
mount/IPC/network namespaces and actual profile path, then verifies descendant,
profile, relay and scan-file cleanup. Earlier private-NSS runs completed in
3,377 ms and 4,035 ms; these are local fixture measurements, not production latency claims.

`scripts/verify_namespaced_chromium.py` now also opts into this filesystem root.
It passed normal certificate verification, complete HTTPS/service-worker capture,
initial-grant pinning, later destination validation, and all six actual Chromium
direct-network bypass denials, with no host loopback listener contacts.
Runtime preparation is documented in `BROWSER_TRUST.md`; copy dependencies to
native Linux storage and run preparation plus verification in one WSL session
as shown in `EGRESS_CAPTURE_WORKER.md`.

## Still open before public capture

The Docker integration checkpoint now uses a read-only executable launcher and
marks inner writable scratch/profile/data mounts `noexec`. Scratch execution
canaries, actual Chromium capture/timeout and direct-network denials pass in the
bounded local fixture image; see `CONTAINER_CAPTURE_FIXTURE.md`. This does not
close the production filter/image/identity/launcher gates below.

Read-only binds prevent writes *from this namespace*, not changes by the host.
Host runtime/library/font sources need immutable, reviewed, patched deployment
images. Same-UID host processes can race mutable sources or inspect/alter the
worker; this is not a confidentiality boundary against the host operator or
cross-worker isolation proof. Trusted setup inputs and the proxy/broker also
need separate process/identity protection.

The tmpfs ceilings are not a whole-worker quota. The explicitly writable browser
cache/data/tmp/profile directories are host-backed and still require disk
limits; CPU, total memory, pids, process escape, seccomp policy and cgroup teardown
must be tested in the deployment. A kernel exploit is not contained by these
local canaries. This has not passed a representative public corpus or production
multi-worker/abuse tests. Arbitrary public scanning remains disabled.
