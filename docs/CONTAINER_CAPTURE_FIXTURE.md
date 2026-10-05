# Gate 3 — actual Chromium inside bounded Docker

This is a **reserved-origin fixture**, not a public scanner image or API/queue
adoption. No public scanning guard was removed. It uses the existing historical
Playwright 1.55.0 / Chromium 140.0.7339.16 measurement pin for regression
comparison; that browser must be upgraded and audited before public deployment.

## Build and verify

Prepare the project-local Linux fixture dependencies described in
`BROWSER_TRUST.md`, then use the installed Docker Desktop Linux engine:

```powershell
python scripts/prepare_fixture_seccomp.py
docker --context desktop-linux build --file containers/capture-fixture.Dockerfile --build-context "fixture-runtime=.dom-xray-data/linux-trust" --tag dom-x-ray-capture-fixture:gate3 .
python scripts/verify_container_capture.py
```

Profile generation refuses to overwrite an existing file. If already generated,
skip that step; the verifier rejects a changed profile. The Ubuntu 24.04 base is
digest-pinned. The image bakes only allowlisted project code and selected fixture
dependencies; runtime containers mount no workspace, host directory, volume,
Docker socket, credentials or device. Source and dependencies are root-owned in
the image, and the outer root filesystem is read-only. Installed OS package
versions are not yet locked/audited for a reproducible production image.

The final 2026-10-06 run used Docker Engine 28.3.2 / cgroup v2 and local image ID
`sha256:a0f1f0543d7aaa97cf201a34af7db2b9645bdafc2832535d902f42596830ccd4`.
The verifier resolves the tag to its immutable local ID before creating any
container; subsequent builds can produce different IDs.

## Engine policy and kernel observations

Each case runs as UID/GID 10001 with `--init`, no outer capabilities,
no-new-privileges, network disabled, a read-only root, one CPU, 1 GiB memory with
zero swap, 128 tasks, 128 MiB outer `/tmp`, and 64 MiB shared memory. Logs use one
bounded 1 MiB local file. Engine configuration is checked before execution,
including the custom syscall profile, identity, no host mounts, and tmpfs sizes.
The real capture verifier also reads back kernel cgroup knobs and its own
capability/no-new-privileges/seccomp status inside the container.

Four cases pass:

1. Default Docker policy rejects the namespace-creation probe. This is a policy
   denial observation, not a claim that its error alone identifies seccomp.
2. A trusted mount diagnostic verifies raw/tool binds and the full private
   filesystem pivot. It identifies Docker's locked `/usr/sbin/docker-init`
   child mount. The browser root now leaves `/usr/sbin` empty: networking setup
   uses `ip` before the pivot; no browser-time sbin tooling is needed. There is
   no recursive mount fallback exposing extra Docker runtime paths.
3. Actual HTTPS/service-worker capture completes in **4,427 ms** and passes
   nonce, schema, semantic, target and grant admission. A live post-capture hang
   times out at **14,508 ms**, returns no record, and leaves no observed browser
   descendants, profile, private trust/config directory or relay socket. The
   stock entrypoint still rejects arbitrary public targets. Maximum observed
   cgroup peak memory is **162,693,120 bytes**, and peak tasks are **91**; these
   are small fixture measurements, not budgets proven against public pages.
4. Actual Chromium denies six proxy-bypass targets (IPv4/IPv6 host loopback,
   metadata, private and public direct destinations), with zero trap-listener
   contacts. Allowed TLS and measured service-worker bootstrap still succeed.

The captured page's context closes before the existing after-capture lifecycle
hook. A fixed, offline page is therefore kept alive only during fixture
diagnostics to observe an actual renderer, with no target request and no change
to the scan record. Observed Chromium processes retain no-new-privileges and no
`--no-sandbox` launch flag; every observed process in Docker inherits a seccomp
filter. Native WSL also observes a live Chromium filter rather than expecting
the unfiltered browser manager to have the renderer's filter after page closure.

## Read-only launcher and writable scratch

Stock capture and the actual-Chromium verifier now execute
`scanner/browser_launcher.py` from the trusted runtime, not a generated script
under temporary storage. Git records it executable for native Linux checkouts;
the image installs it mode 0555. It reads only the per-scan private HOME config,
forwards arguments and Playwright pipes via exec, and retains the parent-death
guard in the namespace launcher. Network-only legacy fixtures still exercise
the generated launcher option.

Inner writable tmpfs and scoped profile/data/cache/temp binds are now `noexec`;
an outer tmpfs flag alone would not cover replacement inner mounts. Native
filesystem canaries verify executable scratch files fail with EACCES, normal
data/NSS writes work, host files/sockets stay hidden, runtime writes fail,
nested user namespaces cannot unlock runtime mounts, and normal/timeout cleanup
remains intact. The native WSL capture regression completes in **4,824 ms** and
times out at **14,508 ms** with the same offline sandbox witness.

## Fixture filter is not a production policy

The generator verifies the exact upstream Playwright v1.55.0 profile bytes
against SHA-256
`cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849`.
The generated profile's canonical JSON SHA-256 is
`242cbd13aa6babf1f163ffa712ee00b0ce95e48c8bb3675d82eb213230b4ff48`.
The driver checks that content locally and reads back the engine-installed
profile. No `seccomp=unconfined`, `apparmor=unconfined` or SYS_ADMIN capability is
used; no host policy is changed.

This upstream deny-by-default profile already broadly permits clone/setns/unshare.
The fixture additionally permits mount, umount2, pivot_root, pidfd_open,
pidfd_send_signal and chroot. The PID-handle calls support util-linux's
kill-child lifecycle; Chromium needs chroot for its own sandbox. Those
allowances remain inherited by descendants, so this is **not** a reviewed minimal
production filter or a stacked post-setup browser filter. Kernel security and
browser escape resistance require separate review.

## Still required for public scanning

There is no engine-side scan launcher, per-scan container result channel, API
adoption, live public egress, independent host-side cgroup-empty/descendant
teardown observation, multi-worker identity proof, or representative URL corpus
in this checkpoint. The native timeout checks the existing worker/PID-namespace
lifecycle *inside* the container; stopped Docker state is not independently
observed `cgroup.events populated=0`. The harness removes only exact-ID containers
whose random name and private invocation label match, including failure paths;
it never prunes unrelated resources. Public capture remains disabled.

Regression checks also pass for the legacy network-only native launcher and the
scan-transport rejection/admission matrix. A mismatched profile is rejected even
when the outer verifier runs with Python `-O`, before any engine call.

Policy references: [Playwright Docker guidance](https://playwright.dev/python/docs/docker),
[version-pinned upstream profile](https://github.com/microsoft/playwright/blob/v1.55.0/utils/docker/seccomp_profile.json),
and [Docker seccomp documentation](https://docs.docker.com/engine/security/seccomp/).
