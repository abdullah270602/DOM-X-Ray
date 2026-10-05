# Gate 3 — current browser runtime candidate

The next public-scanner runtime candidate pins **Playwright 1.63.0 / Chromium
153.0.8010.12**, headless-shell revision 1243. This is a separately built and
tested candidate, not a production-approved image or public-scan enablement.
The historical Chromium 140 fixture remains available for regression comparison.

## Provenance and selection

The release and Linux executable path were checked against official
[PyPI metadata](https://pypi.org/project/playwright/1.63.0/), the version-pinned
[browser manifest](https://github.com/microsoft/playwright/blob/v1.63.0/packages/playwright-core/browsers.json)
and [registry](https://github.com/microsoft/playwright/blob/v1.63.0/packages/playwright-core/src/server/registry/index.ts).
Playwright's bundled Chromium can be ahead of branded Chrome; the version is
not a claim that this is the latest stable branded Chrome or free of known bugs.

All nine Python dependencies are exact-version and SHA-256 locked in
`containers/runtime-candidate.requirements.txt`. The build installs only those
Linux x86-64/CPython 3.12 wheels with `--no-index --require-hashes`. A separate
verifier compares the downloaded files to unyanked official PyPI artifact
metadata. Host Python and certificate stores are not modified. Browser download
uses the declared release's official installer/CDN; its executable SHA is
observed in the built image, not independently authenticated upstream.

`containers/runtime-candidate.json` is baked into the root-owned, read-only
runtime. It specifies the exact executable, expected Chromium version and
Playwright package version. The worker checks installed Playwright metadata and
checks the launched browser version before requesting the page. The grant-file
adapter preserves the trusted pin. Old configs without a version retain the
historical 140 pin; they cannot silently accept the new browser. Stdin continues
to accept only grant/nonce, never browser versions, runtime paths or entrypoints.

## Build and verify

Download the declared wheel pins into the ignored project data directory:

```powershell
python -m pip download --index-url https://pypi.org/simple --only-binary=:all: --platform manylinux_2_28_x86_64 --platform manylinux_2_17_x86_64 --platform manylinux2014_x86_64 --platform manylinux1_x86_64 --python-version 312 --implementation cp --abi cp312 --no-deps --dest .dom-xray-data/candidate-wheels -r containers/runtime-candidate.requirements.txt
python scripts/verify_candidate_wheels.py
docker --context desktop-linux build --file containers/runtime-candidate.Dockerfile --build-context "candidate-wheels=.dom-xray-data/candidate-wheels" --tag dom-x-ray-runtime-candidate:gate3 .
python scripts/verify_container_capture.py --image dom-x-ray-runtime-candidate:gate3 --runtime-inventory --runtime-regressions
python scripts/verify_docker_transport.py --image dom-x-ray-runtime-candidate:gate3
```

Use the previously prepared hash-checked fixture seccomp profile described in
`CONTAINER_CAPTURE_FIXTURE.md`. It was not expanded for the new browser. All
native cases retain non-root identity, sandboxing, no capabilities,
no-new-privileges, read-only root, no host mounts/network, one CPU, 1 GiB/no swap,
128 tasks and bounded scratch. The controlled measurement suite explicitly
requests Chromium sandboxing; its trusted loopback/proxy fixture is not an
independent browser-network containment proof.

`verify_runtime_inventory.py` reports installed package versions, browser
executable SHA, manifest SHA and a SHA of the image's recorded OS package list.
The test drivers resolve the tag to an immutable local image ID before execution.
Current provenance observations:

- Chromium executable SHA: `ded93a9c9a53a1ae040f08124badcca95c938e9d5015ff340c3b5538c41bf39e`.
- Runtime manifest SHA: `43151c85480e60705692e44e6c59277d4453839aac8e0ab8f9c0e9617e70934a`.
- OS package inventory SHA: `40fa2506eb1c479d0bf5fc26234330971ae4d14d212f5b1470c76376406bc14a`.

## Verified checkpoint — 2026-10-06

The final candidate verification used Docker Engine 28.3.2 / cgroup v2 and local
image ID `sha256:17b55596cc4da93ab7cef76b9e12a23abda24c700fbf1b094c88c5fad789143d`.
Subsequent builds can differ; this is a local tested identity, not a registry release.

- All nine wheels matched the lock and official unyanked PyPI artifact hashes.
- Native inventory, default-policy denial, private filesystem pivot, actual
  sandboxed capture/live-renderer timeout, six direct-network bypass denials,
  NSS wrong-root/wrong-host rejection, and sandboxed measurement regressions passed.
- All 31 deterministic measurement fixtures passed repeated capture fingerprints,
  schema/semantic validation, scene mapping, byte limits, service-worker accounting,
  interstitial guards and secret-header canaries on the new browser.
- Explicit version roundtrip, historical default and six malformed version inputs
  were checked. A deliberately incorrect browser pin was rejected **before any
  fixture connector contact**, with no eligible result.
- All twelve Docker transport cases passed on both current and historical images.
  Current host-supervised capture took 6,593 ms; live-renderer timeout returned
  no admitted record at 14,193 ms. These are fixture observations, not public-page
  benchmarks. Inner capture-only observations were 3,843 ms / 14,508 ms; the
  separate transport deadline includes engine setup/teardown.
- Maximum observed candidate cgroup peak was 222,240,768 bytes and 90 tasks in
  the final native capture run. Earlier candidate runs observed 92 tasks; neither
  establishes a safe budget for arbitrary public pages.
- The existing transport tests and ten mocked Docker contract tests also pass,
  including Python optimization mode. Owned native test containers were removed.

## Release gates that remain

This Ubuntu base is digest-pinned, but apt repositories/package selection are
mutable; the recorded inventory is not a reproducible apt lock. A fresh build
can produce a different image and must be verified again. No registry release,
SBOM/vulnerability review, signed artifact provenance, patch SLA or host-kernel
approval is claimed. The retained broad fixture syscall profile still needs
production minimization/review.

Restricted broker connectivity, separate broker/worker identities, durable
orphan recovery, independent cgroup-empty evidence, parser/PSL handling, public
API/queue adoption and representative public corpus measurements remain open.
The stock `.test` guard and API's honest `scanner-disabled` response are unchanged.
