# Disposable Linux browser trust

Status: native sandboxed Chromium fixture proof; public-worker integration and independent network containment remain open.

`scanner/browser_trust.py` supplies `LinuxBrowserTrust`. Each instance creates a
private temporary HOME with its own `.pki/nssdb`, config, data, cache, and temp
directories. Only the public scan root is copied; issuer private keys and
operator trust files are never copied. NSS `certutil` initializes the database,
imports the root with server trust `C,,`, then exports it. The exported DER
identity must exactly match the input root. Root input and export are bounded
to 65,536 bytes; setup commands share a maximum five-second deadline.

The detached launch environment contains only private HOME/XDG/TMP paths and
locale settings, plus an optional explicitly configured library directory.
It does not modify `os.environ` or inherit application secrets. `certutil` must
be an absolute trusted Linux NSS executable, not Windows certutil. Any optional
library directory is trusted code: deployment must review and make it immutable;
path validation alone does not establish that property.

Launch Chromium with `trust.environment`, keep certificate verification and
browser sandboxing enabled, and close **all browser processes before closing
the trust context**. Cleanup removes the owned profile, not the issuer root or
another scan's profile. Worker destruction remains necessary to release loaded
trust and enforce filesystem, process, and disk-output limits. This adapter
does not install OS trust, launch a browser, or provide network containment.

## Evidence

`python scripts/verify_browser_trust.py` checks the command contract, exact root
identity, minimal detached environment, independent profiles, rejected root
inputs, setup failures, actual subprocess timeout, and cleanup. NSS commands
are mocked in this mode; it is not a native browser-trust proof.

The `--native` mode was separately executed on Ubuntu under WSL2 with Python
3.12.3, Playwright 1.55.0, and Chromium 140.0.7339.16. With sandboxing and normal
certificate checks, it produced a complete schema- and semantics-valid HTTPS
fixture capture including service-worker bootstrap bytes. A different scan
root and a wrong-host leaf were rejected before origin contact. Origin sockets
are deterministic fixtures; this does not prove public capture or deployed
firewall containment. No certificate-error switches or OS trust changes were
used in this native test.

## Project-local native test preparation

`scripts/prepare_linux_trust_python.py --bootstrap-wheel /absolute/path/pip-25.3-py3-none-any.whl`
installs pinned Python packages and Playwright browsers only under the ignored
`.dom-xray-data/linux-trust` directory. Download the bootstrap wheel through
pip (`pip download --no-deps pip==25.3`). The preparation script does not install
OS dependencies or change an existing Python environment.

On the tested Ubuntu 24.04 runtime, NSS/NSPR and ALSA dependencies were downloaded
with `apt download libnss3-tools libnss3 libnspr4 libasound2t64` and extracted
with `dpkg-deb --extract` into `.dom-xray-data/linux-trust/root`, without an OS
package installation. Tested package versions were NSS 3.98-1ubuntu0.2,
NSPR 2:4.35-1.1build1, and ALSA 1.2.11-1ubuntu0.3. Dependency preparation requires
network access; these are test-runtime details, not a production image recipe.

From the repository in Linux, use absolute paths for the project-local runtime:

```bash
task_runtime="$PWD/.dom-xray-data/linux-trust"
env LD_LIBRARY_PATH="$task_runtime/root/usr/lib/x86_64-linux-gnu" \
    PLAYWRIGHT_BROWSERS_PATH="$task_runtime/browsers" \
    PYTHONPATH="$task_runtime/python" \
    python3 scripts/verify_browser_trust.py --native \
      --certutil "$task_runtime/root/usr/bin/certutil" \
      --runtime-library-path "$task_runtime/root/usr/lib/x86_64-linux-gnu"
```

The native verifier pins Chromium 140; changing browser versions requires
repeating the trust acceptance, rejection, and cleanup checks.

Next: wire this adapter and the bounded resolver into the public worker/grant
path, prove independent egress denial and full-worker teardown in deployment,
then run the public corpus and latency checks. Arbitrary public scanning stays
disabled until those release gates pass.
