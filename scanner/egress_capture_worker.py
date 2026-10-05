"""Supervised Linux browser-egress lifecycle, still reserved-fixture guarded.

No public API enablement or containment claim. Dependency injection below is
trusted program configuration, never accepted from a visitor/config JSON.
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.bounded_resolver import BoundedSystemResolver
from scanner.browser_egress_proxy import run_browser_egress_proxy
from scanner.browser_trust import LinuxBrowserTrust
from scanner.destination_policy import DestinationPolicy, ValidatedDestination
from scanner.origin_exchange import OriginExchange
from scanner.pinned_connector import connect_pinned
from scanner.scan_certificates import ScanCertificateIssuer
from scanner.scan_transport import PublicScanGrant, WorkerLaunch, check_public_scan_grant
from scanner.worker_supervisor import RESULT_NONCE_ENV, MAX_WORKER_RESULT_BYTES

MAX_CONFIG_BYTES = 16_384
CHROMIUM_VERSION = "140.0.7339.16"


@dataclass(frozen=True)
class CaptureRuntime:
    openssl: Path
    certutil: Path
    chromium: Path
    library_directory: Path | None = None

    def __post_init__(self):
        for path in (self.openssl, self.certutil, self.chromium):
            if not isinstance(path, Path) or not path.is_absolute() or not path.is_file():
                raise ValueError("invalid-capture-runtime")
        path = self.library_directory
        if path is not None and (not isinstance(path, Path) or not path.is_absolute()
                or not path.is_dir() or ":" in str(path)):
            raise ValueError("invalid-capture-runtime")


def create_capture_launch(grant, result_path, runtime, *, packages_directory=None, entrypoint=None):
    """Prepare a bounded private grant file inside the transport-owned directory.

    Optional entrypoint/packages paths are trusted deployment/test code, not
    visitor choices. The stock entrypoint has no fixture origin or DNS override.
    """
    if sys.platform != "linux" or not isinstance(runtime, CaptureRuntime):
        raise ValueError("capture-worker-platform-or-runtime")
    check_public_scan_grant(grant)
    result_path = Path(result_path)
    if (not result_path.is_absolute() or not result_path.parent.is_dir()
            or result_path.parent.stat().st_mode & 0o077):
        raise ValueError("capture-worker-private-directory")
    entry = Path(__file__).resolve() if entrypoint is None else Path(entrypoint)
    if not entry.is_absolute() or not entry.is_file():
        raise ValueError("invalid-capture-entrypoint")
    packages = "-"
    if packages_directory is not None:
        directory = Path(packages_directory)
        if not directory.is_absolute() or not directory.is_dir():
            raise ValueError("invalid-capture-packages")
        packages = str(directory)
    destination = grant.destination
    payload = {"grant": {"targetUrl": grant.target_url, "destination": {
        "purpose": destination.purpose, "scheme": destination.scheme,
        "hostname": destination.hostname, "port": destination.port,
        "addresses": list(destination.addresses)}}, "runtime": {
        "openssl": str(runtime.openssl), "certutil": str(runtime.certutil),
        "chromium": str(runtime.chromium),
        "libraryDirectory": None if runtime.library_directory is None else str(runtime.library_directory)}}
    encoded = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_CONFIG_BYTES:
        raise ValueError("capture-worker-config-limit")
    temporary = result_path.parent / "worker-tmp"
    temporary.mkdir(mode=0o700)
    config = result_path.parent / "capture-config.json"
    descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
    bootstrap = ("import sys,runpy; p=sys.argv.pop(1); "
                 "sys.path[:0]=[p] if p!='-' else []; "
                 "runpy.run_path(sys.argv.pop(1),run_name='__main__')")
    return WorkerLaunch([sys.executable, "-I", "-c", bootstrap, packages,
                         str(entry), str(config), str(result_path)], cwd=ROOT,
        environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                     "HOME": str(temporary), "TMPDIR": str(temporary)})


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("invalid-capture-config")
        value[key] = item
    return value


def load_capture_config(path):
    """Strict bounded regular-file input, with no symlink following on Linux."""
    path = Path(path)
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_CONFIG_BYTES
            or metadata.st_mode & 0o077):
        raise ValueError("invalid-capture-config")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                or opened.st_mode & 0o077 or not 0 < opened.st_size <= MAX_CONFIG_BYTES):
            raise ValueError("invalid-capture-config")
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("invalid-capture-config")
    payload = json.loads(raw, object_pairs_hook=_object)
    if not isinstance(payload, dict) or set(payload) != {"grant", "runtime"}:
        raise ValueError("invalid-capture-config")
    grant, runtime = payload["grant"], payload["runtime"]
    if (not isinstance(grant, dict) or set(grant) != {"targetUrl", "destination"}
            or not isinstance(runtime, dict) or set(runtime) != {"openssl", "certutil", "chromium", "libraryDirectory"}):
        raise ValueError("invalid-capture-config")
    destination = grant["destination"]
    if (not isinstance(destination, dict) or set(destination) != {"purpose", "scheme", "hostname", "port", "addresses"}
            or not isinstance(destination["addresses"], list)
            or isinstance(destination["port"], bool) or not isinstance(destination["port"], int)
            or any(not isinstance(destination[name], str) for name in ("purpose", "scheme", "hostname"))
            or any(not isinstance(runtime[name], str) for name in ("openssl", "certutil", "chromium"))
            or runtime["libraryDirectory"] is not None and not isinstance(runtime["libraryDirectory"], str)):
        raise ValueError("invalid-capture-config")
    destination = ValidatedDestination(**{**destination, "addresses": tuple(destination["addresses"])})
    checked = PublicScanGrant(grant["targetUrl"], destination)
    check_public_scan_grant(checked)
    return checked, CaptureRuntime(Path(runtime["openssl"]), Path(runtime["certutil"]), Path(runtime["chromium"]),
        None if runtime["libraryDirectory"] is None else Path(runtime["libraryDirectory"]))


def capture_granted_page(grant, runtime, *, resolver=None, connector=connect_pinned, after_capture=None):
    """Compose normal TLS, per-scan trust, policy, proxy and actual probe.

    Reserved .test targets only until public containment/parser gates pass.
    after_capture is an internal test lifecycle hook, never a config field.
    """
    from playwright.sync_api import sync_playwright
    from scanner.browser_probe import probe_page, validate_fixture_target
    from scanner.browser_namespace import write_namespace_wrapper
    from scanner.namespace_bridge import NamespaceBridge
    if sys.platform != "linux" or not isinstance(runtime, CaptureRuntime):
        raise ValueError("capture-worker-platform-or-runtime")
    check_public_scan_grant(grant)
    validate_fixture_target(grant.target_url, allow_https=True)
    temporary_parent = os.environ.get("TMPDIR")
    if not temporary_parent:
        raise ValueError("capture-worker-private-temp-required")
    policy = DestinationPolicy(BoundedSystemResolver() if resolver is None else resolver)
    exchange = OriginExchange(policy, user_agent="DOM-X-Ray-Guarded-Capture/0.1",
                              initial_grant=grant, connector=connector)
    with ScanCertificateIssuer(runtime.openssl) as issuer, \
         LinuxBrowserTrust(issuer.trust_certificate, runtime.certutil,
                           runtime_library_path=runtime.library_directory) as trust, \
         run_browser_egress_proxy(initial_url=grant.target_url, policy=policy,
                                 exchange=exchange, tls_context=issuer) as proxy, \
         NamespaceBridge(proxy.server_address[1], temporary_parent=temporary_parent) as bridge, \
         sync_playwright() as playwright:
        wrapper = write_namespace_wrapper(Path(trust.environment["HOME"]), executable=runtime.chromium,
            bridge_path=bridge.path, port=proxy.server_address[1],
            filesystem_runtime_directories=[runtime.chromium.parent,
                *([] if runtime.library_directory is None else [runtime.library_directory])])
        browser = playwright.chromium.launch(headless=True, chromium_sandbox=True,
            executable_path=str(wrapper), env=trust.environment,
            proxy={"server": proxy.url}, args=["--disable-quic"], timeout=5_000)
        try:
            if browser.version != CHROMIUM_VERSION:
                raise ValueError("capture-worker-browser-version")
            probe = probe_page(browser, grant.target_url, trusted_https_fixture=True,
                proxy_server=proxy.url, policy_block_log=proxy.blocked,
                egress_observation_snapshot=proxy.snapshot_observations,
                egress_correlation_key=proxy.correlation_key,
                egress_observations_truncated=lambda: proxy.ledger.truncated or proxy.events_truncated)
            if after_capture is not None:
                after_capture(probe, Path(trust.environment["HOME"]))
        finally:
            browser.close()
    return probe.record


def publish_worker_result(result_path, nonce, record):
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("capture-worker-nonce")
    path = Path(result_path)
    raw = json.dumps({"supervisorNonce": nonce, "result": {"record": record}},
                     separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(raw) > MAX_WORKER_RESULT_BYTES:
        raise ValueError("capture-worker-result-limit")
    if path.exists():
        raise ValueError("capture-worker-result-exists")
    temporary = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    if len(sys.argv) != 3:
        raise ValueError("capture-worker-arguments")
    config, result = Path(sys.argv[1]), Path(sys.argv[2])
    nonce = os.environ.get(RESULT_NONCE_ENV)
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("capture-worker-nonce")
    if not result.is_absolute() or result.parent != config.parent:
        raise ValueError("capture-worker-result-path")
    grant, runtime = load_capture_config(config)
    record = capture_granted_page(grant, runtime)
    publish_worker_result(result, nonce, record)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # No visitor, grant, certificate, filesystem or provider text in output.
        raise SystemExit(2) from None
