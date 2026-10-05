"""Private NSS adapter contract; --native requires real Linux NSS/Chromium.

Contract checks do not imply successful browser trust. Native checks deliberately
use normal verification and browser sandboxing, with no certificate-error flags.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.browser_trust import LinuxBrowserTrust, BrowserTrustError  # noqa: E402
from scanner.scan_certificates import ScanCertificateIssuer  # noqa: E402


def require(value, message):
    if not value:
        raise AssertionError(message)


def reject(action, reason):
    try:
        action()
    except BrowserTrustError as error:
        require(str(error) == reason, "unexpected content-free trust outcome")
        return
    raise AssertionError("trust adapter accepted a rejected case")


class NssCommands:
    """Command contract spy, explicitly not an NSS implementation."""
    def __init__(self, *, failure=None, exported=None):
        self.commands = []
        self.paths = []
        self.roots = {}
        self.failure = failure
        self.exported = exported

    def __call__(self, command, **kwargs):
        directory = Path(kwargs["cwd"])
        environment = kwargs["env"]
        require(environment["HOME"] == str(directory)
                and set(environment) == {"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
                                         "TMPDIR", "LANG", "LC_ALL"}, "NSS inherited credentials or ambient home")
        require(command[command.index("-d") + 1] == f"sql:{directory / '.pki' / 'nssdb'}",
                "NSS command escaped the owned database")
        require(0 < kwargs["timeout"] <= 5 and kwargs["stdin"] == subprocess.DEVNULL
                and kwargs["stderr"] == subprocess.DEVNULL, "NSS command lost time/stream bounds")
        self.commands.append(command)
        self.paths.append(directory)
        if self.failure is not None:
            raise self.failure
        if command[1] == "-A":
            require(command[command.index("-t") + 1] == "C,,", "NSS imported non-server trust")
            root = Path(command[command.index("-i") + 1])
            require(root.parent == directory and b"PRIVATE KEY" not in root.read_bytes(),
                    "NSS import copied private material or used an unowned snapshot")
            self.roots[directory] = root.read_bytes()
        exported = self.exported if self.exported is not None else self.roots.get(directory)
        if command[1] == "-L":
            kwargs["stdout"].write(exported)
        return subprocess.CompletedProcess(command, 0)

    def assert_cleanup(self):
        require(all(not path.exists() for path in self.paths), "trust files survived setup failure/close")


def contract(openssl):
    with ScanCertificateIssuer(openssl) as issuer, ScanCertificateIssuer(openssl) as other:
        root, other_root = issuer.trust_certificate, other.trust_certificate
        if sys.platform != "linux":
            reject(lambda: LinuxBrowserTrust(root, openssl), "browser-trust-platform")
        commands = NssCommands()
        before_home = os.environ.get("HOME")
        with patch("scanner.browser_trust.sys.platform", "linux"), \
             patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "fixture-private-token"}), \
             patch("scanner.browser_trust.subprocess.run", side_effect=commands):
            with LinuxBrowserTrust(root, openssl) as first, LinuxBrowserTrust(other_root, openssl) as second:
                first_home, second_home = Path(first.environment["HOME"]), Path(second.environment["HOME"])
                require(first_home != second_home and first_home.is_dir() and second_home.is_dir(),
                        "trust profiles reused a home")
                require(os.environ.get("HOME") == before_home and "AWS_SECRET_ACCESS_KEY" not in first.environment,
                        "trust profile changed operator home or inherited app secrets")
                detached = first.environment
                detached["HOME"] = "forged"
                require(first.environment["HOME"] == str(first_home), "launch environment mutated trusted state")
                if os.name != "nt":
                    require(first_home.stat().st_mode & 0o777 == 0o700, "trust home is not private")
                first.close()
                require(not first_home.exists() and second_home.is_dir() and root.is_file(),
                        "trust cleanup removed another profile or the issuer root")
                reject(lambda: first.environment, "browser-trust-closed")
        require([command[1] for command in commands.commands] == ["-N", "-A", "-L"] * 2,
                "NSS command sequence drifted")
        commands.assert_cleanup()
        for failure in (OSError("private-provider-text"), subprocess.TimeoutExpired("private-command", 5),
                        subprocess.CalledProcessError(1, "private-command")):
            commands = NssCommands(failure=failure)
            with patch("scanner.browser_trust.sys.platform", "linux"), \
                 patch("scanner.browser_trust.subprocess.run", side_effect=commands):
                reject(lambda: LinuxBrowserTrust(root, openssl),
                       "browser-trust-timeout" if isinstance(failure, subprocess.TimeoutExpired) else "browser-trust-setup")
            commands.assert_cleanup()
        commands = NssCommands(exported=other_root.read_bytes())
        with patch("scanner.browser_trust.sys.platform", "linux"), \
             patch("scanner.browser_trust.subprocess.run", side_effect=commands):
            reject(lambda: LinuxBrowserTrust(root, openssl), "browser-trust-identity")
        commands.assert_cleanup()

        with tempfile.TemporaryDirectory(prefix="dom-xray-trust-invalid-") as temporary:
            invalid = Path(temporary) / "root.pem"
            for data in (b"", b"provider-secret", root.read_bytes() * 2,
                         root.read_bytes() + b"-----BEGIN PRIVATE KEY-----\nsecret", b"x" * 65_537):
                invalid.write_bytes(data)
                with patch("scanner.browser_trust.sys.platform", "linux"), \
                     patch("scanner.browser_trust.subprocess.run") as run:
                    reject(lambda: LinuxBrowserTrust(invalid, openssl), "browser-trust-setup")
                    require(not run.called, "invalid root reached NSS")

        real_run = subprocess.run
        paths = []
        def slow_nss(_command, **kwargs):
            paths.append(Path(kwargs["cwd"]))
            return real_run([sys.executable, "-c", "import time; time.sleep(10)"], **kwargs)
        started = time.monotonic()
        with patch("scanner.browser_trust.sys.platform", "linux"), \
             patch("scanner.browser_trust.subprocess.run", side_effect=slow_nss):
            reject(lambda: LinuxBrowserTrust(root, openssl, timeout_seconds=0.25), "browser-trust-timeout")
        require(time.monotonic() - started < 1 and all(not path.exists() for path in paths),
                "real setup timeout exceeded its bound or left profile files")
    print("Verified private Linux NSS adapter command contract, exact exported root identity, minimal detached "
          "environment, cross-scan ownership, invalid roots, setup failures/real subprocess timeout, and cleanup. "
          "NSS commands were mocked; this is not native Chromium trust proof.")


def native(openssl, certutil, runtime_library_path=None):
    if sys.platform != "linux" or not certutil:
        raise RuntimeError("native trust verification requires Linux NSS certutil")
    from playwright.sync_api import sync_playwright, Error as PlaywrightError
    from scanner.browser_egress_proxy import run_browser_egress_proxy
    from scanner.destination_policy import DestinationPolicy
    from scanner.origin_exchange import OriginExchange
    from scanner.browser_probe import probe_page
    from scripts.verify_browser_egress_proxy import FixtureOrigin
    from scripts.validate_fixtures import validate_semantics
    from jsonschema import Draft202012Validator, FormatChecker
    import json

    policy = DestinationPolicy(lambda _host, _port: ["1.1.1.1"])
    with ScanCertificateIssuer(openssl) as issuer, ScanCertificateIssuer(openssl) as other, \
         LinuxBrowserTrust(issuer.trust_certificate, certutil, runtime_library_path=runtime_library_path) as trust, \
         LinuxBrowserTrust(other.trust_certificate, certutil, runtime_library_path=runtime_library_path) as unrelated:
        with sync_playwright() as playwright:
            for mode in ("trusted", "wrong-root", "wrong-host"):
                requests = []
                exchange = OriginExchange(policy, user_agent="DOM-X-Ray-NSS-Fixture/0.1",
                    connector=lambda grant, **_kwargs: FixtureOrigin(grant, requests))
                factory = (lambda _host: issuer("wrong.test")) if mode == "wrong-host" else issuer
                with run_browser_egress_proxy(initial_url="https://xray.test/", policy=policy,
                        exchange=exchange, tls_context=factory) as proxy:
                    environment = unrelated.environment if mode == "wrong-root" else trust.environment
                    browser = playwright.chromium.launch(headless=True, chromium_sandbox=True,
                        env=environment, proxy={"server": proxy.url}, args=["--disable-quic"], timeout=5_000)
                    try:
                        require(browser.version == "140.0.7339.16", "native verifier requires pinned Chromium")
                        if mode == "trusted":
                            captured = probe_page(browser, "https://xray.test/", trusted_https_fixture=True,
                                proxy_server=proxy.url, policy_block_log=proxy.blocked,
                                egress_observation_snapshot=proxy.snapshot_observations,
                                egress_correlation_key=proxy.correlation_key,
                                egress_observations_truncated=lambda: proxy.ledger.truncated or proxy.events_truncated)
                            validator = Draft202012Validator(json.loads((ROOT / "docs/SCAN_RECORD.schema.json").read_text()),
                                                             format_checker=FormatChecker())
                            validate_semantics(captured.record, "native NSS HTTPS capture", validator)
                            require(captured.record["status"] == "complete" and
                                    captured.record["finalUrl"] == "https://xray.test/",
                                    "normal Chromium NSS capture was not a truthful complete record")
                            require(requests, "trusted browser did not reach origin exchange")
                            require(any(row["fetchDestination"] == "serviceworker" and row["outcome"] == "relayed"
                                        for row in proxy.snapshot_observations()),
                                    "native NSS capture omitted service-worker bootstrap")
                        else:
                            page = browser.new_page(ignore_https_errors=False)
                            try:
                                page.goto("https://xray.test/", timeout=5_000)
                            except PlaywrightError as error:
                                expected = "ERR_CERT_AUTHORITY_INVALID" if mode == "wrong-root" else "ERR_CERT_COMMON_NAME_INVALID"
                                require(expected in str(error), "negative trust failed for an unrelated browser error")
                            else:
                                raise AssertionError("Chromium accepted a wrong root/hostname")
                            require(not requests, "rejected browser trust contacted the origin")
                    finally:
                        browser.close()
    print("Verified native Linux sandboxed Chromium with private NSS trust and normal certificate checks: full "
          "semantically validated HTTPS/service-worker capture, unrelated scan root and wrong hostname rejected "
          "before origin contact. No system trust or "
          "certificate-error switches were used. Independent network containment remains open.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native", action="store_true")
    parser.add_argument("--certutil", help="absolute path to Linux NSS certutil, not Windows certutil")
    parser.add_argument("--runtime-library-path", help="reviewed project-local shared library directory")
    options = parser.parse_args()
    openssl = shutil.which("openssl") or r"C:\Program Files\Git\usr\bin\openssl.exe"
    contract(openssl)
    if options.native:
        native(openssl, options.certutil or shutil.which("certutil"), options.runtime_library_path)


if __name__ == "__main__":
    main()
