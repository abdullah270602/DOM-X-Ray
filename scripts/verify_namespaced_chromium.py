"""Real Chromium HTTPS capture inside the loopback-only network/PID namespace."""

import argparse
import json
import os
import socket
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from playwright.sync_api import sync_playwright, Error as PlaywrightError
from jsonschema import Draft202012Validator, FormatChecker
from scanner.browser_namespace import write_namespace_wrapper
from scanner.namespace_bridge import NamespaceBridge
from scanner.browser_trust import LinuxBrowserTrust
from scanner.scan_certificates import ScanCertificateIssuer
from scanner.browser_egress_proxy import run_browser_egress_proxy
from scanner.browser_probe import probe_page
from scanner.destination_policy import DestinationPolicy
from scanner.origin_exchange import OriginExchange
from scanner.scan_transport import PublicScanGrant
from scripts.verify_browser_egress_proxy import FixtureOrigin
from scripts.validate_fixtures import validate_semantics


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, default=ROOT / ".dom-xray-data/linux-trust")
    base = parser.parse_args().runtime_root.resolve(strict=True)
    require(sys.platform == "linux", "native Linux namespaced Chromium proof required")
    libraries = base / "root/usr/lib/x86_64-linux-gnu"
    executable = base / "browsers/chromium_headless_shell-1187/chrome-linux/headless_shell"
    target = "https://xray.test/"
    grant = PublicScanGrant(target, DestinationPolicy(lambda h, p: ["1.1.1.1"]).validate(target, purpose="initial"))
    requests, grants = [], []
    def connector(destination, **_kwargs):
        grants.append(destination)
        return FixtureOrigin(destination, requests)
    policy = DestinationPolicy(lambda h, p: ["1.0.0.1"])
    exchange = OriginExchange(policy, user_agent="DOM-X-Ray-Netns-Chromium-Fixture/0.1",
                              connector=connector, initial_grant=grant)
    schema = Draft202012Validator(json.loads((ROOT / "docs/SCAN_RECORD.schema.json").read_text()),
                                  format_checker=FormatChecker())
    with ScanCertificateIssuer(Path("/usr/bin/openssl")) as issuer, \
         LinuxBrowserTrust(issuer.trust_certificate, base / "root/usr/bin/certutil",
                           runtime_library_path=libraries) as trust, \
         run_browser_egress_proxy(initial_url=target, policy=policy, exchange=exchange, tls_context=issuer) as proxy, \
         NamespaceBridge(proxy.server_address[1]) as bridge, \
         sync_playwright() as playwright:
        wrapper = write_namespace_wrapper(Path(trust.environment["HOME"]), executable=executable,
            bridge_path=bridge.path, port=proxy.server_address[1],
            filesystem_runtime_directories=[executable.parent, libraries])
        browser = playwright.chromium.launch(executable_path=str(wrapper), headless=True, chromium_sandbox=True,
            env=trust.environment, proxy={"server": proxy.url}, args=["--disable-quic"], timeout=5_000)
        try:
            require(browser.version == "140.0.7339.16", "unpinned namespaced Chromium")
            captured = probe_page(browser, target, trusted_https_fixture=True, proxy_server=proxy.url,
                policy_block_log=proxy.blocked, egress_observation_snapshot=proxy.snapshot_observations,
                egress_correlation_key=proxy.correlation_key,
                egress_observations_truncated=lambda: proxy.ledger.truncated or proxy.events_truncated)
            validate_semantics(captured.record, "namespaced Chromium capture", schema)
            require(captured.record["status"] == "complete" and grants[0] is grant.destination
                    and all(value.addresses == ("1.0.0.1",) for value in grants[1:]),
                    "namespaced capture/pinning was incomplete")
            require(any(row["fetchDestination"] == "serviceworker" and row["outcome"] == "relayed"
                        for row in proxy.snapshot_observations()), "namespaced capture omitted service-worker bootstrap")
            # Deliberately bypass the proxy in a separate browser context.
            # Host loopback listeners must not receive even one connection.
            with socket.socket() as trap, socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as trap6:
                trap.bind(("127.0.0.1", 0))
                trap.listen()
                trap.setblocking(False)
                trap6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                trap6.bind(("::1", 0))
                trap6.listen()
                trap6.setblocking(False)
                before = len(proxy.snapshot_observations())
                direct = browser.new_context(proxy={"server": proxy.url, "bypass": "*"})
                try:
                    page = direct.new_page()
                    for url in (f"http://127.0.0.1:{trap.getsockname()[1]}/",
                                f"http://[::1]:{trap6.getsockname()[1]}/",
                                "http://169.254.169.254/", "http://10.0.0.1/",
                                "http://1.1.1.1/", "http://[2606:4700:4700::1111]/"):
                        try:
                            page.goto(url, timeout=1_000)
                        except PlaywrightError:
                            pass
                        else:
                            raise AssertionError("actual Chromium direct bypass succeeded")
                    require(len(proxy.snapshot_observations()) == before, "direct Chromium bypass still used enforcing proxy")
                    for listener in (trap, trap6):
                        try:
                            connected, _ = listener.accept()
                        except BlockingIOError:
                            pass
                        else:
                            connected.close()
                            raise AssertionError("Chromium bypass reached host-loopback listener")
                finally:
                    direct.close()
            # Observe the actual executable's host-visible namespace/capability
            # state, not just a wrapper name or launch option.
            observed = []
            host_namespace = os.readlink("/proc/self/ns/net")
            require(bridge.peer_ids, "namespace relay identity was not observable")
            relay_users = {os.readlink(f"/proc/{pid}/ns/user") for pid in bridge.peer_ids}
            require(os.readlink("/proc/self/ns/user") not in relay_users, "relay retained host user namespace")
            for directory in Path("/proc").iterdir():
                if not directory.name.isdecimal():
                    continue
                try:
                    if os.readlink(directory / "exe") != str(executable):
                        continue
                    state = dict(line.split(":", 1) for line in (directory / "status").read_text().splitlines() if ":" in line)
                    require(os.readlink(directory / "ns/net") != host_namespace, "Chromium retained host networking")
                    require(os.readlink(directory / "ns/user") != os.readlink("/proc/self/ns/user"),
                            "Chromium retained host user namespace")
                    require(state["NoNewPrivs"].strip() == "1", "Chromium lost no-new-privs")
                    # Chromium's sandbox may create deeper user namespaces,
                    # with capabilities scoped there. Require zero setup caps
                    # in the relay-owned namespace, not an impossible global
                    # zero-cap rule for all nested sandbox namespaces.
                    if os.readlink(directory / "ns/user") in relay_users:
                        require(all(int(state[key], 16) == 0 for key in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")),
                                "Chromium retained namespace setup privileges")
                        observed.append(int(directory.name))
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    pass
            require(observed, "actual Chromium namespace/capabilities were not observable")
        finally:
            browser.close()
    print("Verified actual pinned sandboxed Chromium in a distinct network/PID namespace with zero capabilities/no-new-privs: "
          "normal private NSS TLS, complete schema+semantic HTTPS capture, one-shot initial pinning, later validation and "
          "service-worker bootstrap via the fixed Unix proxy bridge; six actual Chromium direct-proxy-bypass targets denied, "
          "including host loopback with zero listener contacts. The explicit filesystem root is enabled; "
          "runtime integrity, quotas and production containment remain open.")


if __name__ == "__main__":
    main()
