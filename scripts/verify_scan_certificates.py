"""Real certificate chains, scoped TLS/browser trust, and issuer failure checks."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from playwright.sync_api import sync_playwright  # noqa: E402
from scanner.browser_egress_proxy import run_browser_egress_proxy  # noqa: E402
from scanner.destination_policy import DestinationPolicy  # noqa: E402
from scanner.origin_exchange import OriginExchange  # noqa: E402
from scanner.scan_certificates import ScanCertificateIssuer, CertificateIssuerError  # noqa: E402
from scripts.verify_browser_egress_proxy import FixtureOrigin  # noqa: E402


def require(value, message):
    if not value:
        raise AssertionError(message)


def reject(action, expected=None):
    try:
        action()
    except CertificateIssuerError as error:
        if expected:
            require(str(error) == expected, "unexpected content-free issuer outcome")
        return
    raise AssertionError("issuer accepted a rejected case")


def main():
    openssl = shutil.which("openssl") or r"C:\Program Files\Git\usr\bin\openssl.exe"
    require(Path(openssl).is_file(), "OpenSSL is required")
    command = lambda args: subprocess.run([openssl, *args], capture_output=True, timeout=5)
    with ScanCertificateIssuer(openssl, max_hosts=4) as issuer, ScanCertificateIssuer(openssl) as other:
        directory, other_directory = issuer.trust_certificate.parent, other.trust_certificate.parent
        require(directory != other_directory and issuer.trust_certificate.read_bytes() !=
                other.trust_certificate.read_bytes(), "scan roots were reused")
        if os.name != "nt":
            require(directory.stat().st_mode & 0o777 == 0o700, "scan directory is not private")
        first, fresh = issuer("xray.test"), issuer("xray.test")
        require(first is not fresh and first.protocol == ssl.PROTOCOL_TLS_SERVER
                and first.minimum_version == ssl.TLSVersion.TLSv1_2, "TLS context reused or weakened")
        issuer("other.test")
        issuer("1.1.1.1")
        issuer("2606:4700:4700::1111")
        reject(lambda: issuer("overflow.test"), "certificate-host-limit")
        keys = [hashlib.sha256(pair[1].read_bytes()).digest() for pair in issuer._leaves.values()]
        require(len(set(keys)) == 4, "different hosts share a private leaf key")
        for host, (chain, key) in issuer._leaves.items():
            ip = ":" in host or host == "1.1.1.1"
            result = command(["verify", "-CAfile", str(issuer.trust_certificate), "-purpose", "sslserver",
                              "-verify_ip" if ip else "-verify_hostname", host, str(chain)])
            require(result.returncode == 0, "issued leaf failed normal CA/purpose/hostname verification")
            result = command(["verify", "-CAfile", str(other.trust_certificate), str(chain)])
            require(result.returncode != 0, "leaf verified under another scan's root")
            if os.name != "nt":
                require(key.stat().st_mode & 0o777 == 0o600, "leaf key permissions are not private")
        chain = issuer._leaves["xray.test"][0]
        require(command(["verify", "-CAfile", str(issuer.trust_certificate), "-verify_hostname",
                         "wrong.test", str(chain)]).returncode != 0, "wrong hostname verified")
        require(command(["verify", "-CAfile", str(issuer.trust_certificate), "-purpose", "sslclient",
                         str(chain)]).returncode != 0, "server leaf has client authentication purpose")
        long_host = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
        other(long_host)
        require(command(["verify", "-CAfile", str(other.trust_certificate), "-verify_hostname",
                         long_host, str(other._leaves[long_host][0])]).returncode == 0,
                "valid long hostname was rejected by a Common Name length limit")
        with patch.object(issuer, "_run") as run:
            for host in ("*.test", "XRAY.test", "xray.test.", "xray.test:443", "xray.test/evil",
                         "xray.test, DNS:evil.test", "xray.test\nsubjectAltName=DNS:evil.test",
                         "-addext", "user@xray.test", "localhost", "127.0.0.1", "::1", "é.test", ""):
                reject(lambda host=host: issuer(host), "certificate-host")
            require(not run.called, "invalid hostname reached the certificate command")

        requests = []
        policy = DestinationPolicy(lambda _host, _port: ["1.1.1.1"])
        exchange = OriginExchange(policy, user_agent="DOM-X-Ray-Issuer-Fixture/0.1",
            connector=lambda grant, **_kwargs: FixtureOrigin(grant, requests))
        with run_browser_egress_proxy(initial_url="https://xray.test/", policy=policy,
                exchange=exchange, tls_context=issuer) as proxy:
            # Normal CA + hostname verification, not a certificate-error bypass.
            for host in ("xray.test", "other.test", "1.1.1.1", "2606:4700:4700::1111"):
                authority = f"[{host}]:443" if ":" in host else f"{host}:443"
                raw = socket.create_connection(proxy.server_address, timeout=5)
                raw.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
                header = bytearray()
                while not header.endswith(b"\r\n\r\n"):
                    byte = raw.recv(1)
                    require(byte, "CONNECT closed before establishment")
                    header.extend(byte)
                trust = ssl.create_default_context(cafile=str(issuer.trust_certificate))
                with trust.wrap_socket(raw, server_hostname=host) as tls:
                    tls.sendall(f"GET /proof HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
                    require(tls.recv(1024).startswith(b"HTTP/1.1 200"), "verified issuer TLS relay failed")

            # Chromium's SPKI exception is verifier-only; no OS trust changes.
            public = command(["x509", "-pubkey", "-noout", "-in", str(issuer.trust_certificate)])
            der = subprocess.run([openssl, "pkey", "-pubin", "-outform", "DER"], input=public.stdout,
                                 check=True, capture_output=True, timeout=5).stdout
            spki = base64.b64encode(hashlib.sha256(der).digest()).decode()
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True, proxy={"server": proxy.url},
                    args=[f"--ignore-certificate-errors-spki-list={spki}", "--disable-quic"])
                page = browser.new_page()
                response = page.goto("https://xray.test/", wait_until="load")
                require(response.status == 200 and page.locator("#proof").inner_text() == "TLS proxy works",
                        "Chromium did not accept the per-scan issued chain")
                browser.close()
        other_root = other.trust_certificate
        issuer.close()
        require(not directory.exists() and other_root.is_file(), "scan teardown crossed scan ownership")
        reject(lambda: issuer("xray.test"), "certificate-closed")
    require(not other_directory.exists(), "second scan keys survived teardown")

    # Lock acquisition consumes the same operation budget as subprocess work.
    with ScanCertificateIssuer(openssl, operation_seconds=0.25) as bounded:
        bounded_directory = bounded.trust_certificate.parent
        bounded._lock.acquire()
        started = time.monotonic()
        try:
            reject(lambda: bounded("xray.test"), "certificate-timeout")
            require(time.monotonic() - started < 1, "issuer lock exceeded its budget")
            cleanup_started = time.monotonic()
            reject(bounded.close, "certificate-cleanup-timeout")
            require(time.monotonic() - cleanup_started < 6 and bounded_directory.is_dir(),
                    "contended teardown exceeded its bound or removed active files")
        finally:
            bounded._lock.release()
        bounded._expires = time.monotonic() - 1
        reject(lambda: bounded("xray.test"), "certificate-timeout")
        reject(lambda: bounded.trust_certificate, "certificate-timeout")

    real_run = subprocess.run
    def slow_command(_argv, **kwargs):
        # A real process, not a mocked elapsed clock. subprocess.run must kill it.
        return real_run([sys.executable, "-c", "import time; time.sleep(10)"], **kwargs)

    with ScanCertificateIssuer(openssl, operation_seconds=0.25) as bounded:
        directory = bounded.trust_certificate.parent
        before = set(directory.iterdir())
        started = time.monotonic()
        with patch("scanner.scan_certificates.subprocess.run", side_effect=slow_command):
            reject(lambda: bounded("xray.test"), "certificate-issuance")
        require(time.monotonic() - started < 1 and set(directory.iterdir()) == before,
                "timed-out issuance leaked partial files or exceeded its budget")
        with patch("scanner.scan_certificates.subprocess.run", side_effect=OSError("private provider text")):
            reject(lambda: bounded("xray.test"), "certificate-issuance")
        require(set(directory.iterdir()) == before and not bounded._leaves,
                "failed issuance published a leaf or left files")
        original_run = bounded._run
        def extra_identity(arguments, deadline, *, capture=False):
            if capture:
                return b"X509v3 Subject Alternative Name:\n DNS:xray.test, DNS:evil.test\n"
            return original_run(arguments, deadline)
        with patch.object(bounded, "_run", side_effect=extra_identity):
            reject(lambda: bounded("xray.test"), "certificate-issuance")
        require(set(directory.iterdir()) == before and not bounded._leaves,
                "SAN postcondition failure published a leaf or left private files")
    require(not directory.exists(), "failed scan keys survived cleanup")
    real_temporary = __import__("tempfile").TemporaryDirectory
    setup_directories = []
    def tracked_temporary(**kwargs):
        temporary = real_temporary(**kwargs)
        setup_directories.append(Path(temporary.name))
        return temporary

    with patch("scanner.scan_certificates.tempfile.TemporaryDirectory", side_effect=tracked_temporary), \
         patch("scanner.scan_certificates.subprocess.run",
               side_effect=subprocess.CalledProcessError(1, "provider private data")):
        reject(lambda: ScanCertificateIssuer(openssl), "certificate-setup")
    require(setup_directories and all(not path.exists() for path in setup_directories),
            "failed CA setup leaked its private directory")
    with patch("scanner.scan_certificates.tempfile.TemporaryDirectory", side_effect=tracked_temporary), \
         patch("scanner.scan_certificates.Path.chmod", side_effect=OSError("private mode failure")):
        reject(lambda: ScanCertificateIssuer(openssl), "certificate-setup")
    require(all(not path.exists() for path in setup_directories), "early setup failure leaked its directory")
    with patch("scanner.scan_certificates.tempfile.TemporaryDirectory", side_effect=tracked_temporary), \
         patch("scanner.scan_certificates.Path.write_text", side_effect=OSError("private config failure")):
        reject(lambda: ScanCertificateIssuer(openssl), "certificate-setup")
    require(all(not path.exists() for path in setup_directories), "config setup failure leaked its directory")
    print("Verified per-scan CA rotation, independent DNS/IPv4/IPv6 leaves, normal CA/purpose/hostname TLS checks, "
          "real Chromium proxy chain acceptance with verifier-only scoped SPKI, host/cap rejection, fresh contexts, "
          "lock/process/lifetime deadlines, conditional POSIX permission checks, failure cleanup, and scan-owned teardown. "
          "Disposable-browser root installation and deployed containment remain open.")


if __name__ == "__main__":
    main()
