"""Real Chromium HTTPS proxy proof with ephemeral, key-scoped test trust."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.browser_egress_proxy import run_browser_egress_proxy, _Handler  # noqa: E402
from scanner.browser_probe import probe_page, correlate_worker_bootstrap_egress_bytes  # noqa: E402
from scanner.egress_ledger import EgressLedger  # noqa: E402
from scripts.validate_fixtures import validate_semantics  # noqa: E402
from jsonschema import Draft202012Validator, FormatChecker  # noqa: E402
from scanner.destination_policy import DestinationPolicy  # noqa: E402
from scanner.origin_exchange import OriginExchange, EgressLimits  # noqa: E402


def require(value, message):
    if not value:
        raise AssertionError(message)


class FixtureOrigin:
    """Deterministic origin; pinning/TLS-origin proofs are separate verifiers."""
    def __init__(self, grant, requests):
        self.grant = grant
        self.requests = requests
        self.payload = b""

    def settimeout(self, _timeout):
        pass

    def sendall(self, request):
        self.requests.append(request)
        target = request.split(b" ", 2)[1]
        headers = b"Content-Type: text/html\r\n"
        status = b"200 OK"
        if target == b"/":
            body = (b"<html><body><h1 id='proof'>TLS proxy works</h1>"
                    b"<script src='/script.js'></script></body></html>")
        elif target == b"/script.js":
            headers = b"Content-Type: application/javascript\r\n"
            body = (b"document.body.dataset.subresource='passed';"
                    b"navigator.serviceWorker.register('/sw.js');")
        elif target == b"/sw.js":
            headers = b"Content-Type: application/javascript\r\n"
            body = (b"self.addEventListener('install',e=>self.skipWaiting());"
                    b"self.addEventListener('activate',e=>e.waitUntil(fetch('/worker-origin')));")
        elif target == b"/redirect-private":
            status, headers, body = b"302 Found", b"Location: http://127.0.0.1/private-secret\r\n", b""
        elif target == b"/large":
            body = b"x" * 20_000
        else:
            body = b"fixture"
        self.payload = (b"HTTP/1.1 " + status + b"\r\n" + headers
                        + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)

    def recv(self, maximum):
        chunk, self.payload = self.payload[:maximum], self.payload[maximum:]
        return chunk

    def close(self):
        pass


def main():
    openssl = shutil.which("openssl") or r"C:\Program Files\Git\usr\bin\openssl.exe"
    require(Path(openssl).is_file(), "OpenSSL executable is required for temporary fixture certificates")
    with tempfile.TemporaryDirectory(prefix="dom-xray-proxy-tls-") as temporary:
        cert, key = Path(temporary) / "leaf.pem", Path(temporary) / "key.pem"
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(key), "-out", str(cert), "-subj", "/CN=xray.test",
                        "-addext", "subjectAltName=DNS:xray.test"], check=True, capture_output=True)
        public_key = subprocess.run([openssl, "x509", "-pubkey", "-noout", "-in", str(cert)],
                                    check=True, capture_output=True).stdout
        der = subprocess.run([openssl, "pkey", "-pubin", "-outform", "DER"], input=public_key,
                             check=True, capture_output=True).stdout
        spki = base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")

        def tls_context(host):
            require(host == "xray.test", "certificate issued for an unexpected host")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            return context

        requests = []
        policy = DestinationPolicy(lambda _host, _port: ["1.1.1.1"])
        exchange = OriginExchange(policy, user_agent="DOM-X-Ray-Proxy-Fixture/0.1",
            limits=EgressLimits(max_response_bytes=10_000),
            connector=lambda grant, **_kwargs: FixtureOrigin(grant, requests))
        with run_browser_egress_proxy(initial_url="https://xray.test/", policy=policy,
                                      exchange=exchange, tls_context=tls_context) as proxy:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True,
                    proxy={"server": proxy.url},
                    args=[f"--ignore-certificate-errors-spki-list={spki}", "--disable-quic"])
                context = browser.new_context()
                page = context.new_page()
                result = page.goto("https://xray.test/", wait_until="load")
                require(result.status == 200 and page.locator("#proof").inner_text() == "TLS proxy works",
                        "Chromium did not receive the decrypted HTTPS origin response")
                page.wait_for_function("document.body.dataset.subresource === 'passed'")
                page.evaluate("() => navigator.serviceWorker.ready")
                # ready means an active registration, not completion of work
                # covered by the activate event's waitUntil promise.
                page.expose_function('__domXRayWorkerRequestSeen',
                    lambda: any(b"GET /worker-origin " in request for request in requests))
                page.wait_for_function('async () => await window.__domXRayWorkerRequestSeen()', timeout=5000)
                require(any(b"GET /sw.js " in request for request in requests)
                        and any(b"GET /worker-origin " in request for request in requests),
                        "service-worker bootstrap or activation fetch bypassed the proxy")
                redirect = page.goto("https://xray.test/redirect-private")
                require(redirect.status == 403 and page.url == "https://xray.test/redirect-private",
                        "private redirect escaped into the browser")
                large = page.goto("https://xray.test/large")
                require(large.status == 509, "Chromium received an oversized HTTPS origin response")
                require(large.headers.get("x-dom-x-ray-block-id"), "resource limit lacked a block receipt")
                context.close()
                capture_exchange = OriginExchange(policy, user_agent="DOM-X-Ray-Proxy-Fixture/0.1",
                    connector=lambda grant, **_kwargs: FixtureOrigin(grant, requests))
                with run_browser_egress_proxy(initial_url="https://xray.test/", policy=policy,
                        exchange=capture_exchange, tls_context=tls_context) as capture_proxy:
                    capture = probe_page(browser, "https://xray.test/", trusted_https_fixture=True,
                        proxy_server=capture_proxy.url, policy_block_log=capture_proxy.blocked,
                        egress_observation_snapshot=capture_proxy.snapshot_observations,
                        egress_correlation_key=capture_proxy.correlation_key,
                        egress_observations_truncated=lambda: capture_proxy.ledger.truncated or capture_proxy.events_truncated)
                    require(capture.record["finalUrl"] == "https://xray.test/",
                            "HTTPS capture probe did not capture the final document")
                    validator = Draft202012Validator(json.loads((ROOT / "docs/SCAN_RECORD.schema.json").read_text()),
                                                     format_checker=FormatChecker())
                    validate_semantics(capture.record, "HTTPS proxy capture", validator)
                    require(capture.record["status"] == "complete", "HTTPS fixture capture was not complete")
                limited_exchange = OriginExchange(policy, user_agent="DOM-X-Ray-Proxy-Fixture/0.1",
                    connector=lambda grant, **_kwargs: FixtureOrigin(grant, requests))
                before_limited = len(requests)
                with run_browser_egress_proxy(initial_url="https://xray.test/", policy=policy,
                        exchange=limited_exchange, tls_context=tls_context, ledger_limit=1) as limited_proxy:
                    limited = probe_page(browser, "https://xray.test/", trusted_https_fixture=True,
                        proxy_server=limited_proxy.url, policy_block_log=limited_proxy.blocked,
                        egress_observation_snapshot=limited_proxy.snapshot_observations,
                        egress_correlation_key=limited_proxy.correlation_key,
                        egress_observations_truncated=lambda: limited_proxy.ledger.truncated)
                    validate_semantics(limited.record, "truncated HTTPS ledger capture", validator)
                    require(limited.record["status"] == "partial" and any(
                        item["code"] == "egress-observation-limit" for item in limited.record["limitations"]),
                        "ledger truncation was reported as a complete measurement")
                    require(len(requests) - before_limited == 1 and any(
                        block["reason"] == "egress-ledger-limit" for block in limited_proxy.blocked),
                        "ledger overflow reached origin or lost trusted receipt authority")
                capped_exchange = OriginExchange(policy, user_agent="DOM-X-Ray-Proxy-Fixture/0.1",
                    limits=EgressLimits(max_response_bytes=10_000),
                    connector=lambda grant, **_kwargs: FixtureOrigin(grant, requests))
                with run_browser_egress_proxy(initial_url="https://xray.test/large", policy=policy,
                        exchange=capped_exchange, tls_context=tls_context) as capped_proxy:
                    capped = probe_page(browser, "https://xray.test/large", trusted_https_fixture=True,
                        proxy_server=capped_proxy.url, policy_block_log=capped_proxy.blocked,
                        egress_observation_snapshot=capped_proxy.snapshot_observations,
                        egress_correlation_key=capped_proxy.correlation_key,
                        egress_observations_truncated=lambda: capped_proxy.ledger.truncated,
                        max_response_bytes=10_000)
                    validate_semantics(capped.record, "HTTPS response limit capture", validator)
                    require(capped.record["status"] == "partial" and
                            capped.record["failureCode"] == "resource-limit",
                            "instrument-generated HTTPS limit was misclassified as an origin error")
                browser.close()
            events = proxy.snapshot_events()
            require(any(event.get("tls") and event["outcome"] == "relayed" for event in events),
                    "proxy ledger omitted HTTPS relay evidence")
            require(any(event.get("reason") == "response-byte-limit" and event["upstreamBytesRead"] == 10_001
                        for event in events), "proxy ledger lost the exact oversized-response byte count")
            require("private-secret" not in repr(events), "ledger persisted rejected target material")
            observations = proxy.snapshot_observations()
            require(all(row["browserWireBytes"] is not None for row in observations
                        if row["outcome"] == "relayed"), "successful writes lack browser wire bytes")
            require(any(row["fetchDestination"] == "serviceworker" for row in observations),
                        "worker bootstrap destination was not recorded")
            require(any(block["blockId"] == large.headers.get("x-dom-x-ray-block-id")
                        for block in proxy.blocked), "CDP receipt lacks trusted block authority")
            bootstrap = [{"workerBootstrap": True, "transferredBytes": None,
                          "method": "GET", "url": "https://xray.test/sw.js"}]
            one = next(row for row in observations if row["fetchDestination"] == "serviceworker"
                       and row["outcome"] == "relayed")
            require(correlate_worker_bootstrap_egress_bytes(bootstrap, [one], proxy.correlation_key) == 1
                    and bootstrap[0]["transferredBytes"] == one["browserWireBytes"],
                    "real TLS ledger cannot correlate a uniquely identified bootstrap")

            # A manual encrypted request must not pivot away from CONNECT's
            # authority, and framing that declares a body must stop pre-origin.
            def tunnel_request(request):
                host, port = proxy.server_address
                raw = socket.create_connection((host, port), timeout=5)
                raw.sendall(b"CONNECT xray.test:443 HTTP/1.1\r\nHost: xray.test:443\r\n\r\n")
                header = bytearray()
                while not header.endswith(b"\r\n\r\n"):
                    header.extend(raw.recv(1))
                require(bytes(header).startswith(b"HTTP/1.1 200"), "manual CONNECT failed")
                trust = ssl.create_default_context(cafile=str(cert))
                with trust.wrap_socket(raw, server_hostname="xray.test") as tls:
                    tls.sendall(request)
                    return tls.recv(1024)
            before = len(requests)
            rejected = tunnel_request(b"GET / HTTP/1.1\r\nHost: different.test\r\n\r\n")
            require(rejected.startswith(b"HTTP/1.1 403") and len(requests) == before,
                    "decrypted Host pivot contacted a different origin")
            rejected = tunnel_request(b"GET / HTTP/1.1\r\nHost: xray.test\r\nTransfer-Encoding: chunked\r\n\r\n")
            require(rejected.startswith(b"HTTP/1.1 403") and len(requests) == before,
                    "body framing reached origin exchange")
            rejected = tunnel_request(b"GET / HTTP/1.1\r\nHost: xray.test#\r\n\r\n")
            require(rejected.startswith(b"HTTP/1.1 403") and len(requests) == before,
                    "authority fragment delimiter reached the origin")
            raw = socket.create_connection(proxy.server_address, timeout=5)
            raw.sendall(b"CONNECT xray.test:443 HTTP/1.1\r\nHost: xray.test:443\r\n\r\n")
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                header.extend(raw.recv(1))
            trust = ssl.create_default_context(cafile=str(cert))
            try:
                with trust.wrap_socket(raw, server_hostname="different.test"):
                    raise AssertionError("TLS SNI pivot was accepted")
            except ssl.SSLError:
                raw.close()
            require(len(requests) == before, "SNI pivot contacted an origin")
            class DisconnectedBrowser:
                def __init__(self):
                    self.request = (b"GET http://xray.test/write-failure?token=secret HTTP/1.1\r\n"
                                    b"Host: xray.test\r\n\r\n")
                    self.writes = 0

                def settimeout(self, _timeout):
                    pass

                def recv(self, maximum):
                    part, self.request = self.request[:maximum], self.request[maximum:]
                    return part

                def sendall(self, _response):
                    self.writes += 1
                    raise OSError("fixture browser disconnected")

                def close(self):
                    pass

            disconnected = DisconnectedBrowser()
            blocks_before = len(proxy.blocked)
            _Handler(disconnected, ("127.0.0.1", 0), proxy)
            failed = proxy.snapshot_observations()[-1]
            require(disconnected.writes == 1 and len(proxy.blocked) == blocks_before
                    and failed["outcome"] == "client-write-failed"
                    and failed["browserWireBytes"] is None and failed["upstreamBytesRead"] > 0,
                    "browser write failure invented delivered bytes or a policy block")
            require("token=secret" not in repr(proxy.snapshot_observations()),
                    "query secret entered the capture ledger")
            # Leave an incomplete browser request open; context exit must close
            # that socket and wait for the handler rather than leak a daemon.
            stalled = socket.create_connection(proxy.server_address, timeout=5)
            stalled.sendall(b"GET ")
        try:
            closed = stalled.recv(1024) == b""
        except ConnectionResetError:
            # Windows may report a reset instead of EOF after forced shutdown.
            closed = True
        require(closed, "proxy teardown left a stalled browser socket open")
        stalled.close()
        require(all(b"User-Agent: DOM-X-Ray-Proxy-Fixture/0.1" in request for request in requests),
                "browser identity was forwarded to an origin")
    ledger = EgressLedger(limit=1)
    ledger.begin("https://user:secret@xray.test/sw.js?token=private#fragment", "GET", ())
    require("secret" not in repr(ledger.snapshot()) and "private" not in repr(ledger.snapshot()),
            "ledger retained query or credentials")
    require(ledger.correlation_key("https://xray.test/sw.js?a=1") !=
            ledger.correlation_key("https://xray.test/sw.js?a=2"), "query variants collided")
    require(ledger.correlation_key("HTTPS://XRAY.TEST:443/sw.js?a=1#x") ==
            ledger.correlation_key("https://xray.test/sw.js?a=1"), "canonical identity drifted")
    require(ledger.begin("https://xray.test/overflow", "GET", ()) is None and ledger.truncated,
            "bounded ledger did not disclose truncation")
    snapshot = ledger.snapshot()
    snapshot[0]["outcome"] = "forged"
    require(ledger.snapshot()[0]["outcome"] == "pending", "snapshot mutated trusted evidence")
    print("Verified real Chromium HTTPS CONNECT termination with temporary key-scoped trust, "
          "decrypted document/subresource and service-worker requests, private redirect denial, response-byte caps, "
          "content-free block receipts, Host/SNI pivot and request-body rejection, stalled-socket teardown, "
          "semantically validated HTTPS capture, bootstrap bytes, ledger overflow and response-cap partial records. Origin sockets were "
          "deterministic fixtures; container egress and production certificate issuance remain unproven.")


if __name__ == "__main__":
    main()
