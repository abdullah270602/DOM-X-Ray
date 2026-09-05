"""Single-scan HTTP egress proxy for deterministic redirect-policy fixtures.

The proxy maps approved reserved ``.test`` hosts to the loopback fixture server,
relays upstream response bytes unchanged, and validates every redirect target
before Chromium receives the ``Location`` header. It is proof infrastructure,
not the production public-network boundary.
"""

from __future__ import annotations

import socket
from contextlib import contextmanager
from socketserver import StreamRequestHandler, ThreadingTCPServer
from threading import Lock, Thread
from typing import Iterator
from urllib.parse import urljoin, urlsplit, urlunsplit

from scanner.browser_probe import _match_url, _redacted_url, request_block_reason


REDIRECT_LIMIT = 10
MAX_RESPONSE_BYTES = 25_000_000


class FixturePolicyProxy(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, upstream_port: int) -> None:
        super().__init__(("127.0.0.1", 0), FixturePolicyHandler)
        self.upstream_port = upstream_port
        self.ledger: list[dict[str, object]] = []
        self.blocked: list[dict[str, str]] = []
        self.document_chain: list[str] = []
        self.state_lock = Lock()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"

    def clear_state(self) -> None:
        with self.state_lock:
            self.ledger.clear()
            self.blocked.clear()
            self.document_chain.clear()

    def record_request(self, url: str, method: str, is_document: bool) -> None:
        with self.state_lock:
            self.ledger.append(
                {
                    "url": _redacted_url(url),
                    "method": method,
                    "document": is_document,
                }
            )
            if is_document:
                key = _match_url(url)
                if not self.document_chain:
                    self.document_chain.append(key)
                elif key != self.document_chain[-1]:
                    self.document_chain[:] = [key]

    def redirect_rejection(self, source_url: str, target_url: str, method: str, is_document: bool) -> str | None:
        reason = request_block_reason(method, target_url)
        parsed = urlsplit(target_url)
        if reason is None and (not parsed.hostname or not parsed.hostname.endswith(".test")):
            reason = "fixture-host"

        with self.state_lock:
            if reason is None and is_document:
                target_key = _match_url(target_url)
                if target_key in self.document_chain:
                    reason = "redirect-loop"
                elif len(self.document_chain) > REDIRECT_LIMIT:
                    reason = "redirect-limit"
                else:
                    self.document_chain.append(target_key)
            if reason is not None:
                self.blocked.append(
                    {
                        "url": _redacted_url(target_url),
                        "method": method,
                        "reason": reason,
                        "redirect": "true",
                        "sourceUrl": _redacted_url(source_url),
                    }
                )
        return reason


class FixturePolicyHandler(StreamRequestHandler):
    server: FixturePolicyProxy

    def _block(self) -> None:
        body = b"blocked by DOM X-Ray fixture policy"
        response = (
            b"HTTP/1.1 403 Forbidden\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Content-Type: text/plain; charset=utf-8\r\n"
            + b"Connection: close\r\n\r\n"
            + body
        )
        self.wfile.write(response)

    def handle(self) -> None:
        request_line = self.rfile.readline(8192)
        if not request_line:
            return
        try:
            method, target, version = request_line.decode("iso-8859-1").strip().split(" ", 2)
        except ValueError:
            self._block()
            return

        headers: list[tuple[str, str]] = []
        header_map: dict[str, str] = {}
        while True:
            line = self.rfile.readline(65536)
            if line in {b"\r\n", b"\n", b""}:
                break
            name, value = line.decode("iso-8859-1").split(":", 1)
            clean_value = value.strip()
            headers.append((name, clean_value))
            header_map[name.lower()] = clean_value

        if target.startswith(("http://", "https://")):
            url = target
        else:
            host = header_map.get("host", "")
            url = urlunsplit(("http", host, target, "", ""))
        parsed = urlsplit(url)
        is_document = (
            header_map.get("sec-fetch-dest", "").lower() == "document"
            or header_map.get("upgrade-insecure-requests") == "1"
        )
        self.server.record_request(url, method, is_document)

        reason = request_block_reason(method, url)
        if reason is None and (not parsed.hostname or not parsed.hostname.endswith(".test")):
            reason = "fixture-host"
        if reason is not None or parsed.scheme != "http" or parsed.port != self.server.upstream_port:
            with self.server.state_lock:
                self.server.blocked.append(
                    {
                        "url": _redacted_url(url),
                        "method": method,
                        "reason": reason or "fixture-port",
                        "redirect": "false",
                        "sourceUrl": _redacted_url(url),
                    }
                )
            self._block()
            return

        path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        forwarded_headers = [
            (name, value)
            for name, value in headers
            if name.lower() not in {"connection", "host", "proxy-connection"}
        ]
        outbound = f"{method} {path} {version}\r\n".encode("iso-8859-1")
        outbound += f"Host: {parsed.netloc}\r\n".encode("iso-8859-1")
        outbound += b"".join(
            f"{name}: {value}\r\n".encode("iso-8859-1")
            for name, value in forwarded_headers
        )
        outbound += b"Connection: close\r\n\r\n"

        with socket.create_connection(("127.0.0.1", self.server.upstream_port), timeout=5) as upstream:
            upstream.sendall(outbound)
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    self._block()
                    return
                chunks.append(chunk)
        response = b"".join(chunks)

        head, separator, _body = response.partition(b"\r\n\r\n")
        if not separator:
            self._block()
            return
        lines = head.decode("iso-8859-1").split("\r\n")
        try:
            status = int(lines[0].split(" ", 2)[1])
        except (IndexError, ValueError):
            self._block()
            return
        response_headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            response_headers[name.lower()] = value.strip()

        location = response_headers.get("location")
        if 300 <= status < 400 and location:
            target_url = urljoin(url, location)
            if self.server.redirect_rejection(url, target_url, method, is_document) is not None:
                self._block()
                return

        self.wfile.write(response)


@contextmanager
def run_policy_proxy(upstream_port: int) -> Iterator[FixturePolicyProxy]:
    proxy = FixturePolicyProxy(upstream_port)
    thread = Thread(target=proxy.serve_forever, name="dom-xray-policy-proxy", daemon=True)
    thread.start()
    try:
        yield proxy
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=5)
