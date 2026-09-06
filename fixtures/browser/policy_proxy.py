"""Single-scan HTTP egress proxy for deterministic redirect-policy fixtures.

The proxy maps approved reserved ``.test`` hosts to the loopback fixture server,
relays admitted upstream response bytes after removing its reserved marker header,
and validates every redirect target before Chromium receives the ``Location``
header. It is proof infrastructure, not the production public-network boundary.
"""

from __future__ import annotations

import secrets
import socket
from contextlib import contextmanager
from socketserver import StreamRequestHandler, ThreadingTCPServer
from threading import Lock, Thread
from typing import Iterator
from urllib.parse import urljoin, urlsplit, urlunsplit

from scanner.browser_probe import (
    MAX_REQUESTS,
    MAX_RESPONSE_BYTES,
    MAX_TOTAL_RECEIVED_BYTES,
    SCANNER_USER_AGENT,
    SENSITIVE_OUTBOUND_HEADERS,
    _match_url,
    _redacted_url,
    request_block_reason,
)


REDIRECT_LIMIT = 10
LIMIT_REASONS = frozenset(
    {"request-limit", "response-byte-limit", "total-byte-limit"}
)


def _block_response(block_id: str, reason: str) -> bytes:
    is_limit = reason in LIMIT_REASONS
    body = (
        b"stopped by DOM X-Ray fixture resource boundary"
        if is_limit
        else b"blocked by DOM X-Ray fixture policy"
    )
    status_line = (
        b"HTTP/1.1 509 Bandwidth Limit Exceeded\r\n"
        if is_limit
        else b"HTTP/1.1 403 Forbidden\r\n"
    )
    return (
        status_line
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"X-DOM-X-Ray-Block-Id: {block_id}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + body
    )


UNTRACKED_BLOCK_RESPONSE = _block_response("untracked", "policy")


class FixturePolicyProxy(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, upstream_port: int) -> None:
        super().__init__(("127.0.0.1", 0), FixturePolicyHandler)
        self.upstream_port = upstream_port
        self.ledger: list[dict[str, object]] = []
        self.blocked: list[dict[str, object]] = []
        self.document_chain: list[str] = []
        self.state_lock = Lock()
        self.response_budget_lock = Lock()
        self.max_requests = MAX_REQUESTS
        self.max_response_bytes = MAX_RESPONSE_BYTES
        self.max_total_received_bytes = MAX_TOTAL_RECEIVED_BYTES
        self.observed_allowed_requests = 0
        self.relayed_upstream_bytes = 0
        self.relayed_browser_bytes = 0
        self.allow_trusted_loopback = False

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"

    def clear_state(self) -> None:
        with self.state_lock:
            self.ledger.clear()
            self.blocked.clear()
            self.document_chain.clear()
            self.observed_allowed_requests = 0
            self.relayed_upstream_bytes = 0
            self.relayed_browser_bytes = 0
            self.allow_trusted_loopback = False

    def configure_limits(
        self,
        *,
        max_requests: int = MAX_REQUESTS,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        max_total_received_bytes: int = MAX_TOTAL_RECEIVED_BYTES,
        allow_trusted_loopback: bool = False,
    ) -> None:
        for name, value, ceiling in (
            ("max_requests", max_requests, MAX_REQUESTS),
            ("max_response_bytes", max_response_bytes, MAX_RESPONSE_BYTES),
            (
                "max_total_received_bytes",
                max_total_received_bytes,
                MAX_TOTAL_RECEIVED_BYTES,
            ),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
            if value > ceiling:
                raise ValueError(f"{name} cannot exceed its hard ceiling of {ceiling}")
        with self.state_lock:
            if self.ledger or self.blocked:
                raise RuntimeError("network limits can only change between captures")
            self.max_requests = max_requests
            self.max_response_bytes = max_response_bytes
            self.max_total_received_bytes = max_total_received_bytes
            self.observed_allowed_requests = 0
            self.relayed_upstream_bytes = 0
            self.relayed_browser_bytes = 0
            self.allow_trusted_loopback = allow_trusted_loopback

    def request_limit_reached(self) -> bool:
        with self.state_lock:
            self.observed_allowed_requests += 1
            return self.observed_allowed_requests >= self.max_requests

    def is_trusted_loopback_url(self, url: str) -> bool:
        parsed = urlsplit(url)
        return (
            self.allow_trusted_loopback
            and parsed.scheme == "http"
            and parsed.hostname == "localhost"
            and parsed.port == self.upstream_port
        )

    def block_reason_for(self, method: str, url: str) -> str | None:
        reason = request_block_reason(method, url)
        if reason == "private-literal-host" and self.is_trusted_loopback_url(url):
            return None
        return reason

    def record_block(
        self,
        *,
        url: str,
        method: str,
        reason: str,
        upstream_bytes_read: int = 0,
        is_redirect: bool = False,
        source_url: str | None = None,
    ) -> bytes:
        with self.state_lock:
            existing_ids = {
                str(item["blockId"])
                for item in self.blocked
                if item.get("blockId") is not None
            }
            block_id = secrets.token_hex(16)
            while block_id in existing_ids:
                block_id = secrets.token_hex(16)
            response = _block_response(block_id, reason)
            self.blocked.append(
                {
                    "blockId": block_id,
                    "url": _redacted_url(url),
                    "method": method,
                    "reason": reason,
                    "redirect": "true" if is_redirect else "false",
                    "sourceUrl": _redacted_url(source_url or url),
                    "wireBytes": len(response),
                    "upstreamBytesRead": upstream_bytes_read,
                }
            )
        return response

    def record_request(
        self,
        url: str,
        method: str,
        is_document: bool,
        incoming_sensitive_headers: tuple[str, ...],
    ) -> None:
        with self.state_lock:
            self.ledger.append(
                {
                    "url": _redacted_url(url),
                    "method": method,
                    "document": is_document,
                    "incomingSensitiveHeaders": incoming_sensitive_headers,
                }
            )
            if is_document:
                key = _match_url(url)
                if not self.document_chain:
                    self.document_chain.append(key)
                elif key != self.document_chain[-1]:
                    self.document_chain[:] = [key]

    def redirect_rejection(
        self,
        source_url: str,
        target_url: str,
        method: str,
        is_document: bool,
    ) -> tuple[str | None, bytes | None]:
        reason = self.block_reason_for(method, target_url)
        parsed = urlsplit(target_url)
        if reason is None and not (
            parsed.hostname
            and (
                parsed.hostname.endswith(".test")
                or self.is_trusted_loopback_url(target_url)
            )
        ):
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
        if reason is None:
            return None, None
        response = self.record_block(
            url=target_url,
            method=method,
            reason=reason,
            is_redirect=True,
            source_url=source_url,
        )
        return reason, response


class FixturePolicyHandler(StreamRequestHandler):
    server: FixturePolicyProxy

    def _block(self, response: bytes = UNTRACKED_BLOCK_RESPONSE) -> None:
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
        incoming_sensitive_headers = tuple(
            sorted(
                name.lower()
                for name, _value in headers
                if name.lower() in SENSITIVE_OUTBOUND_HEADERS
            )
        )
        self.server.record_request(
            url,
            method,
            is_document,
            incoming_sensitive_headers,
        )

        reason = self.server.block_reason_for(method, url)
        if reason is None and not (
            parsed.hostname
            and (
                parsed.hostname.endswith(".test")
                or self.server.is_trusted_loopback_url(url)
            )
        ):
            reason = "fixture-host"
        if reason is not None or parsed.scheme != "http" or parsed.port != self.server.upstream_port:
            block_response = self.server.record_block(
                url=url,
                method=method,
                reason=reason or "fixture-port",
            )
            self._block(block_response)
            return

        if self.server.request_limit_reached():
            block_response = self.server.record_block(
                url=url,
                method=method,
                reason="request-limit",
            )
            self._block(block_response)
            return

        path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        forwarded_headers = [
            (name, value)
            for name, value in headers
            if name.lower()
            not in {
                "connection",
                "host",
                "proxy-connection",
                "user-agent",
                *SENSITIVE_OUTBOUND_HEADERS,
            }
        ]
        outbound = f"{method} {path} {version}\r\n".encode("iso-8859-1")
        outbound += f"Host: {parsed.netloc}\r\n".encode("iso-8859-1")
        outbound += f"User-Agent: {SCANNER_USER_AGENT}\r\n".encode("ascii")
        outbound += b"".join(
            f"{name}: {value}\r\n".encode("iso-8859-1")
            for name, value in forwarded_headers
        )
        outbound += b"Connection: close\r\n\r\n"

        with self.server.response_budget_lock:
            remaining_total = (
                self.server.max_total_received_bytes
                - self.server.relayed_upstream_bytes
            )
            if remaining_total <= 0:
                block_response = self.server.record_block(
                    url=url,
                    method=method,
                    reason="total-byte-limit",
                )
                self._block(block_response)
                return

            read_ceiling = min(self.server.max_response_bytes, remaining_total)
            with socket.create_connection(
                ("127.0.0.1", self.server.upstream_port), timeout=5
            ) as upstream:
                upstream.sendall(outbound)
                chunks: list[bytes] = []
                size = 0
                while True:
                    remaining_read = read_ceiling + 1 - size
                    if remaining_read <= 0:
                        break
                    chunk = upstream.recv(min(65536, remaining_read))
                    if not chunk:
                        break
                    size += len(chunk)
                    chunks.append(chunk)

            if size > read_ceiling:
                reason = (
                    "response-byte-limit"
                    if self.server.max_response_bytes <= remaining_total
                    else "total-byte-limit"
                )
                block_response = self.server.record_block(
                    url=url,
                    method=method,
                    reason=reason,
                    upstream_bytes_read=size,
                )
                self._block(block_response)
                return

            response = b"".join(chunks)
            self.server.relayed_upstream_bytes += len(response)

        head, separator, body = response.partition(b"\r\n\r\n")
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
        forwarded_response_lines = [lines[0]]
        for line in lines[1:]:
            if ":" not in line:
                forwarded_response_lines.append(line)
                continue
            name, value = line.split(":", 1)
            if name.strip().lower() == "x-dom-x-ray-block-id":
                continue
            forwarded_response_lines.append(line)
            response_headers[name.lower()] = value.strip()
        response = (
            "\r\n".join(forwarded_response_lines).encode("iso-8859-1")
            + separator
            + body
        )

        location = response_headers.get("location")
        if 300 <= status < 400 and location:
            target_url = urljoin(url, location)
            rejection_reason, block_response = self.server.redirect_rejection(
                url, target_url, method, is_document
            )
            if rejection_reason is not None:
                if block_response is None:
                    raise RuntimeError("redirect rejection lacks its block response")
                self._block(block_response)
                return

        with self.server.state_lock:
            self.server.relayed_browser_bytes += len(response)
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
