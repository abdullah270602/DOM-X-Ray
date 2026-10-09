"""Single-scan browser proxy with explicit browser TLS termination.

Certificate issuance and isolated browser trust are deployment dependencies.
Origin HTTPS verification is always owned by the pinned origin connector.
This listener is not an independent network containment boundary.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import socket
import ssl
import time
from collections.abc import Callable
from contextlib import contextmanager
from socketserver import BaseRequestHandler, ThreadingTCPServer
from threading import Condition, Lock, Semaphore, Thread, current_thread
from urllib.parse import urlsplit

from scanner.destination_policy import DestinationPolicy
from scanner.egress_ledger import EgressLedger, redacted_url
from scanner.origin_exchange import OriginExchange, OriginExchangeError

_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def _head(connection, deadline):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or len(data) >= 65_536:
            raise ValueError("invalid request")
        connection.settimeout(remaining)
        byte = connection.recv(1)
        if not byte:
            raise ValueError("incomplete request")
        data.extend(byte)
    lines = bytes(data[:-4]).decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[2] != "HTTP/1.1" or len(lines) > 101:
        raise ValueError("invalid request")
    headers = []
    for line in lines[1:]:
        name, value = line.split(":", 1)
        value = value.strip(" ")
        if not _TOKEN.fullmatch(name) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("invalid header")
        headers.append((name.lower(), value))
    return parts[0], parts[1], tuple(headers)


def _bodyless(headers):
    lengths = [value for name, value in headers if name == "content-length"]
    if (len(lengths) > 1 or (lengths and lengths != ["0"])
            or any(name in {"transfer-encoding", "expect", "upgrade"} for name, _ in headers)):
        raise ValueError("unsupported request body")


def _authority(value, scheme):
    parsed = urlsplit(f"{scheme}://{value}/")
    if (not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.path != "/" or parsed.query or parsed.fragment
            or any(ord(c) <= 32 or ord(c) >= 127 for c in value)
            or any(character in value for character in "\\?#")):
        raise ValueError("invalid authority")
    return parsed.hostname.lower(), parsed.port or (443 if scheme == "https" else 80)


class BrowserEgressProxy(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *, initial_url: str, policy: DestinationPolicy,
                 exchange: OriginExchange, tls_context: Callable[[str], ssl.SSLContext],
                 ledger_limit: int = 1_000):
        if not isinstance(exchange, OriginExchange) or policy is not exchange.destination_policy:
            raise ValueError("proxy-policy-mismatch")
        exchange.validate_initial_target(initial_url)
        self.policy = policy
        self.exchange = exchange
        self.tls_context = tls_context
        self.initial_url = initial_url
        self.ledger = EgressLedger(ledger_limit)
        self.blocked = self.ledger.blocked
        self._slots = Semaphore(16)
        self._events_lock = Lock()
        self._events = []
        self.events_truncated = False
        self._active = set()
        self._handlers = set()
        self._activity = Condition()
        super().__init__(("127.0.0.1", 0), _Handler)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            request.close()
            return
        with self._activity:
            self._active.add(request)
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._activity:
                self._active.discard(request)
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        with self._activity:
            self._handlers.add(current_thread())
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._activity:
                self._active.discard(request)
                self._handlers.discard(current_thread())
                self._activity.notify_all()
            self._slots.release()

    def replace_connection(self, original, replacement):
        with self._activity:
            self._active.discard(original)
            self._active.add(replacement)

    def forget_connection(self, connection):
        with self._activity:
            self._active.discard(connection)

    def close_handlers(self):
        # Accept loop must already be stopped. Close browser sockets to unblock
        # header/TLS reads, then require bounded handler termination. A blocked
        # trusted resolver/issuer still needs disposable-worker destruction.
        deadline = time.monotonic() + 5
        with self._activity:
            for connection in tuple(self._active):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
            while self._handlers or self._active:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("proxy handlers did not terminate")
                self._activity.wait(remaining)

    def handle_error(self, request, client_address):
        # Framework tracebacks may contain request/provider material.
        pass

    def snapshot_events(self):
        with self._events_lock:
            return tuple(dict(event) for event in self._events)

    def snapshot_observations(self):
        return self.ledger.snapshot()

    def correlation_key(self, url):
        return self.ledger.correlation_key(url)

    def event(self, **event):
        with self._events_lock:
            if len(self._events) < 1_000:
                self._events.append(event)
            else:
                self.events_truncated = True


class _Handler(BaseRequestHandler):
    def handle(self):
        connection = self.request
        deadline = time.monotonic() + 15
        observation = None
        try:
            method, target, headers = _head(connection, deadline)
            _bodyless(headers)
            tunnel = None
            if method == "CONNECT":
                host, port = _authority(target, "https")
                grant = self.server.exchange.validate_browser_tunnel(f"https://{target}/")
                if (host, port) != (grant.hostname, grant.port):
                    raise ValueError("authority drift")
                hosts = [value for name, value in headers if name == "host"]
                if len(hosts) != 1 or _authority(hosts[0], "https") != (host, port):
                    raise ValueError("tunnel Host drift")
                context = self.server.tls_context(host)
                if not isinstance(context, ssl.SSLContext) or context.protocol != ssl.PROTOCOL_TLS_SERVER:
                    raise ValueError("invalid browser TLS context")
                # The factory must supply a fresh context with a host-bound leaf.
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.set_alpn_protocols(["http/1.1"])
                def sni_check(_socket, server_name, _context):
                    try:
                        literal = ipaddress.ip_address(host)
                    except ValueError:
                        literal = None
                    if server_name != host and not (server_name is None and literal is not None):
                        return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
                    return None
                context.set_servername_callback(sni_check)
                connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                connection.settimeout(max(0.001, deadline - time.monotonic()))
                original = connection
                connection = context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
                self.server.replace_connection(original, connection)
                connection.do_handshake()
                if connection.selected_alpn_protocol() not in {None, "http/1.1"}:
                    raise ValueError("unsupported browser protocol")
                tunnel = (host, port)
                method, target, headers = _head(connection, deadline)
                _bodyless(headers)
            hosts = [value for name, value in headers if name == "host"]
            if len(hosts) != 1:
                raise ValueError("invalid Host")
            if tunnel is not None:
                if not target.startswith("/") or _authority(hosts[0], "https") != tunnel:
                    raise ValueError("decrypted authority drift")
                url = f"https://{hosts[0]}{target}"
            else:
                parsed = urlsplit(target)
                if parsed.scheme != "http" or _authority(hosts[0], "http") != _authority(parsed.netloc, "http"):
                    raise ValueError("absolute request authority drift")
                url = target
            observation = self.server.ledger.begin(url, method, headers)
            if observation is None:
                observation = {"url": redacted_url(url), "method": method}
                raise OriginExchangeError("egress-ledger-limit")
            if method not in {"GET", "HEAD", "OPTIONS"}:
                raise OriginExchangeError("method")
            purpose = self.server.exchange.request_purpose(url, self.server.initial_url)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OriginExchangeError("timeout")
            result = self.server.exchange.fetch(url, method=method,
                purpose=purpose,
                headers=headers, timeout_seconds=remaining)
            response = f"HTTP/1.1 {result.status} Origin Response\r\n".encode("ascii")
            response += b"".join(f"{name}: {value}\r\n".encode("iso-8859-1") for name, value in result.headers)
            response += b"Connection: close\r\n\r\n" + result.body
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                connection.sendall(response)
            except OSError:
                self.server.ledger.finish(observation, outcome="client-write-failed",
                    responseStatus=result.status, upstreamBytesRead=result.upstream_wire_bytes,
                    upstreamWireBytes=result.upstream_wire_bytes)
                self.server.event(outcome="client-write-failed", status=result.status,
                    upstreamBytesRead=result.upstream_wire_bytes, browserWireBytes=None)
                return
            self.server.ledger.finish(observation, outcome="relayed", responseStatus=result.status,
                upstreamBytesRead=result.upstream_wire_bytes, upstreamWireBytes=result.upstream_wire_bytes,
                browserWireBytes=len(response))
            self.server.event(outcome="relayed", status=result.status, upstreamBytesRead=result.upstream_wire_bytes,
                              browserWireBytes=len(response), tls=tunnel is not None)
        except (OriginExchangeError, ValueError, OSError) as error:
            block_id = secrets.token_hex(16)
            # No request URL/header or provider text enters this event or body.
            reason = str(error) if isinstance(error, OriginExchangeError) else "invalid-browser-request"
            limit = reason in {"request-limit", "response-byte-limit", "total-byte-limit", "egress-ledger-limit"}
            status = 509 if limit else 403
            response = (f"HTTP/1.1 {status} Scan Blocked\r\nContent-Length: 0\r\n"
                        f"X-DOM-X-Ray-Block-Id: {block_id}\r\nConnection: close\r\n\r\n").encode("ascii")
            self.server.ledger.block(observation, block_id=block_id, reason=reason, status=status,
                wire_bytes=len(response), upstream_bytes=getattr(error, "upstream_bytes_read", 0))
            try:
                connection.sendall(response)
                self.server.ledger.finish(observation, browserWireBytes=len(response))
            except OSError:
                pass
            self.server.event(outcome="blocked", status=status, blockId=block_id, reason=reason,
                              upstreamBytesRead=getattr(error, "upstream_bytes_read", 0))
        finally:
            connection.close()
            self.server.forget_connection(connection)


@contextmanager
def run_browser_egress_proxy(**configuration):
    proxy = BrowserEgressProxy(**configuration)
    thread = Thread(target=proxy.serve_forever, kwargs={'poll_interval': 0.05},
                    name="dom-xray-browser-proxy", daemon=True)
    thread.start()
    try:
        yield proxy
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=5)
        proxy.close_handlers()


__all__ = ["BrowserEgressProxy", "run_browser_egress_proxy"]
