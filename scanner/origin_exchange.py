"""Bounded anonymous HTTP exchange behind a future browser egress proxy.

Responses are buffered and validated before release. This module neither
listens for browser connections nor terminates browser TLS or contains Chromium.
"""

from __future__ import annotations

import http.client
import io
import math
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from threading import Lock
from urllib.parse import urljoin, urlsplit, urlunsplit

from scanner.destination_policy import DestinationPolicy, DestinationPolicyError, DestinationPurpose
from scanner.pinned_connector import connect_pinned
from scanner.scan_transport import PublicScanGrant, check_public_scan_grant, public_scan_target_matches

_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_FORWARD_REQUEST = frozenset({
    "accept", "accept-encoding", "accept-language", "cache-control", "range",
    "if-modified-since", "if-none-match", "sec-fetch-dest", "sec-fetch-mode",
    "sec-fetch-site", "sec-fetch-user",
})
_HOP_HEADERS = frozenset({
    "connection", "proxy-connection", "keep-alive", "transfer-encoding",
    "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization",
})


class OriginExchangeError(RuntimeError):
    """Allowlisted failure category with no target or provider text."""

    def __init__(self, reason: str, *, upstream_bytes_read: int = 0):
        super().__init__(reason)
        self.upstream_bytes_read = upstream_bytes_read


@dataclass(frozen=True)
class EgressLimits:
    max_requests: int = 500
    max_response_bytes: int = 20_000_000
    max_total_received_bytes: int = 50_000_000

    def __post_init__(self):
        for value, ceiling in (
            (self.max_requests, 500), (self.max_response_bytes, 20_000_000),
            (self.max_total_received_bytes, 50_000_000),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= ceiling:
                raise ValueError("invalid egress limit")


@dataclass(frozen=True, repr=False)
class OriginResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    upstream_wire_bytes: int

    def __repr__(self):
        return f"OriginResponse(status={self.status}, upstream_wire_bytes={self.upstream_wire_bytes})"


def _header(name: str, value: str) -> tuple[str, str]:
    if (not isinstance(name, str) or not _TOKEN.fullmatch(name)
            or not isinstance(value, str)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise OriginExchangeError("invalid-headers")
    try:
        value.encode("iso-8859-1")
    except UnicodeEncodeError:
        raise OriginExchangeError("invalid-headers") from None
    return name.lower(), value


class _MemorySocket:
    def __init__(self, payload):
        class ReadBuffer(io.BytesIO):
            def close(self):
                # HTTPResponse closes its input after reading. Keep the offset
                # inspectable to reject bytes beyond the one framed message.
                pass
        self.stream = ReadBuffer(payload)

    def makefile(self, _mode):
        return self.stream


def _decode_response(payload: bytes, method: str) -> OriginResponse:
    head, separator, wire_body = payload.partition(b"\r\n\r\n")
    if not separator or len(head) > 65_536:
        raise OriginExchangeError("invalid-response")
    lines = head.split(b"\r\n")
    if not re.fullmatch(rb"HTTP/1\.[01] [2-5][0-9]{2}(?: [\x20-\x7e]*)?", lines[0]):
        raise OriginExchangeError("invalid-response")
    if len(lines) > 101:
        raise OriginExchangeError("invalid-response")
    headers = []
    try:
        for line in lines[1:]:
            name, value = line.decode("iso-8859-1").split(":", 1)
            headers.append(_header(name, value.strip(" ")))
    except (ValueError, OriginExchangeError):
        raise OriginExchangeError("invalid-response") from None
    lengths = [value for name, value in headers if name == "content-length"]
    encodings = [value.lower() for name, value in headers if name == "transfer-encoding"]
    locations = [value for name, value in headers if name == "location"]
    if (len(lengths) > 1 or len(encodings) > 1 or len(locations) > 1
            or (lengths and encodings)
            or (lengths and not re.fullmatch(r"[0-9]{1,10}", lengths[0]))
            or (encodings and encodings != ["chunked"])):
        raise OriginExchangeError("invalid-response")
    nominated = set()
    for name, value in headers:
        if name == "connection":
            for token in value.lower().split(","):
                token = token.strip()
                if not _TOKEN.fullmatch(token):
                    raise OriginExchangeError("invalid-response")
                nominated.add(token)
    # Do not let hop-by-hop nomination hide redirect or framing semantics.
    if nominated & {"location", "content-length", "content-encoding"}:
        raise OriginExchangeError("invalid-response")
    memory = _MemorySocket(payload)
    response = http.client.HTTPResponse(memory, method=method)
    try:
        response.begin()
        body = response.read()
        if memory.stream.tell() != len(payload):
            raise OriginExchangeError("invalid-response")
        if method == "HEAD" or response.status in {204, 304}:
            if wire_body:
                raise OriginExchangeError("invalid-response")
        elif lengths and len(wire_body) != int(lengths[0]):
            raise OriginExchangeError("invalid-response")
        # Decoded chunked bodies are reconstructed below. Trailer fields never
        # enter the browser-facing headers, including reserved block markers.
        filtered = tuple((name, value) for name, value in headers
                         if name not in _HOP_HEADERS | nominated | {"content-length", "set-cookie", "x-dom-x-ray-block-id"})
        if method == "HEAD" or response.status == 304:
            if lengths:
                filtered += (("content-length", lengths[0]),)
        elif response.status != 204:
            filtered += (("content-length", str(len(body))),)
        return OriginResponse(response.status, filtered, body, len(payload))
    except (http.client.HTTPException, ValueError, OSError):
        raise OriginExchangeError("invalid-response") from None
    finally:
        response.close()


class OriginExchange:
    """One scan's serialized request and wire-byte budget.

    Resolver/connector injection is trusted deployment configuration. No grant
    is cached. An optional initial launch grant is consumed once by the exact
    initial GET. Every subsequent request and redirect independently validates DNS.
    A production resolver must be bounded outside this layer as well.
    """

    def __init__(self, policy: DestinationPolicy, *, user_agent: str,
                 limits: EgressLimits = EgressLimits(), connector: Callable = connect_pinned,
                 initial_grant: PublicScanGrant | None = None):
        _header("user-agent", user_agent)
        if not user_agent or len(user_agent) > 512:
            raise ValueError("invalid scanner identity")
        if not isinstance(policy, DestinationPolicy) or not isinstance(limits, EgressLimits):
            raise ValueError("invalid origin exchange configuration")
        self._policy = policy
        self._user_agent = user_agent
        self._limits = limits
        self._connector = connector
        if initial_grant is not None:
            check_public_scan_grant(initial_grant)
        self._initial_grant = initial_grant
        self._initial_consumed = False
        self._lock = Lock()
        self._requests = 0
        self._received = 0

    @property
    def destination_policy(self):
        return self._policy

    @property
    def initial_grant(self):
        return self._initial_grant

    @property
    def initial_grant_consumed(self):
        with self._lock:
            return self._initial_consumed

    def validate_initial_target(self, url):
        """Proxy setup must bind to the launch target without re-resolving it."""
        url = self._policy.canonical_url(url, purpose="initial")
        if self._initial_grant is None:
            return self._policy.validate(url, purpose="initial")
        if not public_scan_target_matches(url, self._initial_grant):
            raise ValueError("initial-grant-target-mismatch")
        return self._initial_grant.destination

    def request_purpose(self, url, initial_url):
        url = self._policy.canonical_url(url, purpose="subresource")
        initial_url = self._policy.canonical_url(initial_url, purpose="initial")
        if self._initial_grant is not None:
            return "initial" if public_scan_target_matches(url, self._initial_grant) else "subresource"
        return "initial" if url == initial_url else "subresource"

    def validate_browser_tunnel(self, url):
        """CONNECT checks authority only; it neither connects nor consumes a grant.

        Pending initial authority uses supplied answers for syntax/policy checks.
        No origin request borrows this result; fetch owns one-shot pinning.
        """
        url = self._policy.canonical_url(url, purpose="subresource")
        with self._lock:
            initial = self._initial_grant if not self._initial_consumed else None
        if initial is not None:
            candidate = DestinationPolicy(lambda _host, _port: initial.destination.addresses).validate(
                url, purpose="subresource")
            target = initial.destination
            if (candidate.scheme, candidate.hostname, candidate.port) == (target.scheme, target.hostname, target.port):
                return candidate
        return self._policy.validate(url, purpose="subresource")

    def fetch(self, url: str, *, method: str = "GET", purpose: DestinationPurpose,
              headers: Sequence[tuple[str, str]] = (), timeout_seconds: float = 10) -> OriginResponse:
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise OriginExchangeError("method")
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (float, int))
                or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 15):
            raise ValueError("invalid exchange timeout")
        if len(headers) > 100:
            raise OriginExchangeError("invalid-headers")
        forwarded = []
        nominated = set()
        checked_headers = []
        for pair in headers:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise OriginExchangeError("invalid-headers")
            name, value = _header(*pair)
            checked_headers.append((name, value))
            if name == "connection":
                for token in value.lower().split(","):
                    token = token.strip()
                    if not _TOKEN.fullmatch(token):
                        raise OriginExchangeError("invalid-headers")
                    nominated.add(token)
        for name, value in checked_headers:
            if name in _FORWARD_REQUEST and name not in nominated:
                if any(existing == name for existing, _ in forwarded):
                    raise OriginExchangeError("invalid-headers")
                forwarded.append((name, value))
        deadline = time.monotonic() + timeout_seconds

        def remaining():
            value = deadline - time.monotonic()
            if value <= 0:
                raise OriginExchangeError("timeout")
            return value

        if not self._lock.acquire(timeout=remaining()):
            raise OriginExchangeError("timeout")
        received_before = self._received
        try:
            # Match the fixture's inclusive request-limit fence: the triggering
            # request is observed but never contacts the origin.
            self._requests += 1
            if self._requests >= self._limits.max_requests:
                raise OriginExchangeError("request-limit")
            available = self._limits.max_total_received_bytes - self._received
            if available <= 0:
                raise OriginExchangeError("total-byte-limit")
            url = self._policy.canonical_url(url, purpose=purpose)
            remaining()  # Parser work cannot authorize connector contact after expiry.
            if self._initial_grant is not None and purpose == "initial":
                if not public_scan_target_matches(url, self._initial_grant):
                    raise OriginExchangeError("destination-policy")
                if not self._initial_consumed:
                    if method != "GET":
                        raise OriginExchangeError("method")
                    # Consume before connector contact, including failed contact.
                    # Never retry this grant or fall back to a new DNS answer.
                    self._initial_consumed = True
                    grant = self._initial_grant.destination
                else:
                    grant = self._policy.validate(url, purpose=purpose)
            else:
                grant = self._policy.validate(url, purpose=purpose)
            parsed = urlsplit(url)
            path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            if any(ord(character) <= 32 or ord(character) >= 127 for character in path):
                raise OriginExchangeError("invalid-request-target")
            host = f"[{grant.hostname}]" if ":" in grant.hostname else grant.hostname
            default_port = 443 if grant.scheme == "https" else 80
            authority = host if grant.port == default_port else f"{host}:{grant.port}"
            request = (f"{method} {path} HTTP/1.1\r\nHost: {authority}\r\n"
                       f"User-Agent: {self._user_agent}\r\n"
                       + "".join(f"{name}: {value}\r\n" for name, value in forwarded)
                       + "Connection: close\r\n\r\n").encode("iso-8859-1")
            if len(request) > 65_536:
                raise OriginExchangeError("invalid-headers")
            ceiling = min(available, self._limits.max_response_bytes)
            connection = self._connector(grant, timeout_seconds=remaining())
            chunks = []
            size = 0
            try:
                connection.settimeout(remaining())
                connection.sendall(request)
                while size <= ceiling:
                    connection.settimeout(remaining())
                    chunk = connection.recv(min(65_536, ceiling + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    self._received += len(chunk)
                    chunks.append(chunk)
                if size > ceiling:
                    raise OriginExchangeError("response-byte-limit" if ceiling == self._limits.max_response_bytes
                                              else "total-byte-limit")
            finally:
                connection.close()
            result = _decode_response(b"".join(chunks), method)
            location = next((value for name, value in result.headers if name == "location"), None)
            if 300 <= result.status < 400 and location is not None:
                self._policy.validate(urljoin(url, location), purpose="redirect")
            remaining()
            return result
        except DestinationPolicyError:
            raise OriginExchangeError("destination-policy", upstream_bytes_read=self._received - received_before) from None
        except TimeoutError:
            raise OriginExchangeError("timeout", upstream_bytes_read=self._received - received_before) from None
        except OriginExchangeError as error:
            raise OriginExchangeError(str(error), upstream_bytes_read=self._received - received_before) from None
        except (OSError, http.client.HTTPException):
            raise OriginExchangeError("upstream-failed", upstream_bytes_read=self._received - received_before) from None
        finally:
            self._lock.release()


__all__ = ["EgressLimits", "OriginExchange", "OriginExchangeError", "OriginResponse"]
