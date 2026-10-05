"""TCP/TLS connection establishment using only a validated address grant.

This is an origin connector for a future enforcing proxy, not a browser proxy
or deployment firewall. The caller owns the returned socket and must enforce
HTTP method/header/byte limits and a lifetime deadline on subsequent I/O.
"""

from __future__ import annotations

import ipaddress
import math
import socket
import ssl
import time

from scanner.destination_policy import DestinationPolicy, ValidatedDestination


class PinnedConnectionError(ConnectionError):
    """Content-free connection failure; no address or TLS provider text escapes."""


def _checked_grant(grant: ValidatedDestination) -> None:
    # Dataclasses can be constructed directly. Recheck the complete grant before
    # even creating a socket, using the supplied answers without resolving DNS.
    if not isinstance(grant, ValidatedDestination) or not isinstance(grant.addresses, tuple):
        raise PinnedConnectionError("invalid-destination-grant")
    try:
        host = f"[{grant.hostname}]" if ":" in grant.hostname else grant.hostname
        checked = DestinationPolicy(lambda _host, _port: grant.addresses).validate(
            f"{grant.scheme}://{host}:{grant.port}/", purpose=grant.purpose,
        )
        if checked != grant:
            raise ValueError("noncanonical grant")
    except (TypeError, ValueError):
        raise PinnedConnectionError("invalid-destination-grant") from None


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise PinnedConnectionError("connection-timeout")
    return remaining


def _check_peer(connection: socket.socket, address: str, port: int) -> None:
    try:
        peer = connection.getpeername()
        matches = ipaddress.ip_address(peer[0]) == ipaddress.ip_address(address) and peer[1] == port
    except (IndexError, TypeError, ValueError):
        matches = False
    if not matches:
        raise PinnedConnectionError("connection-peer-mismatch")


def connect_pinned(
    grant: ValidatedDestination,
    *,
    timeout_seconds: float = 5.0,
) -> socket.socket:
    """Open one TCP/TLS connection, with a total connect/handshake budget.

    No hostname socket helper, DNS lookup, environment proxy, redirect, or
    unapproved address fallback is used. TCP failures may try the remaining
    approved addresses. TLS/authentication failures terminate the call.
    HTTPS preserves the hostname for SNI and certificate validation. Only
    HTTP/1.1 is offered, for the future proxy's HTTP parser.
    """
    _checked_grant(grant)
    if (isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 15):
        raise ValueError("connection timeout must be positive and at most 15 seconds")
    deadline = time.monotonic() + timeout_seconds
    context = None
    if grant.scheme == "https":
        try:
            # Construct directly so SSLKEYLOGFILE cannot enable key logging.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_default_certs(ssl.Purpose.SERVER_AUTH)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(["http/1.1"])
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError("unauthenticated TLS context")
        except (OSError, ValueError):
            raise PinnedConnectionError("tls-configuration-failed") from None

    for address in grant.addresses:
        connection = None
        family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
        endpoint = (address, grant.port, 0, 0) if family == socket.AF_INET6 else (address, grant.port)
        try:
            remaining = _remaining(deadline)
            connection = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            connection.settimeout(remaining)
            connection.connect(endpoint)
            _check_peer(connection, address, grant.port)
        except PinnedConnectionError:
            if connection is not None:
                connection.close()
            raise
        except OSError:
            if connection is not None:
                connection.close()
            continue
        try:
            if context is not None:
                connection.settimeout(_remaining(deadline))
                connection = context.wrap_socket(
                    connection, server_hostname=grant.hostname,
                    do_handshake_on_connect=False,
                )
                connection.settimeout(_remaining(deadline))
                connection.do_handshake()
                _check_peer(connection, address, grant.port)
                if connection.selected_alpn_protocol() not in {None, "http/1.1"}:
                    raise PinnedConnectionError("unsupported-negotiated-protocol")
            connection.settimeout(_remaining(deadline))
            return connection
        except PinnedConnectionError:
            connection.close()
            raise
        except (OSError, ValueError):
            connection.close()
            raise PinnedConnectionError("tls-connection-failed") from None
    # Report budget exhaustion distinctly even if the final connect timed out.
    _remaining(deadline)
    raise PinnedConnectionError("connection-failed")


__all__ = ["PinnedConnectionError", "connect_pinned"]
