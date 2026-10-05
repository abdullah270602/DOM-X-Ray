"""Network-free proof of pinned TCP/TLS connection establishment."""

from __future__ import annotations

import socket
import ssl
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.destination_policy import DestinationPolicy  # noqa: E402
from scanner.pinned_connector import PinnedConnectionError, connect_pinned  # noqa: E402


def require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


class FakeSocket:
    def __init__(self, *, fail=False, peer=None):
        self.fail = fail
        self.peer = peer
        self.endpoint = None
        self.closed = False
        self.timeouts = []
        self.handshakes = 0
        self.tls_failure = False

    def settimeout(self, timeout):
        require(timeout > 0, "nonpositive socket timeout")
        self.timeouts.append(timeout)

    def connect(self, endpoint):
        self.endpoint = endpoint
        if self.fail:
            raise OSError("secret-provider-address")

    def getpeername(self):
        return self.peer or self.endpoint

    def close(self):
        self.closed = True

    def do_handshake(self):
        self.handshakes += 1
        if self.tls_failure:
            raise ssl.SSLCertVerificationError("secret-certificate-error")

    def selected_alpn_protocol(self):
        return "http/1.1"


class FakeTLS:
    check_hostname = True
    verify_mode = ssl.CERT_REQUIRED

    def __init__(self):
        self.calls = []
        self.protocols = None

    def load_default_certs(self, purpose):
        require(purpose == ssl.Purpose.SERVER_AUTH, "wrong trust purpose")

    def set_alpn_protocols(self, protocols):
        self.protocols = protocols

    def wrap_socket(self, connection, **kwargs):
        self.calls.append(kwargs)
        return connection


def rejects(callback, reason=None):
    try:
        callback()
    except PinnedConnectionError as error:
        require("secret" not in str(error), "provider data escaped content-free error")
        if reason:
            require(str(error) == reason, "unexpected rejection category")
    else:
        raise AssertionError("unsafe connection unexpectedly succeeded")


def main():
    grant = DestinationPolicy(lambda _host, _port: ["8.8.8.8", "1.1.1.1"]).validate(
        "https://example.com/", purpose="initial",
    )
    first, second = FakeSocket(fail=True), FakeSocket()
    tls = FakeTLS()
    factories = []

    def factory(*args):
        factories.append(args)
        return first if len(factories) == 1 else second

    with patch("scanner.pinned_connector.socket.socket", side_effect=factory), \
            patch("scanner.pinned_connector.ssl.SSLContext", return_value=tls), \
            patch("socket.getaddrinfo", side_effect=AssertionError("connector resolved DNS")):
        result = connect_pinned(grant)
    require(result is second and first.closed and not second.closed, "TCP fallback socket ownership failed")
    require(first.endpoint == ("1.1.1.1", 443) and second.endpoint == ("8.8.8.8", 443),
            "connect did not use only canonical approved numeric addresses")
    require(all(args == (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP) for args in factories),
            "connector used an unexpected socket transport")
    require(tls.calls == [{"server_hostname": "example.com", "do_handshake_on_connect": False}],
            "TLS hostname binding drifted")
    require(tls.minimum_version == ssl.TLSVersion.TLSv1_2 and tls.protocols == ["http/1.1"],
            "TLS minimum/ALPN configuration drifted")
    require(second.handshakes == 1, "socket escaped before authenticated handshake")

    # All answers must be valid before contact; direct dataclass construction
    # must not bypass policy, and literals must bind the same numeric address.
    invalids = [
        replace(grant, addresses=("1.1.1.1", "127.0.0.1")),
        replace(grant, addresses=()), replace(grant, addresses=("not-an-ip",)),
        replace(grant, addresses=tuple(reversed(grant.addresses))),
        replace(grant, hostname="localhost"), replace(grant, hostname="user@example.com"),
        replace(grant, hostname="1.1.1.1"), replace(grant, port=22),
        replace(grant, scheme="ftp"), replace(grant, purpose="invented"),
    ]
    with patch("scanner.pinned_connector.socket.socket") as blocked:
        for invalid in invalids:
            rejects(lambda: connect_pinned(invalid), "invalid-destination-grant")
        require(not blocked.called, "invalid grant created a socket")

    ipv6 = DestinationPolicy(lambda _host, _port: ["2606:4700:4700::1111"]).validate(
        "http://example.com/", purpose="subresource",
    )
    v6 = FakeSocket()
    with patch("scanner.pinned_connector.socket.socket", return_value=v6) as v6factory, \
            patch("scanner.pinned_connector.ssl.SSLContext") as no_tls:
        require(connect_pinned(ipv6) is v6, "IPv6 connection failed")
        require(not no_tls.called, "HTTP grant unexpectedly used TLS")
    require(v6factory.call_args.args[0] == socket.AF_INET6
            and v6.endpoint == ("2606:4700:4700::1111", 80, 0, 0), "IPv6 endpoint drifted")

    wrong_peer = FakeSocket(peer=("127.0.0.1", 443))
    with patch("scanner.pinned_connector.socket.socket", return_value=wrong_peer), \
            patch("scanner.pinned_connector.ssl.SSLContext", return_value=FakeTLS()):
        rejects(lambda: connect_pinned(grant), "connection-peer-mismatch")
    require(wrong_peer.closed and wrong_peer.handshakes == 0, "mismatched peer escaped or began TLS")

    bad_certificate = FakeSocket()
    bad_certificate.tls_failure = True
    with patch("scanner.pinned_connector.socket.socket", return_value=bad_certificate) as once, \
            patch("scanner.pinned_connector.ssl.SSLContext", return_value=FakeTLS()):
        rejects(lambda: connect_pinned(grant), "tls-connection-failed")
        require(once.call_count == 1 and bad_certificate.closed, "TLS failure fell back or leaked its socket")

    # Connection and TLS share a single absolute budget rather than resetting
    # the timeout for each approved address or handshake.
    exhausted = FakeSocket(fail=True)
    with patch("scanner.pinned_connector.socket.socket", return_value=exhausted) as count, \
            patch("scanner.pinned_connector.ssl.SSLContext", return_value=FakeTLS()), \
            patch("scanner.pinned_connector.time.monotonic", side_effect=[0, 0.1, 6]):
        rejects(lambda: connect_pinned(grant), "connection-timeout")
        require(count.call_count == 1 and exhausted.closed, "deadline failure created or leaked a socket")
    with patch("scanner.pinned_connector.socket.socket") as no_socket:
        for invalid in (0, -1, True, float("nan"), float("inf"), 16):
            try:
                connect_pinned(grant, timeout_seconds=invalid)
            except ValueError:
                pass
            else:
                raise AssertionError("invalid timeout accepted")
        require(not no_socket.called, "invalid timeout created a socket")
    print("Verified pinned IPv4/IPv6 sockets without DNS, complete grant validation before contact, "
          "TCP-only approved fallback, TLS SNI/certificate configuration, no TLS downgrade, "
          "peer verification, total connect/handshake deadline, socket cleanup, and content-free errors. "
          "This network-free verifier does not prove browser proxy integration or deployment egress containment.")


if __name__ == "__main__":
    main()
