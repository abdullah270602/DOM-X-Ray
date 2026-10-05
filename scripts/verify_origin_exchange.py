"""Network-free proof of anonymous, bounded origin HTTP exchanges."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.destination_policy import DestinationPolicy  # noqa: E402
from scanner.origin_exchange import EgressLimits, OriginExchange, OriginExchangeError  # noqa: E402


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def response(body=b"hello", headers=b"", status=b"200 OK"):
    return (b"HTTP/1.1 " + status + b"\r\nContent-Length: " + str(len(body)).encode()
            + b"\r\n" + headers + b"\r\n" + body)


class Socket:
    def __init__(self, payload):
        self.payload = payload
        self.request = None
        self.read = 0
        self.closed = False
        self.timeouts = []
        self.on_recv = lambda: None

    def settimeout(self, value):
        require(value > 0, "nonpositive exchange timeout")
        self.timeouts.append(value)

    def sendall(self, request):
        self.request = request

    def recv(self, limit):
        self.on_recv()
        chunk = self.payload[:min(limit, 13)]
        self.payload = self.payload[len(chunk):]
        self.read += len(chunk)
        return chunk

    def close(self):
        self.closed = True


def harness(payloads, *, limits=EgressLimits(), resolver=None):
    calls = []
    sockets = [Socket(payload) for payload in payloads]

    def connect(grant, *, timeout_seconds):
        calls.append(grant)
        require(0 < timeout_seconds <= 15, "invalid connector budget")
        return sockets[len(calls) - 1]

    exchange = OriginExchange(DestinationPolicy(resolver or (lambda _h, _p: ["1.1.1.1"])),
                              user_agent="DOM-X-Ray-Integration-Proof/0.1",
                              limits=limits, connector=connect)
    return exchange, calls, sockets


def rejects(callback, category, *, upstream_bytes_read=None):
    try:
        callback()
    except OriginExchangeError as error:
        require(str(error) == category, f"unexpected category: {error}")
        require("secret" not in str(error), "provider material escaped error")
        if upstream_bytes_read is not None:
            require(error.upstream_bytes_read == upstream_bytes_read, "failure lost exact received-byte evidence")
    else:
        raise AssertionError(f"expected rejection: {category}")


def main():
    raw = response(headers=b"Set-Cookie: secret-session=yes\r\nX-DOM-X-Ray-Block-Id: forged\r\n")
    exchange, calls, sockets = harness([raw])
    result = exchange.fetch("https://example.com/asset?q=secret-query", purpose="subresource", headers=(
        ("Cookie", "secret-cookie"), ("Authorization", "secret-auth"),
        ("Referer", "secret-referrer"), ("Proxy-Authorization", "secret-proxy"),
        ("Host", "attacker.invalid"), ("User-Agent", "secret-browser"),
        ("Accept", "text/html"), ("Connection", "accept-language"),
        ("Accept-Language", "secret-nominated"),
    ))
    require(result.body == b"hello" and result.upstream_wire_bytes == len(raw), "response/wire identity drifted")
    require(dict(result.headers) == {"content-length": "5"}, "origin cookie or reserved marker escaped")
    outbound = sockets[0].request
    require(b"GET /asset?q=secret-query HTTP/1.1\r\nHost: example.com\r\n" in outbound,
            "request target or Host disagreed with the grant")
    require(b"accept: text/html" in outbound and b"Connection: close" in outbound,
            "anonymous request lost its safe headers")
    require(all(canary not in outbound for canary in (
        b"secret-cookie", b"secret-auth", b"secret-referrer", b"secret-proxy", b"attacker.invalid",
        b"secret-browser", b"secret-nominated")), "sensitive outbound header escaped")
    require("secret" not in repr(result) and sockets[0].closed, "response repr leaked or socket remained open")
    require(calls[0].hostname == "example.com" and calls[0].scheme == "https", "wrong origin grant")

    no_contact, calls, _ = harness([])
    rejects(lambda: no_contact.fetch("https://example.com/", purpose="initial", method="POST"), "method")
    rejects(lambda: no_contact.fetch("https://127.0.0.1/", purpose="initial"), "destination-policy")
    rejects(lambda: no_contact.fetch("https://example.com/", purpose="initial",
                                    headers=(("Accept", "secret\r\nHost: attacker"),)), "invalid-headers")
    require(not calls, "denied request contacted an origin")

    # The redirect is held until its destination passes independent resolution;
    # the subsequent browser request resolves it again instead of reusing DNS.
    dns_calls = []
    def rebinding(host, port):
        dns_calls.append((host, port))
        return ["127.0.0.1"] if len(dns_calls) >= 3 else ["1.1.1.1"]
    redirect, calls, _ = harness([response(b"", b"Location: https://next.example/\r\n", b"302 Found")], resolver=rebinding)
    require(redirect.fetch("https://example.com/", purpose="initial").status == 302, "safe redirect was lost")
    rejects(lambda: redirect.fetch("https://next.example/", purpose="redirect"), "destination-policy")
    require(len(calls) == 1 and len(dns_calls) == 3, "redirect grant was cached or rebound origin contacted")
    private, _, private_sockets = harness([response(b"", b"Location: http://127.0.0.1/secret\r\n", b"302 Found")])
    rejects(lambda: private.fetch("https://example.com/", purpose="initial"), "destination-policy")
    require(private_sockets[0].closed, "redirect rejection leaked origin socket")

    invalids = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\n folded: header\r\n\r\nx",
        response(b"x", b"Connection: location\r\nLocation: http://127.0.0.1/\r\n", b"302 Found"),
        response(b"x") + b"HTTP/1.1 200 OK\r\n\r\nsecret-second-response",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\nsecret-extra",
        response(b"x", b"Location: /a\r\nLocation: /b\r\n", b"302 Found"),
    )
    for payload in invalids:
        invalid, _, invalid_sockets = harness([payload])
        rejects(lambda: invalid.fetch("https://example.com/", purpose="initial"), "invalid-response")
        require(invalid_sockets[0].closed, "invalid framing leaked socket")
    chunked, _, _ = harness([b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                             b"5\r\nhello\r\n0\r\nX-DOM-X-Ray-Block-Id: secret-trailer\r\n\r\n"])
    chunked_result = chunked.fetch("https://example.com/", purpose="initial")
    require(chunked_result.body == b"hello" and dict(chunked_result.headers) == {"content-length": "5"},
            "chunked response reconstruction exposed trailers or invalid framing")
    head, _, _ = harness([b"HTTP/1.1 200 OK\r\nContent-Length: 12345\r\n\r\n"])
    head_result = head.fetch("https://example.com/", method="HEAD", purpose="initial")
    require(head_result.body == b"" and dict(head_result.headers)["content-length"] == "12345",
            "HEAD lost representation length or manufactured a body")
    forbidden_head, _, _ = harness([response(b"unexpected-body")])
    rejects(lambda: forbidden_head.fetch("https://example.com/", method="HEAD", purpose="initial"),
            "invalid-response")

    bounded, _, bounded_sockets = harness([response(b"x" * 100)], limits=EgressLimits(max_response_bytes=60))
    rejects(lambda: bounded.fetch("https://example.com/", purpose="initial"), "response-byte-limit", upstream_bytes_read=61)
    require(bounded_sockets[0].read == 61 and bounded_sockets[0].closed, "response cap exceeded one detection byte")
    good = response()
    total, total_calls, total_sockets = harness([good, response(b"x" * 100)],
        limits=EgressLimits(max_total_received_bytes=len(good) + 10))
    total.fetch("https://example.com/", purpose="initial")
    rejects(lambda: total.fetch("https://example.com/a", purpose="subresource"), "total-byte-limit")
    rejects(lambda: total.fetch("https://example.com/b", purpose="subresource"), "total-byte-limit")
    require(len(total_calls) == 2 and sum(s.read for s in total_sockets) == len(good) + 11,
            "scan total cap or denied-response accounting drifted")
    quota, quota_calls, _ = harness([good], limits=EgressLimits(max_requests=2))
    quota.fetch("https://example.com/", purpose="initial")
    rejects(lambda: quota.fetch("https://example.com/a", purpose="subresource"), "request-limit")
    require(len(quota_calls) == 1, "inclusive request quota contacted triggering request")

    slow, _, slow_sockets = harness([good])
    clock = [0.0]
    slow_sockets[0].on_recv = lambda: clock.__setitem__(0, clock[0] + 0.4)
    with patch("scanner.origin_exchange.time.monotonic", side_effect=lambda: clock[0]):
        rejects(lambda: slow.fetch("https://example.com/", purpose="initial", timeout_seconds=0.5), "timeout")
    require(slow_sockets[0].closed and slow_sockets[0].read > 0, "slow-drip timeout leaked a socket")
    # Synchronous DNS must be bounded by deployment. If it returns after the
    # exchange deadline, no connection is created and nothing is admitted.
    clock = [0.0]
    def late_resolver(_host, _port):
        clock[0] = 2.0
        return ["1.1.1.1"]
    late, late_calls, _ = harness([], resolver=late_resolver)
    with patch("scanner.origin_exchange.time.monotonic", side_effect=lambda: clock[0]):
        rejects(lambda: late.fetch("https://example.com/", purpose="initial", timeout_seconds=1), "timeout")
    require(not late_calls, "late resolver caused contact beyond the exchange deadline")
    print("Verified anonymous pinned HTTP exchange: Host/target binding, credential and marker stripping, "
          "redirect revalidation/rebinding rejection, strict single-response framing, chunked reconstruction, "
          "inclusive request quota, response/scan wire-byte caps plus one detection byte, lifetime timeout, "
          "and socket cleanup. Browser proxy/TLS interception and deployment containment remain unproven.")


if __name__ == "__main__":
    main()
