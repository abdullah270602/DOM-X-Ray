"""One-shot initial launch-grant pinning; no external network contacts."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import socket
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.browser_egress_proxy import BrowserEgressProxy, run_browser_egress_proxy
from scanner.destination_policy import DestinationPolicy
from scanner.origin_exchange import OriginExchange, OriginExchangeError
from scanner.scan_transport import PublicScanGrant, check_public_scan_grant, public_scan_target_matches
from scripts.verify_origin_exchange import Socket, response, require, rejects


def main():
    target = "https://EXAMPLE.com"
    destination = DestinationPolicy(lambda _h, _p: ["1.1.1.1"]).validate(target, purpose="initial")
    grant = PublicScanGrant(target, destination)
    check_public_scan_grant(grant)
    for url in ("https://example.com/", "https://EXAMPLE.com:443/"):
        require(public_scan_target_matches(url, grant), "canonical initial identity was lost")
    for url in ("https://example.com/a", "https://example.com/?", "https://example.com/#",
                "http://example.com/", "https://other.com/", "https://example.com:80/",
                "https://user@example.com/", "https://example.com\\pivot"):
        require(not public_scan_target_matches(url, grant), "initial grant matched a different target")
    for forged in (replace(grant, target_url="https://other.com/"),
                   replace(grant, destination=replace(destination, purpose="subresource")),
                   replace(grant, destination=replace(destination, addresses=("127.0.0.1",))),
                   replace(grant, destination=replace(destination, addresses=("1.1.1.1", "1.1.1.1"))),
                   replace(grant, destination=replace(destination, addresses=["1.1.1.1"])),
                   replace(grant, destination=replace(destination, hostname="EXAMPLE.com"))):
        try:
            check_public_scan_grant(forged)
        except ValueError as error:
            require(str(error) == "invalid-public-scan-grant", "grant rejection leaked target material")
        else:
            raise AssertionError("forged grant accepted")

    dns, connections, sockets = [], [], []
    def resolver(host, port):
        dns.append((host, port))
        return ["127.0.0.1"]
    def connector(value, **_kwargs):
        connections.append(value)
        stream = Socket(response())
        sockets.append(stream)
        return stream
    policy = DestinationPolicy(resolver)
    exchange = OriginExchange(policy, user_agent="DOM-X-Ray-Grant-Fixture/0.1",
                              connector=connector, initial_grant=grant)
    require(exchange.validate_initial_target("https://example.com/") is destination, "setup replaced grant")
    for _ in range(2):
        tunnel = exchange.validate_browser_tunnel("https://example.com:443/")
        require(tunnel.addresses == destination.addresses, "CONNECT replaced initial answers")
    require(not dns and not connections, "setup/CONNECT consumed or re-resolved initial grant")
    for configured_policy, configured_target, expected in (
            (DestinationPolicy(resolver), target, "proxy-policy-mismatch"),
            (policy, "https://example.com/a", "initial-grant-target-mismatch")):
        try:
            BrowserEgressProxy(initial_url=configured_target, policy=configured_policy,
                               exchange=exchange, tls_context=lambda _host: None)
        except ValueError as error:
            require(str(error) == expected, "proxy configuration rejection drifted")
        else:
            raise AssertionError("proxy accepted inconsistent launch configuration")
    require(not dns and not connections, "bad proxy setup resolved/contacted origin")
    rejects(lambda: exchange.fetch("https://example.com/", purpose="initial", method="HEAD"), "method")
    rejects(lambda: exchange.fetch("https://example.com/a", purpose="initial"), "destination-policy")
    require(not dns and not connections, "rejected initial request consumed grant")
    exchange.fetch("https://example.com:443/", purpose="initial")
    require(connections == [destination] and not dns, "first fetch did not pin exact launch answers")
    require(sockets[0].closed and b"GET / HTTP/1.1\r\nHost: example.com\r\n" in sockets[0].request,
            "initial pinning changed request semantics or leaked socket")
    rejects(lambda: exchange.fetch("https://example.com/", purpose="initial"), "destination-policy")
    rejects(lambda: exchange.fetch("https://example.com/asset", purpose="subresource"), "destination-policy")
    require(len(dns) == 2 and len(connections) == 1, "subsequent request reused grant or contacted rebound address")

    # A connector failure consumes the capability; no in-call DNS fallback.
    failed_dns, failed_connects = [], []
    def failed_connector(value, **_kwargs):
        failed_connects.append(value)
        raise OSError("secret-provider-text")
    failed = OriginExchange(DestinationPolicy(lambda h, p: failed_dns.append((h, p)) or ["127.0.0.1"]),
        user_agent="DOM-X-Ray-Grant-Fixture/0.1", connector=failed_connector, initial_grant=grant)
    rejects(lambda: failed.fetch("https://example.com/", purpose="initial"), "upstream-failed")
    require(not failed_dns and failed_connects == [destination], "failed pin fell back to DNS")
    rejects(lambda: failed.fetch("https://example.com/", purpose="initial"), "destination-policy")
    require(len(failed_dns) == 1 and len(failed_connects) == 1, "failed initial grant was reused")

    # Redirect preflight and actual followed fetch each get fresh validation.
    redirect_dns, redirect_connects = [], []
    redirect = OriginExchange(DestinationPolicy(lambda h, p: redirect_dns.append((h, p)) or ["1.0.0.1"]),
        user_agent="DOM-X-Ray-Grant-Fixture/0.1", initial_grant=grant,
        connector=lambda value, **_kwargs: redirect_connects.append(value) or Socket(
            response(b"", headers=b"Location: /next\r\n", status=b"302 Found") if len(redirect_connects) == 1 else response()))
    redirect.fetch("https://example.com/", purpose="initial")
    redirect.fetch("https://example.com/next", purpose="redirect")
    require(len(redirect_dns) == 2 and redirect_connects[0] is destination
            and redirect_connects[1].addresses == ("1.0.0.1",), "redirect reused launch addresses")

    concurrent_dns, concurrent_connects = [], []
    concurrent = OriginExchange(DestinationPolicy(lambda h, p: concurrent_dns.append((h, p)) or ["1.0.0.1"]),
        user_agent="DOM-X-Ray-Grant-Fixture/0.1", initial_grant=grant,
        connector=lambda value, **_kwargs: concurrent_connects.append(value) or Socket(response()))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: concurrent.fetch("https://example.com/", purpose="initial"), range(2)))
    require(all(result.status == 200 for result in results) and len(concurrent_dns) == 1
            and sum(value is destination for value in concurrent_connects) == 1,
            "concurrent initial fetch reused the grant")

    # Real HTTP proxy ingress exercises empty-path/case/default-port normalization.
    http_target = "http://EXAMPLE.com"
    http_grant = PublicScanGrant(http_target, DestinationPolicy(lambda h, p: ["1.1.1.1"]).validate(http_target, purpose="initial"))
    http_dns, http_connects = [], []
    http_policy = DestinationPolicy(lambda h, p: http_dns.append((h, p)) or ["127.0.0.1"])
    http_exchange = OriginExchange(http_policy, user_agent="DOM-X-Ray-Grant-Fixture/0.1", initial_grant=http_grant,
        connector=lambda value, **_kwargs: http_connects.append(value) or Socket(response()))
    with run_browser_egress_proxy(initial_url=http_target, policy=http_policy, exchange=http_exchange,
                                  tls_context=lambda _host: None) as proxy:
        for expected in (b"HTTP/1.1 200", b"HTTP/1.1 403"):
            with socket.create_connection(proxy.server_address, timeout=2) as client:
                client.sendall(b"GET http://example.com:80/ HTTP/1.1\r\nHost: EXAMPLE.com\r\n\r\n")
                payload = b""
                while chunk := client.recv(4096):
                    payload += chunk
                require(payload.startswith(expected), "HTTP proxy initial-grant integration failed")
    require(http_connects == [http_grant.destination] and len(http_dns) == 1,
            "HTTP proxy re-resolved first request or reused initial answers")
    print("Verified exact one-shot launch-address pinning, canonical target matching, forged grants, "
          "non-consuming CONNECT checks, failed-contact consumption, redirect/subresource revalidation, "
          "concurrent use, and real HTTP proxy ingress. Public worker/container integration remains open.")


if __name__ == "__main__":
    main()
