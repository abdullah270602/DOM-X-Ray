"""Native direct-IP bypass and detached-descendant namespace cleanup proof."""

import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from threading import Thread
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.browser_namespace import write_namespace_wrapper
from scanner.namespace_bridge import NamespaceBridge, pump
from scanner.browser_egress_proxy import run_browser_egress_proxy
from scanner.destination_policy import DestinationPolicy
from scanner.origin_exchange import OriginExchange
from scanner.worker_supervisor import run_worker_command


def require(value, message):
    if not value:
        raise AssertionError(message)


def members(namespace):
    result = []
    for directory in Path("/proc").iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            if os.readlink(directory / "ns/pid") == namespace:
                result.append(int(directory.name))
        except OSError:
            pass
    return result


class Origin:
    def __init__(self, contacts):
        self.contacts = contacts
        body = b"<html><body>TLS proxy works</body></html>"
        self.payload = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    def settimeout(self, _value):
        pass
    def sendall(self, request):
        self.contacts.append(request)
    def recv(self, size):
        value, self.payload = self.payload[:size], self.payload[size:]
        return value
    def close(self):
        pass


def verify_partial_writes():
    payload, reply = b"outbound-fixture" * 20_000, b"inbound-fixture" * 20_000
    first, first_peer = socket.socketpair()
    second, second_peer = socket.socketpair()
    errors, received = [], []
    for connection in (first, first_peer, second, second_peer):
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        connection.settimeout(3)
    def relay():
        try:
            pump(first_peer, second_peer)
        except Exception as error:
            errors.append(type(error).__name__)
    def responder():
        try:
            data = bytearray()
            while chunk := second.recv(113):
                data.extend(chunk)
            received.append(bytes(data))
            second.sendall(reply)
            second.shutdown(socket.SHUT_WR)
        except Exception as error:
            errors.append(type(error).__name__)
    relay_thread, response_thread = Thread(target=relay, daemon=True), Thread(target=responder, daemon=True)
    try:
        relay_thread.start()
        response_thread.start()
        first.sendall(payload)
        first.shutdown(socket.SHUT_WR)
        returned = bytearray()
        while chunk := first.recv(127):
            returned.extend(chunk)
        relay_thread.join(timeout=3)
        response_thread.join(timeout=3)
        require(not errors and not relay_thread.is_alive() and not response_thread.is_alive()
                and received == [payload] and returned == reply, "relay partial-write/half-close corruption")
    finally:
        for connection in (first, first_peer, second, second_peer):
            connection.close()


def main():
    require(sys.platform == "linux", "native Linux namespace verification required")
    verify_partial_writes()
    with tempfile.TemporaryDirectory(prefix="dxr-bridge-parent-", dir="/tmp") as temporary:
        parent = Path(temporary)
        with NamespaceBridge(12345, temporary_parent=parent) as bridge:
            owned = bridge.path
            require(owned.is_relative_to(parent) and owned.is_socket(), "bridge ignored owned storage")
        require(not owned.parent.exists(), "orderly bridge shutdown leaked owned directory")
        public = parent / "public"
        public.mkdir(mode=0o755)
        link = parent / "link"
        link.symlink_to(parent, target_is_directory=True)
        long = parent / ("x" * 100)
        long.mkdir(mode=0o700)
        for invalid in (public, link, long):
            try:
                NamespaceBridge(12345, temporary_parent=invalid)
            except ValueError:
                pass
            else:
                raise AssertionError("unsafe or overlong bridge parent accepted")
        require(not list(long.iterdir()), "overlong bridge setup leaked a temporary directory")
    for hang in (False, True):
        with tempfile.TemporaryDirectory(prefix="dxr-ns-proof-") as temporary, \
             socket.socket() as tcp, socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as tcp6, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            directory = Path(temporary)
            tcp.bind(("127.0.0.1", 0))
            tcp.listen()
            tcp.setblocking(False)
            tcp6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            tcp6.bind(("::1", 0))
            tcp6.listen()
            tcp6.setblocking(False)
            udp.bind(("127.0.0.1", 0))
            udp.setblocking(False)
            contacts = []
            policy = DestinationPolicy(lambda h, p: ["1.1.1.1"])
            exchange = OriginExchange(policy, user_agent="DOM-X-Ray-Netns-Fixture/0.1",
                connector=lambda grant, **_kwargs: Origin(contacts))
            with run_browser_egress_proxy(initial_url="http://xray.test/", policy=policy,
                                          exchange=exchange, tls_context=lambda host: None) as proxy, \
                 NamespaceBridge(proxy.server_address[1]) as bridge:
                path = bridge.path
                config, result, marker = directory / "fixture.json", directory / "result.json", directory / "marker.json"
                config.write_text(json.dumps({"proxyPort": proxy.server_address[1], "outsideTcp": tcp.getsockname()[1],
                    "outsideTcp6": tcp6.getsockname()[1], "outsideUdp": udp.getsockname()[1],
                    "marker": str(marker), "hang": hang}))
                wrapper = write_namespace_wrapper(directory, executable=Path(sys.executable), bridge_path=bridge.path,
                    port=proxy.server_address[1], preserve_pipes=False)
                run = run_worker_command([sys.executable, "-I", str(ROOT / "fixtures/worker/detached_namespace_parent.py"),
                                          str(wrapper), "-I", str(ROOT / "fixtures/worker/network_namespace_fixture.py"),
                                          str(config), str(result)], result_path=result, cwd=ROOT,
                    environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, deadline_seconds=4 if hang else 10)
                require(run.outcome == ("timeout" if hang else "completed"), f"namespace outcome: {run.outcome}")
                require(marker.exists(), "namespace bypass/detached-child checks did not finish")
                proof = json.loads(marker.read_text())
                require(proof["network"] != os.readlink("/proc/self/ns/net"), "fixture used host network namespace")
                require(proof["userNamespace"] != os.readlink("/proc/self/ns/user"), "fixture used host user namespace")
                require(proof["tcpBlocked"] == 9 and proof["capabilitiesDropped"] and proof["detachedChildStarted"],
                        "namespace proof omitted an adversarial boundary")
                stopped = time.monotonic() + 0.4
                while members(proof["namespace"]) and time.monotonic() < stopped:
                    time.sleep(0.01)
                require(not members(proof["namespace"]), "detached child survived namespace init destruction")
                require(len(contacts) == 1, "private bridge request contacted origin")
                for listener in (tcp, tcp6):
                    try:
                        connected, _ = listener.accept()
                    except BlockingIOError:
                        pass
                    else:
                        connected.close()
                        raise AssertionError("direct TCP reached outside namespace listener")
                try:
                    udp.recvfrom(1024)
                except BlockingIOError:
                    pass
                else:
                    raise AssertionError("direct UDP reached outside namespace listener")
                require(run.artifact_eligible != hang, "timeout became an eligible namespace result")
            require(not path.exists(), "Unix proxy bridge survived close")
    print("Verified native non-root user/network/PID namespace, loopback-only routes, zero capabilities/no-new-privs, "
          "nine direct IPv4/IPv6 TCP bypass denials including DNS/DoT, denied raw sockets, outside UDP and UDP-DNS isolation, fixed enforcing-proxy bridge, "
          "private-target denial, and setsid descendant cleanup on normal exit and supervised timeout. "
          "Chromium integration, filesystem/other Unix sockets and deployment quotas remain open.")


if __name__ == "__main__":
    main()
