"""Adversarial direct-IP attempts inside the network/PID namespace."""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def require(value, message):
    if not value:
        raise AssertionError(message)


def request(port, target):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
        host = target.split("//", 1)[1].split("/", 1)[0]
        client.sendall(f"GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        result = b""
        while chunk := client.recv(4096):
            result += chunk
        return result


def main():
    config, result = Path(sys.argv[1]), Path(sys.argv[2])
    settings = json.loads(config.read_text())
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(os.getuid() != 0 and all(int(status[key], 16) == 0
            for key in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")) and status["NoNewPrivs"].strip() == "1",
            "child retained setup privileges")
    require({name for _, name in socket.if_nameindex()} == {"lo"}, "external interface visible")
    link = json.loads(subprocess.check_output(["/usr/sbin/ip", "-j", "link", "show", "lo"]))
    require("UP" in link[0]["flags"], "namespace loopback remained down")
    uid_map, gid_map = Path("/proc/self/uid_map").read_text().split(), Path("/proc/self/gid_map").read_text().split()
    require(uid_map == [str(os.getuid()), str(os.getuid()), "1"]
            and gid_map == [str(os.getgid()), str(os.getgid()), "1"], "namespace user/group mapping drifted")
    require(not json.loads(subprocess.check_output(["/usr/sbin/ip", "-j", "route", "show", "table", "main"])),
            "external IPv4 route visible")
    require(not json.loads(subprocess.check_output(["/usr/sbin/ip", "-j", "-6", "route", "show", "table", "main"])),
            "external IPv6 route visible")
    blocked = []
    for family, address, port in (
            (socket.AF_INET, "127.0.0.1", settings["outsideTcp"]),
            (socket.AF_INET6, "::1", settings["outsideTcp6"]),
            (socket.AF_INET, "1.1.1.1", 443), (socket.AF_INET, "10.0.0.1", 80),
            (socket.AF_INET, "1.1.1.1", 53), (socket.AF_INET, "1.1.1.1", 853),
            (socket.AF_INET, "169.254.169.254", 80),
            (socket.AF_INET6, "2001:4860:4860::8888", 443), (socket.AF_INET6, "fd00::1", 80)):
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(0.3)
            outcome = client.connect_ex((address, port))
            require(outcome != 0, "direct TCP bypass connected")
            blocked.append(outcome)
    for family, protocol in ((socket.AF_INET, socket.IPPROTO_ICMP), (socket.AF_PACKET, socket.htons(3))):
        try:
            raw = socket.socket(family, socket.SOCK_RAW, protocol)
        except PermissionError:
            pass
        else:
            raw.close()
            raise AssertionError("raw packet socket permitted after capability drop")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.sendto(b"namespace-fixture", ("127.0.0.1", settings["outsideUdp"]))
        try:
            client.sendto(b"namespace-dns-fixture", ("1.1.1.1", 53))
        except OSError:
            pass
        else:
            raise AssertionError("external UDP/DNS route available")
    relayed = request(settings["proxyPort"], "http://xray.test/")
    require(relayed.startswith(b"HTTP/1.1 200") and b"TLS proxy works" in relayed, "fixed proxy bridge failed")
    denied = request(settings["proxyPort"], "http://127.0.0.1/private")
    require(denied.startswith(b"HTTP/1.1 403"), "bridge bypassed destination policy")
    # Escape the ordinary process group deliberately; namespace PID 1 still
    # owns cleanup when the fixture finishes or the outer supervisor times out.
    detached = subprocess.Popen([sys.executable, "-c", "import os,time; os.setsid(); time.sleep(60)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    time.sleep(0.05)
    require(detached.poll() is None, "detached descendant did not start")
    proof = {"namespace": os.readlink("/proc/self/ns/pid"), "network": os.readlink("/proc/self/ns/net"),
             "userNamespace": os.readlink("/proc/self/ns/user"), "uidMap": uid_map, "gidMap": gid_map,
             "tcpBlocked": len(blocked), "nonRoot": True, "capabilitiesDropped": True,
             "detachedChildStarted": True}
    Path(settings["marker"]).write_text(json.dumps(proof))
    if settings["hang"]:
        time.sleep(60)
    result.write_text(json.dumps({"supervisorNonce": os.environ["DOM_X_RAY_WORKER_RESULT_NONCE"], "result": proof}))


if __name__ == "__main__":
    main()
