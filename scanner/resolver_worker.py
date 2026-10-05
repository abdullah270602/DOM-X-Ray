"""Trusted stdlib-only DNS helper, launched with Python -I -S.

No browser, URL fetch, reverse lookup, cache, or provider error text. The parent
owns deadline termination and public-address admission.
"""

import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys

MAX_ANSWERS = 16
MAX_BYTES = 2_048
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def resolve(hostname, port):
    if (not isinstance(hostname, str) or not hostname or len(hostname) > 253
            or not all(_LABEL.fullmatch(label) for label in hostname.split("."))
            or isinstance(port, bool) or not isinstance(port, int) or port not in {80, 443}):
        raise ValueError("invalid resolver input")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("resolver requires a hostname")
    try:
        answers = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC,
                                     socket.SOCK_STREAM, socket.IPPROTO_TCP, 0)
    except OSError:
        return {"outcome": "unavailable", "addresses": []}
    addresses = []
    try:
        for family, kind, protocol, _canonical, endpoint in answers:
            if len(addresses) >= MAX_ANSWERS:
                return {"outcome": "answer-limit", "addresses": []}
            if (family not in {socket.AF_INET, socket.AF_INET6}
                    or kind != socket.SOCK_STREAM or protocol != socket.IPPROTO_TCP
                    or endpoint[1] != port or "%" in endpoint[0]
                    or (family == socket.AF_INET6 and endpoint[3] != 0)):
                raise ValueError("invalid DNS answer")
            address = ipaddress.ip_address(endpoint[0])
            if address.version != (4 if family == socket.AF_INET else 6):
                raise ValueError("invalid DNS family")
            addresses.append(address.compressed)
    except (ValueError, TypeError, IndexError):
        return {"outcome": "invalid-answer", "addresses": []}
    return {"outcome": "resolved" if addresses else "unavailable", "addresses": addresses}


def main():
    if len(sys.argv) != 3:
        raise ValueError("invalid resolver command")
    input_path, result_path = Path(sys.argv[1]), Path(sys.argv[2])
    metadata = input_path.lstat()
    if not input_path.is_absolute() or not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 512:
        raise ValueError("invalid resolver input")
    def strict_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate resolver field")
            result[key] = value
        return result
    query = json.loads(input_path.read_bytes(), object_pairs_hook=strict_object)
    if not isinstance(query, dict) or set(query) != {"hostname", "port"}:
        raise ValueError("invalid resolver input")
    hostname, port = query["hostname"], query["port"]
    nonce = os.environ.get("DOM_X_RAY_WORKER_RESULT_NONCE", "")
    if not re.fullmatch(r"[0-9a-f]{32}", nonce) or not result_path.is_absolute():
        raise ValueError("invalid resolver envelope")
    payload = json.dumps({"supervisorNonce": nonce, "result": resolve(hostname, port)},
                         separators=(",", ":")).encode("ascii")
    if len(payload) > MAX_BYTES:
        raise ValueError("resolver envelope limit")
    staged = result_path.with_suffix(".staged")
    descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
    os.replace(staged, result_path)


if __name__ == "__main__":
    main()
