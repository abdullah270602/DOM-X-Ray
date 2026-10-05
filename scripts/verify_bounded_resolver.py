"""Deterministic process DNS safety checks; optional live system DNS smoke."""

from __future__ import annotations

import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import sys
from threading import Barrier, Lock
import time
from unittest.mock import patch

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.bounded_resolver import BoundedSystemResolver, MAX_RESOLVER_BYTES, _PROCESS_SLOTS  # noqa: E402
from scanner.destination_policy import DestinationPolicy, DestinationPolicyError  # noqa: E402
from scanner.resolver_worker import resolve  # noqa: E402
from scanner.scan_transport import authorize_connection  # noqa: E402
from scanner.worker_supervisor import run_worker_command, MAX_WORKER_RESULT_BYTES  # noqa: E402

FIXTURE = ROOT / "fixtures/resolver/resolver_fixture.py"


def require(value, message):
    if not value:
        raise AssertionError(message)


def reject(action, reason=None):
    try:
        action()
    except DestinationPolicyError as error:
        if reason:
            require(error.reason == reason, f"unexpected resolver outcome: {error.reason}")
        require("fixture-secret" not in str(error) and "xray.test" not in str(error),
                "resolver error leaked provider/host material")
        return error.reason
    raise AssertionError("rejected lookup admitted a grant")


class Harness:
    def __init__(self, modes=(), delay=0):
        self.modes = deque(modes)
        self.delay = delay
        self.lock = Lock()
        self.paths = []
        self.outcomes = []
        self.child_pids = []
        self.active = 0
        self.peak = 0

    def __call__(self, command, **kwargs):
        query_path, result_path = Path(command[-2]), Path(command[-1])
        query = json.loads(query_path.read_bytes())
        require(query["hostname"] not in repr(command), "hostname leaked into helper argv")
        require(command[1:3] == ["-I", "-S"] and kwargs["max_result_bytes"] == MAX_RESOLVER_BYTES,
                "lookup lost interpreter/output isolation")
        require(not any(key.upper() in {"LOCALDOMAIN", "RES_OPTIONS", "HOSTALIASES"}
                        or key.upper().startswith("PYTHON") for key in kwargs["environment"]),
                "ambient resolver/interpreter configuration escaped filtering")
        require(all(key.upper() in {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "TEMP", "TMP"}
                    for key in kwargs["environment"])
                and "fixture-secret" not in repr(kwargs["environment"]),
                "unrelated app credentials escaped into resolver helper environment")
        if os.name != "nt":
            require(query_path.stat().st_mode & 0o777 == 0o600
                    and query_path.parent.stat().st_mode & 0o777 == 0o700,
                    "lookup input directory/file permissions are not private")
        with self.lock:
            mode = self.modes.popleft() if self.modes else "public"
            self.paths.append(result_path.parent)
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            if self.delay:
                time.sleep(self.delay)
            run = run_worker_command([command[0], "-I", "-S", str(FIXTURE), mode,
                                      str(query_path), str(result_path)], **kwargs)
            with self.lock:
                self.outcomes.append(run.outcome)
                child = result_path.parent / "child.json"
                if child.is_file():
                    self.child_pids.append(json.loads(child.read_bytes())["pid"])
            return run
        finally:
            with self.lock:
                self.active -= 1

    def assert_cleanup(self):
        require(len(set(self.paths)) == len(self.paths) and all(not path.exists() for path in self.paths),
                "resolver reused a path or retained private input/results")
        for pid in self.child_pids:
            try:
                process = psutil.Process(pid)
                alive = process.is_running() and process.status() != psutil.STATUS_ZOMBIE
            except psutil.NoSuchProcess:
                alive = False
            require(not alive, "timed-out resolver descendant survived")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--public", action="store_true", help="also run a labeled live www.python.org DNS smoke")
    options = parser.parse_args()
    # Exercise the actual helper's getaddrinfo call and result protocol without DNS.
    def answer(address):
        if ":" in address:
            return (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "provider-private-name",
                    (address, 443, 0, 0))
        return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "provider-private-name", (address, 443))
    answers = [answer("1.1.1.1"), answer("2606:4700:4700::1111"), answer("1.1.1.1")]
    with patch("scanner.resolver_worker.socket.getaddrinfo", return_value=answers) as call:
        result = resolve("xray.test", 443)
        call.assert_called_once_with("xray.test", 443, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP, 0)
        require(result == {"outcome": "resolved", "addresses": ["1.1.1.1", "2606:4700:4700::1111", "1.1.1.1"]}
                and "provider-private-name" not in repr(result), "helper discarded addresses or retained names")
    with patch("scanner.resolver_worker.socket.getaddrinfo", return_value=[answer("1.1.1.1")] * 16):
        require(len(resolve("xray.test", 443)["addresses"]) == 16, "helper rejected its exact answer boundary")
    with patch("scanner.resolver_worker.socket.getaddrinfo",
               return_value=[answer("1.1.1.1")] * 16 + [answer("127.0.0.1")]):
        require(resolve("xray.test", 443) == {"outcome": "answer-limit", "addresses": []},
                "helper truncated a private seventeenth answer into an allowed prefix")
    for rows in ([answer("fe80::1%interface")], [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                 "private", ("2606:4700:4700::1111", 443, 0, 3))], [answer("not-an-IP")]):
        with patch("scanner.resolver_worker.socket.getaddrinfo", return_value=rows):
            require(resolve("xray.test", 443)["outcome"] == "invalid-answer", "invalid OS answer was admitted")
    with patch("scanner.resolver_worker.socket.getaddrinfo", side_effect=socket.gaierror("fixture-secret")):
        require(resolve("xray.test", 443) == {"outcome": "unavailable", "addresses": []},
                "helper retained provider exception data")

    harness = Harness(["public", "duplicates", "public"])
    with patch.dict(os.environ, {"DOM_X_RAY_PRIVATE_TOKEN": "fixture-secret", "PYTHONPATH": "fixture-secret",
                                "AWS_SECRET_ACCESS_KEY": "fixture-secret", "LOCALDOMAIN": "fixture-secret"}), \
         patch("scanner.bounded_resolver.run_worker_command", side_effect=harness):
        resolver = BoundedSystemResolver()
        policy = DestinationPolicy(resolver)
        initial = policy.validate("https://xray.test/", purpose="initial")
        redirect = policy.validate("https://xray.test/next", purpose="redirect")
        subresource = policy.validate("https://xray.test/image", purpose="subresource")
        require(len(initial.addresses) == 2 and redirect.addresses == ("1.1.1.1",)
                and len(subresource.addresses) == 2 and len(harness.paths) == 3,
                "same-host lookups cached answers or failed duplicate admission")
        require("1.1.1.1" not in repr(initial), "grant representation leaked resolver answers")
    harness.assert_cleanup()

    failed_modes = {"private": "forbidden-address", "mixed": "forbidden-address",
        "mixed-family": "forbidden-address", "unavailable": "dns-unavailable",
        "answer-limit": "dns-answer-limit", "invalid-answer": "invalid-dns-answer"}
    for mode in ("overflow", "invalid-address", "noncanonical", "wrong-type", "scope", "empty",
                 "extra-result", "invalid-outcome", "failure-addresses", "wrong-nonce", "extra-envelope",
                 "oversized", "duplicate-field", "truncated", "directory", "no-artifact", "crash"):
        failed_modes[mode] = "dns-unavailable"
    if os.name != "nt":
        failed_modes["symlink"] = "dns-unavailable"
    for mode, reason in failed_modes.items():
        harness = Harness([mode])
        with patch("scanner.bounded_resolver.run_worker_command", side_effect=harness):
            reject(lambda: DestinationPolicy(BoundedSystemResolver()).validate(
                "https://xray.test/", purpose="initial"), reason)
        if mode in {"oversized", "wrong-nonce", "directory", "no-artifact", "truncated", "symlink"}:
            require(harness.outcomes == ["invalid-result"], "supervisor admitted an ineligible DNS artifact")
        if mode == "duplicate-field":
            require(harness.outcomes == ["completed"], "duplicate-field case did not reach strict DNS decoding")
        harness.assert_cleanup()

    for mode in ("hang-after-result", "hang-descendant"):
        harness = Harness([mode])
        started = time.monotonic()
        with patch("scanner.bounded_resolver.run_worker_command", side_effect=harness):
            reject(lambda: DestinationPolicy(BoundedSystemResolver(lookup_seconds=1.5)).validate(
                "https://xray.test/", purpose="initial"), "dns-timeout")
        require(time.monotonic() - started < 2 and harness.outcomes == ["timeout"],
                "hung resolver exceeded its budget or admitted early output")
        harness.assert_cleanup()

    harness = Harness(["public", "private"])
    contacted = []
    with patch("scanner.bounded_resolver.run_worker_command", side_effect=harness):
        policy = DestinationPolicy(BoundedSystemResolver())
        authorize_connection("https://xray.test/", purpose="initial", policy=policy,
                             connector=lambda grant: contacted.append(grant))
        reject(lambda: authorize_connection("https://xray.test/resource", purpose="subresource", policy=policy,
               connector=lambda grant: contacted.append(grant)), "forbidden-address")
    require(len(contacted) == 1 and len(harness.paths) == 2, "rebinding reached a connector or reused DNS")
    harness.assert_cleanup()

    harness = Harness(delay=0.1)
    barrier = Barrier(6)
    with patch("scanner.bounded_resolver.run_worker_command", side_effect=harness):
        resolver = BoundedSystemResolver(max_parallel=2)
        def parallel(index):
            barrier.wait()
            return DestinationPolicy(resolver).validate(f"https://host-{index}.test/", purpose="initial")
        with ThreadPoolExecutor(max_workers=6) as pool:
            grants = list(pool.map(parallel, range(6)))
    require(len(grants) == 6 and harness.peak == 2, "parallel resolver slots were exceeded or never exercised")
    harness.assert_cleanup()

    harness = Harness(delay=0.1)
    barrier = Barrier(6)
    resolvers = [BoundedSystemResolver() for _ in range(6)]
    with patch("scanner.bounded_resolver.run_worker_command", side_effect=harness):
        def separate_scan(index):
            barrier.wait()
            return DestinationPolicy(resolvers[index]).validate(f"https://scan-{index}.test/", purpose="initial")
        with ThreadPoolExecutor(max_workers=6) as pool:
            grants = list(pool.map(separate_scan, range(6)))
    require(len(grants) == 6 and harness.peak == 4, "separate resolver instances exceeded the process-wide cap")
    harness.assert_cleanup()

    harness = Harness(["public"])
    with patch("scanner.bounded_resolver.run_worker_command", side_effect=harness):
        resolver = BoundedSystemResolver(lookup_seconds=1.5, max_parallel=1, max_lookups=1)
        resolver._slots.acquire()
        started = time.monotonic()
        try:
            reject(lambda: resolver("xray.test", 443), "dns-timeout")
        finally:
            resolver._slots.release()
        require(time.monotonic() - started < 2 and not harness.paths, "semaphore wait escaped lookup budget")
        resolver("xray.test", 443)
        reject(lambda: resolver("xray.test", 443), "dns-lookup-limit")
        resolver._expires = time.monotonic() - 1
        reject(lambda: resolver("xray.test", 443), "dns-timeout")
    harness.assert_cleanup()

    harness = Harness(["public"])
    with patch("scanner.bounded_resolver.run_worker_command", side_effect=harness):
        resolver = BoundedSystemResolver(lookup_seconds=1.5)
        for _ in range(4):
            _PROCESS_SLOTS.acquire()
        started = time.monotonic()
        try:
            reject(lambda: resolver("xray.test", 443), "dns-timeout")
        finally:
            for _ in range(4):
                _PROCESS_SLOTS.release()
        require(time.monotonic() - started < 2 and not harness.paths,
                "process-wide slot wait escaped the lookup budget")
        require(len(resolver("xray.test", 443)) == 2, "process slot timeout leaked an instance slot")
    harness.assert_cleanup()

    with patch("scanner.bounded_resolver.run_worker_command") as launch:
        resolver = BoundedSystemResolver()
        for host, port in (("xray.test?secret", 443), ("xray.test/path", 443), ("xray.test.", 443),
            ("XRAY.test", 443), ("xray.test\n", 443), ("user@xray.test", 443), ("*.test", 443),
            ("127.0.0.1", 443), ("localhost", 443), ("é.test", 443), ("xray.test", True), ("xray.test", 80.0)):
            reject(lambda host=host, port=port: resolver(host, port), "invalid-dns-query")
        require(not launch.called, "invalid query started a resolver process")
        for configuration in ({"lookup_seconds": 3.001}, {"lookup_seconds": 5}, {"lookup_seconds": True},
            {"max_parallel": 5}, {"max_parallel": 16}, {"lifetime_seconds": 15.001}, {"max_lookups": 501}):
            try:
                BoundedSystemResolver(**configuration)
            except ValueError:
                pass
            else:
                raise AssertionError("resolver configuration exceeded a hard ceiling")
    with patch("scanner.worker_supervisor.subprocess.Popen") as launch:
        for limit in (0, -1, True, 2_048.0, None, MAX_WORKER_RESULT_BYTES + 1):
            try:
                run_worker_command(["unused"], result_path="unused-result.json", max_result_bytes=limit)
            except ValueError:
                pass
            else:
                raise AssertionError("supervisor accepted an invalid narrowed result limit")
        require(not launch.called, "invalid result limit created a process")
    for failure in (OSError("fixture-secret"), RuntimeError("fixture-secret")):
        with patch("scanner.bounded_resolver.run_worker_command", side_effect=failure):
            reject(lambda: BoundedSystemResolver()("xray.test", 443), "dns-unavailable")

    harness = Harness(["stdout"])
    with patch("scanner.bounded_resolver.run_worker_command", side_effect=harness):
        require(len(BoundedSystemResolver()("xray.test", 443)) == 2, "closed provider streams blocked resolution")
    harness.assert_cleanup()
    print(f"Verified fresh process DNS: {len(failed_modes)} failure/answer cases, getaddrinfo protocol and 16-answer fence, "
          "strict 2KiB nonce/shape admission, no answer cache, whole-set private/rebinding denial, real timeout/descendant "
          "termination, semaphore/lifetime/lookup limits, isolated private inputs, and cleanup. DNS was deterministic; "
          "deployment resolver configuration and independent browser egress containment remain open.")
    if options.public:
        started = time.monotonic()
        grant = DestinationPolicy(BoundedSystemResolver()).validate("https://www.python.org/", purpose="initial")
        print(f"Live system DNS smoke: www.python.org admitted {len(grant.addresses)} public answers in "
              f"{round((time.monotonic() - started) * 1000)}ms. No origin socket or HTTP request; not deployment proof.")


if __name__ == "__main__":
    main()
