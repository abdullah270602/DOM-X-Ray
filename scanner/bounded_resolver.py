"""Fresh system DNS in deadline-supervised helper processes.

This resolver returns observations, not connection authority. Always compose it
with DestinationPolicy; an OS answer containing private addresses is rejected
there as a whole. The deployment must pin its OS resolver configuration and
independently prevent browser network bypass.
"""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from threading import Lock, Semaphore
import time

from scanner.destination_policy import DestinationPolicy, DestinationPolicyError, MAX_DNS_ANSWERS
from scanner.worker_supervisor import MIN_WORKER_SECONDS, run_worker_command

MAX_RESOLVER_BYTES = 2_048
_WORKER = Path(__file__).with_name("resolver_worker.py").resolve()
_PROCESS_SLOTS = Semaphore(4)


def _reject(reason):
    raise DestinationPolicyError(reason)


def _hostname(hostname, port):
    if isinstance(port, bool) or not isinstance(port, int) or port not in {80, 443}:
        _reject("invalid-dns-query")
    if not isinstance(hostname, str) or not hostname or len(hostname) > 253:
        _reject("invalid-dns-query")
    try:
        grant = DestinationPolicy(lambda _host, _port: ["1.1.1.1"]).validate(
            f"https://{hostname}:{port}/", purpose="initial")
        if grant.hostname != hostname:
            raise ValueError("noncanonical")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError("literal")
    except ValueError:
        _reject("invalid-dns-query")


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _read_answers(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_RESOLVER_BYTES:
        raise ValueError("invalid resolver artifact")
    payload = json.loads(path.read_bytes(), object_pairs_hook=_strict_object)
    if (not isinstance(payload, dict) or set(payload) != {"supervisorNonce", "result"}
            or not isinstance(payload["supervisorNonce"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", payload["supervisorNonce"])):
        raise ValueError("invalid resolver envelope")
    result = payload["result"]
    if not isinstance(result, dict) or set(result) != {"outcome", "addresses"}:
        raise ValueError("invalid resolver result")
    addresses, outcome = result["addresses"], result["outcome"]
    if not isinstance(addresses, list) or not isinstance(outcome, str):
        raise ValueError("invalid resolver result")
    if outcome != "resolved":
        if addresses or outcome not in {"unavailable", "answer-limit", "invalid-answer"}:
            raise ValueError("invalid resolver result")
        _reject({"unavailable": "dns-unavailable", "answer-limit": "dns-answer-limit",
                 "invalid-answer": "invalid-dns-answer"}[outcome])
    if not 1 <= len(addresses) <= MAX_DNS_ANSWERS:
        raise ValueError("invalid resolver answers")
    for address in addresses:
        if not isinstance(address, str) or "%" in address or ipaddress.ip_address(address).compressed != address:
            raise ValueError("invalid resolver answer")
    return tuple(addresses)


class BoundedSystemResolver:
    """One scan's bounded resolver callable, with no answer cache.

    Each call includes semaphore wait, setup, and helper execution in its lookup
    budget. A one-second supervisor minimum is required before launching.
    An external worker deadline remains necessary for OS/filesystem stalls.
    """

    def __init__(self, *, lookup_seconds: float = 3.0, lifetime_seconds: float = 15.0,
                 max_parallel: int = 4, max_lookups: int = 500):
        for value, minimum, maximum in ((lookup_seconds, MIN_WORKER_SECONDS, 3.0),
                                        (lifetime_seconds, MIN_WORKER_SECONDS, 15.0)):
            if (isinstance(value, bool) or not isinstance(value, (float, int))
                    or not minimum <= value <= maximum):
                raise ValueError("invalid resolver configuration")
        if (isinstance(max_parallel, bool) or not isinstance(max_parallel, int) or not 1 <= max_parallel <= 4
                or isinstance(max_lookups, bool) or not isinstance(max_lookups, int) or not 1 <= max_lookups <= 500):
            raise ValueError("invalid resolver configuration")
        self._lookup_seconds = lookup_seconds
        self._expires = time.monotonic() + lifetime_seconds
        self._slots = Semaphore(max_parallel)
        self._count_lock = Lock()
        self._lookups = 0
        self._max_lookups = max_lookups

    def __call__(self, hostname, port):
        _hostname(hostname, port)
        deadline = min(self._expires, time.monotonic() + self._lookup_seconds)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self._slots.acquire(timeout=remaining):
            _reject("dns-timeout")
        process_slot = False
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not _PROCESS_SLOTS.acquire(timeout=remaining):
                _reject("dns-timeout")
            process_slot = True
            with self._count_lock:
                if self._lookups >= self._max_lookups:
                    _reject("dns-lookup-limit")
                self._lookups += 1
            environment = {key: value for key, value in os.environ.items()
                           if key.upper() in {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE"}}
            with tempfile.TemporaryDirectory(prefix="dom-xray-dns-") as temporary:
                directory = Path(temporary)
                directory.chmod(0o700)
                environment["TEMP"] = str(directory)
                environment["TMP"] = str(directory)
                path = directory / "answers.json"
                query = directory / "query.json"
                descriptor = os.open(query, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(json.dumps({"hostname": hostname, "port": port},
                                            separators=(",", ":")).encode("ascii"))
                remaining = deadline - time.monotonic()
                if remaining < MIN_WORKER_SECONDS:
                    _reject("dns-timeout")
                run = run_worker_command([sys.executable, "-I", "-S", str(_WORKER), str(query), str(path)],
                    result_path=path, deadline_seconds=remaining, cwd=directory, environment=environment,
                    max_result_bytes=MAX_RESOLVER_BYTES)
                if run.outcome == "timeout" or time.monotonic() >= deadline:
                    _reject("dns-timeout")
                if not run.artifact_eligible:
                    _reject("dns-unavailable")
                answers = _read_answers(path)
            if time.monotonic() >= deadline:
                _reject("dns-timeout")
            return answers
        except DestinationPolicyError:
            raise
        except Exception:
            # Provider, process, filesystem, and artifact material are private.
            _reject("dns-unavailable")
        finally:
            if process_slot:
                _PROCESS_SLOTS.release()
            self._slots.release()


__all__ = ["BoundedSystemResolver"]
