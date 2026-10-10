"""Deterministic scan deduplication and per-origin cooling primitives.

This module does not choose production durations. Callers must supply both
windows explicitly so product/security policy remains a deployment decision.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class AdmissionDecision:
    action: str
    reason: str | None = None
    retry_after_seconds: int | None = None
    reusable_result_id: str | None = None


@dataclass
class _TargetReservation:
    reserved_at: float
    result_id: str | None = None


def _canonical_target(url: str) -> tuple[str, str]:
    """Return normalized target and origin keys for an already validated URL."""

    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("scan admission requires an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("scan admission does not accept URL credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("scan admission expects a query-free, fragment-free target")

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower().rstrip(".")
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 80 if scheme == "http" else 443
    port = f":{parsed.port}" if parsed.port and parsed.port != default_port else ""
    authority = f"{host}{port}"
    origin = urlunsplit((scheme, authority, "", "", ""))
    target = urlunsplit((scheme, authority, parsed.path or "/", "", ""))
    return target, origin


class ScanAdmissionGate:
    """Reserve new scans, reuse recent exact results, and cool each origin."""

    def __init__(
        self,
        *,
        duplicate_window_seconds: float,
        origin_cooling_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        max_target_reservations: int = 4096,
        max_origin_reservations: int = 4096,
    ) -> None:
        for window in (duplicate_window_seconds, origin_cooling_seconds):
            if type(window) not in (int, float):
                raise ValueError("admission windows must be positive and finite")
            try:
                valid = math.isfinite(window) and window > 0
            except OverflowError:
                valid = False
            if not valid:
                raise ValueError("admission windows must be positive and finite")
        for limit in (max_target_reservations, max_origin_reservations):
            if type(limit) is not int or limit <= 0:
                raise ValueError("admission capacities must be positive integers")
        if duplicate_window_seconds < origin_cooling_seconds:
            raise ValueError("duplicate window must cover the origin cooling window")
        self.duplicate_window_seconds = float(duplicate_window_seconds)
        self.origin_cooling_seconds = float(origin_cooling_seconds)
        self.max_target_reservations = max_target_reservations
        self.max_origin_reservations = max_origin_reservations
        self._clock = clock
        self._targets: dict[str, _TargetReservation] = {}
        self._origins: dict[str, float] = {}
        self._last_now: float | None = None
        self._lock = Lock()

    def _now(self) -> float:
        value = float(self._clock())
        if not math.isfinite(value):
            raise ValueError("admission clock must be finite")
        if self._last_now is not None and value < self._last_now:
            raise ValueError("admission clock moved backwards")
        self._last_now = value
        return value

    @staticmethod
    def _retry_after(expires_at: float, now: float) -> int:
        return max(1, math.ceil(expires_at - now))

    def _prune(self, now: float) -> None:
        self._targets = {
            key: reservation
            for key, reservation in self._targets.items()
            if reservation.result_id is None
            or now - reservation.reserved_at < self.duplicate_window_seconds
        }
        self._origins = {
            key: reserved_at
            for key, reserved_at in self._origins.items()
            if now - reserved_at < self.origin_cooling_seconds
        }

    def reserve(self, url: str) -> AdmissionDecision:
        target, origin = _canonical_target(url)
        with self._lock:
            now = self._now()
            self._prune(now)

            existing = self._targets.get(target)
            if existing is not None:
                if existing.result_id is not None:
                    return AdmissionDecision(
                        action="reuse",
                        reason="recent-identical-scan",
                        reusable_result_id=existing.result_id,
                    )
                return AdmissionDecision(
                    action="reject",
                    reason="identical-scan-in-flight",
                    retry_after_seconds=self._retry_after(
                        existing.reserved_at + self.duplicate_window_seconds,
                        now,
                    ),
                )

            origin_reserved_at = self._origins.get(origin)
            if origin_reserved_at is not None:
                return AdmissionDecision(
                    action="reject",
                    reason="origin-cooling",
                    retry_after_seconds=self._retry_after(
                        origin_reserved_at + self.origin_cooling_seconds,
                        now,
                    ),
                )

            waits = []
            if len(self._targets) >= self.max_target_reservations:
                expiries = [reservation.reserved_at + self.duplicate_window_seconds
                            for reservation in self._targets.values() if reservation.result_id is not None]
                waits.append(self._retry_after(min(expiries), now) if expiries else 1)
            if len(self._origins) >= self.max_origin_reservations:
                waits.append(self._retry_after(
                    min(self._origins.values()) + self.origin_cooling_seconds, now))
            if waits:
                return AdmissionDecision(action="reject", reason="admission-capacity",
                                         retry_after_seconds=max(waits))

            self._targets[target] = _TargetReservation(reserved_at=now)
            self._origins[origin] = now
            return AdmissionDecision(action="scan")

    def complete(self, url: str, result_id: str) -> None:
        if not result_id:
            raise ValueError("completed scan requires a reusable result ID")
        target, _origin = _canonical_target(url)
        with self._lock:
            reservation = self._targets.get(target)
            if reservation is None:
                raise ValueError("cannot complete an unreserved scan")
            reservation.result_id = result_id

    def abandon(self, url: str) -> None:
        """Release an unfinished exact-target reservation after terminal failure.

        The origin cooling timestamp deliberately remains. A failed worker must
        not pin the exact target for the full duplicate window, but it also must
        not let a caller immediately hammer the same origin.
        """

        target, _origin = _canonical_target(url)
        with self._lock:
            reservation = self._targets.get(target)
            if reservation is not None and reservation.result_id is None:
                del self._targets[target]

    def forget_result(self, result_id: str) -> None:
        """Remove completed exact-target mappings after deletion or expiry.

        Origin cooling deliberately remains in force so deletion cannot become
        an immediate rescan bypass.
        """

        if not result_id:
            raise ValueError("result ID is required")
        with self._lock:
            self._targets = {
                target: reservation
                for target, reservation in self._targets.items()
                if reservation.result_id != result_id
            }
