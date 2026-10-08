"""Bounded operator-only recovery scheduling; no discovery or service installation.

One completed visit at a time. This is not hard-real-time isolation between
entries: non-preemptible journal operations can still delay other entries.
"""

from dataclasses import dataclass
import math
from threading import Event, Lock
from time import monotonic

from scanner.docker_worker_supervisor import _require
from scanner.lease_recovery_poller import LeaseRecoveryPoller, PollOutcome

MAX_RECOVERY_ROOTS = 8


@dataclass(frozen=True)
class RegistryOutcome:
    entry_index: int | None
    outcome: PollOutcome | None
    delay_seconds: float


class LeaseRecoveryRegistry:
    def __init__(self, pollers):
        _require(type(pollers) is tuple and 1 <= len(pollers) <= MAX_RECOVERY_ROOTS,
                 'recovery-registry-size')
        _require(all(type(poller) is LeaseRecoveryPoller for poller in pollers), 'recovery-registry-entry')
        _require(len({poller.root for poller in pollers}) == len(pollers)
                 and len({poller.identities[0] for poller in pollers}) == len(pollers),
                 'recovery-registry-duplicate')
        self.pollers, self.position, self.mutex = pollers, 0, Lock()
        self.due = [self._now()] * len(pollers)

    @staticmethod
    def _now():
        value = monotonic()
        _require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
                 'recovery-registry-clock')
        return value

    def tick(self):
        with self.mutex:
            now = self._now()
            count = len(self.pollers)
            for offset in range(count):
                index = (self.position + offset) % count
                if self.due[index] > now:
                    continue
                outcome = self.pollers[index].tick()
                # Typed pollers own all filesystem/provider failure handling.
                # Scheduling state contains no journal path or cleanup token.
                self.due[index] = self._now() + outcome.delay_seconds
                self.position = (index + 1) % count
                delay = max(0.0, min(self.due) - self._now())
                return RegistryOutcome(index, outcome, min(30.0, delay))
            return RegistryOutcome(None, None, min(30.0, max(0.0, min(self.due) - now)))

    def run(self, stop, *, on_status=None, max_ticks=None):
        _require(isinstance(stop, Event) and (on_status is None or callable(on_status)), 'recovery-registry-loop')
        _require(max_ticks is None or type(max_ticks) is int and 1 <= max_ticks <= 1000,
                 'recovery-registry-loop-bound')
        count = 0
        while not stop.is_set() and (max_ticks is None or count < max_ticks):
            outcome = self.tick()
            count += 1
            if on_status is not None:
                on_status(outcome)
            if max_ticks is not None and count >= max_ticks:
                break
            stop.wait(outcome.delay_seconds)
        return count
