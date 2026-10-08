"""Independent replacement-owner polling component, not a lease enforcer.

One operator-registered existing journal/runtime; no discovery, scans or results.
Busy live owners are never displaced. Deployment and overall deadlines remain gates.
"""

from dataclasses import dataclass
import math
import os
from pathlib import Path
import stat
from threading import Event, Lock

from scanner.docker_broker_pair_supervisor import DockerBrokerPairSupervisor
from scanner.docker_worker_supervisor import _require
from scanner.lease_journal import LeaseJournal, LeaseJournalBusy, MAX_BYTES
from scanner.lease_recovery import recover_expired_leases


@dataclass(frozen=True)
class PollOutcome:
    status: str
    delay_seconds: float
    resolved: int = 0
    retained: int = 0
    deferred: int = 0
    skipped: int = 0


class LeaseRecoveryPoller:
    def __init__(self, root, supervisor_factory, *, interval_seconds=0.5):
        _require(type(interval_seconds) in (int, float) and math.isfinite(interval_seconds)
                 and 0.25 <= interval_seconds <= 5, 'recovery-poller-interval')
        _require(callable(supervisor_factory), 'recovery-poller-factory')
        self.root, self.factory = Path(root), supervisor_factory
        self.identities = self._identities()
        prototype = self.factory(None)
        _require(isinstance(prototype, DockerBrokerPairSupervisor) and prototype.journal is None,
                 'recovery-poller-runtime')
        self.fingerprint = prototype.runtime_fingerprint()
        self.interval, self.cursor, self.failures = float(interval_seconds), None, 0
        self.mutex = Lock()

    def _identities(self):
        _require(self.root.is_absolute() and self.root.resolve(strict=True) == self.root,
                 'recovery-poller-root')
        identities = []
        for index, path in enumerate((self.root, self.root / 'owner.lock', self.root / 'leases.sqlite3')):
            metadata = path.lstat()
            _require(not path.is_symlink() and not getattr(metadata, 'st_file_attributes', 0) & 1024
                     and (stat.S_ISDIR(metadata.st_mode) if index == 0 else
                          stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= MAX_BYTES),
                     'recovery-poller-authority')
            identities.append((metadata.st_dev, metadata.st_ino))
        return tuple(identities)

    def _fault(self, status='fault', report=None):
        self.failures = min(10, self.failures + 1)
        delay = min(30.0, self.interval * 2**self.failures)
        return PollOutcome(status, delay, *(() if report is None else
            (report.resolved, report.retained, report.deferred, report.skipped)))

    def tick(self):
        # One instance cannot have overlapping passes or races in cursor state.
        with self.mutex:
            try:
                _require(self._identities() == self.identities, 'recovery-poller-authority-replaced')
                try:
                    journal = LeaseJournal(self.root, create=False)
                except LeaseJournalBusy:
                    return PollOutcome('busy', self.interval)
                with journal:
                    held = os.fstat(journal.lock_fd)
                    _require((held.st_dev, held.st_ino) == self.identities[1], 'recovery-poller-lock-replaced')
                    _require((journal.root_identity, journal.db_identity) == (self.identities[0], self.identities[2]),
                             'recovery-poller-authority-replaced')
                    supervisor = self.factory(journal)
                    _require(isinstance(supervisor, DockerBrokerPairSupervisor) and supervisor.journal is journal
                             and supervisor.runtime_fingerprint() == self.fingerprint, 'recovery-poller-runtime-drift')
                    after = journal.recovery_cursor(self.fingerprint)
                    report = recover_expired_leases(supervisor, after_token=after)
                    journal.save_recovery_cursor(self.fingerprint, report.next_after)
                    self.cursor = report.next_after
                if report.retained:
                    return self._fault('retained', report)
                self.failures = 0
                return PollOutcome('recovered' if report.resolved else 'waiting', self.interval,
                    report.resolved, report.retained, report.deferred, report.skipped)
            except Exception:
                # No raw filesystem/provider/configuration text crosses health.
                return self._fault()

    def run(self, stop, *, on_status=None, max_ticks=None):
        _require(isinstance(stop, Event) and (on_status is None or callable(on_status)), 'recovery-poller-loop')
        _require(max_ticks is None or type(max_ticks) is int and 1 <= max_ticks <= 1000, 'recovery-poller-loop-bound')
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
