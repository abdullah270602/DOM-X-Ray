"""Actual private journals/ownership; simulated Docker, no deployment claim."""

from dataclasses import asdict
from pathlib import Path
import sys
import tempfile
from threading import Event, Thread
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.lease_journal import LeaseJournal
from scanner.lease_recovery_poller import LeaseRecoveryPoller
from scanner.lease_recovery_registry import LeaseRecoveryRegistry
from scanner.worker_supervisor import WorkerContainmentError
from scripts.verify_pair_supervisor_contract import instance, require
from scripts.verify_recovery_paging import token


def rejects(callback):
    try:
        callback()
    except WorkerContainmentError:
        return
    raise AssertionError('invalid registry configuration accepted')


def main():
    with tempfile.TemporaryDirectory(prefix='dxr-recovery-registry-') as temporary:
        parent = Path(temporary).resolve()
        calls = []
        def factory(journal):
            supervisor = instance()
            supervisor.journal = journal
            supervisor._call = lambda *_args: calls.append('unexpected')
            return supervisor
        roots = [parent / f'root-{index}' for index in range(9)]
        fingerprint = factory(None).runtime_fingerprint()
        for index, root in enumerate(roots):
            with LeaseJournal(root) as journal:
                journal.create(token(index + 1), fingerprint, int(time.time() * 1000) + 15000)
        pollers = tuple(LeaseRecoveryPoller(root, factory) for root in roots)
        for invalid in ((), list(pollers[:2]), pollers, (pollers[0], pollers[0]), (None,)):
            rejects(lambda: LeaseRecoveryRegistry(invalid))
        alias = LeaseRecoveryPoller(roots[0], factory)
        rejects(lambda: LeaseRecoveryRegistry((pollers[0], alias)))
        require(len(LeaseRecoveryRegistry(pollers[:8]).pollers) == 8, 'maximum valid registry rejected')
        full = LeaseRecoveryRegistry(pollers[:8])
        require([full.tick().entry_index for _ in range(8)] == list(range(8)),
                'full registry did not visit every due root once in order')
        print('bounded immutable registration and duplicate root/owner rejection: verified')

        clock = [100.0]
        with patch('scanner.lease_recovery_registry.monotonic', side_effect=lambda: clock[0]), \
             patch('scanner.lease_recovery.time.time', return_value=time.time() + 30):
            registry = LeaseRecoveryRegistry(pollers[:3])
            with LeaseJournal(roots[0], create=False):
                first = registry.tick()
                require(first.entry_index == 0 and first.outcome.status == 'busy'
                        and first.delay_seconds == 0, 'busy first entry delayed other due roots')
                second, third = registry.tick(), registry.tick()
                require([second.entry_index, third.entry_index] == [1, 2]
                        and second.outcome.resolved == third.outcome.resolved == 1,
                        'busy owner starved later registered roots')
                idle = registry.tick()
                require(idle.entry_index is None and idle.outcome is None and idle.delay_seconds == 0.5,
                        'registry ignored per-entry retry intervals')
                clock[0] += 0.5
                require(registry.tick().outcome.status == 'busy', 'registry displaced live owner')
            require([registry.tick().entry_index, registry.tick().entry_index] == [1, 2], 'rotation lost later roots')
            clock[0] += 0.5
            released = registry.tick()
            require(released.entry_index == 0 and released.outcome.resolved == 1,
                    'owner release did not allow normal recovery')
            require(not calls, 'empty-intent recovery contacted Docker')
            public = asdict(released)
            require(set(public) == {'entry_index', 'outcome', 'delay_seconds'}
                    and not any(str(root) in str(public) for root in roots), 'registry health exposed private authority')
        print('busy owner yields to other roots, due intervals, rotation, release and bounded health: verified')

        with patch('scanner.lease_recovery_registry.monotonic', side_effect=lambda: clock[0]), \
             patch('scanner.lease_recovery.time.time', return_value=time.time() + 30):
            registry = LeaseRecoveryRegistry(pollers[3:5])
            # Change only this fresh ephemeral fixture database, retaining root
            # and lock: no bootstrap is allowed by the existing poller.
            (roots[3] / 'leases.sqlite3').unlink()
            damaged, healthy = registry.tick(), registry.tick()
            require(damaged.entry_index == 0 and damaged.outcome.status == 'fault'
                    and healthy.entry_index == 1 and healthy.outcome.resolved == 1,
                    'damaged authority delayed healthy registered work')
            clock[0] += 0.5
            require(registry.tick().entry_index == 1, 'fault backoff blocked healthy root retry')
            require(not (roots[3] / 'leases.sqlite3').exists(), 'registry recreated missing authority')
        print('authority fault/backoff stays local; missing database never recreated: verified')

        with patch('scanner.lease_recovery_registry.monotonic', side_effect=lambda: clock[0]):
            registry = LeaseRecoveryRegistry(pollers[5:7])
            original = pollers[5].tick
            def slow_completed_pass():
                outcome = original()
                clock[0] += 2
                return outcome
            with patch.object(pollers[5], 'tick', side_effect=slow_completed_pass):
                completed = registry.tick()
            require(registry.due[0] == clock[0] + completed.outcome.delay_seconds
                    and completed.delay_seconds == 0 and registry.tick().entry_index == 1,
                    'pass duration consumed retry delay or skipped other due root')
        print('retry delay starts after completed work, not before it: verified')

        registry = LeaseRecoveryRegistry(pollers[5:8])
        observed, stop = [], Event()
        def status(outcome):
            observed.append(outcome)
            stop.set()
        require(registry.run(stop, on_status=status, max_ticks=10) == 1 and len(observed) == 1,
                'stop did not interrupt registry loop')
        require(registry.run(stop, max_ticks=1) == 0, 'pre-stopped registry contacted a root')
        for invalid in (0, -1, 1001, True, 1.0):
            rejects(lambda: registry.run(Event(), max_ticks=invalid))
        require(registry.run(Event(), max_ticks=1) == 1, 'valid one-tick bound rejected')
        class ObservableStop(Event):
            def __init__(self):
                super().__init__()
                self.waiting = Event()
                self.delay = None
            def wait(self, timeout=None):
                self.delay = timeout
                self.waiting.set()
                return super().wait(timeout)
        external = ObservableStop()
        ended, failures = [], []
        waiting_registry = LeaseRecoveryRegistry((pollers[8],))
        def run_waiting():
            try:
                ended.append(waiting_registry.run(external, max_ticks=1000))
            except Exception as error:
                failures.append(type(error).__name__)
        worker = Thread(target=run_waiting)
        worker.start()
        try:
            require(external.waiting.wait(2) and external.delay > 0, 'registry never entered timed wait')
            external.set()
            worker.join(timeout=1)
            require(not worker.is_alive() and ended == [1] and not failures,
                    'external stop failed to interrupt pending wait')
        finally:
            external.set()
            worker.join(timeout=2)
        print('interruptible loop and invalid run bounds: verified')
    print('Verified bounded registry with actual journals and OS locks; native multi-root, service supervision and overall deadlines remain open.')


if __name__ == '__main__':
    main()
