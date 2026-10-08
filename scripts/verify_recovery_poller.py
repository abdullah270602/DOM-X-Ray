"""Actual journal/OS lock plus simulated Docker; no deployment claim."""

from contextlib import closing
from dataclasses import asdict
from pathlib import Path
import sqlite3
import sys
import tempfile
from threading import Event
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.lease_journal import LeaseJournal, LeaseJournalBusy
from scanner.lease_recovery_poller import LeaseRecoveryPoller
from scripts.verify_recovery_paging import Pool, token
from scripts.verify_pair_supervisor_contract import instance, require


def main():
    with tempfile.TemporaryDirectory(prefix='dxr-recovery-poller-') as temporary:
        parent = Path(temporary).resolve()
        root = parent / 'busy'
        calls, state = [], {'drift': False, 'factory_busy': False}
        def factory(journal):
            if state['factory_busy']:
                raise LeaseJournalBusy('fixture factory contention is not this root')
            value = instance()
            value.journal = journal
            if state['drift']:
                value.image_id = 'sha256:' + 'f' * 64
            value._call = lambda *_args: calls.append('unexpected-engine')
            return value
        with LeaseJournal(root) as primary:
            primary.create(token(1), factory(None).runtime_fingerprint(), int(time.time() * 1000) + 15000)
            expiry = primary.snapshot()[0]['expiresAtMs']
            poller = LeaseRecoveryPoller(root, factory)
            require(poller.tick().status == 'busy' and not calls, 'live owner was displaced/contacted engine')
        require(poller.tick().status == 'waiting' and not calls, 'future lease unexpectedly reclaimed')
        state['drift'] = True
        require(poller.tick().status == 'fault' and not calls, 'runtime drift was ignored')
        state['drift'], state['factory_busy'] = False, True
        require(poller.tick().status == 'fault', 'factory contention was misclassified as root ownership')
        state['factory_busy'] = False
        with patch('scanner.lease_recovery.time.time', return_value=(expiry + 5000) / 1000):
            result = poller.tick()
        require(result.status == 'recovered' and result.resolved == 1 and poller.failures == 0 and not calls,
                'replacement owner failed empty-intent recovery/reset')
        stop = Event()
        observed = []
        def notify(outcome):
            observed.append(outcome)
            stop.set()
        require(poller.run(stop, on_status=notify, max_ticks=10) == 1 and len(observed) == 1,
                'stop request did not end bounded polling loop')
        require(poller.run(stop, max_ticks=1) == 0, 'stopped loop performed another pass')
        require(set(asdict(result)) == {'status', 'delay_seconds', 'resolved', 'retained', 'deferred', 'skipped'},
                'health payload exposed authority or exception content')
        print('busy owner, future eligibility, runtime/factory fault, handoff, health and stop: verified')
        missing = parent / 'missing'
        try:
            LeaseJournal(missing, create=False)
        except ValueError:
            pass
        else:
            raise AssertionError('no-create mode created a missing root')
        require(not missing.exists(), 'missing root was bootstrapped')
        damaged = parent / 'damaged'
        with LeaseJournal(damaged):
            pass
        damaged_poller = LeaseRecoveryPoller(damaged, factory)
        (damaged / 'leases.sqlite3').unlink()  # only this freshly created ephemeral fixture file
        require(damaged_poller.tick().status == 'fault' and not (damaged / 'leases.sqlite3').exists(),
                'missing authority was recreated/reported idle')
        try:
            LeaseJournal(damaged, create=False)
        except ValueError:
            pass
        else:
            raise AssertionError('no-create mode bootstrapped missing database')
        require(not (damaged / 'leases.sqlite3').exists(), 'database was silently recreated')
        print('missing root/database: fault with no bootstrap: verified')
        schema_root = parent / 'schema'
        with LeaseJournal(schema_root):
            pass
        schema_poller = LeaseRecoveryPoller(schema_root, factory)
        with closing(sqlite3.connect(schema_root / 'leases.sqlite3')) as connection:
            connection.execute('CREATE TABLE unexpected (value TEXT)')
            connection.commit()
        require(schema_poller.tick().status == 'fault' and not calls, 'damaged schema was treated as busy/empty')
        with closing(sqlite3.connect(schema_root / 'leases.sqlite3')) as connection:
            connection.execute('DROP TABLE unexpected')
            connection.commit()
        require(schema_poller.tick().status == 'waiting' and schema_poller.failures == 0,
                'validated repair did not clear fault backoff')
        print('schema fault and validated repair: verified')
        lock_root = parent / 'lock-swap'
        with LeaseJournal(lock_root):
            pass
        lock_poller = LeaseRecoveryPoller(lock_root, factory)
        def swap_lock(path, *, create):
            require(create is False, 'poller attempted authority bootstrap')
            (path / 'owner.lock').rename(parent / 'saved-fixture-lock')
            # Simulate replacement between the poller's metadata check and its
            # acquisition. Only this new, empty, ephemeral fixture root changes.
            with LeaseJournal(path):
                pass
            return LeaseJournal(path, create=False)
        with patch('scanner.lease_recovery_poller.LeaseJournal', side_effect=swap_lock):
            require(lock_poller.tick().status == 'fault' and not calls,
                    'replacement lock inode authorized recovery')
        print('lock replacement between inspection/acquisition: fault before recovery: verified')
        pool_root = parent / 'pool'
        with LeaseJournal(pool_root) as journal:
            source = instance()
            source.journal = journal
            pool = Pool(source, journal, (1, 2))
            expiry = max(r['expiresAtMs'] for r in journal.snapshot())
        def pool_factory(journal):
            value = instance()
            value.journal = journal
            value._call, value._inspect = pool.call, pool.inspect
            return value
        pooled = LeaseRecoveryPoller(pool_root, pool_factory)
        pool.outage = True
        with patch('scanner.lease_recovery.time.time', return_value=(expiry + 5000) / 1000):
            delays = [pooled.tick().delay_seconds for _ in range(10)]
            require(delays[0] == 1 and delays[-1] == 30 and pooled.failures == 10
                    and all(not d.removed for d in pool.daemons.values()), 'outage backoff unbounded or mutated resources')
            pool.outage = False
            recovered = pooled.tick()
        require(recovered.status == 'recovered' and recovered.resolved == 2 and pooled.failures == 0,
                'resumed daemon did not recover/reset')
        print('retained authority, bounded outage backoff and resumed cleanup: verified')
    print('Verified polling component with actual journal/OS lock and simulated daemon; native independence has a separate verifier, deployment remains open.')


if __name__ == '__main__':
    main()
