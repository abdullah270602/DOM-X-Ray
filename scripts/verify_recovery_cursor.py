"""Actual journal cursor transactions/process death, simulated daemon scheduling."""

from contextlib import closing
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.docker_worker_supervisor import _PipeProcess
from scanner.lease_journal import LeaseJournal
from scanner.lease_recovery import recover_expired_leases
from scanner.lease_recovery_poller import LeaseRecoveryPoller
from scripts.verify_lease_journal import rejects
from scripts.verify_pair_supervisor_contract import instance, require
from scripts.verify_recovery_paging import Pool, token


class FailingConnection:
    def __init__(self, connection, statement):
        self.connection, self.statement = connection, statement

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def execute(self, statement, *args):
        if statement.startswith(self.statement):
            raise sqlite3.OperationalError('fixture transaction failure')
        return self.connection.execute(statement, *args)


def failed_save(journal, fingerprint, after, statement):
    original = journal.connection
    journal.connection = FailingConnection(original, statement)
    try:
        rejects(lambda: journal.save_recovery_cursor(fingerprint, after))
    finally:
        journal.connection = original
    require(not original.in_transaction, 'failed cursor transaction remained open')


def child(root):
    with LeaseJournal(root, create=False) as journal:
        journal.save_recovery_cursor(instance().runtime_fingerprint(), token(17))
        sys.stdout.buffer.write(b'cursor-committed\n')
        sys.stdout.buffer.flush()
        sys.stdin.buffer.read()


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--child':
        child(Path(sys.argv[2]))
        return
    fingerprint = instance().runtime_fingerprint()
    with tempfile.TemporaryDirectory(prefix='dxr-recovery-cursor-') as temporary:
        parent = Path(temporary).resolve()
        root = parent / 'transactions'
        with LeaseJournal(root) as journal:
            journal.create(token(1), fingerprint, int(time.time() * 1000) + 15000)
            before = journal.snapshot()
            require(journal.recovery_cursor(fingerprint) is None, 'legacy cursor not empty')
            require(not journal.connection.execute("SELECT 1 FROM sqlite_schema WHERE name='recovery_cursor'").fetchone(),
                    'read silently extended legacy schema')
            failed_save(journal, fingerprint, token(1), 'INSERT INTO recovery_cursor')
            require(journal.recovery_cursor(fingerprint) is None and journal.snapshot() == before,
                    'failed extension changed authority or cursor')
            require(not journal.connection.execute("SELECT 1 FROM sqlite_schema WHERE name='recovery_cursor'").fetchone(),
                    'failed extension left an empty cursor table')
            journal.save_recovery_cursor(fingerprint, token(1))
            failed_save(journal, fingerprint, token(2), 'COMMIT')
            require(journal.recovery_cursor(fingerprint) == token(1), 'failed commit advanced cursor')
            for invalid in ('', 'A' * 32, 'f' * 31, 1, True):
                rejects(lambda: journal.save_recovery_cursor(fingerprint, invalid))
            rejects(lambda: journal.recovery_cursor('e' * 64))
            rejects(lambda: journal.save_recovery_cursor('e' * 64, token(2)))
            with journal.hold():
                rejects(lambda: journal.save_recovery_cursor(fingerprint, token(2)))
            require(journal.snapshot() == before and journal.recovery_cursor(fingerprint) == token(1),
                    'invalid cursor action changed authority')
        with LeaseJournal(root, create=False) as restarted:
            require(restarted.recovery_cursor(fingerprint) == token(1) and restarted.snapshot() == before,
                    'restart lost cursor or obligations')
            restarted.save_recovery_cursor(fingerprint, None)
            require(restarted.recovery_cursor(fingerprint) is None, 'null cursor was not preserved')
        print('legacy read, atomic schema extension/update rollback, validation and reopen: verified')

        pool_root = parent / 'paging'
        with LeaseJournal(pool_root) as journal:
            supervisor = instance()
            supervisor.journal = journal
            pool = Pool(supervisor, journal, (1, 2, 3))
            pool.daemons[1].present.remove('worker')
            expiry = max(row['expiresAtMs'] for row in journal.snapshot())
        def factory(journal):
            value = instance()
            value.journal = journal
            value._call, value._inspect = pool.call, pool.inspect
            return value
        def single_pass(supervisor, *, after_token):
            return recover_expired_leases(supervisor, max_leases=1,
                now_ms=expiry + 5000, after_token=after_token)
        with patch('scanner.lease_recovery_poller.recover_expired_leases', side_effect=single_pass):
            first = LeaseRecoveryPoller(pool_root, factory)
            require(first.tick().status == 'retained' and first.cursor == token(1), 'retained first page did not commit cursor')
            second = LeaseRecoveryPoller(pool_root, factory)
            require(second.cursor is None, 'fixture accidentally inherited volatile cursor')
            require(second.tick().resolved == 1 and second.cursor == token(2), 'restart starved later eligible lease')
            third = LeaseRecoveryPoller(pool_root, factory)
            with patch.object(LeaseJournal, 'save_recovery_cursor', side_effect=ValueError('fixture write fault')):
                require(third.tick().status == 'fault' and third.cursor is None, 'cursor write failure reported successful pass')
            with LeaseJournal(pool_root, create=False) as journal:
                require(journal.recovery_cursor(fingerprint) == token(2), 'failed save advanced durable cursor')
                require([row['token'] for row in journal.snapshot()] == [token(1)],
                        'cursor failure erased retained obligation or rolled back proven cleanup')
            calls_before = len(pool.calls)
            def drifted(journal):
                value = factory(journal)
                value.image_id = 'sha256:' + 'f' * 64
                return value
            require(LeaseRecoveryPoller(pool_root, drifted).tick().status == 'fault'
                    and len(pool.calls) == calls_before, 'persisted runtime mismatch contacted Docker')
            fourth = LeaseRecoveryPoller(pool_root, factory)
            require(fourth.tick().status == 'retained' and fourth.cursor == token(1), 'deleted cursor failed lexical wrap')
            pool.daemons[1].present.add('worker')
            require(LeaseRecoveryPoller(pool_root, factory).tick().resolved == 1, 'late owned resource did not resolve after restart')
        print('new poller instances resume retained pages; failed save faults; runtime drift and deleted cursor: verified')

        crash_root = parent / 'process-death'
        with LeaseJournal(crash_root):
            pass
        owner = _PipeProcess([sys.executable, '-I', str(Path(__file__).resolve()), '--child', str(crash_root)],
                             b'', 1024, keep_stdin=True)
        try:
            owner.wait_prefix(b'cursor-committed\n', time.monotonic() + 5)
            owner.stop(time.monotonic() + 1)
            require(owner.process.returncode != 0, 'fixture owner did not terminate forcibly')
        finally:
            owner.stop(time.monotonic() + 1)
        with LeaseJournal(crash_root, create=False) as journal:
            require(journal.recovery_cursor(fingerprint) == token(17), 'process death lost committed cursor')
        print('forced journal-owner process death preserves committed cursor: verified')

        for name, mutation in (
            ('bad-token', "UPDATE recovery_cursor SET afterToken='invalid'"),
            ('bad-fingerprint', "UPDATE recovery_cursor SET runtimeFingerprint='invalid'"),
            ('empty-table', 'DELETE FROM recovery_cursor'),
        ):
            damaged = parent / name
            with LeaseJournal(damaged) as journal:
                journal.save_recovery_cursor(fingerprint, token(1))
            damaged_poller = LeaseRecoveryPoller(damaged, factory)
            calls_before = len(pool.calls)
            with closing(sqlite3.connect(damaged / 'leases.sqlite3')) as connection:
                connection.execute(mutation)
                connection.commit()
            rejects(lambda: LeaseJournal(damaged, create=False))
            require(damaged_poller.tick().status == 'fault' and len(pool.calls) == calls_before,
                    'malformed cursor contacted Docker or was silently reset')
        print('malformed or missing cursor singleton: rejected, not reset')
    print('Verified actual local cursor persistence and simulated restart fairness; power-loss, native watchdog restart and deployment remain open.')


if __name__ == '__main__':
    main()
