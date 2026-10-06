"""Native local journal/lock/process-crash tests; does not reclaim Docker."""

import json
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.lease_journal import LeaseJournal, MAX_BYTES
from scanner.docker_worker_supervisor import _PipeProcess

TOKEN, FINGERPRINT, IDENTIFIER = 'a' * 32, 'b' * 64, 'c' * 64


def require(value, message):
    if not value:
        raise AssertionError(message)


def rejects(callback):
    try:
        callback()
    except (ValueError, OSError, sqlite3.Error):
        return
    raise AssertionError('invalid journal action accepted')


def begin(journal, token=TOKEN):
    journal.create(token, FINGERPRINT, int(time.time() * 1000) + 15000)
    journal.engine(token, 'fixture-engine-identity')


def child(mode, directory):
    if mode == '--contend':
        try:
            LeaseJournal(directory).close()
        except OSError:
            sys.stdout.buffer.write(b'locked\n')
            return
        raise AssertionError('second controller acquired ownership')
    with LeaseJournal(directory) as journal:
        begin(journal)
        journal.intent(TOKEN, 'volume')
        journal.created(TOKEN, 'volume')
        journal.intent(TOKEN, 'initialize')
        journal.created(TOKEN, 'initialize', IDENTIFIER)
        journal.intent(TOKEN, 'broker')
        sys.stdout.buffer.write(b'journal-ready\n')
        sys.stdout.buffer.flush()
        sys.stdin.buffer.read()


def main():
    if len(sys.argv) == 3:
        child(sys.argv[1], Path(sys.argv[2]))
        return
    with tempfile.TemporaryDirectory(prefix='dxr-journal-') as temporary:
        parent = Path(temporary).resolve()
        root = parent / 'journal'
        with LeaseJournal(root) as journal:
            begin(journal)
            journal.intent(TOKEN, 'volume')
            rejects(lambda: journal.finish(TOKEN))
            rejects(lambda: journal.removed(TOKEN, 'volume'))
            rejects(lambda: journal.created(TOKEN, 'worker', IDENTIFIER))
            journal.created(TOKEN, 'volume')
            rejects(lambda: journal.intent(TOKEN, 'worker'))
            journal.intent(TOKEN, 'initialize')
            journal.created(TOKEN, 'initialize', 'd' * 64)
            journal.intent(TOKEN, 'broker')
            journal.created(TOKEN, 'broker', 'e' * 64)
            journal.intent(TOKEN, 'worker')
            journal.created(TOKEN, 'worker', IDENTIFIER)
            rejects(lambda: journal.removed(TOKEN, 'volume'))
            snapshot = journal.snapshot()[0]
            require(snapshot['resources']['worker']['id'] == IDENTIFIER, 'created identity lost')
            require(not any(value in json.dumps(snapshot) for value in ('https://', '1.1.1.1', 'capability', 'nonce', 'grant')),
                    'journal contains scan content')
            require(os.get_inheritable(journal.lock_fd) is False, 'owner lock inheritable')
            with journal.hold():
                rejects(journal.close)
            journal.removed(TOKEN, 'worker')
            journal.removed(TOKEN, 'broker')
            journal.removed(TOKEN, 'initialize')
            journal.removed(TOKEN, 'volume')
            journal.finish(TOKEN)
            require(journal.snapshot() == [], 'fully removed lease retained')
            print('intent/ID/removal ordering and content-free exclusive owner: verified')

            with patch('scanner.lease_journal.MAX_ROWS', 2):
                begin(journal, '1' * 32)
                begin(journal, '2' * 32)
                rejects(lambda: begin(journal, '3' * 32))
                journal.finish('1' * 32)
                journal.finish('2' * 32)
            print('transactional capacity boundary: backpressure, no row evicted')

            old_size = journal.path.stat().st_size
            os.truncate(journal.path, MAX_BYTES + 1)
            rejects(journal.snapshot)
            os.truncate(journal.path, old_size)
            link = parent / 'journal-hardlink'
            os.link(journal.path, link)
            rejects(journal.snapshot)
            link.unlink()
            require(journal.snapshot() == [], 'valid journal damaged by size/link canary')
            with closing(sqlite3.connect(journal.path)) as connection:
                connection.execute('CREATE TRIGGER hostile AFTER INSERT ON leases BEGIN DELETE FROM leases; END')
                connection.commit()
            rejects(journal.snapshot)
            with closing(sqlite3.connect(journal.path)) as connection:
                connection.execute('DROP TRIGGER hostile')
                connection.commit()
            require(journal.snapshot() == [], 'schema canary cleanup failed')
            print('oversized file, hardlink and unexpected schema: rejected before journal mutation')

        crash_root = parent / 'crash-journal'
        owner = _PipeProcess([sys.executable, '-I', str(Path(__file__).resolve()), '--hold', str(crash_root)],
                             b'', 1024, keep_stdin=True)
        try:
            owner.wait_prefix(b'journal-ready\n', time.monotonic() + 5)
            competitor = _PipeProcess([sys.executable, '-I', str(Path(__file__).resolve()), '--contend', str(crash_root)],
                                      b'', 1024)
            try:
                code, output = competitor.finish(time.monotonic() + 5)
                require(code == 0 and output == b'locked\n', 'second controller was not excluded')
            finally:
                competitor.stop(time.monotonic() + 1)
            owner.stop(time.monotonic() + 1)
            require(owner.process.returncode != 0, 'owner exited gracefully instead of forced termination')
        finally:
            owner.stop(time.monotonic() + 1)
        with LeaseJournal(crash_root) as replacement:
            records = replacement.snapshot()
            require(len(records) == 1 and records[0]['resources']['initialize'] == {'state': 'created', 'id': IDENTIFIER}
                    and records[0]['resources']['broker'] == {'state': 'intent', 'id': None}, 'crash lost durable intent/ID')
            rejects(lambda: replacement.finish(TOKEN))
            require(len(replacement.snapshot()) == 1, 'unresolved intent silently forgotten')
        print('forced owner termination: lock released, replacement retains committed ID and unresolved intent')
    print('Verified local journal persistence; automatic Docker recovery, power-loss and watchdog deployment remain unproven.')


if __name__ == '__main__':
    main()
