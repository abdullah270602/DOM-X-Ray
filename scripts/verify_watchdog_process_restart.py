"""Real foreground process death/restart; unrequested leases, no Docker contact."""

from contextlib import contextmanager
import json
from pathlib import Path
import sys
import tempfile
from threading import Event, Thread
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.lease_journal import LeaseJournal
from scripts.verify_native_recovery_poller import spawn_job, stop_job
from scripts.verify_pair_controller_crash import job_empty
from scripts.verify_pair_supervisor_contract import require
from scripts.verify_recovery_configuration import make_fixture_configuration, write_fixture
from scripts.verify_recovery_paging import token


@contextmanager
def owned_launcher(arguments, expected_resolved):
    process, job = spawn_job(arguments)
    witnessed, failures, messages = Event(), [], []
    def read():
        try:
            while line := process.stdout.readline(4097):
                require(len(line) <= 4096 and line.endswith(b'\n') and len(messages) < 64,
                        'launcher output exceeded fixture bound')
                value = json.loads(line)
                messages.append(value)
                if value == {'entry_index': 0, 'outcome': {'status': 'recovered', 'delay_seconds': 0.5,
                        'resolved': expected_resolved, 'retained': 0, 'deferred': 5 if expected_resolved == 20 else 0,
                        'skipped': 0}}:
                    witnessed.set()
        except Exception as error:
            failures.append(type(error).__name__)
    reader = Thread(target=read, daemon=True)
    reader.start()
    try:
        require(witnessed.wait(5) and not failures, 'exact committed page receipt not observed')
        yield process, job, messages
    finally:
        try:
            stop_job(process, job)
        finally:
            reader.join(timeout=2)
            process.stdout.close()
        require(not reader.is_alive() and not failures, 'launcher pipe reader did not end cleanly')


def seed_expired(journal, fingerprint, index):
    journal.create(token(index), fingerprint, int(time.time() * 1000) + 15000)
    # Only this ephemeral fixture's unrequested lease is made past-eligible.
    # No kernel clock or production journal is changed.
    journal._change(token(index), lambda record: record.update(expiresAtMs=int(time.time() * 1000) - 6000))


def wait_empty(job):
    deadline = time.monotonic() + 5
    while not job_empty(job):
        require(time.monotonic() < deadline, 'launcher Job remained populated')
        time.sleep(0.01)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--child':
        from scripts import run_recovery_watchdog as launcher
        sys.argv.pop(1)
        original = launcher.emit
        def gate(value):
            original(value)
            if value.get('outcome', {}).get('resolved') == 20:
                # Test-only pause after the production launcher emits its
                # committed receipt. Avoid a 500ms parent-kill scheduling race.
                # No ownership lock/transaction is held at this boundary.
                Event().wait(20)
        with patch.object(launcher, 'emit', side_effect=gate):
            return launcher.main()
    require(sys.platform == 'win32', 'process-restart fixture requires Windows Jobs')
    with tempfile.TemporaryDirectory(prefix='dxr-watchdog-restart-') as temporary:
        parent = Path(temporary).resolve()
        config_root, _runtime, entries = make_fixture_configuration(parent, root_count=1)
        root, fingerprint = Path(entries[0]['root']), entries[0]['runtimeFingerprint']
        with LeaseJournal(root, create=False) as journal:
            for index in range(1, 26):
                seed_expired(journal, fingerprint, index)
        config = config_root / 'registry.json'
        digest = write_fixture(config, json.dumps({'version': 1, 'entries': entries}).encode())
        flags = ['-I', *(['-O'] if sys.flags.optimize else [])]
        arguments = [*flags, ROOT / 'scripts/run_recovery_watchdog.py', '--configuration', config,
                     '--configuration-sha256', digest]
        first_arguments = [*flags, Path(__file__).resolve(), '--child', '--configuration', config,
                           '--configuration-sha256', digest]
        with owned_launcher(first_arguments, 20) as (first, job, first_messages):
            require(first_messages[0] == {'status': 'registered', 'entries': 1},
                    'first launcher registration receipt missing')
            require(first.poll() is None, 'first launcher exited before forced death')
            job.terminate()
            first.wait(timeout=5)
            require(first.returncode == 1, 'launcher did not report the scoped Job termination code')
            wait_empty(job)
        with LeaseJournal(root, create=False) as journal:
            require(journal.recovery_cursor(fingerprint) == token(20)
                    and [row['token'] for row in journal.snapshot()] == [token(index) for index in range(21, 26)],
                    'death did not preserve exact first-page cursor and deferred obligations')
            # A new lower token distinguishes true persisted-position resume
            # from merely scanning the surviving records from the beginning.
            seed_expired(journal, fingerprint, 0)
        print('Forced launcher Job empty; committed cursor 20 and five deferred leases preserved.')
        with owned_launcher([*arguments, '--max-ticks', '1'], 6) as (second, job, messages):
            code = second.wait(timeout=5)
            require(code == 0, 'replacement launcher exit code=' + str(code))
            wait_empty(job)
        require(messages[0] == {'status': 'registered', 'entries': 1}
                and messages[-1] == {'status': 'stopped'}, 'replacement registration/stop receipts missing')
        with LeaseJournal(root, create=False) as journal:
            require(not journal.snapshot() and journal.recovery_cursor(fingerprint) == token(0),
                    'replacement failed persisted-position wrap or erased the cursor')
        require(not any('worker-result' in path.name for path in parent.rglob('*')), 'restart admitted a result')
        require(not any(str(parent) in str(message) for message in messages), 'health disclosed private authority')
        print('Replacement loaded same pinned configuration, resolved six leases and wrapped to cursor zero.')
    print('Verified real Windows launcher death/restart with durable paging; no Docker resources existed. '
          'Installed supervision, native Docker restart and overall deadlines remain open.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
