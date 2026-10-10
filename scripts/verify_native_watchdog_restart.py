"""Forced foreground watchdog restart with a real Docker orphan; fixture only."""

import argparse
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
from threading import Event, Thread
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.docker_worker_supervisor import LABEL
from scanner.lease_journal import LeaseJournal
from scanner.lease_recovery import _name, recover_expired_leases
from scanner.lease_recovery_poller import LeaseRecoveryPoller
from scripts.verify_native_recovery_poller import spawn_job, stop_job
from scripts.verify_pair_controller_crash import controller, inventory_guard, wait_eligible
from scripts.verify_pair_supervisor_contract import require
from scripts.verify_recovery_configuration import write_fixture
from scripts.verify_watchdog_process_restart import seed_expired
from scripts.verify_docker_transport import PROFILE_SHA
from scripts.verify_pair_transport import ENTRY


class Receipts:
    def __init__(self, process):
        self.process = process
        self.messages, self.failures = [], []
        self.resolved = Event()
        self.thread = Thread(target=self.read, daemon=True)
        self.thread.start()

    def read(self):
        try:
            while line := self.process.stdout.readline(4097):
                require(len(line) <= 4096 and line.endswith(b'\n') and len(self.messages) < 128,
                        'native launcher output bound')
                value = json.loads(line)
                self.messages.append(value)
                if value == {'entry_index': 0, 'outcome': {'status': 'recovered', 'delay_seconds': 0.5,
                        'resolved': 1, 'retained': 0, 'deferred': 0, 'skipped': 0}}:
                    self.resolved.set()
        except Exception as error:
            self.failures.append(type(error).__name__)

    def close(self):
        self.thread.join(timeout=2)
        require(not self.thread.is_alive(), 'native launcher reader did not stop; pipe retained')
        self.process.stdout.close()
        require(not self.failures, 'native launcher reader failed')


def stop_owned_jobs(jobs):
    failures = []
    for process, job in reversed(jobs):
        try:
            stop_job(process, job)
        except Exception as error:
            failures.append(type(error).__name__)
    return failures


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--first':
        from scripts import run_recovery_watchdog as launcher
        sys.argv.pop(1)
        emit = launcher.emit
        def pause(value):
            emit(value)
            if value.get('outcome', {}).get('resolved') == 1:
                # Fixture-only gate after the committed receipt, outside locks.
                # Recovery/configuration code is not replaced. Parent kills Job.
                Event().wait(60)
        with patch.object(launcher, 'emit', side_effect=pause):
            return launcher.main()
    options = argparse.ArgumentParser()
    options.add_argument('--image', default='dom-x-ray-runtime-candidate:gate3-profile')
    args = options.parse_args()
    require(sys.platform == 'win32', 'native watchdog restart fixture requires Windows Jobs')
    executable = str(Path(shutil.which('docker')).resolve(strict=True))
    def docker(*arguments):
        return subprocess.run([executable, '--context', 'desktop-linux', *arguments],
            capture_output=True, check=True, timeout=10).stdout.decode().strip()
    image = docker('image', 'inspect', args.image, '--format', '{{.Id}}')
    before = docker('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL)
    volumes_before = docker('volume', 'ls', '-q', '--filter', 'label=' + LABEL)
    parent = ROOT / '.dom-xray-data' / ('native-watchdog-restart-' + secrets.token_hex(16))
    root, config_root = parent / 'journal', parent / 'configuration'
    with LeaseJournal(parent):
        pass
    with LeaseJournal(root):
        pass
    with LeaseJournal(config_root):
        pass
    runtime = {'docker_executable': executable, 'context': 'desktop-linux', 'image_id': image,
        'seccomp_path': str(ROOT / '.dom-xray-data/fixture-seccomp-capture.json'), 'seccomp_sha256': PROFILE_SHA,
        'command': ['/usr/bin/python3', '-I', ENTRY, 'worker-hang'],
        'initializer_command': ['/usr/bin/python3', '-I', ENTRY, 'initialize'],
        'broker_command': ['/usr/bin/python3', '-I', ENTRY, 'broker']}
    poller = LeaseRecoveryPoller(root, lambda journal: controller(image, journal))
    entry = {'root': str(root), 'identities': [list(v) for v in poller.identities],
             'runtimeFingerprint': poller.fingerprint, 'runtime': runtime}
    config = config_root / 'registry.json'
    digest = write_fixture(config, json.dumps({'version': 1, 'entries': [entry]}).encode())
    with LeaseJournal(root, create=False) as journal:
        seed_expired(journal, poller.fingerprint, 0)
    flags = ['-I', *(['-O'] if sys.flags.optimize else [])]
    common = ['--configuration', config, '--configuration-sha256', digest]
    jobs, receipts, producer_reader = [], [], None
    automatic = False
    print('Persistent native restart authority: ' + str(parent), flush=True)
    with inventory_guard(docker, before, volumes_before), tempfile.TemporaryDirectory(prefix='dxr-native-restart-results-') as temporary:
        results = Path(temporary) / 'results'
        results.mkdir()
        try:
            first, first_job = spawn_job([*flags, Path(__file__).resolve(), '--first', *common])
            jobs.append((first, first_job))
            first_receipts = Receipts(first)
            receipts.append(first_receipts)
            require(first_receipts.resolved.wait(5) and first.poll() is None, 'first committed receipt missing')
            producer, producer_job = spawn_job([*flags, ROOT / 'scripts/verify_pair_controller_crash.py', '--child',
                '--announce-owner', '--image', image, '--journal-root', root, '--results', results])
            jobs.append((producer, producer_job))
            owned, renderer = Event(), Event()
            def read_producer():
                while line := producer.stdout.readline(65):
                    if line in (b'controller-owned\n', b'controller-owned\r\n'):
                        owned.set()
                    elif line in (b'renderer-live\n', b'renderer-live\r\n'):
                        renderer.set()
                    else:
                        break
            producer_reader = Thread(target=read_producer, daemon=True)
            producer_reader.start()
            require(owned.wait(5) and renderer.wait(15) and producer.poll() is None,
                    'actual renderer/controller witness missing')
            require(first.poll() is None, 'fixture watchdog pause expired')
            stop_job(producer, producer_job)
            stop_job(first, first_job)
            require(first.returncode == 1 and producer.returncode == 1, 'forced Job exit code mismatch')
            with LeaseJournal(root, create=False) as journal:
                record, = journal.snapshot()
                require(journal.recovery_cursor(poller.fingerprint) == '0' * 32, 'committed cursor lost on death')
                identifier = record['resources']['worker']['id']
                probe = controller(image, journal)
                row = probe._inspect(identifier, time.monotonic() + 5)
                probe._ownership(row, _name(record['token'], 'worker'), record['token'], identifier)
                probe._preflight_role(row, 'worker', _name(record['token'], 'worker'), record['token'],
                    identifier, _name(record['token'], 'volume'), require_unstarted=False)
                require(row['State']['Running'] and row['State']['Pid'] > 0, 'live owned orphan not observed')
                orphan_token = record['token']
            print('Both Jobs empty; saved cursor intact; exact owned Docker worker still running.', flush=True)
            second, second_job = spawn_job([*flags, ROOT / 'scripts/run_recovery_watchdog.py', *common, '--max-ticks', '120'])
            jobs.append((second, second_job))
            second_receipts = Receipts(second)
            receipts.append(second_receipts)
            require(second_receipts.resolved.wait(45) and not second_receipts.failures,
                    'replacement did not automatically resolve real orphan')
            stop_job(second, second_job)
            with LeaseJournal(root, create=False) as journal:
                require(not journal.snapshot() and journal.recovery_cursor(poller.fingerprint) == orphan_token,
                        'replacement left obligations or lost committed recovery position')
            for observed in receipts:
                require(observed.messages[0] == {'status': 'registered', 'entries': 1}, 'same-config reload not registered')
                require(str(parent) not in str(observed.messages), 'health disclosed private authority')
            require(not any(results.rglob('worker-result.json')), 'restart admitted result artifact')
            automatic = True
        finally:
            cleanup_faults = stop_owned_jobs(jobs)
            jobs_stopped = not cleanup_faults
            for observed in receipts:
                try:
                    observed.close()
                except Exception as error:
                    cleanup_faults.append(type(error).__name__)
            if producer_reader is not None:
                try:
                    producer_reader.join(timeout=2)
                    require(not producer_reader.is_alive(), 'producer reader did not end')
                    producer.stdout.close()
                except Exception as error:
                    cleanup_faults.append(type(error).__name__)
            if not automatic and not jobs_stopped:
                print('Fixture Jobs not proven empty; preserve journal authority without manual recovery.', flush=True)
            if not automatic and jobs_stopped:
                with LeaseJournal(root, create=False) as journal:
                    for record in journal.snapshot():
                        wait_eligible(record)
                    report = recover_expired_leases(controller(image, journal))
                    print('Failed-fixture manual recovery retained leases=' + str(report.retained), flush=True)
            require(not cleanup_faults, 'owned fixture process/pipe cleanup fault; authority retained')
    print('Verified forced watchdog/controller death, same pinned registry reload, live orphan recovery, '
          'persisted cursor and no result. No installed restart supervisor, overall death bound or independent cgroup proof.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
