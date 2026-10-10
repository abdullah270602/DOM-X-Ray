"""Kill an actual fixture controller, then recover using a replacement owner.

Native engine evidence only: no automatic watchdog or independent cgroup proof.
Failed journals are persistent; never erase ambiguous resource authority.
"""

import argparse
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
from dataclasses import asdict
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
from threading import Event, Lock, Thread
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.docker_broker_pair_supervisor import DockerBrokerPairSupervisor
from scanner.docker_worker_supervisor import LABEL, CONTROL_BYTES
from scanner.destination_policy import DestinationPolicy
from scanner.lease_journal import LeaseJournal
from scanner.lease_recovery import recover_expired_leases, _name
from scanner.scan_transport import run_public_scan_transport
from scanner.worker_supervisor import _WindowsJob, _resume_windows_process
from scripts.verify_docker_transport import PROFILE_SHA, require
from scripts.verify_pair_transport import ENTRY
from scripts.verify_scan_transport import validators


def controller(image, journal):
    return DockerBrokerPairSupervisor(docker_executable=shutil.which('docker'), context='desktop-linux',
        image_id=image, seccomp_path=ROOT / '.dom-xray-data/fixture-seccomp-capture.json',
        seccomp_sha256=PROFILE_SHA, command=('/usr/bin/python3', '-I', ENTRY, 'worker-hang'),
        initializer_command=('/usr/bin/python3', '-I', ENTRY, 'initialize'),
        broker_command=('/usr/bin/python3', '-I', ENTRY, 'broker'), lease_journal=journal)


def witness_pipe_factory(original, cleaning, notify, phase_lock):
    def pipe(arguments, payload=None, limit=CONTROL_BYTES):
        value = original(arguments, payload, limit)
        if arguments[0] == 'start' and payload:
            def observe():
                while not cleaning.is_set() and value.process.poll() is None:
                    if b'renderer-live\n' in value.data:
                        with phase_lock:
                            if not cleaning.is_set():
                                notify()
                        return
                    time.sleep(0.005)
            Thread(target=observe, daemon=True).start()
        return value
    return pipe


def child(image, journal_root, results, *, announce_owner=False, announce_resources=False):
    with LeaseJournal(journal_root) as journal:
        if announce_owner:
            print('controller-owned', flush=True)
        supervisor = controller(image, journal)
        original_call = supervisor._call
        def diagnostic_call(arguments, deadline):
            started = time.monotonic()
            status = 'ok'
            try:
                return original_call(arguments, deadline)
            except Exception as error:
                status = 'timeout' if isinstance(error, TimeoutError) else 'failed'
                raise
            finally:
                print(f'fixture-control {arguments[0]} {status} '
                      f'{int((time.monotonic() - started) * 1000)}', file=sys.stderr, flush=True)
        supervisor._call = diagnostic_call
        cleaning = Event()
        phase_lock = Lock()
        original_cleanup = supervisor._cleanup
        def cleanup(*args, **kwargs):
            with phase_lock:
                cleaning.set()
            return original_cleanup(*args, **kwargs)
        supervisor._cleanup = cleanup
        def notify():
            if announce_resources:
                record, = journal.snapshot()
                require(all(r['state'] == 'created' for r in record['resources'].values()),
                        'resource witness was not fully committed')
                print('fixture-resources ' + json.dumps(record, separators=(',', ':')), flush=True)
            print('renderer-live', flush=True)
        supervisor._pipe = witness_pipe_factory(supervisor._pipe, cleaning, notify, phase_lock)
        schema, semantic = validators()
        run_public_scan_transport('https://xray.test/',
            policy=DestinationPolicy(lambda _h, _p: ['1.1.1.1']),
            launch_worker=supervisor.launch, worker_supervisor=supervisor.run,
            schema_validator=schema, semantic_validator=semantic,
            temporary_root=results, deadline_seconds=15)
    return 2  # A normal controller exit is never crash-recovery evidence.


def job_empty(job):
    class Accounting(ctypes.Structure):
        _fields_ = [(name, ctypes.c_int64) for name in ('user', 'kernel', 'period_user', 'period_kernel')] + [
            ('page_faults', wintypes.DWORD), ('total', wintypes.DWORD),
            ('active', wintypes.DWORD), ('terminated', wintypes.DWORD)]
    query = job._kernel32.QueryInformationJobObject
    query.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                      ctypes.POINTER(wintypes.DWORD)]
    query.restype = wintypes.BOOL
    accounting = Accounting()
    if not query(job._handle, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return accounting.active == 0


@contextmanager
def inventory_guard(docker, before, volumes_before):
    failed = False
    try:
        yield
    except BaseException:
        failed = True
        raise
    finally:
        try:
            containers_match = before == docker('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL)
            volumes_match = volumes_before == docker('volume', 'ls', '-q', '--filter', 'label=' + LABEL)
            print(f'Final scoped inventory: containers unchanged={containers_match}; '
                  f'volumes unchanged={volumes_match}', flush=True)
            if not failed:
                require(containers_match and volumes_match, 'scoped resources survived')
        except Exception:
            if not failed:
                raise
            print('Final scoped inventory not proven; retain persistent journal authority.', flush=True)


def wait_eligible(record):
    # Real wall-clock eligibility, no injected time or shortened grace.
    eligible_at = record['expiresAtMs'] + 5000
    limit = time.monotonic() + 25
    while int(time.time() * 1000) < eligible_at:
        require(time.monotonic() < limit, 'clock moved backwards; authority retained')
        time.sleep(0.05)


def observe_orphan(supervisor, record):
    require(record['runtimeFingerprint'] == supervisor.runtime_fingerprint(), 'runtime binding drifted')
    require(all(r['state'] == 'created' for r in record['resources'].values()), 'crash did not retain created obligations')
    identifier = record['resources']['worker']['id']
    row = supervisor._inspect(identifier, time.monotonic() + 5)
    supervisor._ownership(row, _name(record['token'], 'worker'), record['token'], identifier)
    supervisor._preflight_role(row, 'worker', _name(record['token'], 'worker'),
        record['token'], identifier, _name(record['token'], 'volume'), require_unstarted=False)
    require(row['State']['Running'] and row['State']['Pid'] > 0, 'owned worker did not survive controller death')
    print('Controller Job empty; journal lock handed off; owned worker still running=True', flush=True)
    calls = []
    original_call = supervisor._call
    def counted(arguments, deadline):
        calls.append(arguments[0])
        return original_call(arguments, deadline)
    supervisor._call = counted
    early = recover_expired_leases(supervisor)
    require(early.skipped == 1 and not calls, 'ineligible recovery contacted engine')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', default='dom-x-ray-runtime-candidate:gate3-profile')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--journal-root', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--results', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--announce-owner', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--announce-resources', action='store_true', help=argparse.SUPPRESS)
    options = parser.parse_args()
    if options.child:
        require(options.journal_root is not None and options.results is not None, 'child configuration missing')
        return child(options.image, options.journal_root, options.results,
                     announce_owner=options.announce_owner, announce_resources=options.announce_resources)
    require(sys.platform == 'win32', 'this controller-tree fixture requires Windows Job Objects')
    executable = shutil.which('docker')
    require(executable is not None, 'Docker CLI missing')
    prefix = [executable, '--context', 'desktop-linux']
    def docker(*arguments):
        return subprocess.run([*prefix, *arguments], capture_output=True, check=True,
                              timeout=10).stdout.decode().strip()
    image = docker('image', 'inspect', options.image, '--format', '{{.Id}}')
    before = docker('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL)
    volumes_before = docker('volume', 'ls', '-q', '--filter', 'label=' + LABEL)
    journal_root = ROOT / '.dom-xray-data' / ('pair-crash-journal-' + secrets.token_hex(16))
    print('Persistent crash journal: ' + str(journal_root), flush=True)
    with inventory_guard(docker, before, volumes_before), tempfile.TemporaryDirectory(prefix='dxr-controller-crash-') as temporary:
        results = Path(temporary) / 'results'
        results.mkdir()
        flags = {'creationflags': subprocess.CREATE_NO_WINDOW | 0x00000004}  # CREATE_SUSPENDED
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--child',
            '--image', image, '--journal-root', str(journal_root), '--results', str(results)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **flags)
        job = None
        try:
            job = _WindowsJob(process)
            _resume_windows_process(process)
        except Exception:
            process.kill()
            process.wait(timeout=5)
            if job is not None:
                job.close()
            process.stdout.close()
            process.stderr.close()
            raise
        diagnostics = []
        def read_diagnostics():
            import re
            while line := process.stderr.readline(200):
                if len(diagnostics) < 100 and re.fullmatch(
                        rb'fixture-control (info|volume|create|inspect|kill|rm|container) (ok|timeout|failed) [0-9]{1,8}\r?\n', line):
                    diagnostics.append(line.decode('ascii').strip())
        diagnostic_reader = Thread(target=read_diagnostics, daemon=True)
        diagnostic_reader.start()
        witness, unexpected = Event(), Event()
        def read():
            # One fixed line only; neither Docker output nor job payload is forwarded.
            line = process.stdout.readline(65)
            if line == b'renderer-live\n' or line == b'renderer-live\r\n':
                witness.set()
            else:
                unexpected.set()
        reader = Thread(target=read, daemon=True)
        reader.start()
        witnessed = False
        report = None
        try:
            limit = time.monotonic() + 20
            while not witness.is_set() and not unexpected.is_set() and process.poll() is None:
                require(time.monotonic() < limit, 'renderer witness deadline expired')
                time.sleep(0.01)
            witnessed = witness.is_set() and process.poll() is None
        finally:
            # This Job owns the suspended-before-assignment controller and its
            # Docker CLI descendants, never Docker Desktop/engine processes.
            try:
                job.terminate()
                process.wait(timeout=5)
                empty_deadline = time.monotonic() + 5
                while not job_empty(job):
                    require(time.monotonic() < empty_deadline, 'controller Job still contains processes')
                    time.sleep(0.01)
            finally:
                job.close()
            reader.join(timeout=2)
            diagnostic_reader.join(timeout=2)
            process.stdout.close()
            process.stderr.close()
            if not witnessed:
                for line in diagnostics:
                    print(line, flush=True)
            with LeaseJournal(journal_root) as journal:
                records = journal.snapshot()
                supervisor = controller(image, journal)
                validated_crash = False
                if witnessed and len(records) == 1:
                    try:
                        observe_orphan(supervisor, records[0])
                        validated_crash = True
                    except Exception:
                        print('Crash observation failed validation; attempting only journal-authorized recovery.', flush=True)
                # Also attempt safe recovery on failed witness/setup: preserve
                # the durable root if ambiguity prevents positive cleanup.
                for record in records:
                    wait_eligible(record)
                started = time.monotonic()
                report = recover_expired_leases(supervisor)
                duration = (time.monotonic() - started) * 1000
                remaining = journal.snapshot()
                print('Replacement recovery: ' + json.dumps(asdict(report)) + f'; {duration:.0f} ms', flush=True)
                require(not remaining, 'recovery retained obligations; persistent journal must be kept')
                require(witnessed and validated_crash and report.resolved == 1 and report.retained == 0,
                        'actual live-renderer controller crash was not proven')
                require(duration <= 15000, 'recovery pass overran its scheduling budget')
                require(not any(results.rglob('worker-result.json')), 'controller crash published a result artifact')
    print('Verified native controller kill after real renderer witness, durable owner handoff, '
          'live orphan teardown and no result admission. Automatic watchdog/cgroup-empty proof remain open.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
