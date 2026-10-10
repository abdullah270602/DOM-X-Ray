"""Independent poll process after a real controller-tree crash; fixture only.

No service installation, live-owner enforcement or overall 15-second bound.
"""

import argparse
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
from threading import Event, Thread
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.docker_worker_supervisor import LABEL
from scanner.lease_journal import LeaseJournal, LeaseJournalBusy
from scanner.lease_recovery import _name, recover_expired_leases
from scanner.lease_recovery_poller import LeaseRecoveryPoller
from scanner.worker_supervisor import _WindowsJob, _resume_windows_process
from scripts.verify_pair_controller_crash import controller, inventory_guard, job_empty, wait_eligible
from scripts.verify_pair_supervisor_contract import require


def spawn_job(arguments):
    process = subprocess.Popen([sys.executable, *map(str, arguments)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW | 0x00000004)
    job = None
    try:
        job = _WindowsJob(process)
        _resume_windows_process(process)
        return process, job
    except Exception:
        process.kill()
        process.wait(timeout=5)
        if job is not None:
            job.close()
        process.stdout.close()
        raise


def stop_job(process, job):
    if job._handle is None:
        return
    try:
        job.terminate()
        process.wait(timeout=5)
        deadline = time.monotonic() + 5
        while not job_empty(job):
            require(time.monotonic() < deadline, 'fixture Job did not become empty')
            time.sleep(0.01)
    finally:
        job.close()


def watch(image, root):
    poller = LeaseRecoveryPoller(root, lambda journal: controller(image, journal))
    stop, busy, recovered = Event(), False, False
    def status(outcome):
        nonlocal busy, recovered
        if outcome.status == 'busy' and not busy:
            busy = True
            print('poller-busy', flush=True)
        if outcome.status == 'recovered' and outcome.resolved == 1 and not outcome.retained:
            recovered = True
            print('poller-recovered', flush=True)
            stop.set()
    poller.run(stop, on_status=status, max_ticks=120)
    return 0 if recovered else 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', default='dom-x-ray-runtime-candidate:gate3-profile')
    parser.add_argument('--probe-host-cgroup', action='store_true', help='read-only populated cgroup-path candidate; not identity or empty proof')
    parser.add_argument('--watch', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--root', type=Path, help=argparse.SUPPRESS)
    options = parser.parse_args()
    if options.watch:
        return watch(options.image, options.root)
    require(sys.platform == 'win32', 'native process-tree fixture requires Windows')
    prefix = [shutil.which('docker'), '--context', 'desktop-linux']
    def docker(*args):
        return subprocess.run([*prefix, *args], capture_output=True, check=True,
                              timeout=10).stdout.decode().strip()
    image = docker('image', 'inspect', options.image, '--format', '{{.Id}}')
    before = docker('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL)
    volumes_before = docker('volume', 'ls', '-q', '--filter', 'label=' + LABEL)
    root = ROOT / '.dom-xray-data' / ('pair-poller-journal-' + secrets.token_hex(16))
    with LeaseJournal(root):
        pass
    print('Persistent poller journal: ' + str(root), flush=True)
    with inventory_guard(docker, before, volumes_before), tempfile.TemporaryDirectory(prefix='dxr-native-poller-') as temporary:
        results = Path(temporary) / 'results'
        results.mkdir()
        producer, producer_job = spawn_job([ROOT / 'scripts/verify_pair_controller_crash.py', '--child',
            '--announce-owner', '--image', image, '--journal-root', root, '--results', results])
        owner, renderer, busy, recovered = Event(), Event(), Event(), Event()
        watchers, automatic = [], False
        def read_producer():
            while line := producer.stdout.readline(65):
                if line in (b'controller-owned\n', b'controller-owned\r\n'):
                    owner.set()
                elif line in (b'renderer-live\n', b'renderer-live\r\n'):
                    renderer.set()
                else:
                    break
        reader = Thread(target=read_producer, daemon=True)
        reader.start()
        try:
            require(owner.wait(5) and producer.poll() is None, 'controller did not hold authority')
            watcher, watcher_job = spawn_job([Path(__file__).resolve(), '--watch', '--image', image, '--root', root])
            watchers.append((watcher, watcher_job))
            def read_watcher():
                while line := watcher.stdout.readline(65):
                    if line in (b'poller-busy\n', b'poller-busy\r\n'):
                        busy.set()
                    elif line in (b'poller-recovered\n', b'poller-recovered\r\n'):
                        recovered.set()
                    else:
                        break
            watch_reader = Thread(target=read_watcher, daemon=True)
            watch_reader.start()
            require(busy.wait(5), 'independent poller never observed busy primary')
            require(renderer.wait(15) and producer.poll() is None, 'real renderer witness missing')
            stop_job(producer, producer_job)
            require(watcher.poll() is None, 'poller died with controller Job')
            # Observe without doing recovery. The poller may briefly own the
            # journal, so retry only the typed contention result.
            observed = False
            deadline = time.monotonic() + 3
            while not observed:
                try:
                    with LeaseJournal(root, create=False) as journal:
                        record, = journal.snapshot()
                        identifier = record['resources']['worker']['id']
                        probe = controller(image, journal)
                        row = probe._inspect(identifier, time.monotonic() + 3)
                        probe._ownership(row, _name(record['token'], 'worker'), record['token'], identifier)
                        probe._preflight_role(row, 'worker', _name(record['token'], 'worker'), record['token'],
                            identifier, _name(record['token'], 'volume'), require_unstarted=False)
                        require(row['State']['Running'] and row['State']['Pid'] > 0, 'live orphan was not observed')
                        if options.probe_host_cgroup:
                            from scripts.docker_host_cgroup_fixture import verify_populated_candidate
                            verify_populated_candidate(identifier)
                            print('Linux cgroup-path candidate populated; identity and empty proof remain open.', flush=True)
                        observed = True
                except LeaseJournalBusy:
                    require(time.monotonic() < deadline, 'journal observation remained busy')
                    time.sleep(0.01)
            print('Controller Job empty; separate poller alive; exact owned worker still running.', flush=True)
            require(recovered.wait(35), 'poller did not automatically recover eligible orphan')
            require(watcher.wait(timeout=5) == 0, 'poller exited without verified recovery')
            watch_reader.join(timeout=2)
            with LeaseJournal(root, create=False) as journal:
                require(not journal.snapshot(), 'automatic recovery left obligations')
            require(not any(results.rglob('worker-result.json')), 'crash admitted a result artifact')
            automatic = True
        finally:
            try:
                stop_job(producer, producer_job)
            finally:
                try:
                    for watcher, job in watchers:
                        try:
                            stop_job(watcher, job)
                        finally:
                            watcher.stdout.close()
                finally:
                    reader.join(timeout=2)
                    producer.stdout.close()
            if not automatic:
                # Not counted as automatic proof: stop both process trees before
                # attempting only exact journal-authorized replacement cleanup.
                with LeaseJournal(root, create=False) as journal:
                    for record in journal.snapshot():
                        wait_eligible(record)
                    report = recover_expired_leases(controller(image, journal))
                    print('Failed-fixture manual recovery retained leases=' + str(report.retained), flush=True)
    print('Verified independent polling survives controller-tree death, honors busy ownership, '
          'automatically cleans the real eligible orphan and publishes no result. '
          'Overall death deadline, restart persistence and deployment remain open.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
