"""Independent poll process after a real controller-tree crash; fixture only.

No service installation, live-owner enforcement or overall 15-second bound.
"""

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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.docker_worker_supervisor import LABEL, _pairs, _invalid_constant
from scanner.lease_journal import LeaseJournal, LeaseJournalBusy, _validate
from scanner.lease_recovery import _name, recover_expired_leases
from scanner.lease_recovery_poller import LeaseRecoveryPoller
from scanner.worker_supervisor import _WindowsJob, _resume_windows_process
from scripts.verify_pair_controller_crash import controller, inventory_guard, job_empty, wait_eligible
from scripts.verify_pair_supervisor_contract import require


def decode_resource_witness(line):
    require(isinstance(line, bytes) and len(line) <= 8192 and line.endswith(b'\n')
            and line.startswith(b'fixture-resources '), 'invalid resource witness framing')
    return _validate(json.loads(line[18:], object_pairs_hook=_pairs, parse_constant=_invalid_constant))


def host_interpreter_flags(optimization):
    require(type(optimization) is int and optimization in (0, 1, 2), 'invalid host optimization')
    return ['-I', *(['-' + 'O' * optimization] if optimization else [])]


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
        initiated_at = time.monotonic()
        job.terminate()
        process.wait(timeout=5)
        deadline = time.monotonic() + 5
        while not job_empty(job):
            require(time.monotonic() < deadline, 'fixture Job did not become empty')
            time.sleep(0.01)
    finally:
        job.close()
    return initiated_at


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
    parser.add_argument('--probe-cgroup-root-identity', action='store_true', help='trusted fixture cross-view root corroboration; not adversarial binding')
    parser.add_argument('--observe-worker-cgroup-transition', action='store_true', help='host candidate events 1-to-0 observation; not full worker/broker gate')
    parser.add_argument('--observe-pair-cgroup-transitions', action='store_true', help='attach both host candidates before controller crash; not adversarial binding')
    parser.add_argument('--probe-host-pid-membership', action='store_true', help='require engine-reported PID number in candidate cgroup.procs; namespace alignment unverified')
    parser.add_argument('--watch', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--root', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--expected-host-optimization', type=int, choices=(0, 1, 2), help=argparse.SUPPRESS)
    options = parser.parse_args()
    require(not (options.observe_worker_cgroup_transition and options.observe_pair_cgroup_transitions),
            'choose worker-only or pair observation')
    if options.watch:
        require(sys.flags.optimize == options.expected_host_optimization and sys.flags.isolated == 1,
                'watcher interpreter flags differ')
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
        flags = host_interpreter_flags(sys.flags.optimize)
        producer_arguments = [*flags, ROOT / 'scripts/verify_pair_controller_crash.py', '--child',
            '--announce-owner', '--image', image, '--journal-root', root, '--results', results,
            '--expected-host-optimization', str(sys.flags.optimize)]
        if options.observe_pair_cgroup_transitions:
            producer_arguments.append('--announce-resources')
        producer, producer_job = spawn_job(producer_arguments)
        owner, renderer, busy, recovered = Event(), Event(), Event(), Event()
        watchers, automatic, cgroup_observer = [], False, None
        pair_observers, resource_witness = [], []
        def read_producer():
            while line := producer.stdout.readline(8193 if options.observe_pair_cgroup_transitions else 65):
                if line in (b'controller-owned\n', b'controller-owned\r\n'):
                    owner.set()
                elif line in (b'renderer-live\n', b'renderer-live\r\n'):
                    renderer.set()
                elif options.observe_pair_cgroup_transitions and line.startswith(b'fixture-resources '):
                    try:
                        require(not resource_witness, 'duplicate resource witness')
                        resource_witness.append(decode_resource_witness(line))
                    except Exception:
                        break
                else:
                    break
        reader = Thread(target=read_producer, daemon=True)
        reader.start()
        try:
            require(owner.wait(5) and producer.poll() is None, 'controller did not hold authority')
            watcher, watcher_job = spawn_job([*flags, Path(__file__).resolve(), '--watch', '--image', image,
                '--root', root, '--expected-host-optimization', str(sys.flags.optimize)])
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
            print('Both host children verified isolation=1, optimization=' + str(sys.flags.optimize) + '.', flush=True)
            require(renderer.wait(15) and producer.poll() is None, 'real renderer witness missing')
            if options.observe_pair_cgroup_transitions:
                from scripts.docker_host_cgroup_fixture import CandidateTransitionObserver, verify_root_identity_match
                require(len(resource_witness) == 1, 'committed pair resource witness missing')
                witness, = resource_witness
                probe = controller(image, None)
                require(witness['runtimeFingerprint'] == probe.runtime_fingerprint(), 'witness runtime drift')
                for role in ('worker', 'broker'):
                    identifier = witness['resources'][role]['id']
                    require(witness['resources'][role]['state'] == 'created', 'witness role not created')
                    row = probe._inspect(identifier, time.monotonic() + 3)
                    probe._ownership(row, _name(witness['token'], role), witness['token'], identifier)
                    probe._preflight_role(row, role, _name(witness['token'], role), witness['token'],
                        identifier, _name(witness['token'], 'volume'), require_unstarted=False)
                    require(row['State']['Running'] and row['State']['Pid'] > 0, 'pair role not live before crash')
                    if options.probe_host_pid_membership:
                        from scripts.docker_host_cgroup_fixture import verify_engine_pid_membership
                        verify_engine_pid_membership(identifier, row['State']['Pid'])
                        print('Host ' + role + ' candidate PID-number match; namespace alignment unverified.', flush=True)
                    observer = CandidateTransitionObserver(identifier)
                    pair_observers.append((role, observer))
                    observer.wait_ready()
                    if options.probe_cgroup_root_identity:
                        verify_root_identity_match(identifier, prefix)
                    print('Pre-crash ' + role + ' candidate events retained with populated=1.', flush=True)
                require(producer.poll() is None, 'controller exited during observer setup')
                require(all(not observer.empty.is_set() and observer.process.poll() is None
                            for _, observer in pair_observers), 'pair candidate emptied during setup')
            termination_initiated_at = stop_job(producer, producer_job)
            require(watcher.poll() is None, 'poller died with controller Job')
            # Observe without doing recovery. The poller may briefly own the
            # journal, so retry only the typed contention result.
            observed = False
            deadline = time.monotonic() + 3
            while not observed:
                try:
                    with LeaseJournal(root, create=False) as journal:
                        record, = journal.snapshot()
                        if options.observe_pair_cgroup_transitions:
                            require(record == resource_witness[0], 'post-crash journal differs from witness')
                        identifier = record['resources']['worker']['id']
                        probe = controller(image, journal)
                        row = probe._inspect(identifier, time.monotonic() + 3)
                        probe._ownership(row, _name(record['token'], 'worker'), record['token'], identifier)
                        probe._preflight_role(row, 'worker', _name(record['token'], 'worker'), record['token'],
                            identifier, _name(record['token'], 'volume'), require_unstarted=False)
                        require(row['State']['Running'] and row['State']['Pid'] > 0, 'live orphan was not observed')
                        if options.probe_host_pid_membership and not options.observe_pair_cgroup_transitions:
                            from scripts.docker_host_cgroup_fixture import verify_engine_pid_membership
                            verify_engine_pid_membership(identifier, row['State']['Pid'])
                            print('Host worker candidate PID-number match; namespace alignment unverified.', flush=True)
                        if options.observe_worker_cgroup_transition:
                            from scripts.docker_host_cgroup_fixture import CandidateTransitionObserver
                            cgroup_observer = CandidateTransitionObserver(identifier)
                            cgroup_observer.wait_ready()
                            print('Host candidate events handle retained with populated=1.', flush=True)
                        if options.probe_cgroup_root_identity and not options.observe_pair_cgroup_transitions:
                            from scripts.docker_host_cgroup_fixture import verify_root_identity_match
                            verify_root_identity_match(identifier, prefix)
                            print('Trusted fixture private cgroup root matches host device/inode.', flush=True)
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
            if cgroup_observer is not None:
                cgroup_observer.verify_empty()
                print('Retained host candidate events handle observed populated=0.', flush=True)
            for role, observer in pair_observers:
                observer.verify_empty(observed_after=termination_initiated_at)
                print('Retained ' + role + ' zero marker received after termination began.', flush=True)
            watch_reader.join(timeout=2)
            with LeaseJournal(root, create=False) as journal:
                require(not journal.snapshot(), 'automatic recovery left obligations')
            require(not any(results.rglob('worker-result.json')), 'crash admitted a result artifact')
            automatic = True
        finally:
            observer_error = False
            for observer in ([cgroup_observer] if cgroup_observer is not None else []) + [o for _, o in pair_observers]:
                try:
                    observer.close()
                except Exception:
                    observer_error = True
                    print('Host observer teardown unverified; continuing exact-resource cleanup.', flush=True)
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
            require(not observer_error or not automatic, 'successful fixture observer teardown failed')
    print('Verified independent polling survives controller-tree death, honors busy ownership, '
          'automatically cleans the real eligible orphan and publishes no result. '
          'Overall death deadline, restart persistence and deployment remain open.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
