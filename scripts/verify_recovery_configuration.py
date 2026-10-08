"""Private config loading and actual launcher process; no native Docker proof."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.docker_broker_pair_supervisor import DockerBrokerPairSupervisor
from scanner.lease_journal import LeaseJournal
from scanner.lease_recovery_poller import LeaseRecoveryPoller
from scanner.recovery_configuration import load_recovery_registry, MAX_CONFIGURATION_BYTES
from scanner.worker_supervisor import WorkerContainmentError
from scripts.verify_pair_supervisor_contract import require


def rejects(callback):
    try:
        callback()
    except (ValueError, OSError, WorkerContainmentError):
        return
    raise AssertionError('invalid recovery configuration accepted')


def write_fixture(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def main():
    with tempfile.TemporaryDirectory(prefix='dxr-recovery-config-') as temporary:
        parent = Path(temporary).resolve()
        config_root = parent / 'private-config'
        with LeaseJournal(config_root):
            pass  # provision the fixture directory's exact private ACL/mode
        profile = parent / 'profile.json'
        profile_value = {'defaultAction': 'SCMP_ACT_ERRNO', 'syscalls': []}
        profile.write_text(json.dumps(profile_value), encoding='utf-8')
        profile_digest = hashlib.sha256(json.dumps(profile_value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        runtime = {'docker_executable': str(Path(sys.executable).resolve()), 'context': 'fixture-context',
            'image_id': 'sha256:' + 'a' * 64, 'seccomp_path': str(profile), 'seccomp_sha256': profile_digest,
            'command': ['/usr/bin/python3', '-I', '/fixture.py', 'worker'],
            'initializer_command': ['/usr/bin/python3', '-I', '/fixture.py', 'initialize'],
            'broker_command': ['/usr/bin/python3', '-I', '/fixture.py', 'broker']}
        entries = []
        for index in range(2):
            root = parent / f'journal-{index}'
            with LeaseJournal(root):
                pass
            poller = LeaseRecoveryPoller(root, lambda journal: DockerBrokerPairSupervisor(**runtime, lease_journal=journal))
            entries.append({'root': str(root), 'identities': [list(item) for item in poller.identities],
                'runtimeFingerprint': poller.fingerprint, 'runtime': copy.deepcopy(runtime)})
        manifest = {'version': 1, 'entries': entries}
        path = config_root / 'registry.json'
        def load(value):
            digest = write_fixture(path, json.dumps(value).encode())
            return load_recovery_registry(path, digest)
        first, restarted = load(manifest), load(manifest)
        require(first is not restarted and len(restarted.pollers) == 2
                and restarted.pollers[0].identities == first.pollers[0].identities,
                'operator registry did not reload exact journal bindings')
        require(first.tick().outcome.status == 'waiting', 'empty configured journal was not usable')
        print('private configuration reload and empty-journal launch binding: verified')

        invalid = []
        for field, value in (('version', True), ('entries', []), ('entries', entries * 5)):
            changed = copy.deepcopy(manifest)
            changed[field] = value
            invalid.append(changed)
        for field, value in (('root', str(parent / 'absent')), ('identities', [[0, 0]] * 3),
                             ('root', entries[1]['root']),
                             ('runtimeFingerprint', 'f' * 64), ('extra', 'forbidden')):
            changed = copy.deepcopy(manifest)
            changed['entries'][0][field] = value
            invalid.append(changed)
        for field, value in (('image_id', 'mutable:tag'), ('command', ['relative-command']),
                             ('image_id', 'sha256:' + 'b' * 64),
                             ('command', ['/usr/bin/python3', '\0bad']), ('context', 1),
                             ('seccomp_sha256', 'f' * 64), ('docker_executable', 'relative.exe'),
                             ('lease_journal', 'visitor-choice')):
            changed = copy.deepcopy(manifest)
            changed['entries'][0]['runtime'][field] = value
            invalid.append(changed)
        changed = copy.deepcopy(manifest)
        changed['entries'][1] = copy.deepcopy(changed['entries'][0])
        invalid.append(changed)
        for value in invalid:
            rejects(lambda: load(value))
        for raw in (b'{"version":1,"version":1,"entries":[]}', b'{"version":NaN,"entries":[]}',
                    b'{"version":1e999,"entries":[]}', b'[]', b'\xff', b'x' * (MAX_CONFIGURATION_BYTES + 1)):
            digest = write_fixture(path, raw)
            rejects(lambda: load_recovery_registry(path, digest))
        digest = write_fixture(path, json.dumps(manifest).encode())
        rejects(lambda: load_recovery_registry(path, '0' * 64))
        for invalid_digest in (None, 'f' * 63, 'F' * 64):
            rejects(lambda: load_recovery_registry(path, invalid_digest))
        link = config_root / 'hardlink.json'
        os.link(path, link)
        try:
            rejects(lambda: load_recovery_registry(path, digest))
        finally:
            link.unlink()
        if os.name == 'nt':
            subprocess.run(['icacls', str(path), '/grant', '*S-1-1-0:(R)'], capture_output=True,
                           check=True, timeout=3)
            try:
                rejects(lambda: load_recovery_registry(path, digest))
            finally:
                subprocess.run(['icacls', str(path), '/remove:g', '*S-1-1-0'], capture_output=True,
                               check=True, timeout=3)
        else:
            path.chmod(0o644)
            try:
                rejects(lambda: load_recovery_registry(path, digest))
            finally:
                path.chmod(0o600)
        require(len(load_recovery_registry(path, digest).pollers) == 2, 'permission fixture restoration failed')
        symbolic = config_root / 'symlink.json'
        try:
            symbolic.symlink_to(path)
        except OSError:
            print('native symlink fixture unavailable on this host; symlink evidence not claimed')
        else:
            try:
                rejects(lambda: load_recovery_registry(symbolic, digest))
            finally:
                symbolic.unlink()
            print('native configuration symlink rejected: verified')
        public = parent / 'public-config'
        public.mkdir()
        public_path = public / 'registry.json'
        write_fixture(public_path, json.dumps(manifest).encode())
        rejects(lambda: load_recovery_registry(public_path, digest))
        print('strict shape/identity/runtime, duplicate/nonfinite JSON, size/hash and nonprivate file/directory rejection: verified')

        command = [sys.executable, '-I', str(ROOT / 'scripts/run_recovery_watchdog.py'),
                   '--configuration', str(path), '--configuration-sha256', digest]
        options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
        for arguments, expected in ((['--check'], 0), (['--max-ticks', '1'], 0),
                                    (['--max-ticks', '0'], 2)):
            completed = subprocess.run([*command, *arguments], capture_output=True, timeout=10, **options)
            require(completed.returncode == expected and not completed.stderr, 'launcher status/exit contract failed')
            messages = [json.loads(line) for line in completed.stdout.splitlines()]
            require(messages and not any(str(parent) in str(message) for message in messages),
                    'launcher exposed private configuration path')
            if expected == 0:
                require(messages[0] == {'status': 'registered', 'entries': 2}, 'launcher failed exact registration')
                if arguments == ['--check']:
                    require(len(messages) == 1, 'check mode performed a recovery visit')
                else:
                    require(len(messages) == 3 and messages[1]['entry_index'] == 0
                            and messages[1]['outcome'] == {'status': 'waiting', 'delay_seconds': 0.5,
                                'resolved': 0, 'retained': 0, 'deferred': 0, 'skipped': 0}
                            and messages[2] == {'status': 'stopped'},
                            'finite launcher contacted fixture executable or reported failed cleanup')
        write_fixture(path, b'{}')
        failed = subprocess.run([*command, '--check'], capture_output=True, timeout=10, **options)
        require(failed.returncode == 2 and failed.stdout == b'{"status":"configuration-fault"}\n'.replace(b'\n', os.linesep.encode())
                and not failed.stderr, 'bad configuration leaked error or started watchdog')
        print('actual isolated launcher check/finite run/failure: content-free statuses, no Docker resources: verified')
    print('Verified private durable registry loading and foreground launcher; service supervision, native Docker restart and deadlines remain open.')


if __name__ == '__main__':
    main()
