"""Verifier-only consumer read batching; never selected by production code."""
import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from types import MethodType

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.experimental_engine_reads import ContainerRead, run as engine_reads
from scripts.verify_pair_supervisor_contract import (instance, scoped_row, engine, run as mock_run,
    IDS, TOKEN, VOLUME, require)
from scanner.docker_broker_pair_supervisor import DockerBrokerPairSupervisor
from scanner.docker_worker_supervisor import LABEL
from scanner.lease_journal import LeaseJournal
from scanner.worker_supervisor import WorkerContainmentError, run_worker_command
from scripts.verify_docker_transport import PROFILE_SHA

ENTRY = '/opt/dom-xray/fixtures/worker/container_broker_pair.py'


def candidate_prepare(self, names, token, volume, deadline, attempted, identifiers, note):
    """Create in journal dependency order; validate both before either starts."""
    require(type(self.journal) is LeaseJournal, 'candidate needs durable journal')
    records = [record for record in self.journal.snapshot() if record['token'] == token]
    require(len(records) == 1 and records[0]['runtimeFingerprint'] == self.runtime_fingerprint()
        and records[0]['engineId'] is not None, 'candidate engine binding missing')
    expected = hashlib.sha256(records[0]['engineId'].encode()).hexdigest()
    for role in ('broker', 'worker'):
        attempted.add(role)
        note('intent', role)
        identifier = self._create_role(role, names[role], token, volume, deadline)
        identifiers[role] = identifier
        note('created', role, identifier)
    plan = tuple(ContainerRead(identifiers[role], names[role], token) for role in ('broker', 'worker'))
    digest, rows = self._experimental_reads(self.prefix[0], plan, deadline)
    require(digest == expected and type(rows) is tuple and len(rows) == 2
        and all(row is not None for row in rows), 'candidate engine/inspect missing')
    for role, row in zip(('broker', 'worker'), rows):
        self._preflight_role(row, role, names[role], token, identifiers[role], volume)


def contracts():
    names = {role: 'dom-x-ray-pair-' + role + '-' + TOKEN for role in IDS}
    for fault in (None, 'engine', 'missing', 'resource', 'worker-intent', 'worker-id', 'read-timeout'):
        with tempfile.TemporaryDirectory(prefix='dxr-read-candidate-') as temporary, \
                LeaseJournal(Path(temporary).resolve(strict=True) / 'journal') as journal:
            pair = instance()
            pair.journal = journal
            pair._prepare_consumers = MethodType(candidate_prepare, pair)
            journal.create(TOKEN, pair.runtime_fingerprint(), int(time.time() * 1000) + 15000)
            journal.engine(TOKEN, 'fixture-engine')
            journal.intent(TOKEN, 'volume')
            journal.created(TOKEN, 'volume')
            journal.intent(TOKEN, 'initialize')
            journal.created(TOKEN, 'initialize', IDS['initialize'])
            attempted, identifiers, events = set(), {}, []
            def note(method, role, *args):
                getattr(journal, method)(TOKEN, role, *args)
                events.append((method, role))
                if (fault == 'worker-intent' and method == 'intent' and role == 'worker') or \
                        (fault == 'worker-id' and method == 'created' and role == 'worker'):
                    raise OSError('committed-then-raised')
            def create(role, name, token, volume, deadline):
                require(deadline == 12345 and name == names[role] and token == TOKEN and volume == VOLUME,
                    'creation arguments changed')
                events.append(('create', role))
                return IDS[role]
            pair._create_role = create
            rows = tuple(scoped_row(pair, role) for role in ('broker', 'worker'))
            digest = hashlib.sha256(b'fixture-engine').hexdigest()
            if fault == 'engine':
                digest = 'f' * 64
            if fault == 'missing':
                rows = (rows[0], None)
            if fault == 'resource':
                rows[1]['HostConfig']['Privileged'] = True
            def reads(docker, plan, deadline):
                require(deadline == 12345 and tuple(item.identifier for item in plan) ==
                    (IDS['broker'], IDS['worker']), 'batch plan/deadline changed')
                require(all(journal.snapshot()[0]['resources'][role]['state'] == 'created'
                    for role in ('broker', 'worker')), 'batch preceded durable IDs')
                events.append(('read', 'both'))
                if fault == 'read-timeout':
                    raise TimeoutError('controlled read timeout')
                return digest, rows
            pair._experimental_reads = reads
            try:
                pair._prepare_consumers(names, TOKEN, VOLUME, 12345, attempted, identifiers, note)
            except (AssertionError, OSError, TimeoutError, WorkerContainmentError):
                require(fault is not None, 'valid batch candidate failed')
            else:
                require(fault is None, 'faulted batch candidate admitted')
            require(attempted == {'broker', 'worker'} and identifiers['broker'] == IDS['broker'],
                'ambiguous role tracking lost')
            require(('worker' in identifiers) == (fault != 'worker-intent'), 'worker identity invented/lost')
            require(('read', 'both') in events or fault in ('worker-intent', 'worker-id'),
                'candidate skipped required batch')
            if fault is None:
                require(events == [('intent', 'broker'), ('create', 'broker'), ('created', 'broker'),
                    ('intent', 'worker'), ('create', 'worker'), ('created', 'worker'), ('read', 'both')],
                    'journal/create/batch order changed')
    print('Pair read candidate controls pass: serial durable intents/IDs, bound engine, '
        'full preflight, shared deadline and fault refusal. Not native capture proof.')
    for fault in (None, 'engine', 'missing', 'resource', 'read-timeout'):
        with tempfile.TemporaryDirectory(prefix='dxr-read-run-') as temporary, \
                LeaseJournal(Path(temporary).resolve(strict=True) / 'journal') as journal:
            pair = instance()
            pair.journal = journal
            worker, broker, _, _ = engine(pair)
            base_call = pair._call
            def call(arguments, deadline):
                if arguments[0] == 'info':
                    return json.dumps({'OSType': 'linux', 'CgroupVersion': '2', 'ID': 'fixture-engine'})
                return base_call(arguments, deadline)
            pair._call = call
            pair._prepare_consumers = MethodType(candidate_prepare, pair)
            rows = tuple(scoped_row(pair, role) for role in ('broker', 'worker'))
            if fault == 'resource':
                rows[1]['HostConfig']['Privileged'] = True
            if fault == 'missing':
                rows = (rows[0], None)
            def reads(*args):
                if fault == 'read-timeout':
                    raise TimeoutError('controlled timeout')
                return ('f' * 64 if fault == 'engine' else hashlib.sha256(b'fixture-engine').hexdigest()), rows
            pair._experimental_reads = reads
            result_path = Path(temporary).resolve(strict=True) / 'result.json'
            result = mock_run(pair, result_path, reject=fault in ('engine', 'missing', 'resource'))
            require(pair._cleanup.call_count == 3, 'run fault skipped exact-role cleanup')
            if fault is None:
                require(result.artifact_eligible and journal.snapshot() == [], 'valid run retained journal')
            else:
                require(not result_path.exists() and not broker.finished and not worker.finished,
                    'fault started consumers or wrote artifact')
                if fault == 'read-timeout':
                    require(result.outcome == 'timeout' and journal.snapshot() == [], 'timeout state changed')
                else:
                    require(len(journal.snapshot()) == 1 and all(resource['state'] == 'removed'
                        for resource in journal.snapshot()[0]['resources'].values()),
                        'control failure lost journal obligations/removal notes')
    print('Mocked full-run candidate controls pass: faulted batches never start consumers; '
        'all roles cleaned, no fault artifact, timeout finish or retained control-failure journal.')


def configured(options, journal):
    return DockerBrokerPairSupervisor(docker_executable=options.docker, context='desktop-linux',
        image_id=options.image, seccomp_path=ROOT / '.dom-xray-data/fixture-seccomp-capture.json',
        seccomp_sha256=PROFILE_SHA, command=('/usr/bin/python3', '-I', ENTRY, 'worker'),
        initializer_command=('/usr/bin/python3', '-I', ENTRY, 'initialize'),
        broker_command=('/usr/bin/python3', '-I', ENTRY, 'broker'), lease_journal=journal)


def native_child(options):
    from scanner.destination_policy import DestinationPolicy
    from scanner.scan_transport import run_public_scan_transport
    from scripts.verify_scan_transport import validators
    with LeaseJournal(options.journal) as journal:
        pair = configured(options, journal)
        pair._prepare_consumers = MethodType(candidate_prepare, pair)
        pair._experimental_reads = engine_reads
        passed = []
        original = pair._preflight_role
        def preflight(row, role, *args, **kwargs):
            original(row, role, *args, **kwargs)
            passed.append(role)
        pair._preflight_role = preflight
        schema, semantic = validators()
        started = time.monotonic()
        result = run_public_scan_transport('https://xray.test/',
            policy=DestinationPolicy(lambda _h, _p: ['1.1.1.1']), launch_worker=pair.launch,
            worker_supervisor=pair.run, schema_validator=schema, semantic_validator=semantic,
            temporary_root=Path(options.result).parent, deadline_seconds=13)
        evidence = {'outcome': result.outcome, 'preflights': passed,
            'journalEmpty': journal.snapshot() == [], 'seconds': time.monotonic() - started,
            'worker': None if result.worker is None else asdict(result.worker)}
        Path(options.result).write_bytes(json.dumps({'supervisorNonce':
            os.environ['DOM_X_RAY_WORKER_RESULT_NONCE'], 'result': evidence}).encode('ascii'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--child', action='store_true')
    parser.add_argument('--image')
    parser.add_argument('--docker')
    parser.add_argument('--journal', type=Path)
    parser.add_argument('--result')
    parser.add_argument('--recover-journal', type=Path)
    options = parser.parse_args()
    if options.child:
        native_child(options)
        return
    contracts()
    if not options.native and options.recover_journal is None:
        return
    import re
    require(isinstance(options.image, str) and re.fullmatch('sha256:[0-9a-f]{64}', options.image),
        'explicit immutable image required')
    options.docker = shutil.which('docker')
    require(options.docker is not None, 'Docker unavailable')
    if options.recover_journal is not None:
        from scanner.lease_recovery import recover_expired_leases
        options.journal = options.recover_journal.resolve(strict=True)
        require(options.journal.parent == (ROOT / '.dom-xray-data').resolve(strict=True)
            and re.fullmatch('pair-read-journal-[0-9a-f]{32}', options.journal.name),
            'exact existing candidate journal required')
        with LeaseJournal(options.journal) as journal:
            report = recover_expired_leases(configured(options, journal))
            print('Exact candidate recovery: ' + json.dumps(asdict(report)), flush=True)
            require(journal.snapshot() == [], 'candidate recovery retained obligations')
        return
    def inventory(kind):
        args = ['ps', '-aq', '--no-trunc'] if kind == 'containers' else ['volume', 'ls', '-q']
        response = subprocess.run([options.docker, '--context', 'desktop-linux', *args,
            '--filter', 'label=' + LABEL], capture_output=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        require(response.returncode == 0 and len(response.stdout) <= 65536, 'inventory failed')
        return response.stdout
    before = {kind: inventory(kind) for kind in ('containers', 'volumes')}
    options.journal = ROOT / '.dom-xray-data' / ('pair-read-journal-' + secrets.token_hex(16))
    print('Persistent candidate journal: ' + str(options.journal), flush=True)
    names = ('PATH', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'LOCALAPPDATA',
        'PROGRAMFILES', 'PROGRAMFILES(X86)', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH')
    environment = {name: os.environ[name] for name in names if name in os.environ}
    with tempfile.TemporaryDirectory(prefix='dxr-pair-read-native-') as temporary:
        path = Path(temporary) / 'result.json'
        worker = run_worker_command([sys.executable, str(Path(__file__).resolve()), '--child',
            '--image', options.image, '--docker', options.docker, '--journal', str(options.journal),
            '--result', str(path)], result_path=path, deadline_seconds=15, cwd=ROOT,
            environment=environment, max_result_bytes=8192)
        evidence = json.loads(path.read_bytes())['result'] if worker.artifact_eligible else None
        print(json.dumps({'outer': asdict(worker), 'evidence': evidence}, sort_keys=True), flush=True)
    with LeaseJournal(options.journal) as journal:
        states = [{role: resource['state'] for role, resource in record['resources'].items()}
            for record in journal.snapshot()]
        print('Retained states: ' + json.dumps(states), flush=True)
    restored = {kind: inventory(kind) == before[kind] for kind in before}
    print('Scoped inventories restored: ' + json.dumps(restored), flush=True)
    require(worker.artifact_eligible and evidence['outcome'] == 'admitted'
        and evidence['journalEmpty'] and all(restored.values()), 'native candidate did not pass')


if __name__ == '__main__':
    main()
