"""Reserved-origin native Chromium pair through real HTTP publication. Not public egress."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import secrets
import re
import shutil
import subprocess
import sys
from threading import Thread
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.api_contract import validate_viewer_bundle
from scanner.destination_policy import DestinationPolicy
from scanner.docker_broker_pair_supervisor import DockerBrokerPairSupervisor
from scanner.docker_worker_supervisor import LABEL
from scanner.lease_journal import LeaseJournal
from scanner.lease_recovery import recover_expired_leases
from scanner.local_scan_api import API_VERSION, LocalScanJobService, TransportScanExecutor, build_server
from scanner.result_store import MemoryResultStore
from scripts.verify_docker_transport import PROFILE_SHA
from scripts.verify_local_scan_api import deletion_digest, json_request, request, require
from scripts.verify_pair_transport import trace_supervisor

ENTRY = '/opt/dom-xray/fixtures/worker/container_broker_pair.py'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--recover-journal', type=Path)
    options = parser.parse_args()
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', options.image),
        'explicit immutable image required')
    docker = shutil.which('docker')
    require(docker is not None, 'Docker runtime unavailable')
    def control(*args):
        result = subprocess.run([docker, '--context', 'desktop-linux', *args],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
        require(result.returncode == 0 and len(result.stdout) <= 65536, 'Docker control failed')
        return result.stdout.decode().strip()
    require(control('image', 'inspect', options.image, '--format', '{{.Id}}') == options.image,
        'image identity changed')
    before = control('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL)
    volumes = control('volume', 'ls', '-q', '--filter', 'label=' + LABEL)
    owner = 'dxrd_' + secrets.token_hex(32)
    journal_root = ROOT / '.dom-xray-data' / ('pair-api-journal-' + secrets.token_hex(16))
    if options.recover_journal is not None:
        journal_root = options.recover_journal.resolve(strict=True)
        require(journal_root.parent == (ROOT / '.dom-xray-data').resolve(strict=True)
            and re.fullmatch(r'pair-api-journal-[0-9a-f]{32}', journal_root.name),
            'recovery must name one existing invocation-owned API fixture journal')
    print('Persistent recovery journal: ' + str(journal_root), flush=True)
    with LeaseJournal(journal_root) as journal:
        pair = DockerBrokerPairSupervisor(docker_executable=docker, context='desktop-linux',
            image_id=options.image, seccomp_path=ROOT / '.dom-xray-data/fixture-seccomp-capture.json',
            seccomp_sha256=PROFILE_SHA, command=('/usr/bin/python3', '-I', ENTRY, 'worker'),
            initializer_command=('/usr/bin/python3', '-I', ENTRY, 'initialize'),
            broker_command=('/usr/bin/python3', '-I', ENTRY, 'broker'), lease_journal=journal)
        if options.recover_journal is not None:
            report = recover_expired_leases(pair)
            print('Exact journal recovery: ' + json.dumps(asdict(report)), flush=True)
            require(journal.snapshot() == [], 'exact journal recovery retained obligations')
            return
        if options.trace:
            trace_supervisor(pair)
        executor = TransportScanExecutor(supported_targets=('https://xray.test/',),
            policy_factory=lambda: DestinationPolicy(lambda _h, _p: ['1.1.1.1']),
            launch_worker=pair.launch, worker_supervisor=pair.run, deadline_seconds=15)
        store = MemoryResultStore(keys=(b'A' * 32,))
        service = LocalScanJobService(executor, result_backend=store)
        server = build_server('127.0.0.1', 0, service)
        host = Thread(target=server.serve_forever, daemon=True)
        base = f'http://127.0.0.1:{server.server_port}'
        def submit(target):
            return json_request(base, '/api/scans', method='POST',
                value={'apiVersion': API_VERSION, 'url': target},
                headers={'X-Deletion-Token-Digest': 'sha256=' + deletion_digest(owner)})
        try:
            host.start()
            status, _, rejected = submit('https://arbitrary.example/')
            require(status == 503 and rejected['error']['code'] == 'scanner-disabled'
                and journal.snapshot() == [], 'arbitrary target reached pair')
            status, _, job = submit('https://xray.test/')
            require(status == 202, 'reserved origin was not queued')
            until = time.monotonic() + 60  # Observation only; native scan lease remains 15s.
            while job['state'] in ('queued', 'running') and time.monotonic() < until:
                time.sleep(.1)
                status, headers, job = json_request(base, '/api/scans/' + job['jobId'])
                require(status == 200 and headers['Cache-Control'] == 'no-store', 'polling changed')
            require(job['state'] == 'ready', 'native API publication failed: ' + str(job.get('error')))
            require(journal.snapshot() == [], 'ready job retained unresolved pair lease')
            result_id = job['result']['resultId']
            status, headers, payload = request(base, '/api/results/' + result_id)
            require(status == 200 and headers['Cache-Control'] == 'no-store', 'published bundle unavailable')
            bundle = json.loads(payload)
            validate_viewer_bundle(bundle)
            require(bundle['record']['requestedUrl'] == 'https://xray.test/'
                and store.get(result_id).payload == payload, 'capture identity/immutable bytes drifted')
            status, _, reused = submit('https://xray.test/')
            require(status == 200 and reused['result']['resultId'] == result_id, 'pair result reuse changed')
            status, _, _ = request(base, '/api/results/' + result_id, method='DELETE',
                headers={'X-Deletion-Token': owner})
            require(status == 204 and store.get(result_id) is None, 'owner deletion failed')
            print('Reserved-origin Chromium capture -> validated scene/runtime -> HTTP ready result '
                  '-> exact reuse -> HMAC owner deletion passed.', flush=True)
        finally:
            if host.is_alive():
                server.shutdown()
            server.server_close()
            service.shutdown()
            host.join(timeout=2)
            require(not host.is_alive(), 'owned HTTP server did not stop')
            matching_containers = before == control('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL)
            matching_volumes = volumes == control('volume', 'ls', '-q', '--filter', 'label=' + LABEL)
            print(f'Final scoped inventory: containers unchanged={matching_containers}; '
                  f'volumes unchanged={matching_volumes}', flush=True)
            if sys.exc_info()[0] is None:
                require(matching_containers and matching_volumes, 'owned resources leaked')
        require(journal.snapshot() == [], 'unresolved journal remains; inspect persistent journal')
    require(before == control('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL)
        and volumes == control('volume', 'ls', '-q', '--filter', 'label=' + LABEL), 'owned resources leaked')
    print('Scoped inventory unchanged. Not public egress, independent cgroup binding, '
          'installed supervision, persistent backend or public API enablement.')


if __name__ == '__main__':
    main()
