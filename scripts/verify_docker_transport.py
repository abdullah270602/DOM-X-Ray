"""Native Docker transport proof; reserved origins and trusted fixture modes only."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.destination_policy import DestinationPolicy
from scanner.docker_worker_supervisor import DockerWorkerSupervisor, LABEL
from scanner.scan_transport import run_public_scan_transport
from scripts.verify_scan_transport import validators

PROFILE_SHA = '242cbd13aa6babf1f163ffa712ee00b0ce95e48c8bb3675d82eb213230b4ff48'


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', default='dom-x-ray-capture-fixture:gate3')
    options = parser.parse_args()
    executable = shutil.which('docker')
    require(executable is not None, 'Docker CLI missing')
    prefix = [executable, '--context', 'desktop-linux']
    image = subprocess.run([*prefix, 'image', 'inspect', options.image, '--format', '{{.Id}}'],
                           capture_output=True, check=True, timeout=10).stdout.decode().strip()
    profile = ROOT / '.dom-xray-data/fixture-seccomp-capture.json'
    digest = hashlib.sha256(json.dumps(json.loads(profile.read_bytes()), sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()
    require(digest == PROFILE_SHA, 'fixture profile changed')
    before = subprocess.run([*prefix, 'ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL],
                            capture_output=True, check=True, timeout=10).stdout
    schema, semantic = validators()
    cases = [('valid', 'admitted'), ('capture', 'admitted'),
             ('capture-hang', 'worker-timeout'), ('crash', 'worker-crashed'),
             ('wrong-nonce', 'worker-invalid-result'), ('trailing', 'worker-invalid-result'),
             ('duplicate-key', 'worker-invalid-result'),
             ('oversize', 'worker-invalid-result'), ('stderr-flood', 'admitted'),
             ('wrong-target', 'invalid-record'), ('stock-public', 'worker-crashed')]
    with tempfile.TemporaryDirectory(prefix='dxr-docker-verifier-') as temporary:
        for mode, expected in cases:
            command = ('/usr/bin/python3', '-I', '/opt/dom-xray/fixtures/worker/container_stdio_fixture.py', mode)
            if mode == 'stock-public':
                command = ('/usr/bin/python3', '-I', '/opt/dom-xray/scanner/container_capture_entry.py')
            elif mode == 'wrong-target':
                command = ('/usr/bin/python3', '-I', '/opt/dom-xray/fixtures/worker/container_stdio_fixture.py', 'valid')
            supervisor = DockerWorkerSupervisor(docker_executable=executable, context='desktop-linux',
                image_id=image, seccomp_path=profile, seccomp_sha256=PROFILE_SHA, command=command)
            result = run_public_scan_transport(
                'https://xray.test/' if mode.startswith('capture') or mode == 'wrong-target' else 'https://clean.example/',
                policy=DestinationPolicy(lambda _h, _p: ['1.1.1.1']),
                launch_worker=supervisor.launch, worker_supervisor=supervisor.run,
                schema_validator=schema, semantic_validator=semantic,
                temporary_root=temporary, deadline_seconds=15)
            require(result.outcome == expected,
                    f'{mode}: expected {expected}, got {result.outcome}')
            require(not list(Path(temporary).iterdir()), 'host temporary result survived return')
            require(result.admitted == (expected == 'admitted'), 'ineligible result admitted')
            print(f'{mode}: {result.outcome}; {result.worker.duration_ms:.0f} ms', flush=True)
    after = subprocess.run([*prefix, 'ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL],
                           capture_output=True, check=True, timeout=10).stdout
    require(before == after, 'fixture-owned containers survived verification')
    print('Validated native Docker stdin/stdout transport and engine-reported exact-container teardown.')


if __name__ == '__main__':
    main()
