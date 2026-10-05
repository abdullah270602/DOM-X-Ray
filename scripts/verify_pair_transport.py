"""Native startup-inclusive pair lease, reserved fixtures only."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.docker_broker_pair_supervisor import DockerBrokerPairSupervisor
from scanner.docker_worker_supervisor import LABEL
from scanner.destination_policy import DestinationPolicy
from scanner.scan_transport import run_public_scan_transport
from scripts.verify_scan_transport import validators
from scripts.verify_docker_transport import PROFILE_SHA, require

ENTRY = '/opt/dom-xray/fixtures/worker/container_broker_pair.py'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', default='dom-x-ray-runtime-candidate:gate3')
    parser.add_argument('--case', choices=('capture', 'hang', 'wrong-capability', 'wrong-uid'))
    options = parser.parse_args()
    executable = shutil.which('docker')
    prefix = [executable, '--context', 'desktop-linux']
    def control(*arguments):
        return subprocess.run([*prefix, *arguments], capture_output=True, check=True, timeout=10).stdout.decode().strip()
    image = control('image', 'inspect', options.image, '--format', '{{.Id}}')
    before = control('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL)
    volumes_before = control('volume', 'ls', '-q', '--filter', 'label=' + LABEL)
    schema, semantic = validators()
    cases = (options.case,) if options.case else ('capture', 'hang', 'wrong-capability', 'wrong-uid')
    with tempfile.TemporaryDirectory(prefix='dxr-pair-transport-') as temporary:
        for case in cases:
            mode = 'worker' if case == 'capture' else 'worker-' + case
            supervisor = DockerBrokerPairSupervisor(docker_executable=executable, context='desktop-linux', image_id=image,
                seccomp_path=ROOT / '.dom-xray-data/fixture-seccomp-capture.json', seccomp_sha256=PROFILE_SHA,
                command=('/usr/bin/python3', '-I', ENTRY, mode),
                initializer_command=('/usr/bin/python3', '-I', ENTRY, 'initialize'),
                broker_command=('/usr/bin/python3', '-I', ENTRY, 'broker-wrong-uid' if case == 'wrong-uid' else 'broker'))
            observed = []
            original_pipe = supervisor._pipe
            def record_pipe(*args, **kwargs):
                pipe = original_pipe(*args, **kwargs)
                if args[0][0] == 'start' and args[1] is not None and args[1]:
                    observed.append(pipe)
                return pipe
            supervisor._pipe = record_pipe
            result = run_public_scan_transport('https://xray.test/', policy=DestinationPolicy(lambda _h, _p: ['1.1.1.1']),
                launch_worker=supervisor.launch, worker_supervisor=supervisor.run,
                schema_validator=schema, semantic_validator=semantic, temporary_root=temporary, deadline_seconds=15)
            expected = 'admitted' if case == 'capture' else 'worker-timeout' if case == 'hang' else 'worker-invalid-result'
            require(result.outcome == expected, f'{case}: expected {expected}, got {result.outcome}')
            require(result.worker is not None and result.worker.duration_ms <= 15000 and not list(Path(temporary).iterdir()),
                    'lease overrun or retained host result')
            if case == 'hang':
                require(any(b'renderer-live\n' in pipe.data for pipe in observed), 'real renderer timeout witness missing')
            print(f'{case}: {result.outcome}, startup-through-cleanup {result.worker.duration_ms:.0f} ms', flush=True)
    require(before == control('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL), 'owned containers leaked')
    require(volumes_before == control('volume', 'ls', '-q', '--filter', 'label=' + LABEL), 'owned volumes leaked')
    print('Verified native pair lease and transport admission. Public egress/API and durable recovery remain gated.')


if __name__ == '__main__':
    main()
