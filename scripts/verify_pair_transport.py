"""Native startup-inclusive pair lease, reserved fixtures only."""

import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import secrets
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.docker_broker_pair_supervisor import DockerBrokerPairSupervisor
from scanner.docker_worker_supervisor import LABEL
from scanner.destination_policy import DestinationPolicy
from scanner.scan_transport import run_public_scan_transport
from scanner.lease_journal import LeaseJournal
from scripts.verify_scan_transport import validators
from scripts.verify_docker_transport import PROFILE_SHA, require

ENTRY = '/opt/dom-xray/fixtures/worker/container_broker_pair.py'


def trace_supervisor(supervisor):
    """Fixture-only timings: never print payloads, IDs, URLs or daemon errors."""
    started = time.monotonic()
    def wrap(callback, label):
        def measured(*args, **kwargs):
            before = time.monotonic()
            status = 'ok'
            try:
                return callback(*args, **kwargs)
            except Exception as error:
                status = type(error).__name__
                raise
            finally:
                print(f'trace {label}: {(time.monotonic() - before) * 1000:.0f} ms '
                      f'elapsed={(time.monotonic() - started) * 1000:.0f} ms {status}', flush=True)
        return measured
    original_call = supervisor._call
    def call(arguments, deadline):
        label = 'control-' + arguments[0]
        if arguments[0] in ('volume', 'container'):
            label += '-' + arguments[1]
        return wrap(original_call, label)(arguments, deadline)
    supervisor._call = call
    for factory in ('_pipe', '_held_pipe'):
        original_factory = getattr(supervisor, factory)
        def make(*args, _factory=original_factory, _label=factory, **kwargs):
            pipe = _factory(*args, **kwargs)
            for method in ('finish', 'wait_prefix', 'close_input'):
                setattr(pipe, method, wrap(getattr(pipe, method), _label + '-' + method))
            return pipe
        setattr(supervisor, factory, make)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', default='dom-x-ray-runtime-candidate:gate3')
    parser.add_argument('--case', choices=('capture', 'profile', 'hang', 'wrong-capability', 'wrong-uid'))
    parser.add_argument('--journal', action='store_true', help='also require durable per-resource journal commits')
    parser.add_argument('--trace', action='store_true', help='print content-free control and pipe timings')
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
    with tempfile.TemporaryDirectory(prefix='dxr-pair-transport-') as temporary, ExitStack() as stack:
        journal_root = ROOT / '.dom-xray-data' / ('pair-lease-journal-' + secrets.token_hex(16))
        journal = stack.enter_context(LeaseJournal(journal_root)) if options.journal else None
        results = Path(temporary) / 'results'
        results.mkdir()
        for case in cases:
            mode = 'worker' if case == 'capture' else 'worker-' + case
            supervisor = DockerBrokerPairSupervisor(docker_executable=executable, context='desktop-linux', image_id=image,
                seccomp_path=ROOT / '.dom-xray-data/fixture-seccomp-capture.json', seccomp_sha256=PROFILE_SHA,
                command=('/usr/bin/python3', '-I', ENTRY, mode),
                initializer_command=('/usr/bin/python3', '-I', ENTRY, 'initialize'),
                broker_command=('/usr/bin/python3', '-I', ENTRY, 'broker-wrong-uid' if case == 'wrong-uid' else 'broker'))
            supervisor.journal = journal
            observed = []
            original_pipe = supervisor._pipe
            def record_pipe(*args, **kwargs):
                pipe = original_pipe(*args, **kwargs)
                if args[0][0] == 'start' and args[1] is not None and args[1]:
                    observed.append(pipe)
                return pipe
            supervisor._pipe = record_pipe
            if options.trace:
                trace_supervisor(supervisor)
            result = run_public_scan_transport('https://xray.test/', policy=DestinationPolicy(lambda _h, _p: ['1.1.1.1']),
                launch_worker=supervisor.launch, worker_supervisor=supervisor.run,
                schema_validator=schema, semantic_validator=semantic, temporary_root=results, deadline_seconds=15)
            if case == 'profile':
                markers = set()
                for pipe in observed:
                    for line in bytes(pipe.data).splitlines():
                        if re.fullmatch(rb'profile [a-z-]+ [0-9]{1,8}', line):
                            markers.add(line.split()[1])
                            print(line.decode('ascii'), flush=True)
                require({'installed', 'browser-end', 'navigation-end'} <= markers,
                        'profile did not reach actual sandboxed Chromium navigation')
                require(result.outcome in ('worker-timeout', 'worker-invalid-result'),
                        'profiling output was admitted or failed outside measurement')
                require(result.worker is not None and not result.admitted,
                        'profile unexpectedly produced an eligible artifact')
                expected = result.outcome
            else:
                expected = 'admitted' if case == 'capture' else 'worker-timeout' if case == 'hang' else 'worker-invalid-result'
            if journal is not None and result.outcome != expected:
                print('Retained journal: ' + str(journal_root), flush=True)
                print(json.dumps([{role: resource['state'] for role, resource in record['resources'].items()}
                                  for record in journal.snapshot()]), flush=True)
            require(result.outcome == expected, f'{case}: expected {expected}, got {result.outcome}')
            require(result.worker is not None and result.worker.duration_ms <= 15000 and not list(results.iterdir()),
                    'lease overrun or retained host result')
            if journal is not None:
                require(journal.snapshot() == [], 'removed resources retained unresolved journal state')
            if case == 'hang':
                require(any(b'renderer-live\n' in pipe.data for pipe in observed), 'real renderer timeout witness missing')
            print(f'{case}: {result.outcome}, startup-through-cleanup {result.worker.duration_ms:.0f} ms', flush=True)
    require(before == control('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL), 'owned containers leaked')
    require(volumes_before == control('volume', 'ls', '-q', '--filter', 'label=' + LABEL), 'owned volumes leaked')
    print('Verified scoped fixture outcomes and cleanup. Profile runs prove no scan admission; '
          'public egress/API and durable recovery remain gated.')


if __name__ == '__main__':
    main()
