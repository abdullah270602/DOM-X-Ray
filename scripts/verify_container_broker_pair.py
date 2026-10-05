"""Docker-native identity/socket mount fixture. Not production pair supervision."""

import argparse
import json
from pathlib import Path
import queue
import re
import secrets
import subprocess
import sys
from threading import Thread
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.docker_worker_supervisor import _PipeProcess, _pairs, _invalid_constant
from scripts.verify_docker_transport import PROFILE_SHA
from scripts.verify_scan_transport import validators
from scripts.verify_container_capture import require
import hashlib

LABEL = 'org.dom-x-ray.broker-pair-fixture'
ENTRY = '/opt/dom-xray/fixtures/worker/container_broker_pair.py'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', default='dom-x-ray-runtime-candidate:gate3')
    parser.add_argument('--case', choices=('capture', 'wrong-capability', 'wrong-uid', 'wrong-gid', 'no-volume', 'hang'))
    options = parser.parse_args()
    prefix = ['docker', '--context', 'desktop-linux']
    def call(*args, timeout=10):
        process = subprocess.run([*prefix, *args], capture_output=True, timeout=timeout)
        require(process.returncode == 0 and len(process.stdout) <= 65536, 'Docker control call failed')
        return process.stdout.decode().strip()
    image = call('image', 'inspect', options.image, '--format', '{{.Id}}')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'immutable image required')
    engine = json.loads(call('info', '--format', '{{json .}}'))
    require(engine['OSType'] == 'linux' and engine['CgroupVersion'] == '2', 'Linux cgroup v2 required')
    profile = ROOT / '.dom-xray-data/fixture-seccomp-capture.json'
    require(hashlib.sha256(json.dumps(json.loads(profile.read_bytes()), sort_keys=True,
        separators=(',', ':')).encode()).hexdigest() == PROFILE_SHA, 'fixture profile changed')
    schema, semantic = validators()
    cases = (options.case,) if options.case else ('capture', 'wrong-capability', 'wrong-uid', 'wrong-gid', 'no-volume', 'hang')
    for case in cases:
        token = secrets.token_hex(16)
        volume = 'dxr-broker-pair-' + token
        containers, broker_pipe, worker_pipe = [], None, None
        broker_rows = queue.Queue(maxsize=4)
        capability, nonce = secrets.token_hex(32), secrets.token_hex(16)
        job = json.dumps({'nonce': nonce, 'capability': capability, 'grant': {
            'targetUrl': 'https://xray.test/', 'destination': {'purpose': 'initial', 'scheme': 'https',
                'hostname': 'xray.test', 'port': 443, 'addresses': ['1.1.1.1']}}}, separators=(',', ':')).encode() + b'\n'
        volume_created = False
        def inspect(identifier):
            row = json.loads(call('inspect', identifier))[0]
            require(row['Id'] == identifier and row['Config']['Labels'].get(LABEL) == token,
                    'container ownership differs')
            return row
        def create(role, mode, uid, gid, *, mounted=True):
            mount = ([] if not mounted else ['--mount', f'type=volume,src={volume},dst=/run/dxr-broker,volume-nocopy'
                     + (',readonly' if role == 'worker' else '')])
            flags = ['--cap-add=CHOWN'] if role == 'initialize' else []
            identifier = call('create', '-i', '--pull=never', '--name', f'dxr-{role}-{token}', '--label', f'{LABEL}={token}',
                '--init', '--network=none', '--ipc=private', '--cgroupns=private', '--read-only',
                f'--user={uid}:{gid}', '--cap-drop=ALL', *flags, '--security-opt=no-new-privileges=true',
                '--security-opt=seccomp=' + str(profile), '--memory=1g', '--memory-swap=1g', '--cpus=1',
                '--pids-limit=128', '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777', '--shm-size=64m',
                '--log-driver=none', '--restart=no', '--no-healthcheck', *mount,
                '--entrypoint=/usr/bin/python3', image, '-I', ENTRY, mode)
            require(re.fullmatch('[0-9a-f]{64}', identifier), 'invalid container ID')
            containers.append(identifier)
            row = inspect(identifier)
            host = row['HostConfig']
            require(row['Image'] == image and row['Config']['User'] == f'{uid}:{gid}'
                    and row['Config']['Cmd'] == ['-I', ENTRY, mode] and row['Config']['Entrypoint'] == ['/usr/bin/python3']
                    and host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] and not host['Privileged']
                    and host['CapDrop'] == ['ALL'] and host['CapAdd'] == (['CAP_CHOWN'] if flags else None)
                    and host['Memory'] == host['MemorySwap'] == 1073741824 and host['NanoCpus'] == 1000000000
                    and host['PidsLimit'] == 128 and host['Init'] and host['IpcMode'] == 'private'
                    and host['CgroupnsMode'] == 'private' and not host['PidMode'] and not host['UsernsMode']
                    and not host.get('Binds') and not host.get('Devices') and not host.get('DeviceRequests')
                    and host['LogConfig']['Type'] == 'none' and not row['State']['Running'], 'isolation readback differs')
            mounts = row['Mounts']
            require(len(mounts) == int(mounted) and (not mounted or (mounts[0]['Type'] == 'volume'
                    and mounts[0]['Name'] == volume and mounts[0]['Destination'] == '/run/dxr-broker'
                    and mounts[0]['RW'] == (role != 'worker'))), 'mount readback differs')
            security = host['SecurityOpt']
            require(len(security) == 2 and any(s in ('no-new-privileges', 'no-new-privileges=true') for s in security)
                    and [json.loads(s.split('=', 1)[1]) for s in security if s.startswith('seccomp=')]
                    == [json.loads(profile.read_bytes())], 'security policy readback differs')
            return identifier
        try:
            require(call('volume', 'create', '--driver=local', '--label', f'{LABEL}={token}', volume) == volume,
                    'volume create differs')
            volume_created = True
            volume_row = json.loads(call('volume', 'inspect', volume))[0]
            require(volume_row['Name'] == volume and volume_row['Labels'].get(LABEL) == token
                    and volume_row['Driver'] == 'local' and not volume_row['Options'], 'volume ownership differs')
            initialize = create('initialize', 'initialize', 0, 0)
            require(not call('start', '--attach', '--interactive', initialize), 'initializer output differs')
            require(inspect(initialize)['State']['ExitCode'] == 0, 'initializer failed')
            broker = create('broker', 'broker-wrong-uid' if case == 'wrong-uid' else 'broker', 10002, 10001)
            mode = 'worker' if case == 'capture' else 'worker-' + case
            worker = create('worker', mode, 10001, 10003 if case == 'wrong-gid' else 10001, mounted=case != 'no-volume')
            options_popen = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {}
            broker_pipe = subprocess.Popen([*prefix, 'start', '--attach', '--interactive', broker],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, **options_popen)
            def read_broker():
                try:
                    while line := broker_pipe.stdout.readline(4097):
                        if len(line) > 4096:
                            broker_rows.put_nowait(b'overflow')
                            return
                        broker_rows.put_nowait(line)
                except (OSError, queue.Full):
                    pass
            reader = Thread(target=read_broker, daemon=True)
            reader.start()
            broker_pipe.stdin.write(job)
            broker_pipe.stdin.flush()
            require(broker_rows.get(timeout=3) == b'ready\n', 'broker readiness failed')
            broker_state, worker_state = inspect(broker), inspect(worker)
            require(broker_state['State']['Pid'] > 0 and worker_state['State']['Pid'] == 0, 'startup ordering differs')
            started = time.monotonic()
            worker_pipe = _PipeProcess([*prefix, 'start', '--attach', '--interactive', worker], job, 4_000_000)
            if case == 'hang':
                try:
                    worker_pipe.finish(started + 10)
                except TimeoutError:
                    require(b'renderer-live\n' in worker_pipe.data, 'actual renderer did not reach timeout witness')
                else:
                    raise AssertionError('hang worker exited before timeout')
                call('kill', worker)
                worker_pipe.stop(time.monotonic() + 1)
                output = b''
            else:
                code, output = worker_pipe.finish(started + 10)
                require(code == 0, 'worker attach failed')
                require(inspect(worker)['State']['ExitCode'] == 0, 'worker failed')
            broker_pipe.stdin.close()
            require(broker_pipe.wait(timeout=5) == 0 and inspect(broker)['State']['ExitCode'] == 0, 'broker exit failed')
            reader.join(timeout=1)
            report = json.loads(broker_rows.get(timeout=1), object_pairs_hook=_pairs, parse_constant=_invalid_constant)
            require(report['uid'] == 10002 and report['socketRemoved'] and report['empty'], 'broker cleanup differs')
            if case in ('capture', 'hang'):
                require(report['initialPinned'] and report['laterPinned'] and report['contacts'] >= 3
                        and report['lookups'] >= 1, 'broker origin observations differ')
            else:
                require(output == b'denied\n' and report['contacts'] == report['lookups'] == 0,
                        'unauthorized worker contacted origin')
            if case == 'capture':
                payload = json.loads(output, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
                require(set(payload) == {'supervisorNonce', 'result'} and payload['supervisorNonce'] == nonce
                        and set(payload['result']) == {'record'}, 'result envelope differs')
                record = payload['result']['record']
                schema(record)
                semantic(record)
            print(f'{case}: verified distinct UID containers, socket access and cleanup; {1000*(time.monotonic()-started):.0f} ms', flush=True)
        finally:
            if worker_pipe is not None:
                worker_pipe.stop(time.monotonic() + 1)
            if broker_pipe is not None:
                if not broker_pipe.stdin.closed:
                    broker_pipe.stdin.close()
                if broker_pipe.poll() is None:
                    broker_pipe.kill()
                    broker_pipe.wait(timeout=3)
                broker_pipe.stdout.close()
            for identifier in reversed(containers):
                row = inspect(identifier)
                if row['State']['Running']:
                    call('kill', identifier)
                row = inspect(identifier)
                require(not row['State']['Running'] and row['State']['Pid'] == 0, 'container survived cleanup')
                call('rm', identifier)
                require(not call('ps', '-aq', '--no-trunc', '--filter', f'id={identifier}'), 'container survived removal')
            if volume_created:
                row = json.loads(call('volume', 'inspect', volume))[0]
                require(row['Name'] == volume and row['Labels'].get(LABEL) == token, 'volume cleanup ownership differs')
                call('volume', 'rm', volume)
                require(not call('volume', 'ls', '-q', '--filter', f'name=^{volume}$'), 'volume survived removal')
    print('Verified Docker cross-container broker fixture. Public egress and production pair supervisor remain gated.')


if __name__ == '__main__':
    main()
