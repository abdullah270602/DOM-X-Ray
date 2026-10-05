"""Exercise native Docker quotas without mounts, networking, or scanner adoption.

Requires an already-pulled official Python image. Resolves the image to its
immutable local ID before starting any probes. Removes only uniquely named,
token-labelled containers owned by this invocation; never prunes other resources.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import secrets
import subprocess
import time


LABEL = 'org.dom-x-ray.resource-proof'


def main() -> None:
    if not __debug__:
        raise RuntimeError('Quota proof requires enabled assertions; optimized Python is rejected')
    parser = argparse.ArgumentParser()
    parser.add_argument('--context', default='desktop-linux')
    parser.add_argument('--image', default='python:3.12-slim-bookworm')
    args = parser.parse_args()
    prefix = ['docker', '--context', args.context]

    def docker(*arguments: str, timeout: float = 15) -> str:
        result = subprocess.run([*prefix, *arguments], capture_output=True,
                                text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f'Docker {arguments[0]} failed: {result.stderr.strip()}')
        return (result.stdout + (result.stderr if arguments[0] == 'logs' else '')).strip()

    engine = json.loads(docker('info', '--format', '{{json .}}'))
    assert engine['OSType'] == 'linux', 'Linux Docker engine required'
    assert engine['CgroupVersion'] == '2', 'cgroup v2 required'
    image = json.loads(docker('image', 'inspect', args.image))[0]
    image_id = image['Id']
    assert re.fullmatch(r'sha256:[0-9a-f]{64}', image_id)
    assert any(digest.startswith('python@sha256:') for digest in image.get('RepoDigests', [])), \
        'Use the pulled official python repository image, not a locally retagged image'
    fixture = (Path(__file__).resolve().parents[1] / 'fixtures' / 'worker' /
               'container_resource_fixture.py').read_text(encoding='utf-8')
    report = {'engine': engine['ServerVersion'], 'image_id': image_id,
              'repo_digests': image.get('RepoDigests', []), 'probes': []}
    for mode in ('configuration', 'cpu', 'pids', 'disk', 'memory',
                 'detached-normal', 'detached-timeout'):
        token = secrets.token_hex(16)
        name = f'dom-x-ray-resource-proof-{token}'
        container_id = None
        try:
            container_id = docker(
                'create', '--pull=never', '--name', name, '--label', f'{LABEL}={token}',
                '--network=none', '--user=65534:65534', '--read-only',
                '--cap-drop=ALL', '--security-opt=no-new-privileges=true',
                '--memory=64m', '--memory-swap=64m', '--pids-limit=32',
                '--cpus=0.25', '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777',
                '--shm-size=8m', '--log-driver=local', '--log-opt=max-size=1m',
                '--log-opt=max-file=1', '--log-opt=compress=false',
                image_id, 'python', '-I', '-c', fixture, mode)
            assert re.fullmatch(r'[0-9a-f]{64}', container_id)
            config = json.loads(docker('inspect', container_id))[0]['HostConfig']
            assert config['Memory'] == config['MemorySwap'] == 67108864
            assert config['PidsLimit'] == 32 and config['NanoCpus'] == 250000000
            assert config['ReadonlyRootfs'] and config['NetworkMode'] == 'none'
            assert config['CapDrop'] == ['ALL'] and not config['Privileged']
            assert not config.get('Binds') and not config.get('Devices')
            assert config['Tmpfs'] == {'/tmp': 'rw,noexec,nosuid,nodev,size=16m,mode=1777'}
            assert config['ShmSize'] == 8 * 1024 * 1024
            assert config['LogConfig'] == {'Type': 'local', 'Config': {
                'max-size': '1m', 'max-file': '1', 'compress': 'false'}}
            docker('start', container_id)
            if mode == 'detached-timeout':
                deadline = time.monotonic() + 5
                while not docker('logs', container_id):
                    assert time.monotonic() < deadline, 'detached fixture failed to start'
                    time.sleep(0.1)
                state = json.loads(docker('inspect', container_id))[0]['State']
                assert state['Running']
                docker('kill', container_id)
            exit_code = int(docker('wait', container_id, timeout=20))
            state = json.loads(docker('inspect', container_id))[0]['State']
            assert not state['Running'] and state['Pid'] == 0
            logs = docker('logs', container_id)
            assert exit_code == (137 if mode == 'detached-timeout' else 0), (mode, exit_code, logs)
            evidence = json.loads(logs)
            assert evidence['mode'] == mode
            report['probes'].append({**evidence, 'exit_code': exit_code,
                                     'container_stopped': True})
        finally:
            # Creation can time out after the engine created a container. The
            # random name plus private ownership token protects that path too.
            lookup = subprocess.run([*prefix, 'container', 'ls', '-aq',
                                     '--filter', f'name=^/{name}$'],
                                    capture_output=True, text=True, timeout=15, check=True)
            found = lookup.stdout.strip()
            if found:
                owned = json.loads(docker('inspect', found))[0]
                assert owned['Name'] == '/' + name
                assert owned['Config']['Labels'].get(LABEL) == token
                docker('rm', '--force', owned['Id'])
                assert not docker('container', 'ls', '-aq',
                                  '--filter', f'name=^/{name}$')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
