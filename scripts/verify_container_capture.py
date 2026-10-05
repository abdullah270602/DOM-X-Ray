"""Run the real reserved-origin capture verifier inside a bounded Docker image.

No scan API adoption or production seccomp claim. Does not mount host paths,
enable network/privileges, or remove unrelated containers/images.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess


LABEL = 'org.dom-x-ray.capture-fixture'
PROFILE_SHA = '242cbd13aa6babf1f163ffa712ee00b0ce95e48c8bb3675d82eb213230b4ff48'


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--context', default='desktop-linux')
    parser.add_argument('--image', default='dom-x-ray-capture-fixture:gate3')
    parser.add_argument('--seccomp', type=Path, default=Path(__file__).resolve().parents[1] /
                        '.dom-xray-data/fixture-seccomp-capture.json')
    parser.add_argument('--runtime-inventory', action='store_true',
                        help='also verify the current candidate manifest and installed package pins')
    parser.add_argument('--runtime-regressions', action='store_true',
                        help='also run current-candidate NSS and sandboxed measurement regressions')
    options = parser.parse_args()
    profile = json.loads(options.seccomp.read_text(encoding='utf-8'))
    fingerprint = hashlib.sha256(json.dumps(profile, sort_keys=True,
                                            separators=(',', ':')).encode()).hexdigest()
    require(fingerprint == PROFILE_SHA, 'fixture profile differs from reviewed generated policy')
    prefix = ['docker', '--context', options.context]

    def docker(*arguments, timeout=15):
        result = subprocess.run([*prefix, *arguments], capture_output=True,
                                text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f'Docker {arguments[0]} failed: {result.stderr.strip()}')
        return (result.stdout + (result.stderr if arguments[0] == 'logs' else '')).strip()

    image = json.loads(docker('image', 'inspect', options.image))[0]['Id']
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'immutable image ID required')
    engine = json.loads(docker('info', '--format', '{{json .}}'))
    require(engine['OSType'] == 'linux' and engine['CgroupVersion'] == '2', 'Linux cgroup v2 required')
    report = {'engine': engine['ServerVersion'], 'image_id': image,
              'profile_sha256': fingerprint, 'cases': []}
    cases = ('default-policy-denial', 'mount-compatibility', 'capture-and-timeout', 'network-bypass')
    if options.runtime_inventory:
        cases = ('runtime-inventory', *cases)
    if options.runtime_regressions:
        cases = (*cases, 'nss-trust', 'measurement-regressions')
    for case in cases:
        token = secrets.token_hex(16)
        name = 'dom-x-ray-capture-fixture-' + token
        try:
            security = [] if case == 'default-policy-denial' else [
                '--security-opt=seccomp=' + str(options.seccomp.resolve(strict=True))]
            command = ['unshare', '--user', '--map-current-user', 'true'] if case == 'default-policy-denial' else []
            if case == 'mount-compatibility':
                command = ['python3', '-I', 'fixtures/worker/container_mount_probe.py']
            if case == 'network-bypass':
                command = ['python3', 'scripts/verify_namespaced_chromium.py', '--runtime-root', '/opt/runtime']
            if case == 'runtime-inventory':
                command = ['python3', 'scripts/verify_runtime_inventory.py']
            if case == 'nss-trust':
                command = ['python3', 'scripts/verify_browser_trust.py', '--native',
                           '--certutil', '/usr/bin/certutil', '--expected-chromium-version', '153.0.8010.12']
            if case == 'measurement-regressions':
                command = ['python3', 'scripts/verify_browser_fixtures.py',
                           '--expected-chromium-version', '153.0.8010.12', '--sandbox']
            identifier = docker('create', '--pull=never', '--name', name,
                '--label', f'{LABEL}={token}', '--init', '--network=none', '--read-only',
                '--user=10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges=true',
                *security, '--memory=1g', '--memory-swap=1g', '--cpus=1', '--pids-limit=128',
                '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777', '--shm-size=64m',
                '--log-driver=local', '--log-opt=max-size=1m', '--log-opt=max-file=1',
                '--log-opt=compress=false', image, *command)
            require(re.fullmatch(r'[0-9a-f]{64}', identifier), 'invalid created container ID')
            configured = json.loads(docker('inspect', identifier))[0]
            host = configured['HostConfig']
            require(host['Memory'] == host['MemorySwap'] == 1073741824 and
                    host['NanoCpus'] == 1000000000 and host['PidsLimit'] == 128, 'resource readback mismatch')
            require(host['ReadonlyRootfs'] and host['NetworkMode'] == 'none' and
                    host['CapDrop'] == ['ALL'] and not host['Privileged'] and host['Init'] and
                    not host.get('Binds') and not host.get('Devices') and not configured['Mounts'],
                    'fixture unexpectedly has privileges or host mounts')
            require(configured['Config']['User'] == '10001:10001', 'non-root identity mismatch')
            require(any(item.startswith('no-new-privileges') for item in host['SecurityOpt']),
                    'no-new-privileges missing')
            require(host['Tmpfs'] == {'/tmp': 'rw,noexec,nosuid,nodev,size=128m,mode=1777'} and
                    host['ShmSize'] == 64 * 1024 * 1024, 'temporary mount configuration mismatch')
            installed = [item.split('=', 1)[1] for item in host['SecurityOpt'] if item.startswith('seccomp=')]
            if case == 'default-policy-denial':
                require(not installed, 'default-policy case unexpectedly has a custom filter')
            else:
                require(len(installed) == 1 and json.loads(installed[0]) == profile,
                        'engine did not receive the reviewed fixture syscall profile')
            docker('start', identifier)
            exit_code = int(docker('wait', identifier, timeout=180 if case == 'measurement-regressions' else 50))
            state = json.loads(docker('inspect', identifier))[0]['State']
            logs = docker('logs', identifier)
            require(not state['Running'] and state['Pid'] == 0 and not state['OOMKilled'],
                    'container did not stop normally or exceeded memory allowance')
            if case == 'default-policy-denial':
                require(exit_code != 0 and 'Operation not permitted' in logs,
                        f'default policy did not reject user namespace setup: {exit_code}; {logs}')
            else:
                require(exit_code == 0, f'{case} failed: {exit_code}; {logs}')
                if case == 'capture-and-timeout':
                    require('Native supervised complete evidence:' in logs and
                            'Native supervised timeout evidence:' in logs and
                            'Verified native sandboxed Chromium capture' in logs,
                            'capture verifier did not finish all checks')
                elif case == 'network-bypass':
                    require('Verified' in logs, 'network verifier did not finish')
                elif case == 'runtime-inventory':
                    require('Verified candidate runtime inventory' in logs, 'runtime inventory verifier did not finish')
                elif case == 'nss-trust':
                    require('Verified native Linux sandboxed Chromium with private NSS trust' in logs,
                            'native NSS acceptance/rejection verifier did not finish')
                elif case == 'measurement-regressions':
                    require('Validated controlled Chromium 153.0.8010.12 against 31 deterministic browser fixtures.' in logs
                            and 'Validated schema-conformant scene manifests for all 31 browser fixtures.' in logs,
                            'current-browser measurement regression verifier did not finish')
            print(f'{case}: {logs}', flush=True)
            report['cases'].append({'case': case, 'exit_code': exit_code, 'container_stopped': True})
        finally:
            found = docker('container', 'ls', '-aq', '--filter', f'name=^/{name}$')
            if found:
                owned = json.loads(docker('inspect', found))[0]
                require(owned['Name'] == '/' + name and owned['Config']['Labels'].get(LABEL) == token,
                        'refusing cleanup of an unowned container')
                docker('rm', '--force', owned['Id'])
                require(not docker('container', 'ls', '-aq', '--filter', f'name=^/{name}$'),
                        'owned fixture container survived removal')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
