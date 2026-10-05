"""Mocked fail-closed contract checks for DockerWorkerSupervisor.

These checks exercise host-side decision paths only. They do not prove Docker,
kernel, cgroup, or seccomp enforcement; use verify_docker_transport.py for the
separate native fixture run.
"""

import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.docker_worker_supervisor import DockerWorkerSupervisor, LABEL
from scanner.destination_policy import DestinationPolicy
from scanner.scan_transport import WorkerLaunch, run_public_scan_transport
from scanner.worker_supervisor import WorkerContainmentError


IMAGE = 'sha256:' + 'a' * 64
IDENTIFIER = 'b' * 64
TOKEN = 'c' * 32
NONCE = 'd' * 32
COMMAND = ('/usr/bin/python3', '-I', '/opt/dom-x-ray/fixtures/worker/container_stdio_fixture.py')
PROFILE = {'defaultAction': 'SCMP_ACT_ERRNO'}


def require(value, message):
    if not value:
        raise AssertionError(message)


def supervisor():
    instance = DockerWorkerSupervisor.__new__(DockerWorkerSupervisor)
    instance.command = COMMAND
    instance.image_id = IMAGE
    instance.profile = PROFILE
    instance.profile_path = Path('/operator/fixture-seccomp.json')
    instance.prefix = ('/usr/bin/docker', '--context', 'fixture')
    return instance


def row(*, network='none'):
    host = {
        'Memory': 1073741824, 'MemorySwap': 1073741824, 'NanoCpus': 1000000000,
        'PidsLimit': 128, 'OomKillDisable': False, 'ReadonlyRootfs': True,
        'NetworkMode': network, 'CapDrop': ['ALL'], 'CapAdd': [], 'Privileged': False,
        'Init': True, 'Binds': [], 'Devices': [], 'PidMode': '', 'IpcMode': 'private',
        'CgroupnsMode': 'private', 'UsernsMode': '', 'AutoRemove': False,
        'RestartPolicy': {'Name': 'no'}, 'LogConfig': {'Type': 'none'},
        'Tmpfs': {'/tmp': 'rw,noexec,nosuid,nodev,size=128m,mode=1777'},
        'ShmSize': 67108864,
        'SecurityOpt': ['no-new-privileges=true', 'seccomp=' + json.dumps(PROFILE)],
    }
    return {
        'Id': IDENTIFIER, 'Name': '/dom-x-ray-worker-' + TOKEN, 'Image': IMAGE,
        'Config': {'Labels': {LABEL: TOKEN}, 'User': '10001:10001',
                   'Entrypoint': [COMMAND[0]], 'Cmd': list(COMMAND[1:]),
                   'OpenStdin': True, 'Tty': False, 'Healthcheck': {'Test': ['NONE']}},
        'HostConfig': host, 'Mounts': [],
        'State': {'Running': False, 'Pid': 0, 'ExitCode': 0, 'OOMKilled': False},
    }


def launch(instance):
    payload = {
        'grant': {
            'targetUrl': 'https://clean.example/',
            'destination': {
                'purpose': 'initial', 'scheme': 'https', 'hostname': 'clean.example',
                'port': 443, 'addresses': ['1.1.1.1'],
            },
        },
    }
    return WorkerLaunch(instance.command, input_payload=json.dumps(payload).encode())


class FakePipe:
    def __init__(self, output, on_finish=None, code=0):
        self.output, self.on_finish, self.code = output, on_finish, code

    def finish(self, _deadline):
        if self.on_finish:
            self.on_finish()
        return self.code, self.output

    def stop(self, _deadline):
        pass


def stub_engine(instance, container, output, *, attach_code=0):
    list_count = 0

    def call(arguments, _deadline):
        nonlocal list_count
        if arguments[0] == 'info':
            return json.dumps({'OSType': 'linux', 'CgroupVersion': '2'})
        if arguments[0] == 'create':
            return IDENTIFIER
        if arguments[0] == 'inspect':
            return json.dumps([container])
        if arguments[:2] == ['container', 'ls']:
            list_count += 1
            return IDENTIFIER if list_count == 1 else ''
        if arguments[0] in ('kill', 'rm'):
            return ''
        raise AssertionError(f'unexpected docker operation: {arguments[0]}')

    instance._call = call
    instance._pipe = lambda _args, _payload, _limit: FakePipe(output, code=attach_code)
    return call


def test_config_drift_prevents_start():
    instance = supervisor()
    container = row(network='bridge')
    instance._call = lambda arguments, _deadline: (
        json.dumps({'OSType': 'linux', 'CgroupVersion': '2'}) if arguments[0] == 'info'
        else IDENTIFIER if arguments[0] == 'create'
        else json.dumps([container]) if arguments[0] == 'inspect'
        else '')
    cleanup_state = {'ExitCode': 1, 'OOMKilled': False}
    instance._cleanup = Mock(return_value=cleanup_state)
    instance._pipe = Mock(side_effect=AssertionError('start must not run after config drift'))
    with tempfile.TemporaryDirectory() as temporary, patch(
            'scanner.docker_worker_supervisor.secrets.token_hex', side_effect=[NONCE, TOKEN]):
        path = Path(temporary) / 'result.json'
        try:
            instance.run(launch(instance), path, 5)
        except WorkerContainmentError:
            pass
        else:
            raise AssertionError('configuration drift was accepted')
        require(instance._pipe.call_count == 0, 'container started before config readback passed')
        instance._cleanup.assert_called_once()
        require(not path.exists(), 'config drift created an artifact')


def test_malformed_launch_does_not_contact_engine():
    instance = supervisor()
    instance._call = Mock(side_effect=AssertionError('engine contacted for malformed input'))
    with tempfile.TemporaryDirectory() as temporary:
        malformed = WorkerLaunch(COMMAND, input_payload=b'{"grant":{},"grant":{}}')
        try:
            instance.run(malformed, Path(temporary) / 'result.json', 5)
        except (ValueError, WorkerContainmentError):
            pass
        else:
            raise AssertionError('malformed duplicate-key launch accepted')
    require(instance._call.call_count == 0, 'engine contacted before input validation')


def test_cleanup_failure_blocks_artifact_eligibility():
    instance = supervisor()
    container = row()
    output = json.dumps({'supervisorNonce': NONCE, 'result': {'record': {}}}).encode()
    stub_engine(instance, container, output)
    instance._cleanup = Mock(side_effect=WorkerContainmentError('teardown-unproven'))
    with tempfile.TemporaryDirectory() as temporary, patch(
            'scanner.docker_worker_supervisor.secrets.token_hex', side_effect=[NONCE, TOKEN]):
        path = Path(temporary) / 'result.json'
        try:
            instance.run(launch(instance), path, 5)
        except WorkerContainmentError:
            pass
        else:
            raise AssertionError('cleanup failure returned a WorkerRun')
        require(not path.exists(), 'artifact written before teardown was proven')


def test_known_container_missing_from_lookup_is_not_proof():
    instance = supervisor()
    instance._call = lambda _arguments, _deadline: ''
    try:
        instance._cleanup('dom-x-ray-worker-' + TOKEN, TOKEN, IDENTIFIER, 10**9)
    except WorkerContainmentError:
        pass
    else:
        raise AssertionError('missing container lookup treated as cleanup proof')


def test_wrong_nonce_is_ineligible():
    instance = supervisor()
    container = row()
    output = json.dumps({'supervisorNonce': 'e' * 32, 'result': {'record': {}}}).encode()
    stub_engine(instance, container, output)
    with tempfile.TemporaryDirectory() as temporary, patch(
            'scanner.docker_worker_supervisor.secrets.token_hex', side_effect=[NONCE, TOKEN]):
        result = instance.run(launch(instance), Path(temporary) / 'result.json', 5)
    require(not result.artifact_eligible, 'wrong nonce produced an eligible artifact')
    require(not result.artifact_present, 'wrong nonce was written as an artifact')


def test_deadline_overrun_blocks_artifact():
    instance = supervisor()
    container = row()
    output = json.dumps({'supervisorNonce': NONCE, 'result': {'record': {}}}).encode()
    stub_engine(instance, container, output)
    with tempfile.TemporaryDirectory() as temporary, patch(
            'scanner.docker_worker_supervisor.secrets.token_hex', side_effect=[NONCE, TOKEN]), patch(
            'scanner.docker_worker_supervisor.time.monotonic', side_effect=[0.0, 6.0, 6.0]):
        path = Path(temporary) / 'result.json'
        try:
            instance.run(launch(instance), path, 5)
        except WorkerContainmentError:
            pass
        else:
            raise AssertionError('late result was admitted')
        require(not path.exists(), 'deadline overrun wrote an artifact')


def test_transport_rejects_provider_without_worker_run():
    instance = supervisor()
    grant_launch = launch(instance)
    policy = DestinationPolicy(lambda _host, _port: ['1.1.1.1'])
    result = run_public_scan_transport(
        'https://clean.example/', policy=policy,
        launch_worker=lambda _grant, _path: grant_launch,
        worker_supervisor=lambda _launch, _path, _seconds: object(),
        schema_validator=lambda _record: None, semantic_validator=lambda _record: None,
    )
    require(result.outcome == 'supervisor-failed' and result.worker is None and not result.admitted,
            'non-WorkerRun provider result was accepted')


def test_transport_requires_provider_for_stdin_payload():
    instance = supervisor()
    grant_launch = launch(instance)
    policy = DestinationPolicy(lambda _host, _port: ['1.1.1.1'])
    result = run_public_scan_transport(
        'https://clean.example/', policy=policy,
        launch_worker=lambda _grant, _path: grant_launch,
        schema_validator=lambda _record: None, semantic_validator=lambda _record: None,
    )
    require(result.outcome == 'supervisor-failed' and result.worker is None and not result.admitted,
            'stdin payload silently fell back to ordinary process launch')


def test_attach_failure_blocks_valid_stdout():
    instance = supervisor()
    container = row()
    output = json.dumps({'supervisorNonce': NONCE, 'result': {'record': {}}}).encode()
    stub_engine(instance, container, output, attach_code=125)
    with tempfile.TemporaryDirectory() as temporary, patch(
            'scanner.docker_worker_supervisor.secrets.token_hex', side_effect=[NONCE, TOKEN]):
        path = Path(temporary) / 'result.json'
        result = instance.run(launch(instance), path, 5)
    require(result.outcome == 'crashed' and not result.artifact_eligible,
            'valid bytes overrode attach-client failure')
    require(not path.exists(), 'failed attach wrote an artifact')


def test_create_timeout_without_found_container_is_unresolved():
    instance = supervisor()

    def call(arguments, _deadline):
        if arguments[0] == 'info':
            return json.dumps({'OSType': 'linux', 'CgroupVersion': '2'})
        if arguments[0] == 'create':
            raise TimeoutError('create request timed out')
        if arguments[:2] == ['container', 'ls']:
            return ''
        raise AssertionError(f'unexpected docker operation: {arguments[0]}')

    instance._call = call
    with tempfile.TemporaryDirectory() as temporary, patch(
            'scanner.docker_worker_supervisor.secrets.token_hex', side_effect=[NONCE, TOKEN]):
        path = Path(temporary) / 'result.json'
        try:
            instance.run(launch(instance), path, 5)
        except WorkerContainmentError:
            pass
        else:
            raise AssertionError('ambiguous create timeout was treated as clean absence')
        require(not path.exists(), 'unresolved create wrote an artifact')


def main():
    tests = [test_config_drift_prevents_start, test_malformed_launch_does_not_contact_engine,
             test_cleanup_failure_blocks_artifact_eligibility,
             test_known_container_missing_from_lookup_is_not_proof,
             test_wrong_nonce_is_ineligible, test_deadline_overrun_blocks_artifact,
             test_transport_rejects_provider_without_worker_run,
             test_transport_requires_provider_for_stdin_payload,
             test_attach_failure_blocks_valid_stdout,
             test_create_timeout_without_found_container_is_unresolved]
    for test in tests:
        test()
        print(f'{test.__name__}: ok')
    print(f'Validated {len(tests)} mocked Docker supervisor contract cases (not engine enforcement).')


if __name__ == '__main__':
    main()
