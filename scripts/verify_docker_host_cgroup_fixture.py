"""Portable protocol checks; these mocks are not native cgroup evidence."""

from pathlib import Path
from io import BytesIO
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.docker_host_cgroup_fixture import (PROGRAM, CONTAINER_ROOT_PROGRAM,
    HOST_ROOT_PROGRAM, TRANSITION_PROGRAM, CandidateTransitionObserver,
    verify_populated_candidate, verify_root_identity_match)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    identifier = 'a' * 64
    for invalid in ('a' * 63, 'A' * 64, identifier + ';echo unsafe', None, 1):
        with patch('scripts.docker_host_cgroup_fixture.shutil.which') as locate:
            try:
                verify_populated_candidate(invalid)
            except ValueError:
                pass
            else:
                raise RuntimeError('invalid identifier accepted')
            require(not locate.called, 'invalid identifier reached process setup')

    for code, output, accepted in (
        (0, b'candidate-populated\n', True),
        (0, b'candidate-populated\r\n', True),
        (1, b'candidate-populated\n', False),
        (0, b'candidate-populated\nextra\n', False),
        (2, b'directory-unavailable\n', False),
        (2, b'filesystem-mismatch\n', False),
    ):
        with patch('scripts.docker_host_cgroup_fixture.shutil.which', return_value=__file__), \
                patch('scripts.docker_host_cgroup_fixture.Path.resolve', return_value=Path(__file__)), \
                patch('scripts.docker_host_cgroup_fixture.subprocess.CREATE_NO_WINDOW', 0, create=True), \
                patch('scripts.docker_host_cgroup_fixture.subprocess.run',
                      return_value=subprocess.CompletedProcess([], code, output)) as run:
            succeeded = False
            try:
                verify_populated_candidate(identifier)
                succeeded = True
            except ValueError:
                pass
            require(succeeded == accepted, 'response acceptance mismatch')
            args, kwargs = run.call_args
            require(args[0][-4:] == ['sh', '-s', '--', identifier], 'identifier not positional')
            require(kwargs['input'] == PROGRAM.encode() and kwargs['timeout'] == 5,
                    'fixed program or timeout changed')
    for host_code, host_output, container_code, container_output, accepted in (
        (0, b'28:987\n', 0, b'28:987\n', True),
        (0, b'28:987\n', 0, b'28:987\r\n', True),
        (0, b'28:987\n', 0, b'28:988\n', False),
        (0, b'28:987\n', 1, b'28:987\n', False),
        (1, b'28:987\n', 0, b'28:987\n', False),
        (0, b'28:987\nextra\n', 0, b'28:987\nextra\n', False),
        (0, b'0:0\n', 0, b'0:0\n', False),
        (0, b'28:' + b'9' * 21 + b'\n', 0, b'28:987\n', False),
    ):
        with patch('scripts.docker_host_cgroup_fixture.shutil.which', return_value=__file__), \
                patch('scripts.docker_host_cgroup_fixture.Path.resolve', return_value=Path(__file__)), \
                patch('scripts.docker_host_cgroup_fixture.subprocess.CREATE_NO_WINDOW', 0, create=True), \
                patch('scripts.docker_host_cgroup_fixture.subprocess.run', side_effect=[
                    subprocess.CompletedProcess([], host_code, host_output),
                    subprocess.CompletedProcess([], container_code, container_output)]) as run:
            succeeded = False
            try:
                verify_root_identity_match(identifier, ['docker', '--context', 'desktop-linux'])
                succeeded = True
            except ValueError:
                pass
            require(succeeded == accepted, 'identity response acceptance mismatch')
            host_args, host_kwargs = run.call_args_list[0]
            container_args, container_kwargs = run.call_args_list[1]
            require(host_args[0][-4:] == ['sh', '-s', '--', identifier]
                    and host_kwargs['input'] == HOST_ROOT_PROGRAM.encode(), 'host identity protocol changed')
            require(container_args[0][-8:] == ['exec', '--user', '10001:10001', identifier,
                    '/usr/bin/python3', '-I', '-c', CONTAINER_ROOT_PROGRAM], 'container identity protocol changed')
            require(host_kwargs['timeout'] == container_kwargs['timeout'] == 5, 'identity timeouts changed')
    with patch('scripts.docker_host_cgroup_fixture.shutil.which') as locate:
        try:
            verify_root_identity_match(identifier + ';', ['docker'])
        except ValueError:
            pass
        else:
            raise RuntimeError('identity probe accepted invalid ID')
        require(not locate.called, 'invalid identity ID reached process setup')
    for output, ready, empty in (
        (b'events-populated\nevents-empty\n', True, True),
        (b'events-populated\r\nevents-empty\r\n', True, True),
        (b'events-empty\n', False, False),
        (b'events-populated\n', True, False),
        (b'events-populated\nevents-empty\nextra', True, False),
        (b'x' * 100, False, False),
    ):
        pipe = BytesIO()
        process = SimpleNamespace(stdin=pipe, stdout=BytesIO(output),
            poll=lambda: None, wait=lambda timeout: 0, kill=lambda: None)
        with patch('scripts.docker_host_cgroup_fixture.shutil.which', return_value=__file__), \
                patch('scripts.docker_host_cgroup_fixture.Path.resolve', return_value=Path(__file__)), \
                patch('scripts.docker_host_cgroup_fixture.subprocess.CREATE_NO_WINDOW', 0, create=True), \
                patch('scripts.docker_host_cgroup_fixture.subprocess.Popen', return_value=process) as launch:
            # Keep the test input observable after the constructor closes stdin.
            with patch.object(pipe, 'close'):
                observer = CandidateTransitionObserver(identifier)
            observer.reader.join(timeout=2)
            require(not observer.reader.is_alive(), 'mock reader remained live')
            require(observer.ready.is_set() == ready and observer.empty.is_set() == empty,
                    'transition protocol acceptance mismatch')
            require(pipe.getvalue() == TRANSITION_PROGRAM.encode(), 'observer input changed')
            require(launch.call_args.args[0][-8:] == ['timeout', '-s', 'KILL', '40',
                    'sh', '-s', '--', identifier], 'observer argument protocol changed')
            if empty:
                observer.wait_ready()
                observer.verify_empty()
                observer.verify_empty(observed_after=observer.empty_observed_at)
                try:
                    observer.verify_empty(observed_after=observer.empty_observed_at + 1)
                except ValueError:
                    pass
                else:
                    raise RuntimeError('pre-crash receive time accepted')
            observer.close()
            require(process.stdout.closed, 'stopped reader pipe remained open')
    print('Verified candidate, cross-view and observer protocols; no native gate closure claim.')


if __name__ == '__main__':
    main()
