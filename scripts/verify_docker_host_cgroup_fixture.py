"""Portable protocol checks; these mocks are not native cgroup evidence."""

from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.docker_host_cgroup_fixture import PROGRAM, verify_populated_candidate


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
    print('Verified candidate probe argument and response protocol; no native identity/empty claim.')


if __name__ == '__main__':
    main()
