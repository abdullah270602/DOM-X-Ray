"""Host path candidate and trusted-fixture root corroboration, not empty proof.

The optional container diagnostic creates a transient unprivileged exec process;
it is not an adversarial identity binding or production observer.
"""

from pathlib import Path
import re
import shutil
import subprocess

# Fixed shell program; immutable container ID is a positional argument, not code.
PROGRAM = r'''
set -eu
identifier="$1"
directory="/sys/fs/cgroup/docker/$identifier"
[ -d "$directory" ] || { printf 'directory-unavailable\n'; exit 2; }
[ "$(stat -fc %t "$directory")" = "63677270" ] || { printf 'filesystem-mismatch\n'; exit 2; }
[ ! -L "$directory" ]
[ -f "$directory/cgroup.events" ] && [ ! -L "$directory/cgroup.events" ]
populated=''
while read -r key value; do
    case "$key" in
        populated) [ -z "$populated" ]; populated="$value" ;;
        frozen) [ "$value" = 0 ] || [ "$value" = 1 ] ;;
        *) exit 2 ;;
    esac
done < "$directory/cgroup.events"
[ "$populated" = 1 ]
printf 'candidate-populated\n'
'''

# Fixture corroboration only: the in-container result is not trusted evidence
# against a compromised renderer. No new privilege or mounts are requested.
CONTAINER_ROOT_PROGRAM = """import os
from pathlib import Path
if Path('/proc/self/cgroup').read_bytes() != b'0::/\\n':
    raise SystemExit(2)
value = os.stat('/sys/fs/cgroup', follow_symlinks=False)
print(str(value.st_dev) + ':' + str(value.st_ino))
"""
HOST_ROOT_PROGRAM = r'''
set -eu
directory="/sys/fs/cgroup/docker/$1"
[ -d "$directory" ] && [ ! -L "$directory" ]
[ "$(stat -fc %t "$directory")" = "63677270" ]
stat -c '%d:%i' "$directory"
'''


def verify_root_identity_match(identifier, docker_prefix):
    """Corroborate a trusted fixture's private root; not adversarial binding."""
    if not isinstance(identifier, str) or not re.fullmatch('[0-9a-f]{64}', identifier):
        raise ValueError('cgroup-fixture-identity')
    try:
        executable = str(Path(shutil.which('wsl.exe')).resolve(strict=True))
        host = subprocess.run([executable, '-d', 'docker-desktop', '-u', 'root', '--',
            'sh', '-s', '--', identifier], input=HOST_ROOT_PROGRAM.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW)
        container = subprocess.run([*docker_prefix, 'exec', '--user', '10001:10001',
            identifier, '/usr/bin/python3', '-I', '-c', CONTAINER_ROOT_PROGRAM],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW)
        pattern = rb'[1-9][0-9]{0,19}:[1-9][0-9]{0,19}\r?\n'
        if (host.returncode != 0 or container.returncode != 0
                or re.fullmatch(pattern, host.stdout) is None
                or re.fullmatch(pattern, container.stdout) is None
                or host.stdout.strip() != container.stdout.strip()):
            raise ValueError('cgroup-fixture-identity')
    except Exception:
        raise ValueError('cgroup-fixture-identity') from None


def verify_populated_candidate(identifier):
    if not isinstance(identifier, str) or not re.fullmatch('[0-9a-f]{64}', identifier):
        raise ValueError('cgroup-fixture-binding')
    executable = shutil.which('wsl.exe')
    if executable is None:
        raise ValueError('cgroup-fixture-unavailable')
    reason = 'cgroup-fixture-binding'
    try:
        executable = str(Path(executable).resolve(strict=True))
        result = subprocess.run([executable, '-d', 'docker-desktop', '-u', 'root', '--',
            'sh', '-s', '--', identifier], input=PROGRAM.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode != 0 or result.stdout not in (b'candidate-populated\n', b'candidate-populated\r\n'):
            if result.stdout.strip() in (b'directory-unavailable', b'filesystem-mismatch'):
                reason = 'cgroup-fixture-' + result.stdout.strip().decode('ascii')
            raise ValueError(reason)
    except Exception:
        raise ValueError(reason) from None
