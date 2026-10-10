"""Read-only Docker Desktop cgroup-path candidate; not identity/empty proof."""

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
