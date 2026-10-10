"""Host candidate diagnostics including an opt-in retained events observation.

The optional container diagnostic creates a transient unprivileged exec process;
it is not an adversarial identity binding or production observer.
Worker-only observed transitions do not close the worker/broker release gate.
"""

from pathlib import Path
import re
import shutil
import subprocess
import time
from threading import Event, Thread

MEMBERSHIP_PROGRAM = r'''
set -eu
directory="/sys/fs/cgroup/docker/$1"
expected="$2"
[ -d "$directory" ] && [ ! -L "$directory" ]
[ "$(stat -fc %t "$directory")" = "63677270" ]
[ -f "$directory/cgroup.procs" ] && [ ! -L "$directory/cgroup.procs" ]
found=0
visible=0
count=0
while read -r pid extra; do
    [ -z "$extra" ]
    case "$pid" in ''|*[!0-9]*) exit 2 ;; esac
    count=$((count + 1))
    [ "$count" -le 256 ]
    [ "$pid" = 0 ] || visible=1
    [ "$pid" != "$expected" ] || found=1
done < "$directory/cgroup.procs"
if [ "$found" = 1 ]; then
    printf 'membership-matched\n'
elif [ "$visible" = 0 ]; then
    printf 'membership-not-visible\n'
    exit 2
else
    printf 'membership-mismatched\n'
    exit 2
fi
'''


def verify_engine_pid_membership(identifier, pid):
    """Require a PID-number match only; namespace alignment remains unproven."""
    if (not isinstance(identifier, str) or not re.fullmatch('[0-9a-f]{64}', identifier)
            or type(pid) is not int or not 0 < pid < 2**31):
        raise ValueError('cgroup-fixture-membership')
    reason = 'cgroup-fixture-membership'
    try:
        executable = str(Path(shutil.which('wsl.exe')).resolve(strict=True))
        result = subprocess.run([executable, '-d', 'docker-desktop', '-u', 'root', '--',
            'sh', '-s', '--', identifier, str(pid)], input=MEMBERSHIP_PROGRAM.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode != 0 or result.stdout not in (b'membership-matched\n', b'membership-matched\r\n'):
            if result.stdout.strip() in (b'membership-not-visible', b'membership-mismatched'):
                reason = 'cgroup-fixture-' + result.stdout.strip().decode('ascii')
            raise ValueError(reason)
    except Exception:
        raise ValueError(reason) from None

TRANSITION_PROGRAM = r'''
set -eu
set -f
directory="/sys/fs/cgroup/docker/$1"
[ -d "$directory" ] && [ ! -L "$directory" ]
[ "$(stat -fc %t "$directory")" = "63677270" ]
[ -f "$directory/cgroup.events" ] && [ ! -L "$directory/cgroup.events" ]
exec 3< "$directory/cgroup.events"
descriptor="/proc/$$/fd/3"
identity="$(stat -Lc '%d:%i' "$descriptor")"
[ "$identity" = "$(stat -c '%d:%i' "$directory/cgroup.events")" ]
first=1
while :; do
    populated=''
    frozen=''
    while read -r key value extra; do
        [ -z "$extra" ]
        case "$key" in
            populated) [ -z "$populated" ]; populated="$value" ;;
            frozen) [ -z "$frozen" ]; frozen="$value" ;;
            *) exit 2 ;;
        esac
    done < "$descriptor"
    [ "$frozen" = 0 ] || [ "$frozen" = 1 ]
    if [ "$first" = 1 ]; then
        [ "$populated" = 1 ]
        printf 'events-populated\n'
        first=0
    elif [ "$populated" = 0 ]; then
        printf 'events-empty\n'
        exit 0
    else
        [ "$populated" = 1 ]
    fi
    sleep 0.001
done
'''


class CandidateTransitionObserver:
    """Direct host events observation; candidate identity is not adversarially bound."""

    def __init__(self, identifier):
        if not isinstance(identifier, str) or not re.fullmatch('[0-9a-f]{64}', identifier):
            raise ValueError('cgroup-fixture-transition')
        executable = str(Path(shutil.which('wsl.exe')).resolve(strict=True))
        self.ready, self.empty = Event(), Event()
        self.empty_observed_at = None
        self.process = subprocess.Popen([executable, '-d', 'docker-desktop', '-u', 'root', '--',
            'timeout', '-s', 'KILL', '40', 'sh', '-s', '--', identifier],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            self.process.stdin.write(TRANSITION_PROGRAM.encode())
            self.process.stdin.close()
        except Exception:
            self.process.kill()
            self.process.wait(timeout=5)
            self.process.stdout.close()
            self.process.stdin.close()
            raise
        def read():
            try:
                first = self.process.stdout.readline(65)
                if first not in (b'events-populated\n', b'events-populated\r\n'):
                    return
                self.ready.set()
                second = self.process.stdout.readline(65)
                if second not in (b'events-empty\n', b'events-empty\r\n'):
                    return
                # Parent receive time, not the kernel transition's timestamp.
                self.empty_observed_at = time.monotonic()
                if self.process.stdout.read(1) == b'':
                    self.empty.set()
            except Exception:
                return  # No positive protocol event on a read error.
        self.reader = Thread(target=read, daemon=True)
        self.reader.start()

    def wait_ready(self):
        if not self.ready.wait(5) or self.process.poll() is not None:
            raise ValueError('cgroup-fixture-transition-ready')

    def verify_empty(self, *, observed_after=None):
        if not self.empty.wait(5) or self.process.wait(timeout=5) != 0:
            raise ValueError('cgroup-fixture-transition-empty')
        self.reader.join(timeout=2)
        if self.reader.is_alive():
            raise ValueError('cgroup-fixture-transition-reader')
        if observed_after is not None and (self.empty_observed_at is None
                or self.empty_observed_at < observed_after):
            raise ValueError('cgroup-fixture-transition-pre-crash')

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        # Do not close a buffered pipe while its reader owns the lock.
        if not self.reader.is_alive():
            self.process.stdout.close()

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
