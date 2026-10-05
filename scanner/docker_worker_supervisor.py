"""Trusted Docker CLI boundary, not public API adoption or egress enablement.

Grant/nonce travel only over stdin. A capped stdout artifact is considered only
after engine-reported stop and exact owned-container removal. Engine state is
not an independent host cgroup-empty observation. Controller-death recovery and
a production-reviewed image/filter/egress broker remain release gates.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import threading
import time

from scanner.scan_transport import WorkerLaunch, check_public_scan_grant, decode_public_scan_grant
from scanner.worker_supervisor import (MAX_WORKER_RESULT_BYTES, WorkerContainmentError,
                                       WorkerRun, _artifact_is_valid, _validated_deadline)

MAX_INPUT_BYTES = 16384
CONTROL_BYTES = 65536
LABEL = 'org.dom-x-ray.worker-lease'


def _require(value, code):
    if not value:
        raise WorkerContainmentError(code)


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError('duplicate-worker-input-key')
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError('nonfinite-worker-json')


def _valid_output(output, nonce):
    try:
        payload = json.loads(output, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
        return (isinstance(payload, dict) and set(payload) == {'supervisorNonce', 'result'}
                and payload['supervisorNonce'] == nonce
                and isinstance(payload['result'], dict) and set(payload['result']) == {'record'}
                and isinstance(payload['result']['record'], dict))
    except (ValueError, UnicodeError, RecursionError):
        return False


class _PipeProcess:
    """One bounded pipe reader and finite stdin writer; never communicate()."""

    def __init__(self, command, payload, limit, *, keep_stdin=False):
        options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False, **options)
        self.data = bytearray()
        self.overflow = False
        self.failed = False
        self.read_done = threading.Event()
        self.write_done = threading.Event()
        self.keep_stdin = keep_stdin

        def read():
            try:
                while chunk := os.read(self.process.stdout.fileno(), 65536):
                    remaining = max(0, limit + 1 - len(self.data))
                    self.data.extend(chunk[:remaining])
                    if len(self.data) > limit:
                        self.overflow = True
            except OSError:
                self.failed = True
            finally:
                self.process.stdout.close()
                self.read_done.set()

        def write():
            try:
                self.process.stdin.write(payload)
                self.process.stdin.flush()
            except (OSError, ValueError):
                self.failed = True
            finally:
                if not keep_stdin:
                    try:
                        self.process.stdin.close()
                    except OSError:
                        self.failed = True
                self.write_done.set()

        threading.Thread(target=read, daemon=True).start()
        if payload is None:
            self.write_done.set()
        else:
            threading.Thread(target=write, daemon=True).start()

    def finish(self, deadline):
        while True:
            if self.overflow:
                raise OverflowError('worker-output-limit')
            if self.failed:
                raise WorkerContainmentError('worker-pipe-failure')
            code = self.process.poll()
            if code is not None and self.read_done.is_set() and self.write_done.is_set():
                return code, bytes(self.data)
            if time.monotonic() >= deadline:
                raise TimeoutError('docker-command-deadline')
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))

    def wait_prefix(self, prefix, deadline):
        while True:
            if self.failed or self.overflow:
                raise WorkerContainmentError('docker-readiness-pipe-failed')
            available = bytes(self.data[:len(prefix)])
            _require(prefix.startswith(available), 'docker-readiness-prefix')
            if len(available) == len(prefix):
                _require(self.process.poll() is None, 'docker-broker-exited-before-worker')
                return
            if self.process.poll() is not None:
                raise WorkerContainmentError('docker-broker-no-readiness')
            if time.monotonic() >= deadline:
                raise TimeoutError('docker-readiness-deadline')
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))

    def close_input(self, deadline):
        if self.keep_stdin:
            if not self.write_done.wait(max(0, deadline - time.monotonic())):
                raise TimeoutError('docker-stdin-close-deadline')
            _require(not self.failed, 'docker-stdin-write-failed')
            if not self.process.stdin.closed:
                self.process.stdin.close()

    def stop(self, deadline):
        if self.process.poll() is None:
            self.process.kill()
        try:
            self.process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise WorkerContainmentError('docker-client-survived-stop') from None
        remaining = max(0, deadline - time.monotonic())
        self.read_done.wait(remaining)
        self.write_done.wait(max(0, deadline - time.monotonic()))
        _require(self.read_done.is_set() and self.write_done.is_set(), 'docker-client-pipes-survived-stop')
        if self.keep_stdin and not self.process.stdin.closed:
            self.process.stdin.close()


class DockerWorkerSupervisor:
    """Operator-selected immutable runtime. Never configured from visitor JSON.

    Current policy is network-none. A production capture cannot fetch public
    origins until a separately reviewed restricted broker path is adopted.
    """

    def __init__(self, *, docker_executable, context, image_id, seccomp_path,
                 seccomp_sha256, command):
        executable = Path(docker_executable).resolve(strict=True)
        if not executable.is_file() or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', context):
            raise ValueError('docker-runtime-configuration')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
            raise ValueError('docker-runtime-requires-immutable-image')
        profile_path = Path(seccomp_path).resolve(strict=True)
        if profile_path.stat().st_size > CONTROL_BYTES:
            raise ValueError('docker-profile-size')
        profile = json.loads(profile_path.read_bytes(), object_pairs_hook=_pairs)
        digest = hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if digest != seccomp_sha256 or profile.get('defaultAction') != 'SCMP_ACT_ERRNO':
            raise ValueError('docker-profile-integrity')
        if (not isinstance(command, (tuple, list)) or not command or len(command) > 16
                or any(not isinstance(item, str) or not item or len(item) > 4096 for item in command)
                or not command[0].startswith('/')):
            raise ValueError('docker-trusted-command')
        self.prefix = (str(executable), '--context', context)
        self.image_id, self.profile_path, self.profile = image_id, profile_path, profile
        self.command = tuple(command)

    def launch(self, grant, _result_path):
        check_public_scan_grant(grant)
        destination = grant.destination
        payload = json.dumps({'grant': {'targetUrl': grant.target_url, 'destination': {
            'purpose': destination.purpose, 'scheme': destination.scheme, 'hostname': destination.hostname,
            'port': destination.port, 'addresses': list(destination.addresses)}}}, separators=(',', ':')).encode()
        if len(payload) > MAX_INPUT_BYTES - 128:
            raise ValueError('docker-grant-size')
        return WorkerLaunch(self.command, input_payload=payload)

    def _pipe(self, arguments, payload=None, limit=CONTROL_BYTES):
        return _PipeProcess([*self.prefix, *arguments], payload, limit)

    def _call(self, arguments, deadline):
        _require(time.monotonic() < deadline, 'docker-control-deadline')
        pipe = self._pipe(arguments)
        try:
            code, data = pipe.finish(deadline)
            _require(code == 0, 'docker-control-failed')
            return data.decode('utf-8').strip()
        finally:
            pipe.stop(min(deadline, time.monotonic() + 0.15))

    def _inspect(self, identifier, deadline):
        rows = json.loads(self._call(['inspect', identifier], deadline))
        _require(isinstance(rows, list) and len(rows) == 1, 'docker-inspect-shape')
        return rows[0]

    def _ownership(self, row, name, token, identifier=None):
        _require(row['Name'] == '/' + name and row['Config']['Labels'].get(LABEL) == token
                 and re.fullmatch(r'[0-9a-f]{64}', row['Id'])
                 and (identifier is None or row['Id'] == identifier), 'docker-container-ownership')

    def _preflight(self, row, name, token, identifier):
        self._ownership(row, name, token, identifier)
        host, config = row['HostConfig'], row['Config']
        _require(row['Image'] == self.image_id and config['User'] == '10001:10001'
                 and config['Entrypoint'] == [self.command[0]] and config['Cmd'] == list(self.command[1:])
                 and config['OpenStdin'] and not config['Tty']
                 and config['Healthcheck']['Test'] == ['NONE'], 'docker-command-readback')
        _require(host['Memory'] == host['MemorySwap'] == 1073741824 and host['NanoCpus'] == 1000000000
                 and host['PidsLimit'] == 128 and not host['OomKillDisable'], 'docker-resource-readback')
        _require(host['ReadonlyRootfs'] and host['NetworkMode'] == 'none' and host['CapDrop'] == ['ALL']
                 and not host.get('CapAdd') and not host['Privileged'] and host['Init']
                 and not host.get('Binds') and not host.get('Devices') and not row['Mounts']
                 and not host.get('DeviceRequests') and not host.get('DeviceCgroupRules')
                 and host['PidMode'] == '' and host['IpcMode'] == 'private'
                 and host['CgroupnsMode'] == 'private' and host['UsernsMode'] == ''
                 and not host['AutoRemove'] and host['RestartPolicy']['Name'] == 'no'
                 and host['LogConfig']['Type'] == 'none', 'docker-isolation-readback')
        _require(host['Tmpfs'] == {'/tmp': 'rw,noexec,nosuid,nodev,size=128m,mode=1777'}
                 and host['ShmSize'] == 67108864, 'docker-tmpfs-readback')
        options = host['SecurityOpt']
        profiles = [json.loads(item.split('=', 1)[1], object_pairs_hook=_pairs)
                    for item in options if item.startswith('seccomp=')]
        _require(len(options) == 2 and any(item in ('no-new-privileges', 'no-new-privileges=true') for item in options)
                 and profiles == [self.profile], 'docker-security-readback')
        _require(not row['State']['Running'] and row['State']['Pid'] == 0, 'docker-started-before-preflight')

    def _cleanup(self, name, token, identifier, deadline):
        found = self._call(['container', 'ls', '-aq', '--no-trunc', '--filter', f'name=^/{name}$'], deadline)
        if not found:
            _require(identifier is None, 'docker-container-disappeared-before-teardown-proof')
            return None
        _require(re.fullmatch(r'[0-9a-f]{64}', found), 'docker-cleanup-lookup')
        row = self._inspect(found, deadline)
        self._ownership(row, name, token, identifier)
        if row['State']['Running']:
            self._call(['kill', row['Id']], deadline)
        row = self._inspect(row['Id'], deadline)
        self._ownership(row, name, token, identifier)
        _require(not row['State']['Running'] and row['State']['Pid'] == 0, 'docker-container-survived-kill')
        state = row['State']
        self._call(['rm', row['Id']], deadline)
        _require(not self._call(['container', 'ls', '-aq', '--no-trunc', '--filter', f'name=^/{name}$'], deadline),
                 'docker-container-survived-removal')
        return state

    def run(self, launch, result_path, deadline_seconds):
        deadline_seconds = _validated_deadline(deadline_seconds)
        if (not isinstance(launch, WorkerLaunch) or tuple(launch.command) != self.command
                or launch.environment is not None or launch.cwd is not None
                or not isinstance(launch.input_payload, bytes) or len(launch.input_payload) > MAX_INPUT_BYTES - 128):
            raise ValueError('docker-launch-shape')
        payload = json.loads(launch.input_payload, object_pairs_hook=_pairs)
        if not isinstance(payload, dict) or set(payload) != {'grant'}:
            raise ValueError('docker-launch-input')
        decode_public_scan_grant(payload['grant'])
        result_path = Path(result_path)
        if not result_path.is_absolute() or result_path.exists() or result_path.is_symlink():
            raise ValueError('docker-result-path')
        nonce = secrets.token_hex(16)
        encoded = json.dumps({**payload, 'nonce': nonce}, separators=(',', ':')).encode()
        if len(encoded) > MAX_INPUT_BYTES:
            raise ValueError('docker-input-limit')
        token = secrets.token_hex(16)
        name = 'dom-x-ray-worker-' + token
        started = time.monotonic()
        deadline = started + deadline_seconds
        execution_deadline = deadline - min(2.0, deadline_seconds * 0.4)
        identifier, pipe, output, timed_out, overflow = None, None, b'', False, False
        attach_code, create_attempted = None, False
        failure = None
        try:
            engine = json.loads(self._call(['info', '--format', '{{json .}}'], execution_deadline))
            _require(engine['OSType'] == 'linux' and engine['CgroupVersion'] == '2', 'docker-engine-required')
            create_attempted = True
            identifier = self._call(['create', '-i', '--pull=never', '--name', name, '--label', f'{LABEL}={token}',
                '--init', '--network=none', '--ipc=private', '--cgroupns=private',
                '--read-only', '--user=10001:10001', '--cap-drop=ALL',
                '--security-opt=no-new-privileges=true', '--security-opt=seccomp=' + str(self.profile_path),
                '--memory=1g', '--memory-swap=1g', '--cpus=1', '--pids-limit=128',
                '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777', '--shm-size=64m',
                '--log-driver=none', '--restart=no', '--no-healthcheck', '--entrypoint', self.command[0],
                self.image_id, *self.command[1:]], execution_deadline)
            _require(re.fullmatch(r'[0-9a-f]{64}', identifier), 'docker-created-id')
            self._preflight(self._inspect(identifier, execution_deadline), name, token, identifier)
            pipe = self._pipe(['start', '--attach', '--interactive', identifier], encoded, MAX_WORKER_RESULT_BYTES)
            attach_code, output = pipe.finish(execution_deadline)
        except TimeoutError:
            timed_out = True
        except OverflowError:
            overflow = True
        except Exception as error:
            failure = error
        finally:
            # Kill the client independently; its exit does not terminate Docker.
            if pipe is not None:
                try:
                    pipe.stop(min(deadline, time.monotonic() + 0.2))
                except Exception as error:
                    failure = error
            state = self._cleanup(name, token, identifier, deadline)
            if create_attempted and identifier is None and state is None:
                failure = WorkerContainmentError('docker-create-ownership-unresolved')
        if failure is not None:
            raise WorkerContainmentError('docker-worker-launch-or-control-failed') from None
        if time.monotonic() > deadline:
            raise WorkerContainmentError('docker-worker-cleanup-exceeded-deadline')
        code = None if state is None else state['ExitCode']
        if timed_out:
            outcome = 'timeout'
        elif overflow:
            outcome = 'invalid-result'
        elif code != 0 or attach_code != 0 or state is None or state['OOMKilled']:
            outcome = 'crashed'
        else:
            outcome = 'invalid-result'
            if output and _valid_output(output, nonce):
                descriptor = os.open(result_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(output)
                if _artifact_is_valid(result_path, nonce):
                    outcome = 'completed'
        if time.monotonic() > deadline:
            raise WorkerContainmentError('docker-result-admission-exceeded-deadline')
        return WorkerRun(outcome, code, round((time.monotonic() - started) * 1000, 3),
                         deadline_seconds, result_path.is_file())
