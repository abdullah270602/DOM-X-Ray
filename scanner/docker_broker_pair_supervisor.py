"""Trusted startup-inclusive pair lease. Network-none; public scanning stays gated.

Engine observations do not prove independent cgroup emptiness or controller-death
recovery. A failed cleanup is never converted into a successful scan.
"""

import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time

from scanner.docker_worker_supervisor import (DockerWorkerSupervisor, _PipeProcess, _require,
    _pairs, _invalid_constant, _valid_output, LABEL, MAX_INPUT_BYTES, CONTROL_BYTES)
from scanner.scan_transport import WorkerLaunch, decode_public_scan_grant
from scanner.lease_journal import LeaseJournal
from scanner.worker_supervisor import (WorkerContainmentError, WorkerRun,
    MAX_WORKER_RESULT_BYTES, _artifact_is_valid, _validated_deadline)


class DockerBrokerPairSupervisor(DockerWorkerSupervisor):
    """Three fixed operator commands, one fresh socket volume, one absolute lease."""

    def __init__(self, *, initializer_command, broker_command, lease_journal=None, **configuration):
        super().__init__(**configuration)
        self.roles = {'worker': self}
        for role, command in [('initialize', initializer_command), ('broker', broker_command)]:
            self.roles[role] = DockerWorkerSupervisor(**{**configuration, 'command': command})
        if lease_journal is not None and type(lease_journal) is not LeaseJournal:
            raise ValueError('docker-pair-journal-configuration')
        self.journal = lease_journal

    def runtime_fingerprint(self):
        raw = json.dumps({'policy': 'pair-policy-1', 'docker': self.prefix, 'image': self.image_id,
            'profile': self.profile, 'commands': {role: controller.command for role, controller in self.roles.items()}},
            sort_keys=True, separators=(',', ':')).encode()
        return hashlib.sha256(raw).hexdigest()

    def _preflight_role(self, row, role, name, token, identifier, volume, *, require_unstarted=True):
        config, host = row['Config'], row['HostConfig']
        expected_uid = {'initialize': '0:0', 'broker': '10002:10001', 'worker': '10001:10001'}[role]
        _require(config['User'] == expected_uid and not host.get('GroupAdd'), 'docker-pair-identity')
        _require(host.get('CapAdd') == ['CAP_CHOWN'] if role == 'initialize' else not host.get('CapAdd'),
                 'docker-pair-capabilities')
        mounts = row['Mounts']
        _require(len(mounts) == 1 and mounts[0]['Type'] == 'volume' and mounts[0]['Name'] == volume
                 and mounts[0]['Driver'] == 'local' and mounts[0]['Destination'] == '/run/dxr-broker'
                 and mounts[0]['RW'] == (role != 'worker'), 'docker-pair-mount')
        # Only the verified role differences are normalized for the common policy.
        normalized = copy.deepcopy(row)
        normalized['Config']['User'] = '10001:10001'
        normalized['HostConfig']['CapAdd'] = []
        normalized['Mounts'] = []
        self.roles[role]._preflight(normalized, name, token, identifier, require_unstarted=require_unstarted)

    def _volume_row(self, name, token, deadline):
        rows = json.loads(self._call(['volume', 'inspect', name], deadline), object_pairs_hook=_pairs,
                          parse_constant=_invalid_constant)
        _require(isinstance(rows, list) and len(rows) == 1, 'docker-pair-volume-shape')
        row = rows[0]
        _require(row['Name'] == name and row['Labels'].get(LABEL) == token and row['Driver'] == 'local'
                 and not row.get('Options') and row['Scope'] == 'local', 'docker-pair-volume-ownership')
        return row

    def _remove_volume(self, name, token, known, deadline):
        found = self._call(['volume', 'ls', '-q', '--filter', f'name=^{name}$'], deadline)
        _require(found == name, 'docker-pair-volume-missing-or-ambiguous')
        self._volume_row(name, token, deadline)
        self._call(['volume', 'rm', name], deadline)
        _require(not self._call(['volume', 'ls', '-q', '--filter', f'name=^{name}$'], deadline),
                 'docker-pair-volume-survived')
        _require(known, 'docker-pair-volume-create-unresolved')

    def _create_role(self, role, name, token, volume, deadline):
        command = self.roles[role].command
        user = {'initialize': '0:0', 'broker': '10002:10001', 'worker': '10001:10001'}[role]
        extra = ['--cap-add=CHOWN'] if role == 'initialize' else []
        mount = f'type=volume,src={volume},dst=/run/dxr-broker,volume-nocopy' + (',readonly' if role == 'worker' else '')
        identifier = self._call(['create', '-i', '--pull=never', '--name', name, '--label', f'{LABEL}={token}',
            '--init', '--network=none', '--ipc=private', '--cgroupns=private', '--read-only', '--user=' + user,
            '--cap-drop=ALL', *extra, '--security-opt=no-new-privileges=true',
            '--security-opt=seccomp=' + str(self.profile_path), '--memory=1g', '--memory-swap=1g', '--cpus=1',
            '--pids-limit=128', '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777', '--shm-size=64m',
            '--log-driver=none', '--restart=no', '--no-healthcheck', '--mount', mount,
            '--entrypoint', command[0], self.image_id, *command[1:]], deadline)
        _require(re.fullmatch(r'[0-9a-f]{64}', identifier), 'docker-pair-created-id')
        return identifier

    def _held_pipe(self, arguments, payload):
        return _PipeProcess([*self.prefix, *arguments], payload, CONTROL_BYTES, keep_stdin=True)

    def _cleanup(self, name, token, identifier, deadline):
        if identifier is None:
            return super()._cleanup(name, token, identifier, deadline)
        # A known immutable ID needs no preliminary name lookup. Inspect still
        # proves name/token/ID ownership before every destructive operation.
        row = self._inspect(identifier, deadline)
        self._ownership(row, name, token, identifier)
        if row['State']['Running']:
            try:
                self._call(['kill', identifier], deadline)
            except (WorkerContainmentError, TimeoutError):
                # A process may exit after inspect but before kill reaches the
                # engine. Only a fresh positive stopped/ownership observation
                # can reconcile the failed control call; absence is not proof.
                row = self._inspect(identifier, deadline)
                self._ownership(row, name, token, identifier)
                _require(not row['State']['Running'] and row['State']['Pid'] == 0,
                         'docker-pair-kill-failed-unproven-stop')
            else:
                row = self._inspect(identifier, deadline)
                self._ownership(row, name, token, identifier)
        _require(not row['State']['Running'] and row['State']['Pid'] == 0, 'docker-pair-container-survived-kill')
        state = row['State']
        self._call(['rm', identifier], deadline)
        _require(not self._call(['container', 'ls', '-aq', '--no-trunc', '--filter', f'name=^/{name}$'], deadline),
                 'docker-pair-container-survived-removal')
        return state

    def _cleanup_roles(self, names, token, identifiers, attempted, deadline, note):
        """Overlap independent exact-role proofs; join before touching the volume.

        Fixed three-role concurrency, no fresh deadlines. Only this controller
        thread mutates states or commits journal proofs. A failed submit is
        ambiguous, so it is not retried destructively or treated as cleaned.
        """
        states, failure = {}, None
        roles = [role for role in ('worker', 'broker', 'initialize') if role in attempted]
        if not roles:
            return states, failure
        try:
            with ThreadPoolExecutor(max_workers=3, thread_name_prefix='dxr-pair-cleanup') as pool:
                pending = {}
                for role in roles:
                    try:
                        future = pool.submit(self._cleanup, names[role], token, identifiers.get(role), deadline)
                        pending[future] = role
                    except Exception as error:
                        failure = error
                for future in as_completed(pending):
                    role = pending[future]
                    try:
                        state = future.result()
                        _require(state is not None, 'docker-pair-create-ownership-unresolved')
                        states[role] = state
                        note('removed', role)
                    except Exception as error:
                        failure = error
        except Exception as error:
            failure = error
        if set(states) != set(roles):
            failure = failure or WorkerContainmentError('docker-pair-role-cleanup-unproven')
        return states, failure

    @staticmethod
    def _broker_report(output):
        _require(len(output) <= CONTROL_BYTES and output.startswith(b'ready\n')
                 and output.endswith(b'\n') and output.count(b'\n') == 2, 'docker-pair-broker-framing')
        report = json.loads(output[6:-1], object_pairs_hook=_pairs, parse_constant=_invalid_constant)
        _require(isinstance(report, dict) and set(report) == {'uid', 'contacts', 'lookups', 'initialPinned',
                 'laterPinned', 'socketRemoved', 'empty'}, 'docker-pair-broker-report')
        _require(type(report['uid']) is int and report['uid'] == 10002, 'docker-pair-broker-uid')
        for field in ('contacts', 'lookups'):
            _require(type(report[field]) is int and 0 <= report[field] <= 2000, 'docker-pair-broker-count')
        for field in ('initialPinned', 'laterPinned', 'socketRemoved', 'empty'):
            _require(type(report[field]) is bool, 'docker-pair-broker-boolean')
        _require(report['socketRemoved'] and report['empty'] and report['laterPinned'], 'docker-pair-broker-cleanup')
        return report

    def run(self, launch, result_path, deadline_seconds):
        journal = getattr(self, 'journal', None)
        if journal is None:
            return self._run(launch, result_path, deadline_seconds)
        with journal.hold():
            return self._run(launch, result_path, deadline_seconds)

    def _run(self, launch, result_path, deadline_seconds):
        deadline_seconds = _validated_deadline(deadline_seconds)
        if (not isinstance(launch, WorkerLaunch) or tuple(launch.command) != self.command
                or launch.environment is not None or launch.cwd is not None
                or not isinstance(launch.input_payload, bytes) or len(launch.input_payload) > MAX_INPUT_BYTES - 256):
            raise ValueError('docker-pair-launch-shape')
        payload = json.loads(launch.input_payload, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
        if not isinstance(payload, dict) or set(payload) != {'grant'}:
            raise ValueError('docker-pair-launch-input')
        decode_public_scan_grant(payload['grant'])
        result_path = Path(result_path)
        if not result_path.is_absolute() or result_path.exists() or result_path.is_symlink():
            raise ValueError('docker-pair-result-path')
        started = time.monotonic()
        deadline = started + deadline_seconds
        execution_deadline = deadline - min(5.0, deadline_seconds * 0.45)
        token, nonce, capability = secrets.token_hex(16), secrets.token_hex(16), secrets.token_hex(32)
        volume = 'dom-x-ray-pair-' + token
        names = {role: 'dom-x-ray-pair-' + role + '-' + token for role in self.roles}
        job = json.dumps({**payload, 'nonce': nonce, 'capability': capability}, separators=(',', ':')).encode() + b'\n'
        if len(job) > MAX_INPUT_BYTES:
            raise ValueError('docker-pair-job-size')
        attempted, identifiers, pipes, states = set(), {}, {}, {}
        volume_attempted = volume_known = timed_out = overflow = False
        failure, output, report, worker_code, broker_code = None, b'', None, None, None
        journal = getattr(self, 'journal', None)
        def note(method, *arguments):
            if journal is not None:
                _require(time.monotonic() < deadline, 'docker-pair-journal-deadline')
                getattr(journal, method)(token, *arguments)
                _require(time.monotonic() < deadline, 'docker-pair-journal-deadline')
        try:
            note('create', self.runtime_fingerprint(), int(time.time() * 1000 + max(0, deadline - time.monotonic()) * 1000))
            engine = json.loads(self._call(['info', '--format', '{{json .}}'], execution_deadline))
            _require(engine['OSType'] == 'linux' and engine['CgroupVersion'] == '2', 'docker-pair-engine')
            note('engine', engine.get('ID'))
            note('intent', 'volume')
            volume_attempted = True
            created = self._call(['volume', 'create', '--driver=local', '--label', f'{LABEL}={token}', volume], execution_deadline)
            _require(created == volume, 'docker-pair-volume-create')
            note('created', 'volume')
            self._volume_row(volume, token, execution_deadline)
            volume_known = True
            for role in ('initialize', 'broker', 'worker'):
                note('intent', role)
                attempted.add(role)
                identifier = self._create_role(role, names[role], token, volume, execution_deadline)
                identifiers[role] = identifier
                note('created', role, identifier)
                self._preflight_role(self._inspect(identifier, execution_deadline), role, names[role], token, identifier, volume)
                if role == 'initialize':
                    pipes[role] = self._pipe(['start', '--attach', '--interactive', identifier], b'', CONTROL_BYTES)
            # Creating stopped roles may overlap the initializer's attach/start
            # round trip. Neither consumer starts until initialization has a
            # positive zero-exit/PID-zero proof. All intents remain serialized.
            code, data = pipes['initialize'].finish(execution_deadline)
            state = self._inspect(identifiers['initialize'], execution_deadline)['State']
            _require(code == 0 and not data and state['ExitCode'] == 0 and not state['OOMKilled']
                     and not state['Running'] and state['Pid'] == 0, 'docker-pair-initializer-exit')
            pipes['broker'] = self._held_pipe(['start', '--attach', '--interactive', identifiers['broker']], job)
            pipes['broker'].wait_prefix(b'ready\n', execution_deadline)
            pipes['worker'] = self._pipe(['start', '--attach', '--interactive', identifiers['worker']], job, MAX_WORKER_RESULT_BYTES)
            worker_code, output = pipes['worker'].finish(execution_deadline)
            worker_state = self._inspect(identifiers['worker'], execution_deadline)['State']
            _require(not worker_state['Running'] and worker_state['Pid'] == 0, 'docker-pair-worker-not-stopped')
            pipes['broker'].close_input(execution_deadline)
            broker_code, broker_output = pipes['broker'].finish(execution_deadline)
            _require(broker_code == 0, 'docker-pair-broker-exit')
            # The exact-owned stopped cleanup inspection below supplies the
            # broker engine exit/OOM proof before artifact admission. Avoid a
            # duplicate control round trip at the execution cutoff.
            report = self._broker_report(broker_output)
        except TimeoutError:
            timed_out = True
        except OverflowError:
            overflow = True
        except Exception as error:
            failure = error
        finally:
            # Stopping attach clients is not engine/container termination proof.
            for pipe in pipes.values():
                try:
                    pipe.stop(min(deadline, time.monotonic() + 0.2))
                except Exception as error:
                    failure = error
            states, cleanup_failure = self._cleanup_roles(names, token, identifiers, attempted, deadline, note)
            cleanup_ok = cleanup_failure is None
            if cleanup_failure is not None:
                failure = cleanup_failure
            if volume_attempted:
                if cleanup_ok:
                    try:
                        self._remove_volume(volume, token, volume_known, deadline)
                        note('removed', 'volume')
                    except Exception as error:
                        failure = error
                else:
                    failure = WorkerContainmentError('docker-pair-volume-retained-unproven-containers')
        if failure is not None or time.monotonic() >= deadline:
            raise WorkerContainmentError('docker-pair-control-or-cleanup-unproven') from None
        try:
            note('finish')
        except Exception:
            raise WorkerContainmentError('docker-pair-journal-completion-unproven') from None
        state = states.get('worker')
        broker_state = states.get('broker')
        code = None if state is None else state['ExitCode']
        if timed_out:
            outcome = 'timeout'
        elif overflow:
            outcome = 'invalid-result'
        elif (code != 0 or worker_code != 0 or state is None or state['OOMKilled']
              or broker_code != 0 or broker_state is None or broker_state['ExitCode'] != 0
              or broker_state['OOMKilled']):
            outcome = 'crashed'
        else:
            outcome = 'invalid-result'
            if (_valid_output(output, nonce) and report is not None and report['initialPinned']
                    and report['contacts'] > 0):
                descriptor = os.open(result_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(output)
                if _artifact_is_valid(result_path, nonce):
                    outcome = 'completed'
        if time.monotonic() >= deadline:
            raise WorkerContainmentError('docker-pair-admission-deadline')
        return WorkerRun(outcome, code, round((time.monotonic() - started) * 1000, 3),
                         deadline_seconds, result_path.is_file())
