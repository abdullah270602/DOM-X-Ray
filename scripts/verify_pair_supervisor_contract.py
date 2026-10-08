"""Mocked pair-lease admission/control tests, not kernel enforcement evidence."""

import copy
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.docker_broker_pair_supervisor import DockerBrokerPairSupervisor
from scanner.docker_worker_supervisor import DockerWorkerSupervisor, LABEL
from scanner.worker_supervisor import WorkerContainmentError
from scanner.scan_transport import WorkerLaunch
from scripts.verify_docker_supervisor_contract import row, launch, supervisor, require

TOKEN, NONCE, CAPABILITY = 'a' * 32, 'b' * 32, 'c' * 64
IDS = {'initialize': '1' * 64, 'broker': '2' * 64, 'worker': '3' * 64}
VOLUME = 'dom-x-ray-pair-' + TOKEN
REPORT = {'uid': 10002, 'contacts': 3, 'lookups': 2, 'initialPinned': True,
          'laterPinned': True, 'socketRemoved': True, 'empty': True}


class Pipe:
    def __init__(self, output, *, code=0, timeout=False):
        self.output, self.code, self.timeout = output, code, timeout
        self.closed = self.stopped = False
        self.finished = False

    def finish(self, deadline):
        if self.timeout:
            raise TimeoutError('fixture timeout')
        self.finished = True
        return self.code, self.output

    def wait_prefix(self, prefix, deadline):
        require(self.output.startswith(prefix), 'fixture prefix mismatch')

    def close_input(self, deadline):
        self.closed = True

    def stop(self, deadline):
        self.stopped = True


def instance():
    base = supervisor()
    value = DockerBrokerPairSupervisor.__new__(DockerBrokerPairSupervisor)
    value.__dict__.update(base.__dict__)
    value.roles = {'worker': value, 'broker': supervisor(), 'initialize': supervisor()}
    return value


def scoped_row(value, role):
    result = row()
    result['Id'] = IDS[role]
    result['Name'] = '/dom-x-ray-pair-' + role + '-' + TOKEN
    result['Config']['Labels'] = {LABEL: TOKEN}
    result['Config']['User'] = {'initialize': '0:0', 'broker': '10002:10001', 'worker': '10001:10001'}[role]
    command = value.roles[role].command
    result['Config']['Entrypoint'], result['Config']['Cmd'] = [command[0]], list(command[1:])
    result['HostConfig']['CapAdd'] = ['CAP_CHOWN'] if role == 'initialize' else []
    result['Mounts'] = [{'Type': 'volume', 'Name': VOLUME, 'Driver': 'local',
                         'Destination': '/run/dxr-broker', 'RW': role != 'worker'}]
    return result


def engine(value, *, broker_output=None, worker_code=0, worker_timeout=False, initializer_code=0):
    reports = b'ready\n' + json.dumps(REPORT).encode() + b'\n' if broker_output is None else broker_output
    worker = Pipe(json.dumps({'supervisorNonce': NONCE, 'result': {'record': {}}}).encode(),
                  code=worker_code, timeout=worker_timeout)
    broker = Pipe(reports)
    initializer = Pipe(b'', code=initializer_code)
    events, deadlines, removed = [], [], False
    started_pipes = []
    volume_row = {'Name': VOLUME, 'Labels': {LABEL: TOKEN}, 'Driver': 'local', 'Options': {}, 'Scope': 'local'}
    def call(arguments, deadline):
        nonlocal removed
        deadlines.append(deadline)
        events.append(tuple(arguments[:2]))
        if arguments[0] == 'info':
            return json.dumps({'OSType': 'linux', 'CgroupVersion': '2'})
        if arguments[:2] == ['volume', 'create']:
            return VOLUME
        if arguments[:2] == ['volume', 'inspect']:
            return json.dumps([volume_row])
        if arguments[:2] == ['volume', 'ls']:
            return '' if removed else VOLUME
        if arguments[:2] == ['volume', 'rm']:
            require(all(pipe.stopped for pipe in started_pipes), 'volume removed before pipe stop')
            removed = True
            return VOLUME
        raise AssertionError('unexpected mock control call')
    value._call = call
    def create(role, *_args):
        if role != 'initialize':
            require(initializer in started_pipes and not initializer.finished,
                    'stopped-role creation did not overlap initializer startup')
        return IDS[role]
    value._create_role = create
    value._inspect = lambda identifier, _deadline: scoped_row(value, next(role for role in IDS if IDS[role] == identifier))
    def pipe(arguments, payload, limit):
        if arguments[-1] == IDS['initialize']:
            require(payload == b'', 'initializer received job secrets')
            started_pipes.append(initializer)
            return initializer
        require(not broker.closed, 'broker ownership pipe closed before worker')
        started_pipes.append(worker)
        return worker
    def held(*_args):
        require(initializer.finished and initializer.code == 0,
                'broker started without successful initializer completion')
        started_pipes.append(broker)
        return broker
    value._pipe, value._held_pipe = pipe, held
    value._cleanup = Mock(return_value={'ExitCode': 0, 'OOMKilled': False})
    return worker, broker, events, deadlines


def run(value, path, *, reject=False):
    with patch('scanner.docker_broker_pair_supervisor.secrets.token_hex', side_effect=[TOKEN, NONCE, CAPABILITY]):
        try:
            outcome = value.run(launch(value), path, 15)
        except WorkerContainmentError:
            require(reject and not path.exists(), 'unexpected failure/artifact after failure')
            return None
    require(not reject, 'unsafe pair admitted')
    return outcome


def main():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        value = instance()
        worker, broker, events, deadlines = engine(value)
        result = run(value, root / 'good.json')
        require(result.artifact_eligible and broker.closed and worker.stopped and broker.stopped,
                'valid pair did not finish/cleanup')
        require(events[0] == ('info', '--format') and len(set(deadlines[:2])) == 1,
                'setup did not share execution deadline')
        require(len(set(deadlines)) == 2 and max(deadlines) - min(deadlines) == 5.0, 'cleanup reserve not shared')
        print('valid pair: cleanup and shared reserve before artifact', flush=True)

        value = instance()
        worker, broker, _, _ = engine(value, initializer_code=2)
        run(value, root / 'initializer-failed.json', reject=True)
        require(not worker.stopped and not broker.stopped and value._cleanup.call_count == 3,
                'failed initializer started consumers or skipped stopped-role cleanup')
        print('overlapped initializer failure: consumers never started; all stopped roles cleaned', flush=True)

        for name, output in [('wrong-uid', b'ready\n' + json.dumps({**REPORT, 'uid': 10001}).encode() + b'\n'),
                             ('extra-line', b'ready\n{}\n{}\n'), ('missing-report', b'ready\n'),
                             ('duplicate-key', b'ready\n' + json.dumps(REPORT).encode()[:-1] + b',"uid":10002}\n'),
                             ('bool-count', b'ready\n' + json.dumps({**REPORT, 'contacts': True}).encode() + b'\n'),
                             ('false-cleanup', b'ready\n' + json.dumps({**REPORT, 'empty': False}).encode() + b'\n')]:
            value = instance()
            engine(value, broker_output=output)
            run(value, root / (name + '.json'), reject=True)
            require(value._cleanup.call_count == 3, 'bad report skipped remaining cleanup')
            print(name + ': rejected, all cleanup attempted', flush=True)

        value = instance()
        engine(value)
        value._cleanup.side_effect = [WorkerContainmentError('worker stop failed'),
                                     {'ExitCode': 0, 'OOMKilled': False}, {'ExitCode': 0, 'OOMKilled': False}]
        value._remove_volume = Mock(side_effect=AssertionError('volume removed with unproven worker'))
        run(value, root / 'cleanup-failed.json', reject=True)
        require(value._cleanup.call_count == 3 and not value._remove_volume.called, 'cleanup failure skipped other roles')
        print('partial cleanup: all roles attempted, volume retained, no artifact', flush=True)

        value = instance()
        engine(value)
        value._remove_volume = Mock(side_effect=WorkerContainmentError('volume removal failed'))
        run(value, root / 'volume-failed.json', reject=True)
        print('volume cleanup failure: no artifact', flush=True)

        value = instance()
        engine(value, worker_timeout=True)
        result = run(value, root / 'timeout.json')
        require(result.outcome == 'timeout' and not result.artifact_present, 'timeout admitted')
        print('timeout: removed owned resources, no artifact', flush=True)

        value = instance()
        worker, broker, *_ = engine(value, worker_code=1)
        result = run(value, root / 'bad-worker-attach.json')
        require(result.outcome == 'crashed' and not result.artifact_present, 'attach error admitted engine-zero result')
        print('worker attach nonzero, engine zero: no artifact', flush=True)

        value = instance()
        worker, broker, *_ = engine(value)
        broker.code = 1
        run(value, root / 'bad-broker-attach.json', reject=True)
        print('broker attach nonzero, engine zero: no artifact', flush=True)

        value = instance()
        worker, broker, *_ = engine(value)
        worker.output = worker.output.replace(NONCE.encode(), b'd' * 32)
        result = run(value, root / 'wrong-nonce.json')
        require(result.outcome == 'invalid-result' and not result.artifact_present, 'wrong nonce admitted')
        print('wrong worker nonce: no artifact', flush=True)

        value = instance()
        worker, broker, *_ = engine(value)
        clock = [100.0]
        def late_finish(_deadline):
            clock[0] = 116.0
            return 0, worker.output
        worker.finish = late_finish
        with patch('scanner.docker_broker_pair_supervisor.time.monotonic', side_effect=lambda: clock[0]):
            run(value, root / 'late.json', reject=True)
        print('late setup/execution clock: no artifact after lease', flush=True)

        for role in value.roles:
            original = scoped_row(value, role)
            changes = [lambda r: r['Config'].update(User='0:0' if role != 'initialize' else '10001:10001'),
                       lambda r: r['Mounts'][0].update(RW=role == 'worker'),
                       lambda r: r['Mounts'][0].update(Name='unrelated'),
                       lambda r: r['HostConfig'].update(GroupAdd=['0']),
                       lambda r: r['HostConfig'].update(NetworkMode='host'),
                       lambda r: r['State'].update(Running=True, Pid=999)]
            for change in changes:
                changed = copy.deepcopy(original)
                change(changed)
                try:
                    value._preflight_role(changed, role, original['Name'][1:], TOKEN, IDS[role], VOLUME)
                except WorkerContainmentError:
                    pass
                else:
                    raise AssertionError('altered role policy accepted')
        print('18 altered role identity/mount/group/network/start states: rejected', flush=True)

        value = instance()
        engine(value)
        value._create_role = Mock(side_effect=TimeoutError('ambiguous create'))
        value._cleanup = Mock(return_value=None)
        value._remove_volume = Mock(side_effect=AssertionError('volume removed before create resolved'))
        run(value, root / 'ambiguous.json', reject=True)
        require(value._cleanup.call_count == 1 and not value._remove_volume.called, 'ambiguous create accepted')
        print('ambiguous create with empty lookup: unresolved, no artifact', flush=True)

        value = instance()
        engine(value)
        value._create_role = Mock(side_effect=TimeoutError('ambiguous late create'))
        value._cleanup = Mock(return_value={'ExitCode': 0, 'OOMKilled': False})
        result = run(value, root / 'ambiguous-found.json')
        require(result.outcome == 'timeout' and not result.artifact_present and value._cleanup.call_count == 1,
                'ambiguous late create yielded an artifact')
        print('ambiguous create found by exact ownership lookup: removed, no artifact', flush=True)

        value = instance()
        engine(value)
        clock = [100.0]
        def exhausted_cleanup(*_args):
            clock[0] = 116.0
            raise WorkerContainmentError('cleanup deadline exhausted')
        value._cleanup = Mock(side_effect=exhausted_cleanup)
        value._remove_volume = Mock(side_effect=AssertionError('volume removed after failed cleanup'))
        with patch('scanner.docker_broker_pair_supervisor.time.monotonic', side_effect=lambda: clock[0]):
            run(value, root / 'cleanup-exhausted.json', reject=True)
        require(value._cleanup.call_count == 3 and not value._remove_volume.called, 'deadline skipped cleanup roles')
        print('deadline exhausted during cleanup: all roles attempted, no artifact', flush=True)

        value = instance()
        value._call = Mock(side_effect=AssertionError('engine contacted for invalid grant'))
        with patch('scanner.docker_broker_pair_supervisor.secrets.token_hex'):
            try:
                value.run(WorkerLaunch(value.command, input_payload=b'{"grant":{},"capability":"forged"}'), root / 'bad.json', 15)
            except ValueError:
                pass
            else:
                raise AssertionError('visitor capability accepted')
        require(not value._call.called, 'malformed input reached engine')
        print('visitor capability/invalid grant: zero engine contact', flush=True)

        for remains_running in (False, True):
            value = instance()
            running = scoped_row(value, 'worker')
            running['State'].update(Running=True, Pid=321)
            fresh = copy.deepcopy(running)
            if not remains_running:
                fresh['State'].update(Running=False, Pid=0)
            value._inspect = Mock(side_effect=[running, fresh])
            value._call = Mock(side_effect=[WorkerContainmentError('docker-control-failed'), '', ''])
            try:
                state = value._cleanup(running['Name'][1:], TOKEN, IDS['worker'], 999999999999.0)
            except WorkerContainmentError:
                require(remains_running and value._call.call_count == 1, 'failed kill bypassed state proof')
            else:
                require(not remains_running and state['ExitCode'] == 0 and value._call.call_count == 3,
                        'inspect-to-kill exit race not safely reconciled')
        print('kill error: fresh owned stopped proof reconciles exit race; still-running state rejects', flush=True)
    print('Verified mocked pair-supervisor contract; not engine or recovery evidence.')


if __name__ == '__main__':
    main()
