"""Actual journal + simulated daemon; not native Docker recovery evidence."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.lease_journal import LeaseJournal
from scanner.lease_recovery import recover_expired_leases, _name
from scanner.worker_supervisor import WorkerContainmentError
from scripts.verify_pair_supervisor_contract import instance, scoped_row, IDS, TOKEN, require


class Daemon:
    def __init__(self, controller):
        self.controller = controller
        self.rows = {role: scoped_row(controller, role) for role in IDS}
        self.present = set(IDS)
        self.volume = True
        self.engine_id = 'fixture-engine'
        self.calls, self.removed, self.fail_role = [], [], None
        controller._call = self.call
        controller._inspect = lambda identifier, _deadline: copy.deepcopy(self.rows[self.role(identifier)])

    def role(self, identifier):
        return next(role for role, expected in IDS.items() if identifier == expected)

    def call(self, args, deadline):
        self.calls.append(args)
        if args[0] == 'info':
            return json.dumps({'OSType': 'linux', 'CgroupVersion': '2', 'ID': self.engine_id})
        if args[:2] == ['container', 'ls']:
            role = next(role for role in IDS if args[-1] == f'name=^/{_name(TOKEN, role)}$')
            return IDS[role] if role in self.present else ''
        if args[:2] == ['volume', 'ls']:
            return _name(TOKEN, 'volume') if self.volume else ''
        if args[:2] == ['volume', 'inspect']:
            return json.dumps([{'Name': _name(TOKEN, 'volume'), 'Labels': {'org.dom-x-ray.worker-lease': TOKEN},
                                'Driver': 'local', 'Options': {}, 'Scope': 'local'}])
        if args[:2] == ['volume', 'rm']:
            require(not self.present, 'volume removed while container retained')
            self.volume = False
            self.removed.append('volume')
            return ''
        if args[0] == 'kill':
            self.rows[self.role(args[1])]['State'].update(Running=False, Pid=0)
            return ''
        if args[0] == 'rm':
            role = self.role(args[1])
            if role == self.fail_role:
                raise WorkerContainmentError('fixture failed removal')
            self.present.remove(role)
            self.removed.append(role)
            return ''
        raise AssertionError('unexpected recovery control call')


def seed(journal, controller, *, worker_intent=False):
    journal.create(TOKEN, controller.runtime_fingerprint(), int(time.time() * 1000) + 15000)
    journal.engine(TOKEN, 'fixture-engine')
    journal.intent(TOKEN, 'volume')
    journal.created(TOKEN, 'volume')
    for role in ('initialize', 'broker', 'worker'):
        journal.intent(TOKEN, role)
        if not (role == 'worker' and worker_intent):
            journal.created(TOKEN, role, IDS[role])


def main():
    with tempfile.TemporaryDirectory(prefix='dxr-recovery-') as temporary:
        parent = Path(temporary).resolve()
        cases = ('valid', 'running', 'network', 'mount', 'not-expired', 'daemon', 'fingerprint', 'label', 'image', 'id', 'uid', 'command',
                 'absent', 'late-create', 'partial', 'reappeared', 'active', 'budget')
        for case in cases:
            with LeaseJournal(parent / case) as journal:
                controller = instance()
                controller.journal = journal
                daemon = Daemon(controller)
                seed(journal, controller, worker_intent=case == 'late-create')
                now = int(time.time() * 1000) + 30000
                if case == 'running':
                    daemon.rows['worker']['State'].update(Running=True, Pid=123)
                if case == 'network':
                    daemon.rows['worker']['HostConfig']['NetworkMode'] = 'host'
                if case == 'mount':
                    daemon.rows['worker']['Mounts'][0]['RW'] = True
                if case == 'not-expired':
                    now = int(time.time() * 1000)
                if case == 'daemon':
                    daemon.engine_id = 'other-engine'
                if case == 'fingerprint':
                    controller.image_id = 'sha256:' + 'f' * 64
                if case == 'label':
                    daemon.rows['worker']['Config']['Labels']['org.dom-x-ray.worker-lease'] = 'f' * 32
                if case == 'image':
                    daemon.rows['worker']['Image'] = 'sha256:' + 'f' * 64
                if case == 'uid':
                    daemon.rows['worker']['Config']['User'] = '0:0'
                if case == 'command':
                    daemon.rows['worker']['Config']['Cmd'] = ['unrelated']
                if case == 'id':
                    original = daemon.call
                    def wrong_id(args, deadline):
                        if args[:2] == ['container', 'ls'] and '-worker-' in args[-1]:
                            return 'f' * 64
                        return original(args, deadline)
                    controller._call = wrong_id
                if case in ('absent', 'late-create'):
                    daemon.present.remove('worker')
                if case == 'partial':
                    daemon.fail_role = 'worker'
                if case == 'reappeared':
                    journal.removed(TOKEN, 'worker')
                if case == 'active':
                    with journal.hold():
                        try:
                            recover_expired_leases(controller, now_ms=now)
                        except ValueError:
                            pass
                        else:
                            raise AssertionError('recovery overlapped an active controller')
                    require(not daemon.calls, 'active recovery contacted daemon')
                    print('active controller: excluded before daemon contact')
                    continue
                if case == 'budget':
                    clock = [100.0]
                    original = daemon.call
                    def slow(args, deadline):
                        result = original(args, deadline)
                        clock[0] = 200.0
                        return result
                    controller._call = slow
                    with patch('scanner.lease_recovery.time.monotonic', side_effect=lambda: clock[0]):
                        report = recover_expired_leases(controller, now_ms=now)
                    require(report.retained == 1 and journal.snapshot(), 'expired budget forgot authority')
                    require(len(daemon.calls) == 1 and not daemon.removed,
                            'expired budget issued additional control actions')
                    print('budget exhaustion: retained authority')
                    continue
                report = recover_expired_leases(controller, now_ms=now)
                if case in ('valid', 'running'):
                    require(report.resolved == 1 and not journal.snapshot() and not daemon.volume and not daemon.present,
                            'valid recovery failed cleanup')
                elif case in ('not-expired', 'fingerprint'):
                    require(report.skipped == 1 and not daemon.calls and len(journal.snapshot()) == 1,
                            'ineligible lease contacted daemon')
                elif case == 'daemon':
                    require(report.retained == 1 and not daemon.removed, 'daemon mismatch mutated resources')
                else:
                    require(report.retained == 1 and len(journal.snapshot()) == 1 and daemon.volume
                            and 'worker' not in daemon.removed, 'unproven worker/volume removal accepted')
                    require(set(daemon.removed) == {'broker', 'initialize'}, 'worker failure skipped remaining roles')
                if case == 'late-create':
                    require(journal.snapshot()[0]['resources']['worker']['state'] == 'intent', 'missing intent forgotten')
                    daemon.present.add('worker')
                    report = recover_expired_leases(controller, now_ms=now)
                    require(report.resolved == 1 and not journal.snapshot() and not daemon.volume,
                            'later owned create did not resolve retained intent')
                print(case + ': verified recovery/retention decisions')
    print('Verified 18 actual-journal simulated-daemon recovery cases; native controller-death proof remains open.')


if __name__ == '__main__':
    main()
