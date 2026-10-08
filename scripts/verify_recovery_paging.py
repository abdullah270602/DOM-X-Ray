"""Actual journals and multiple simulated leases; not native fairness evidence."""

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
from scripts.verify_lease_recovery import Daemon, seed
from scripts.verify_pair_supervisor_contract import instance, require


def token(index):
    return f'{index:032x}'


class Pool:
    def __init__(self, controller, journal, indices, *, short_lived=(), mismatched=()):
        self.controller, self.daemons, self.calls = controller, {}, []
        self.outage, self.bad_json = False, None
        self.by_id, self.by_name = {}, {}
        for index in indices:
            identifiers = {role: f'{index * 3 + offset:064x}'
                           for offset, role in enumerate(('initialize', 'broker', 'worker'), 1)}
            daemon = Daemon(controller, token=token(index), identifiers=identifiers)
            self.daemons[index] = daemon
            original_image = controller.image_id
            try:
                if index in mismatched:
                    controller.image_id = 'sha256:' + 'f' * 64
                seed(journal, controller, token=token(index), identifiers=identifiers,
                     lifetime_ms=5000 if index in short_lived else 15000)
            finally:
                controller.image_id = original_image
            for role, identifier in identifiers.items():
                self.by_id[identifier] = daemon
                self.by_name[_name(token(index), role)] = daemon
            self.by_name[_name(token(index), 'volume')] = daemon
        controller._call, controller._inspect = self.call, self.inspect

    def inspect(self, identifier, _deadline):
        daemon = self.by_id[identifier]
        return copy.deepcopy(daemon.rows[daemon.role(identifier)])

    def call(self, arguments, deadline):
        self.calls.append(arguments[0])
        if self.outage:
            raise WorkerContainmentError('fixture outage')
        if arguments[0] == 'info':
            return self.bad_json if self.bad_json is not None else json.dumps(
                {'OSType': 'linux', 'CgroupVersion': '2', 'ID': 'fixture-engine'})
        if arguments[0] in ('kill', 'rm'):
            return self.by_id[arguments[1]].call(arguments, deadline)
        if arguments[:2] == ['container', 'ls']:
            name = arguments[-1].removeprefix('name=^/').removesuffix('$')
        elif arguments[:2] == ['volume', 'ls']:
            name = arguments[-1].removeprefix('name=^').removesuffix('$')
        else:
            name = arguments[-1]
        return self.by_name[name].call(arguments, deadline)


def main():
    with tempfile.TemporaryDirectory(prefix='dxr-recovery-paging-') as temporary:
        root = Path(temporary).resolve()
        with LeaseJournal(root / 'fair') as journal:
            controller = instance()
            controller.journal = journal
            pool = Pool(controller, journal, (1, 2, 3))
            pool.daemons[1].present.remove('worker')
            now = int(time.time() * 1000) + 30000
            report = recover_expired_leases(controller, max_leases=1, now_ms=now)
            require((report.resolved, report.retained, report.deferred, report.next_after) == (0, 1, 2, token(1)),
                    'first retained lease did not yield a forward cursor')
            for index in (2, 3):
                report = recover_expired_leases(controller, max_leases=1, after_token=report.next_after, now_ms=now)
                require(report.resolved == 1 and report.next_after == token(index), 'failed lease starved a later lease')
            report = recover_expired_leases(controller, max_leases=1, after_token=report.next_after, now_ms=now)
            require(report.retained == 1 and report.next_after == token(1), 'deleted cursor did not wrap to retained authority')
            pool.daemons[1].present.add('worker')
            report = recover_expired_leases(controller, after_token='f' * 32, now_ms=now)
            require(report.resolved == 1 and not journal.snapshot(), 'missing cursor did not wrap and resolve late owned resource')
            print('retention, forward paging, deleted/missing cursors and late-resource wrap: verified')
        with LeaseJournal(root / 'batch') as journal:
            controller = instance()
            controller.journal = journal
            calls = []
            controller._call = lambda *_args: calls.append('unexpected')
            for index in range(1, 26):
                journal.create(token(index), controller.runtime_fingerprint(), int(time.time() * 1000) + 15000)
            now = int(time.time() * 1000) + 30000
            first = recover_expired_leases(controller, now_ms=now)
            require(first.resolved == 20 and first.deferred == 5 and first.next_after == token(20), 'batch ceiling/cursor drift')
            second = recover_expired_leases(controller, now_ms=now, after_token=first.next_after)
            require(second.resolved == 5 and not journal.snapshot() and not calls, 'remaining batch or empty-intent engine avoidance failed')
            print('20-lease ceiling and remaining page with zero engine contact: verified')
        with LeaseJournal(root / 'mixed') as journal:
            controller = instance()
            controller.journal = journal
            pool = Pool(controller, journal, range(1, 7), short_lived=(2, 4, 6), mismatched=(1, 3))
            before = journal.snapshot()
            now = max(r['expiresAtMs'] for r in before if r['token'] in {token(i) for i in (2, 4, 6)}) + 5000
            cursor = token(3)
            for index in (4, 6, 2):
                report = recover_expired_leases(controller, max_leases=1, after_token=cursor, now_ms=now)
                require(report.resolved == 1 and report.skipped == 3 and report.next_after == token(index),
                        'interspersed mismatched/future leases changed eligible page order')
                cursor = report.next_after
            require(journal.snapshot() == [r for r in before if r['token'] in {token(i) for i in (1, 3, 5)}]
                    and all(not pool.daemons[i].removed for i in (1, 3, 5)), 'paging mutated skipped lease authority/resources')
            print('sparse eligible set around mixed skipped rows and lexical-end wrap: verified')
        with LeaseJournal(root / 'outage') as journal:
            controller = instance()
            controller.journal = journal
            pool = Pool(controller, journal, (1, 2, 3))
            pool.outage = True
            now = int(time.time() * 1000) + 30000
            before = journal.snapshot()
            first = recover_expired_leases(controller, max_leases=2, now_ms=now)
            require(first.retained == 2 and first.deferred == 1 and journal.snapshot() == before
                    and all(not d.removed for d in pool.daemons.values()), 'outage lost authority or mutated resources')
            pool.outage = False
            second = recover_expired_leases(controller, max_leases=1, after_token=first.next_after, now_ms=now)
            require(second.resolved == 1 and second.next_after == token(3), 'outage cursor starved deferred lease')
            final = recover_expired_leases(controller, after_token=second.next_after, now_ms=now)
            require(final.resolved == 2 and not journal.snapshot(), 'recovered daemon did not resolve earlier retained leases')
            print('outage authority retention and resumed cursor fairness: verified')
        with LeaseJournal(root / 'clock') as journal:
            controller = instance()
            controller.journal = journal
            pool = Pool(controller, journal, (1,))
            expiry = journal.snapshot()[0]['expiresAtMs']
            for now in (expiry - 100000, expiry + 4999):
                report = recover_expired_leases(controller, now_ms=now)
                require(report.skipped == 1 and not pool.calls, 'rollback/grace boundary contacted engine')
            report = recover_expired_leases(controller, now_ms=expiry + 5000)
            require(report.resolved == 1 and not journal.snapshot(), 'exact grace boundary failed eligibility')
            print('clock rollback and exact grace eligibility: verified')
        with LeaseJournal(root / 'budget') as journal:
            controller = instance()
            controller.journal = journal
            pool = Pool(controller, journal, (1, 2, 3))
            clock, original = [100.0], pool.call
            def slow(arguments, deadline):
                result = original(arguments, deadline)
                clock[0] = 200.0
                return result
            controller._call = slow
            now = int(time.time() * 1000) + 30000
            with patch('scanner.lease_recovery.time.monotonic', side_effect=lambda: clock[0]):
                first = recover_expired_leases(controller, now_ms=now)
            require(first.retained == 1 and first.deferred == 2 and first.next_after == token(1)
                    and pool.calls == ['info'] and all(not d.removed for d in pool.daemons.values()),
                    'exhausted pass issued actions or lost next-page position')
            controller._call = original
            second = recover_expired_leases(controller, now_ms=now, max_leases=1, after_token=first.next_after)
            require(second.resolved == 1 and second.next_after == token(2), 'budget-exhausted lease starved next pass')
            print('budget-exhausted pass preserves authority and next-page progress: verified')
            pool.calls.clear()
            with patch('scanner.lease_recovery.time.monotonic', side_effect=[100.0, 200.0]):
                empty = recover_expired_leases(controller, now_ms=now, after_token=second.next_after)
            require(empty.deferred == 2 and empty.retained == empty.resolved == 0
                    and empty.next_after == second.next_after and not pool.calls,
                    'budget expiry before first attempt advanced cursor or contacted engine')
        for index, raw in enumerate((
                '{"OSType":"linux","CgroupVersion":"2","ID":"other","ID":"fixture-engine"}',
                '{"OSType":"linux","CgroupVersion":"2","ID":"fixture-engine","extra":NaN}',
                '{"OSType":"linux","CgroupVersion":"2","ID":"fixture-engine","extra":1e999}',
                '{"OSType":"linux","CgroupVersion":"2","ID":"fixture-engine","extra":{"x":1,"x":2}}',
                '[]', 'null', '', '{',
                '{"OSType":"linux","ID":"fixture-engine"}',
                '{"OSType":"linux","CgroupVersion":"2","ID":true}',
                '{"OSType":"linux","CgroupVersion":"2","ID":"fixture-engine"} trailing')):
            with LeaseJournal(root / ('json-' + str(index))) as journal:
                controller = instance()
                controller.journal = journal
                pool = Pool(controller, journal, (1, 2))
                pool.bad_json = raw
                before = journal.snapshot()
                report = recover_expired_leases(controller, now_ms=int(time.time() * 1000) + 30000)
                require(report.retained == 2 and journal.snapshot() == before
                        and all(not d.removed for d in pool.daemons.values()), 'ambiguous/nonfinite engine JSON authorized cleanup')
        print('eleven malformed/ambiguous/nonfinite daemon replies reject every lease without mutation: verified')
        with LeaseJournal(root / 'bounds') as journal:
            controller = instance()
            controller.journal = journal
            pool = Pool(controller, journal, (1,))
            before = journal.snapshot()
            for configuration in ({'max_leases': False}, {'max_leases': 0}, {'max_leases': 21},
                                  {'grace_seconds': True}, {'grace_seconds': -1}, {'grace_seconds': 61},
                                  {'now_ms': True}, {'now_ms': 0}, {'now_ms': 2**53},
                                  {'after_token': ''}, {'after_token': 'z' * 32}):
                try:
                    recover_expired_leases(controller, **configuration)
                except (ValueError, WorkerContainmentError):
                    pass
                else:
                    raise AssertionError('invalid scheduling configuration accepted')
            require(not pool.calls and journal.snapshot() == before, 'invalid bounds contacted engine or mutated journal')
            print('eleven invalid scheduling configurations reject before engine/journal mutation: verified')
    print('Verified actual-journal simulated multi-lease scheduling/decoder cases; watchdog/native race coverage remains open.')


if __name__ == '__main__':
    main()
