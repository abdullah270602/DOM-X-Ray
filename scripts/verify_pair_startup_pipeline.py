"""Test-only startup candidate, not adopted by the production controller."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import sys
import tempfile
import time
from threading import Barrier, Lock, current_thread, get_ident
from unittest.mock import Mock
from types import MethodType

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.lease_journal import LeaseJournal
from scanner.worker_supervisor import WorkerContainmentError
from scripts.verify_pair_supervisor_contract import instance, engine, run, TOKEN, IDS, VOLUME, require


def candidate_prepare_consumers(self, names, token, volume, deadline, attempted, identifiers, note):
    """Overlap broker inspection and worker creation without changing journal states."""
    attempted.add('broker')
    note('intent', 'broker')
    identifier = self._create_role('broker', names['broker'], token, volume, deadline)
    identifiers['broker'] = identifier
    note('created', 'broker', identifier)
    failure = None
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix='dxr-pair-prepare-experiment') as pool:
        pending = {pool.submit(self._inspect, identifier, deadline): 'broker'}
        try:
            attempted.add('worker')
            note('intent', 'worker')
            pending[pool.submit(self._create_role, 'worker', names['worker'], token, volume, deadline)] = 'worker'
        except Exception as error:
            failure = error
        for future in as_completed(pending):
            role = pending[future]
            try:
                result = future.result()
                if role == 'worker':
                    identifiers[role] = result
                    note('created', role, result)
                    row = self._inspect(result, deadline)
                else:
                    row = result
                self._preflight_role(row, role, names[role], token, identifiers[role], volume)
            except Exception as error:
                failure = error
    if failure is not None:
        raise failure


def candidate_instance():
    value = instance()
    value._prepare_consumers = MethodType(candidate_prepare_consumers, value)
    return value


def main():
    controller = get_ident()
    names = {role: 'dom-x-ray-pair-' + role + '-' + TOKEN for role in IDS}
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve()
        for failing in (None, 'worker-create', 'worker-ID', 'broker-inspect', 'broker-preflight'):
            with LeaseJournal(root / str(failing)) as journal:
                journal.create(TOKEN, 'a' * 64, int(time.time() * 1000) + 10000)
                journal.engine(TOKEN, 'fixture-engine')
                journal.intent(TOKEN, 'volume')
                journal.created(TOKEN, 'volume')
                journal.intent(TOKEN, 'initialize')
                journal.created(TOKEN, 'initialize', IDS['initialize'])
                value = candidate_instance()
                barrier, lock = Barrier(2), Lock()
                threads, deadlines, preflights, notes = set(), [], set(), []
                attempted, identifiers = set(), {}
                def note(method, *args):
                    require(get_ident() == controller, 'journal moved off controller')
                    notes.append((method, *args))
                    if failing == 'worker-ID' and method == 'created' and args[0] == 'worker':
                        raise OSError('controlled worker ID failure')
                    getattr(journal, method)(TOKEN, *args)
                def create(role, name, token, volume, deadline):
                    require(name == names[role] and token == TOKEN and volume == VOLUME, 'ownership input changed')
                    if role == 'worker':
                        with lock:
                            threads.add(current_thread())
                            deadlines.append(deadline)
                        snapshot = journal.snapshot()[0]['resources']
                        require(snapshot['broker']['state'] == 'created' and snapshot['worker']['state'] == 'intent',
                            'worker launched before broker-created/write-ahead intent')
                        barrier.wait(timeout=3)
                        if failing == 'worker-create':
                            raise TimeoutError('controlled ambiguous create')
                    else:
                        require(role == 'broker' and get_ident() == controller, 'broker create not serialized')
                    return IDS[role]
                def inspect(identifier, deadline):
                    if identifier == IDS['broker']:
                        with lock:
                            threads.add(current_thread())
                            deadlines.append(deadline)
                        barrier.wait(timeout=3)
                        if failing == 'broker-inspect':
                            raise WorkerContainmentError('controlled inspect fault')
                    return {'Id': identifier}
                def preflight(row, role, *_args):
                    require(get_ident() == controller and ('created', role, IDS[role]) in notes,
                        'preflight before ID commit/off controller')
                    preflights.add(role)
                    if failing == 'broker-preflight' and role == 'broker':
                        raise WorkerContainmentError('controlled preflight fault')
                value._create_role, value._inspect, value._preflight_role = create, inspect, preflight
                try:
                    value._prepare_consumers(names, TOKEN, VOLUME, 12345, attempted, identifiers, note)
                except (TimeoutError, OSError, WorkerContainmentError):
                    require(failing is not None, 'valid pipeline failed')
                else:
                    require(failing is None, 'faulted pipeline admitted')
                require(attempted == {'broker', 'worker'} and len(threads) == 2
                    and all(not thread.is_alive() and thread.ident != controller for thread in threads)
                    and deadlines == [12345, 12345], 'overlap/join/deadline changed')
                require(identifiers['broker'] == IDS['broker']
                    and ('worker' in identifiers) == (failing != 'worker-create'), 'returned identity lost/invented')
                snapshot = journal.snapshot()[0]['resources']
                require(snapshot['broker']['state'] == 'created'
                    and snapshot['worker']['state'] == ('intent' if failing in ('worker-create', 'worker-ID') else 'created'),
                    'durable dependency state changed/lost')
                if failing is None:
                    require(preflights == {'broker', 'worker'}, 'valid pipeline skipped preflight')
        value = candidate_instance()
        _, broker, _, _ = engine(value)
        original = value._preflight_role
        def bad_broker(row, role, *args):
            if role == 'broker':
                raise WorkerContainmentError('controlled stopped preflight fault')
            return original(row, role, *args)
        value._preflight_role = bad_broker
        run(value, root / 'bad-preflight.json', reject=True)
        require(not broker.stopped and value._cleanup.call_count == 3,
            'consumer started after preflight fault or cleanup skipped roles')
    value = candidate_instance()
    value._create_role = Mock(return_value=IDS['broker'])
    value._inspect = Mock(return_value={})
    value._preflight_role = Mock()
    attempted, identifiers = set(), {}
    def failed_intent(method, role, *_):
        if method == 'intent' and role == 'worker':
            raise OSError('controlled intent fault')
    try:
        value._prepare_consumers(names, TOKEN, VOLUME, 12345, attempted, identifiers, failed_intent)
    except OSError:
        pass
    else:
        raise AssertionError('failed intent admitted')
    require(attempted == {'broker', 'worker'} and identifiers == {'broker': IDS['broker']}
        and value._create_role.call_count == 1, 'failed intent lost broker or launched worker')
    print('Startup pipeline controls pass: broker-created before worker-intent, actual inspect/create '
          'overlap, shared deadline, joined threads, controller-only journal/preflight and fault refusal. '
          'Controlled Docker, not native latency/containment proof.')


if __name__ == '__main__':
    main()
