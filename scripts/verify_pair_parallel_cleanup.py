"""Real bounded threads, controlled Docker proofs; no native containment claim."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import sys
import tempfile
from threading import Barrier, Lock, current_thread, get_ident
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.worker_supervisor import WorkerContainmentError
from scripts.verify_pair_supervisor_contract import instance, engine, run, TOKEN, IDS, require


def main():
    controller = get_ident()
    with tempfile.TemporaryDirectory() as temporary:
        for failing in (False, True):
            value = instance()
            engine(value)
            barrier, lock = Barrier(3), Lock()
            completed, threads, deadlines = set(), set(), []
            def cleanup(name, token, identifier, deadline):
                role = next(role for role in IDS if identifier == IDS[role])
                require(name == 'dom-x-ray-pair-' + role + '-' + TOKEN and token == TOKEN,
                    'cleanup ownership inputs changed')
                with lock:
                    threads.add(current_thread())
                    deadlines.append(deadline)
                barrier.wait(timeout=3)  # All three must actually overlap.
                with lock:
                    completed.add(role)
                if failing and role == 'worker':
                    raise WorkerContainmentError('controlled role failure')
                return {'ExitCode': 0, 'OOMKilled': False}
            value._cleanup = Mock(side_effect=cleanup)
            original = value._remove_volume
            def remove(*args):
                require(get_ident() == controller and completed == set(IDS)
                    and len(threads) == 3 and all(thread.ident != controller
                        and not thread.is_alive() for thread in threads),
                    'volume touched before all cleanup workers joined')
                return original(*args)
            value._remove_volume = Mock(side_effect=remove)
            result = run(value, Path(temporary) / f'{failing}.json', reject=failing)
            require(value._cleanup.call_count == 3 and len(set(deadlines)) == 1,
                'role work/deadline was skipped or reset')
            require(all(not thread.is_alive() for thread in threads), 'cleanup thread survived return')
            require(value._remove_volume.called != failing, 'failed role allowed volume removal')
            if not failing:
                require(result.artifact_eligible, 'valid overlap lost result')
        value = instance()
        names = {role: 'dom-x-ray-pair-' + role + '-' + TOKEN for role in IDS}
        value._cleanup = Mock(return_value={'ExitCode': 0, 'OOMKilled': False})
        callbacks = []
        states, failure = value._cleanup_roles(names, TOKEN, IDS, set(IDS), 12345,
            lambda method, role: callbacks.append((get_ident(), method, role)))
        require(failure is None and set(states) == set(IDS) and len(callbacks) == 3
            and all(thread == controller and method == 'removed' for thread, method, _ in callbacks),
            'journal proofs moved into cleanup threads')
        def failed_note(*_):
            raise OSError('controlled journal fault')
        _, failure = value._cleanup_roles(names, TOKEN, IDS, set(IDS), 12345, failed_note)
        require(failure is not None and value._cleanup.call_count == 6, 'journal failure admitted/skipped roles')
        with patch('scanner.docker_broker_pair_supervisor.ThreadPoolExecutor', side_effect=RuntimeError('no pool')):
            states, failure = value._cleanup_roles(names, TOKEN, IDS, set(IDS), 12345, failed_note)
        require(not states and failure is not None, 'unavailable control pool admitted cleanup')
        submissions = []
        class FailedSubmission:
            def __init__(self, **kwargs):
                self.pool = ThreadPoolExecutor(**kwargs)
            def __enter__(self):
                self.pool.__enter__()
                return self
            def __exit__(self, *args):
                return self.pool.__exit__(*args)
            def submit(self, function, name, *args):
                submissions.append(name)
                if name == names['broker']:
                    raise RuntimeError('controlled submit failure')
                return self.pool.submit(function, name, *args)
        callbacks.clear()
        value._cleanup.reset_mock()
        with patch('scanner.docker_broker_pair_supervisor.ThreadPoolExecutor', FailedSubmission):
            states, failure = value._cleanup_roles(names, TOKEN, IDS, set(IDS), 12345,
                lambda method, role: callbacks.append((get_ident(), method, role)))
        require(failure is not None and set(states) == {'worker', 'initialize'}
            and len(submissions) == 3 and value._cleanup.call_count == 2
            and len(callbacks) == 2, 'submit failure skipped later roles, retried or admitted cleanup')
    print('Parallel cleanup controls pass: exactly three overlapping role threads, shared deadline, '
          'controller-only journal proofs, joined before volume, failure/journal/pool refusal. '
          'Controlled Docker, not native timing/containment proof.')


if __name__ == '__main__':
    main()
