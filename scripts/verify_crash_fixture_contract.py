"""Portable hook and failure-path audit tests; not native crash evidence."""

from contextlib import redirect_stdout
import io
from pathlib import Path
import sys
from threading import Event, Lock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_pair_controller_crash import inventory_guard, witness_pipe_factory
from scanner.docker_worker_supervisor import CONTROL_BYTES


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    calls, notified, cleaning = [], Event(), Event()
    phase_lock = Lock()
    pipe = SimpleNamespace(process=SimpleNamespace(poll=lambda: None), data=b'renderer-live\n')
    def original(arguments, payload, limit):
        calls.append((arguments, payload, limit))
        return pipe
    factory = witness_pipe_factory(original, cleaning, notified.set, phase_lock)
    require(factory(['info']) is pipe and calls[-1][1:] == (None, CONTROL_BYTES),
            'control call defaults were lost by witness hook')
    require(not notified.is_set(), 'control response became a renderer witness')
    factory(['start'], b'')
    require(not notified.is_set(), 'initializer became a renderer witness')
    factory(['start'], b'fixture', 123)
    require(notified.wait(1) and calls[-1][2] == 123, 'worker witness or output limit was lost')
    notified.clear()
    cleaning.set()
    factory(['start'], b'fixture')
    require(not notified.wait(0.05), 'cleanup-phase output became a crash witness')
    cleaning.clear()
    interleaved = Event()
    class RacingData:
        def __contains__(self, _marker):
            with phase_lock:
                cleaning.set()
            interleaved.set()
            return True
    pipe.data = RacingData()
    factory(['start'], b'fixture')
    require(interleaved.wait(1) and not notified.wait(0.05),
            'cleanup between marker observation and notification escaped phase guard')
    audits = []
    def docker(*args):
        audits.append(args)
        return ''
    with redirect_stdout(io.StringIO()):
        try:
            with inventory_guard(docker, '', ''):
                raise RuntimeError('fixture failure')
        except RuntimeError:
            pass
        else:
            raise AssertionError('audit swallowed the original failure')
    require(len(audits) == 2, 'failure path skipped scoped container/volume observations')
    print('Verified optional pipe arguments, worker-only/pre-cleanup witness and failure-path inventory audit.')


if __name__ == '__main__':
    main()
