"""Native host pipe lifecycle tests; no Docker/network or fixture assertions."""

from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.docker_worker_supervisor import _PipeProcess
from scanner.worker_supervisor import WorkerContainmentError


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    child = ('import sys; sys.stdin.buffer.readline(); sys.stdout.buffer.write(b"ready\\n"); sys.stdout.buffer.flush(); '
             'sys.stdin.buffer.read(); sys.stdout.buffer.write(b"closed\\n"); sys.stdout.buffer.flush()')
    deadline = time.monotonic() + 3
    pipe = _PipeProcess([sys.executable, '-I', '-c', child], b'job\n', 100, keep_stdin=True)
    try:
        pipe.wait_prefix(b'ready\n', deadline)
        require(pipe.process.poll() is None and not pipe.process.stdin.closed, 'ownership stdin closed early')
        pipe.close_input(deadline)
        code, output = pipe.finish(deadline)
        require(code == 0 and output == b'ready\nclosed\n', 'EOF did not release broker-shaped child')
    finally:
        pipe.stop(time.monotonic() + 1)
    print('held stdin: ready while alive, explicit EOF, bounded complete output')

    deadline = time.monotonic() + 3
    pipe = _PipeProcess([sys.executable, '-I', '-c', child.replace('ready', 'noise')], b'job\n', 100, keep_stdin=True)
    try:
        try:
            pipe.wait_prefix(b'ready\n', deadline)
        except WorkerContainmentError:
            pass
        else:
            raise AssertionError('noise accepted as readiness')
    finally:
        pipe.stop(time.monotonic() + 1)
    require(pipe.process.stdin.closed, 'aborted held stdin leaked')
    print('unexpected readiness: fail closed; client pipes closed')

    deadline = time.monotonic() + 3
    pipe = _PipeProcess([sys.executable, '-I', '-c', 'print("x"*10000, flush=True)'], b'', 20)
    try:
        try:
            pipe.finish(deadline)
        except OverflowError:
            require(len(pipe.data) == 21 and pipe.overflow, 'reader exceeded cap plus detection byte')
        else:
            raise AssertionError('overflow accepted')
    finally:
        pipe.stop(time.monotonic() + 1)
    print('stdout overflow: bounded cap plus detection byte')


if __name__ == '__main__':
    main()
