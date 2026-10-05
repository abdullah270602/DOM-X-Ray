"""Bounded native quota probes; never accepts a visitor URL or executes a scan."""

import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import time


if not __debug__:
    raise RuntimeError('Quota proof requires enabled assertions; optimized Python is rejected')


def read(name):
    return Path('/sys/fs/cgroup', name).read_text().strip()


def counters(name):
    return dict((key, int(value)) for key, value in
                (line.split() for line in read(name).splitlines()))


mode = sys.argv[1]
if mode == 'configuration':
    assert os.getuid() == 65534
    assert read('memory.max') == '67108864'
    assert read('memory.swap.max') == '0'
    assert read('pids.max') == '32'
    assert read('cpu.max') == '25000 100000'
    for line in Path('/proc/self/status').read_text().splitlines():
        if line.startswith(('CapEff:', 'CapPrm:', 'CapBnd:')):
            assert int(line.split()[1], 16) == 0
        if line.startswith('NoNewPrivs:'):
            assert line.split()[1] == '1'
    try:
        Path('/root-write-probe').write_text('blocked')
        raise AssertionError('root was writable')
    except OSError as error:
        assert error.errno in (errno.EROFS, errno.EACCES)
    print(json.dumps({'mode': mode, 'limits': 'read back from cgroup v2'}), flush=True)
elif mode == 'cpu':
    before = counters('cpu.stat')
    end = time.monotonic() + 3
    while time.monotonic() < end:
        pass
    after = counters('cpu.stat')
    assert after['nr_throttled'] > before['nr_throttled']
    assert after['throttled_usec'] > before['throttled_usec']
    print(json.dumps({'mode': mode, 'throttled_periods':
                      after['nr_throttled'] - before['nr_throttled']}), flush=True)
elif mode == 'pids':
    children = []
    before = counters('pids.events')['max']
    try:
        for _ in range(40):
            try:
                child = os.fork()
                if child == 0:
                    time.sleep(30)
                    os._exit(0)
                children.append(child)
            except OSError as error:
                assert error.errno == errno.EAGAIN
                break
        else:
            raise AssertionError('process limit did not reject a fork')
        assert counters('pids.events')['max'] > before
        print(json.dumps({'mode': mode, 'children_before_rejection': len(children)}), flush=True)
    finally:
        for child in children:
            os.kill(child, 9)
        for child in children:
            os.waitpid(child, 0)
elif mode == 'disk':
    mount = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()
             if line.split()[4] == '/tmp']
    assert len(mount) == 1 and mount[0][mount[0].index('-') + 1] == 'tmpfs'
    volume = os.statvfs('/tmp')
    assert volume.f_blocks * volume.f_frsize == 16 * 1024 * 1024
    written = 0
    try:
        with open('/tmp/disk-probe', 'wb', buffering=0) as output:
            for _ in range(32):
                written += output.write(b'x' * 1024 * 1024)
        raise AssertionError('tmpfs exceeded its fixed size')
    except OSError as error:
        assert error.errno == errno.ENOSPC
        assert written <= 16 * 1024 * 1024
    print(json.dumps({'mode': mode, 'bytes_before_ENOSPC': written}), flush=True)
elif mode == 'memory':
    before = counters('memory.events')['oom_kill']
    child = subprocess.Popen([sys.executable, '-c',
                              'x=bytearray(128*1024*1024); print(len(x))'])
    assert child.wait(timeout=10) == -9
    assert counters('memory.events')['oom_kill'] > before
    print(json.dumps({'mode': mode, 'kernel_oom_kill': True}), flush=True)
elif mode in ('detached-normal', 'detached-timeout'):
    child = os.fork()
    if child == 0:
        os.setsid()
        time.sleep(30)
        os._exit(0)
    print(json.dumps({'mode': mode, 'detached_pid': child}), flush=True)
    if mode == 'detached-timeout':
        time.sleep(30)
else:
    raise ValueError('unknown fixed probe')
