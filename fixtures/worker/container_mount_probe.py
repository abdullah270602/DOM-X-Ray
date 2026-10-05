"""Trusted local-only syscall versus mount-tool compatibility diagnostic."""

import ctypes
import os
from pathlib import Path
import subprocess
import socket
import sys
import tempfile


def main():
    if sys.argv[-1] != '--child':
        raise SystemExit(subprocess.run(['/usr/bin/unshare', '--user', '--map-current-user',
            '--net', '--pid', '--ipc', '--mount-proc', '--fork', '--kill-child', '--keep-caps',
            '/usr/bin/python3', '-I', __file__, '--child']).returncode)
    library = ctypes.CDLL(None, use_errno=True)
    with tempfile.TemporaryDirectory(dir='/tmp') as name:
        root = Path(name)
        if library.mount(None, b'/', None, 16384 | (1 << 18), None) != 0:
            raise OSError(ctypes.get_errno(), 'probe-private-propagation')
        if library.mount(b'tmpfs', os.fsencode(root), b'tmpfs', 0, b'size=1m') != 0:
            raise OSError(ctypes.get_errno(), 'probe-tmpfs')
        tool_target, raw_target = root / 'tool', root / 'raw'
        tool_target.mkdir()
        raw_target.mkdir()
        tool = subprocess.run(['/usr/bin/mount', '--bind', '/usr/bin', str(tool_target)],
                              capture_output=True, text=True, timeout=2)
        print('tool-bind:', tool.returncode, tool.stderr.strip(), flush=True)
        status = library.mount(b'/usr/bin', os.fsencode(raw_target), None, 4096, None)
        print('raw-bind:', status, 'errno:', ctypes.get_errno() if status else 0, flush=True)
        if status:
            raise OSError(ctypes.get_errno(), 'probe-raw-bind')
        # All mounts are private to this diagnostic namespace; detach only its root.
        if library.umount2(os.fsencode(root), 2) != 0:
            raise OSError(ctypes.get_errno(), 'probe-detach')
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    print('sbin-child-mounts:', [line.split()[4] for line in Path('/proc/self/mountinfo').read_text().splitlines()
                                if line.split()[4].startswith('/usr/sbin/')], flush=True)
    import scanner.browser_filesystem as filesystem
    home = Path(tempfile.mkdtemp(prefix='dxr-mount-probe-', dir='/tmp'))
    for name in ('.pki', 'config', 'data', 'cache', 'tmp'):
        (home / name).mkdir(mode=0o700)
    database = home / '.pki/nssdb'
    database.mkdir(mode=0o700)
    for name in ('cert9.db', 'key4.db', 'pkcs11.txt'):
        (database / name).write_bytes(b'fixture-only bounded setup canary')
    bridge = home / 'proxy.sock'
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(bridge))
    config = filesystem.filesystem_config(home, [])

    def diagnostic_mount(*arguments):
        result = subprocess.run(['/usr/bin/mount', *map(str, arguments)],
                                capture_output=True, text=True, timeout=2)
        if result.returncode:
            # Trusted reserved fixture only: no target or visitor configuration.
            print('fixture-mount-failure:', arguments, result.stderr.strip(), flush=True)
            if arguments[0] == '--bind':
                raw = library.mount(os.fsencode(arguments[1]), os.fsencode(arguments[2]), None, 4096, None)
                print('fixture-raw-bind:', raw, 'errno:', ctypes.get_errno() if raw else 0, flush=True)
            raise RuntimeError('fixture-mount-operation-rejected')
    filesystem._mount = diagnostic_mount
    filesystem.enter_browser_filesystem(config, bridge, preserve_pipes=False)
    print('filesystem-pivot-success', flush=True)
    os._exit(0)


if __name__ == '__main__':
    main()
