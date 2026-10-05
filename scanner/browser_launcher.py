#!/usr/bin/python3 -I
"""Read-only launcher: executable code never needs the scan's temporary mount."""

import os
from pathlib import Path
import stat
import sys


def main():
    home = Path(os.environ.get('HOME', ''))
    if (not home.is_absolute() or not home.is_dir() or home.resolve(strict=True) != home
            or home.stat().st_uid != os.getuid() or home.stat().st_mode & 0o077):
        raise ValueError('namespace-launch-private-home')
    config = home / 'namespace-config.json'
    metadata = config.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077 or not 0 < metadata.st_size <= 16384):
        raise ValueError('namespace-launch-private-config')
    entry = Path(__file__).resolve().with_name('browser_namespace.py')
    os.execv('/usr/bin/python3', ['/usr/bin/python3', '-I', str(entry),
                                '--launch', str(config), *sys.argv[1:]])


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit(2) from None
