"""Observe the current candidate identity/inventory inside its immutable image."""

import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), '/opt/runtime/python']
from scanner.container_capture_entry import runtime


def main():
    configured = runtime()
    locked = {}
    for line in Path('/opt/runtime/requirements.txt').read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([a-z0-9-]+)==([0-9.]+) --hash=sha256:([0-9a-f]{64})', line)
        if match is None or version(match[1]) != match[2]:
            raise ValueError('candidate-installed-package-pin')
        locked[match[1]] = match[2]
    with configured.chromium.open('rb') as stream:
        executable_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    manifest = Path('/opt/runtime/capture-runtime.json').read_bytes()
    inventory = Path('/opt/runtime/os-packages.txt').read_bytes()
    print(json.dumps({'playwright': version('playwright'),
        'expectedChromium': configured.expected_chromium_version,
        'chromiumExecutableSha256': executable_hash,
        'manifestSha256': hashlib.sha256(manifest).hexdigest(),
        'osInventorySha256': hashlib.sha256(inventory).hexdigest(),
        'pythonPackages': locked}, sort_keys=True))
    print('Verified candidate runtime inventory; not a vulnerability audit or reproducible apt lock.')


if __name__ == '__main__':
    main()
