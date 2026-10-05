"""Generate a version/hash-pinned syscall profile for reserved-origin tests only.

This is not a production security profile. It retains an upstream deny-by-default
filter but permits namespace-local mount setup needed by the existing wrapper.
The container must still have zero host capabilities, no mounts and no network.
"""

import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

SOURCE = 'https://raw.githubusercontent.com/microsoft/playwright/v1.55.0/utils/docker/seccomp_profile.json'
SHA256 = 'cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parents[1] /
                        '.dom-xray-data' / 'fixture-seccomp-capture.json')
    options = parser.parse_args()
    with urllib.request.urlopen(SOURCE, timeout=15) as response:
        payload = response.read(65537)
    if len(payload) > 65536 or hashlib.sha256(payload).hexdigest() != SHA256:
        raise ValueError('fixture-seccomp-upstream-integrity')
    profile = json.loads(payload)
    if profile.get('defaultAction') != 'SCMP_ACT_ERRNO':
        raise ValueError('fixture-seccomp-default-action')
    profile['syscalls'].append({
        'comment': 'FIXTURE ONLY: namespace-local filesystem setup; no host capabilities',
        'names': ['mount', 'umount2', 'pivot_root', 'pidfd_open', 'pidfd_send_signal', 'chroot'], 'action': 'SCMP_ACT_ALLOW',
        'args': [], 'includes': {}, 'excludes': {}})
    options.output.parent.mkdir(parents=True, exist_ok=True)
    # Never overwrite an existing profile silently. Caller reviews/removes an old
    # generated artifact explicitly; the profile itself is not a source file.
    with options.output.open('x', encoding='utf-8') as output:
        json.dump(profile, output, indent=2)
    print(f'Generated fixture-only profile: {options.output.resolve()}')


if __name__ == '__main__':
    main()
