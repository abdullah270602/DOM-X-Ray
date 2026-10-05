"""Verify local candidate wheel hashes against the lock and official PyPI metadata."""

import hashlib
import json
from pathlib import Path
import re
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'containers/runtime-candidate.requirements.txt'
WHEELS = ROOT / '.dom-xray-data/candidate-wheels'


def main():
    files = {path.name: path for path in WHEELS.iterdir() if path.is_file()}
    verified = set()
    for line in LOCK.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([a-z0-9-]+)==([0-9.]+) --hash=sha256:([0-9a-f]{64})', line)
        if match is None:
            raise ValueError('candidate-lock-shape')
        name, version, digest = match.groups()
        with urllib.request.urlopen(f'https://pypi.org/pypi/{name}/{version}/json', timeout=10) as response:
            raw = response.read(1_000_001)
        if len(raw) > 1_000_000:
            raise ValueError('candidate-metadata-limit')
        metadata = json.loads(raw)
        candidates = [row for row in metadata['urls'] if row['digests']['sha256'] == digest
                      and row['filename'].endswith('.whl') and not row['yanked']]
        if len(candidates) != 1 or candidates[0]['filename'] not in files:
            raise ValueError('candidate-wheel-not-official-unyanked-artifact')
        path = files[candidates[0]['filename']]
        with path.open('rb') as stream:
            observed = hashlib.file_digest(stream, 'sha256').hexdigest()
        if observed != digest:
            raise ValueError('candidate-wheel-hash')
        verified.add(path.name)
        print(f'{name}=={version}: official hash matched', flush=True)
    if verified != set(files) or len(verified) != 9:
        raise ValueError('candidate-wheel-set')
    print('Verified all nine pinned candidate wheels; no package installation or host environment changes.')


if __name__ == '__main__':
    main()
