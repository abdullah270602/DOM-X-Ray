"""Fixed image entrypoint: bounded stdin grant, one stdout envelope, .test only.

No runtime selection or origin injection is accepted from stdin. Docker's host
supervisor owns the deadline and teardown; there is no nested 15-second runner.
"""

import json
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), '/opt/runtime/python']

from scanner.docker_worker_supervisor import MAX_INPUT_BYTES, _pairs
from scanner.egress_capture_worker import CaptureRuntime, capture_granted_page
from scanner.scan_transport import decode_public_scan_grant
from scanner.worker_supervisor import MAX_WORKER_RESULT_BYTES


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if not 0 < len(raw) <= MAX_INPUT_BYTES:
        raise ValueError('container-input-limit')
    payload = json.loads(raw, object_pairs_hook=_pairs)
    if (not isinstance(payload, dict) or set(payload) != {'grant', 'nonce'}
            or not isinstance(payload['nonce'], str)
            or not re.fullmatch(r'[0-9a-f]{32}', payload['nonce'])):
        raise ValueError('container-input-shape')
    return decode_public_scan_grant(payload['grant']), payload['nonce']


def emit_record(record, nonce):
    raw = json.dumps({'supervisorNonce': nonce, 'result': {'record': record}},
                     separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > MAX_WORKER_RESULT_BYTES:
        raise ValueError('container-output-limit')
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


def runtime():
    return CaptureRuntime(Path('/usr/bin/openssl'), Path('/opt/runtime/root/usr/bin/certutil'),
        Path('/opt/runtime/browsers/chromium_headless_shell-1187/chrome-linux/headless_shell'),
        Path('/opt/runtime/root/usr/lib/x86_64-linux-gnu'))


def main():
    if len(sys.argv) != 1:
        raise ValueError('container-arguments')
    grant, nonce = read_request()
    with tempfile.TemporaryDirectory(prefix='dxr-stdio-', dir='/tmp') as temporary:
        os.environ.clear()
        os.environ.update(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8',
                          HOME=temporary, TMPDIR=temporary)
        emit_record(capture_granted_page(grant, runtime()), nonce)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit(2) from None
