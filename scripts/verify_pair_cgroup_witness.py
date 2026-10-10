"""Portable announcement framing/schema checks, not native pair evidence."""

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_native_recovery_poller import decode_resource_witness, host_interpreter_flags


def main():
    for optimization, flags in ((0, ['-I']), (1, ['-I', '-O']), (2, ['-I', '-OO'])):
        if host_interpreter_flags(optimization) != flags:
            raise RuntimeError('host flags not propagated exactly')
    for invalid in (-1, 3, True, '1', None):
        try:
            host_interpreter_flags(invalid)
        except AssertionError:
            pass
        else:
            raise RuntimeError('invalid optimization accepted')
    record = {'version': 1, 'token': 'a' * 32, 'runtimeFingerprint': 'b' * 64,
        'engineId': 'fixture-engine', 'expiresAtMs': 123456,
        'resources': {role: {'state': 'created', 'id': None if role == 'volume' else digit * 64}
            for role, digit in [('volume', '0'), ('initialize', '1'), ('broker', '2'), ('worker', '3')]}}
    line = b'fixture-resources ' + json.dumps(record, separators=(',', ':')).encode() + b'\n'
    if decode_resource_witness(line) != record or decode_resource_witness(line[:-1] + b'\r\n') != record:
        raise RuntimeError('valid witness rejected')
    invalid = [line[:-1], b'other ' + line, b'fixture-resources ' + b'x' * 8192 + b'\n',
        line.replace(b'"version":1', b'"version":1,"version":1'),
        line.replace(b'"expiresAtMs":123456', b'"expiresAtMs":NaN'),
        line.replace(b'"version":1', b'"version":true'),
        line.replace(b'"id":"' + b'2' * 64 + b'"', b'"id":"not-an-id"'),
        line + b'{}\n', 'not-bytes']
    for value in invalid:
        try:
            decode_resource_witness(value)
        except (ValueError, RuntimeError, TypeError, AssertionError):
            pass
        else:
            raise RuntimeError('invalid witness accepted')
    print('Verified pair resource witness framing/schema; no native identity or transition claim.')


if __name__ == '__main__':
    main()
