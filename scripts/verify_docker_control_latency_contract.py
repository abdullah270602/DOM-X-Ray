"""Captured framing controls; no Docker process or performance proof."""
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_docker_control_latency import (
    BODY_LIMIT, COUNT, WIRE_LIMIT, child, decode_info_responses, fixed_requests, require)


def main():
    info = {'OSType': 'linux', 'CgroupVersion': '2', 'ID': 'PRIVATE_ENGINE_CANARY'}
    body = json.dumps(info).encode()
    def response(data=body, fields=None):
        fields = fields or f'Content-Length: {len(data)}\r\n'.encode()
        return b'HTTP/1.1 200 OK\r\n' + fields + b'\r\n' + data
    fixed = response() * COUNT
    digest = decode_info_responses(fixed)
    chunked = response(f'{len(body):x}\r\n'.encode() + body + b'\r\n0\r\n\r\n', b'Transfer-Encoding: chunked\r\n') * COUNT
    require(decode_info_responses(chunked) == digest and 'PRIVATE_ENGINE_CANARY' not in digest,
        'fixed/chunked framing or redaction changed')
    malformed = [fixed[:-1], fixed + b'private trailing output', response() * (COUNT - 1),
        fixed.replace(b'200 OK', b'500 Error', 1), b'x' * (WIRE_LIMIT + 1),
        response(fields=b'Content-Length: 1\r\nContent-Length: 1\r\n') * COUNT,
        response(fields=b'Transfer-Encoding: chunked\r\nContent-Length: 1\r\n') * COUNT,
        response(fields=b'Content-Length: +' + str(len(body)).encode() + b'\r\n') * COUNT,
        response(fields=b'Content-Length: ' + b'9' * 5000 + b'\r\n') * COUNT,
        response(fields=f'Content-Length: {BODY_LIMIT + 1}\r\n'.encode()) * COUNT,
        response(json.dumps({**info, 'ID': 'different'}).encode()) + response() * (COUNT - 1),
        response(b'{"OSType":"linux","OSType":"linux"}') * COUNT,
        response(json.dumps({**info, 'CgroupVersion': '1'}).encode()) * COUNT]
    for payload in malformed:
        try:
            decode_info_responses(payload)
        except Exception:
            continue
        raise AssertionError('malformed control evidence admitted')
    require(fixed_requests().count(b'GET /v1.51/info HTTP/1.1') == COUNT
        and b'POST' not in fixed_requests() and b'containers' not in fixed_requests(),
        'diagnostic request whitelist changed')
    class FailedClient:
        starts = 0
        stops = 0
        def __init__(self, *_):
            FailedClient.starts += 1
        def finish(self, _):
            return 1, b'PRIVATE_ERROR_CANARY'
        def stop(self, _):
            FailedClient.stops += 1
    with tempfile.TemporaryDirectory(prefix='dxr-control-contract-') as temporary:
        result = Path(temporary) / 'result.json'
        with patch('scanner.docker_worker_supervisor._PipeProcess', FailedClient), \
                patch.dict(os.environ, {'DOM_X_RAY_WORKER_RESULT_NONCE': 'contract'}):
            child(SimpleNamespace(docker=sys.executable, mode='dial', result=str(result)))
        encoded = result.read_bytes()
        evidence = json.loads(encoded)['result']
        require(evidence['outcome'] == 'client-nonzero' and evidence['clientExitCode'] == 1
            and evidence['responses'] == 0 and evidence['engineDigest'] is None
            and len(evidence['seconds']) == 1 and evidence['seconds'][0] >= 0
            and FailedClient.starts == FailedClient.stops == 1
            and b'PRIVATE_ERROR_CANARY' not in encoded,
            'failed-client timing, cleanup, redaction or no-retry accounting changed')
        class PartialClient(FailedClient):
            attempts = 0
            def finish(self, _):
                PartialClient.attempts += 1
                if PartialClient.attempts == 1:
                    return 0, body
                raise TimeoutError('PRIVATE_ERROR_CANARY')
        with patch('scanner.docker_worker_supervisor._PipeProcess', PartialClient), \
                patch.dict(os.environ, {'DOM_X_RAY_WORKER_RESULT_NONCE': 'contract'}):
            child(SimpleNamespace(docker=sys.executable, mode='cli', result=str(result)))
        encoded = result.read_bytes()
        evidence = json.loads(encoded)['result']
        require(evidence['outcome'] == 'control-failed' and evidence['responses'] == 1
            and evidence['clientExitCode'] is None and len(evidence['seconds']) == 2
            and PartialClient.attempts == 2 and FailedClient.stops == 3
            and b'PRIVATE_ERROR_CANARY' not in encoded,
            'partial completion or failed-iteration exit accounting changed')
    print('Read-only diagnostic controls pass: fixed/chunked replies, caps, exact count/identity, '
          'ambiguous/incomplete/malformed refusal and fixed GET-only requests. No native proof.')


if __name__ == '__main__':
    main()
