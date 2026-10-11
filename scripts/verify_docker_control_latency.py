"""Read-only CLI startup vs one internal stdio connection. Never a supervisor."""
from __future__ import annotations

import argparse
import hashlib
import http.client
from io import BytesIO
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
COUNT = 5
BODY_LIMIT = 65536
HEADER_LIMIT = 16384
WIRE_LIMIT = COUNT * (BODY_LIMIT + HEADER_LIMIT)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def info_identity(payload):
    from scanner.docker_worker_supervisor import _pairs, _invalid_constant
    require(0 < len(payload) <= BODY_LIMIT, 'info body outside envelope')
    value = json.loads(payload, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
    require(isinstance(value, dict) and value.get('OSType') == 'linux'
        and value.get('CgroupVersion') == '2' and isinstance(value.get('ID'), str)
        and 0 < len(value['ID']) <= 256, 'unexpected engine info identity')
    return hashlib.sha256(value['ID'].encode('utf-8')).hexdigest()


def decode_info_responses(payload):
    """Decode only fixed engine-info replies, never a generic network client."""
    require(isinstance(payload, bytes) and 0 < len(payload) <= WIRE_LIMIT, 'wire outside envelope')
    source = BytesIO(payload)
    class SharedReader:
        def read(self, size=-1):
            return source.read(size)
        def readline(self, size=-1):
            return source.readline(size)
        def close(self):
            pass  # HTTPResponse must not close the next captured response.
        def flush(self):
            pass
    class CapturedSocket:
        def makefile(self, *_):
            return SharedReader()
    identities = []
    for _ in range(COUNT):
        before = source.tell()
        response = http.client.HTTPResponse(CapturedSocket())
        response.begin()
        require(source.tell() - before <= HEADER_LIMIT and response.version == 11
            and response.status == 200, 'unexpected info HTTP response')
        lengths = response.headers.get_all('Content-Length', [])
        codings = response.headers.get_all('Transfer-Encoding', [])
        require((len(lengths) == 1 and not codings) or
            (not lengths and len(codings) == 1 and codings[0].lower().strip() == 'chunked'),
            'ambiguous/unsupported engine response framing')
        if lengths:
            digits = lengths[0].strip(' \t')
            require(re.fullmatch('[0-9]+', digits) is not None, 'invalid response length')
            digits = digits.lstrip('0') or '0'
            require(len(digits) <= len(str(BODY_LIMIT)) and int(digits) <= BODY_LIMIT,
                'oversized response length')
        body = response.read(BODY_LIMIT + 1)
        require(response.isclosed() and len(body) <= BODY_LIMIT, 'incomplete/oversized info reply')
        identities.append(info_identity(body))
    require(source.tell() == len(payload) and len(set(identities)) == 1,
        'extra output or changed engine identity')
    return identities[0]


def fixed_requests():
    # Deliberately no input URL, engine mutation, attach or upgrade endpoints.
    return b''.join(b'GET /v1.51/info HTTP/1.1\r\nHost: docker\r\nConnection: '
        + (b'close' if index == COUNT - 1 else b'keep-alive') + b'\r\n\r\n' for index in range(COUNT))


def child(options):
    from scanner.docker_worker_supervisor import _PipeProcess
    candidate = Path(options.docker)
    require(candidate.is_absolute() and candidate.is_file() and not candidate.is_symlink(), 'invalid Docker executable')
    docker = candidate.resolve(strict=True)
    prefix = [str(docker), '--context', 'desktop-linux']
    deadline = time.monotonic() + 12  # Inside the existing owned outer 15s worker.
    durations, identities, failure, returncode = [], [], None, None
    modes = range(COUNT) if options.mode == 'cli' else range(1)
    for _ in modes:
        started = time.monotonic()
        pipe = None
        returncode = None
        try:
            require(time.monotonic() < deadline, 'diagnostic budget exhausted')
            command = [*prefix, 'info', '--format', '{{json .}}'] if options.mode == 'cli' else [*prefix, 'system', 'dial-stdio']
            pipe = _PipeProcess(command, None if options.mode == 'cli' else fixed_requests(),
                BODY_LIMIT if options.mode == 'cli' else WIRE_LIMIT)
            code, output = pipe.finish(min(deadline, started + 10))
            returncode = code
            if code != 0:
                failure = 'client-nonzero'
            else:
                identities.append(info_identity(output.strip()) if options.mode == 'cli' else decode_info_responses(output))
        except Exception:
            failure = 'control-failed'  # No provider response or error text in evidence.
        finally:
            if pipe is not None:
                try:
                    pipe.stop(deadline)
                except Exception:
                    failure = 'client-cleanup-unproven'
        durations.append(time.monotonic() - started)
        if failure is not None:
            break  # Do not restart uncertain client/connection state.
    evidence = {'mode': options.mode, 'outcome': failure or 'ok', 'seconds': durations,
        'clientExitCode': returncode,
        'responses': COUNT * len(identities) if options.mode == 'dial' else len(identities),
        'engineDigest': identities[0] if failure is None and len(set(identities)) == 1 else None}
    if failure is None and evidence['engineDigest'] is None:
        evidence['outcome'] = 'engine-changed'
    envelope = {'supervisorNonce': os.environ['DOM_X_RAY_WORKER_RESULT_NONCE'], 'result': evidence}
    Path(options.result).write_bytes(json.dumps(envelope, allow_nan=False).encode('ascii'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=('cli', 'dial'))
    parser.add_argument('--docker')
    parser.add_argument('--result')
    options = parser.parse_args()
    if options.mode:
        child(options)
        return
    from scanner.worker_supervisor import run_worker_command
    docker = shutil.which('docker')
    require(docker is not None, 'Docker runtime unavailable')
    names = ('PATH', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'LOCALAPPDATA',
             'PROGRAMFILES', 'PROGRAMFILES(X86)', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH')
    environment = {name: os.environ[name] for name in names if name in os.environ}
    reports = []
    with tempfile.TemporaryDirectory(prefix='dxr-readonly-control-') as temporary:
        for mode in ('cli', 'dial'):
            path = Path(temporary) / (mode + '.json')
            run = run_worker_command([sys.executable, str(Path(__file__).resolve()),
                '--mode', mode, '--docker', docker, '--result', str(path)],
                result_path=path, deadline_seconds=15, cwd=ROOT, environment=environment,
                max_result_bytes=4096)
            require(run.artifact_eligible, 'owned diagnostic worker did not complete: ' + run.outcome)
            report = json.loads(path.read_bytes())['result']
            # Do not print even hashed engine identity; only compare it privately.
            public = {key: value for key, value in report.items() if key != 'engineDigest'}
            public['supervisedSeconds'] = run.duration_ms / 1000
            print(json.dumps(public, sort_keys=True, allow_nan=False), flush=True)
            reports.append(report)
    require(all(report['outcome'] == 'ok' and report['responses'] == COUNT for report in reports),
        'read-only control comparison did not complete')
    require(reports[0]['engineDigest'] == reports[1]['engineDigest'], 'comparison engine changed')
    print(json.dumps({'cliTotalSeconds': sum(reports[0]['seconds']),
        'cliMedianSeconds': statistics.median(reports[0]['seconds']),
        'singleConnectionTotalSeconds': reports[1]['seconds'][0],
        'responsesPerMode': COUNT}), flush=True)
    print('Read-only same-engine observation only; CLI negotiation vs fixed API requests '
          'are not identical workloads. Hidden stdio transport is not production adoption.')


if __name__ == '__main__':
    main()
