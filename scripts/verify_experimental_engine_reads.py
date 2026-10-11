"""Contracts and optional owned native probe for the test-only read adapter."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.experimental_engine_reads import ContainerRead, decode, requests, run
from scripts.verify_docker_control_latency import BODY_LIMIT, require
from scanner.docker_worker_supervisor import LABEL


def contracts():
    target = ContainerRead('a' * 64, 'dom-x-ray-contract-' + 'b' * 32, 'b' * 32)
    plan = (target,)
    info = {'OSType': 'linux', 'CgroupVersion': '2', 'ID': 'PRIVATE_ENGINE_CANARY'}
    row = {'Id': target.identifier, 'Name': '/' + target.name,
        'Config': {'Labels': {LABEL: target.token}}, 'State': {'Pid': 0}}
    def reply(value, status=200, headers=None):
        body = json.dumps(value).encode()
        fields = headers or f'Content-Length: {len(body)}\r\n'.encode()
        return f'HTTP/1.1 {status} Reply\r\n'.encode() + fields + b'\r\n' + body
    valid = reply(info) + reply(row) + reply(info)
    digest, rows = decode(valid, plan)
    require(rows == (row,) and 'PRIVATE_ENGINE_CANARY' not in digest, 'owned read changed')
    missing = reply(info) + reply({'message': 'PRIVATE_NOT_FOUND'}, 404) + reply(info)
    require(decode(missing, plan)[1] == (None,), 'missing observation changed')
    wire = requests(plan)
    require(wire.count(b'GET ') == 3 and wire.count(b'Connection: close') == 1
        and wire.endswith(b'Connection: close\r\n\r\n')
        and b'/containers/' + target.identifier.encode() + b'/json' in wire
        and b'POST' not in wire and b'DELETE' not in wire, 'read allowlist changed')
    invalid_plans = [(), list(plan), plan * 2, plan * 4, (ContainerRead('../x', target.name, target.token),),
        (ContainerRead('A' * 64, target.name, target.token),),
        (ContainerRead(target.identifier, 'x\r\nGET /containers/json', target.token),),
        (ContainerRead(target.identifier, target.name, 'wrong'),)]
    for invalid in invalid_plans:
        try:
            requests(invalid)
        except Exception:
            continue
        raise AssertionError('invalid read plan admitted')
    malformed = [valid[:-1], valid + b'PRIVATE_TRAILING', reply(info) + reply(row),
        reply(info) + reply({**row, 'Id': 'c' * 64}) + reply(info),
        reply(info) + reply({**row, 'Name': '/other'}) + reply(info),
        reply(info) + reply({**row, 'Config': {'Labels': {LABEL: 'wrong'}}}) + reply(info),
        reply(info) + reply(row, 500) + reply(info),
        reply(info, 404) + reply(row) + reply(info),
        reply(info) + reply({'message': 'x', 'other': 1}, 404) + reply(info),
        reply(info) + reply(row) + reply({**info, 'ID': 'different'}),
        reply(info, headers=b'Content-Length: 1\r\nContent-Length: 1\r\n') + valid,
        reply(info, headers=b'Transfer-Encoding: chunked\r\nContent-Length: 1\r\n') + valid,
        reply(info, headers=f'Content-Length: {BODY_LIMIT + 1}\r\n'.encode()) + valid]
    for value in malformed:
        try:
            decode(value, plan)
        except Exception:
            continue
        raise AssertionError('malformed/foreign read admitted')
    class Pipe:
        stops = 0
        timed_out = False
        def __init__(self, command, payload, limit, *, keep_stdin):
            require(command[-2:] == ['system', 'dial-stdio'] and keep_stdin
                and payload == wire and limit > len(valid), 'client request changed')
        def finish(self, deadline):
            if self.timed_out:
                raise TimeoutError('PRIVATE_ERROR')
            return 0, valid
        def stop(self, deadline):
            Pipe.stops += 1
    with patch('scripts.experimental_engine_reads._PipeProcess', Pipe):
        require(run(sys.executable, plan, time.monotonic() + 1)[1] == (row,), 'run decode changed')
        Pipe.timed_out = True
        try:
            run(sys.executable, plan, time.monotonic() + 1)
        except TimeoutError:
            pass
        else:
            raise AssertionError('timeout admitted')
    require(Pipe.stops == 2, 'success/timeout cleanup changed')
    with patch('scripts.experimental_engine_reads._PipeProcess') as unopened:
        for budget in (float('inf'), float('nan'), time.monotonic() - 1, time.monotonic() + 30):
            try:
                run(sys.executable, plan, budget)
            except Exception:
                continue
            raise AssertionError('unbounded/expired read budget admitted')
        require(not unopened.called, 'invalid budget opened client')
    print('Read batch contracts pass: closed plan, exact ownership, bookend identity, '
        'missing observation, framing/caps, timeout cleanup. No native containment proof.')


def child(options):
    # Random full ID: no inventory listing and no resource creation.
    token = secrets.token_hex(16)
    plan = (ContainerRead(secrets.token_hex(32), 'dom-x-ray-read-probe-' + token, token),)
    started = time.monotonic()
    _, rows = run(options.docker, plan, started + 12)
    require(rows == (None,), 'random probe unexpectedly matched a resource')
    evidence = {'outcome': 'ok', 'responses': 3, 'missingObservations': 1,
        'seconds': time.monotonic() - started}
    Path(options.result).write_bytes(json.dumps({'supervisorNonce':
        os.environ['DOM_X_RAY_WORKER_RESULT_NONCE'], 'result': evidence}).encode('ascii'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--child', action='store_true')
    parser.add_argument('--docker')
    parser.add_argument('--result')
    options = parser.parse_args()
    if options.child:
        child(options)
        return
    contracts()
    if not options.native:
        return
    from scanner.worker_supervisor import run_worker_command
    docker = shutil.which('docker')
    require(docker is not None, 'Docker unavailable')
    names = ('PATH', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'LOCALAPPDATA',
        'PROGRAMFILES', 'PROGRAMFILES(X86)', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH')
    environment = {name: os.environ[name] for name in names if name in os.environ}
    with tempfile.TemporaryDirectory(prefix='dxr-read-batch-') as temporary:
        path = Path(temporary) / 'result.json'
        worker = run_worker_command([sys.executable, str(Path(__file__).resolve()), '--child',
            '--docker', docker, '--result', str(path)], result_path=path, deadline_seconds=15,
            cwd=ROOT, environment=environment, max_result_bytes=4096)
        require(worker.artifact_eligible, 'owned read worker failed: ' + worker.outcome)
        evidence = json.loads(path.read_bytes())['result']
        evidence['supervisedSeconds'] = worker.duration_ms / 1000
        print(json.dumps(evidence, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
