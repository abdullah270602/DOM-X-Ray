"""Loopback admission capacity with controlled parser synchronization.

Not a Node runtime, process-tree, memory or distributed abuse bound.
"""

from pathlib import Path
import sys
from threading import Event, Lock, Thread
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.api_contract import API_VERSION
from scanner.destination_policy import DestinationPolicyError
from scanner.local_scan_api import LocalScanJobService, build_server
from scripts.verify_local_scan_api import json_request, require
from scripts.verify_whatwg_api_admission import fixture_parser


def main():
    parser = fixture_parser()
    executor = Mock()
    executor.supports.return_value = False
    service = LocalScanJobService(executor, target_parser=parser, max_concurrent_target_parsers=2)
    server = build_server('127.0.0.1', 0, service, static_root=None)
    host = Thread(target=server.serve_forever, daemon=True)
    host.start()
    base = 'http://127.0.0.1:' + str(server.server_port)
    entered, release, mutex = Event(), Event(), Lock()
    active, maximum, invocations = 0, 0, 0
    outcomes, failures, clients = [], [], []
    original = parser.parse
    def blocked(value, *, purpose):
        nonlocal active, maximum, invocations
        with mutex:
            active += 1
            invocations += 1
            maximum = max(maximum, active)
            if active == 2:
                entered.set()
        try:
            require(release.wait(5), 'controlled parser release timed out')
            return original(value, purpose=purpose)
        finally:
            with mutex:
                active -= 1
    def request():
        return json_request(base, '/api/scans', method='POST',
            value={'apiVersion': API_VERSION, 'url': 'https://example.com/'},
            headers={'X-Deletion-Token-Digest': 'sha256=' + 'a' * 64})
    def client():
        try:
            outcomes.append(request())
        except Exception as error:
            failures.append(type(error).__name__)
    try:
        with patch.object(parser, 'parse', side_effect=blocked), \
                patch.object(service._admission, 'reserve', wraps=service._admission.reserve) as reserve:
            for _ in range(2):
                thread = Thread(target=client)
                clients.append(thread)
                thread.start()
            require(entered.wait(2), 'two parser slots not occupied')
            status, headers, job = request()
            require(status == 429 and headers['Retry-After'] == '1'
                    and headers['Cache-Control'] == 'no-store' and job['error']['code'] == 'queue-full'
                    and invocations == 2 and not executor.supports.called and not reserve.called,
                    'overflow performed parser/executor/admission work')
            release.set()
            for thread in clients:
                thread.join(timeout=5)
            require(all(not thread.is_alive() for thread in clients) and not failures
                    and len(outcomes) == 2 and maximum == 2 and active == 0
                    and all(status == 503 and result['error']['code'] == 'scanner-disabled'
                            for status, _, result in outcomes),
                    'parser slot bound or owned clients failed')
        for reason, expected in (('invalid-url', 403), ('url-parser-unavailable', 503)):
            with patch.object(parser, 'parse', side_effect=DestinationPolicyError(reason)):
                for _ in range(3):
                    status, _, _ = request()
                    require(status == expected, 'parser fault leaked permit')
        status, _, job = request()
        require(status == 503 and job['error']['code'] == 'scanner-disabled'
                and not executor.execute.called, 'capacity not reusable after parser failures')
    finally:
        release.set()
        for thread in clients:
            thread.join(timeout=5)
        server.shutdown()
        server.server_close()
        host.join(timeout=2)
        service.shutdown()
    for invalid in (0, -1, True, 1.5, '2', None):
        try:
            LocalScanJobService(max_concurrent_target_parsers=invalid)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid parser concurrency accepted')
    print('Loopback admission: two occupied parser slots, overflow 429 before parser/executor/reservation, permits restored after success/policy/infrastructure faults. Not whole-API resource containment.')


if __name__ == '__main__':
    main()
