"""Bounded local wrong-token bookkeeping; authority checked before throttling."""

from pathlib import Path
import sys
import threading
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.local_scan_api import LocalScanJobService, MAX_DELETION_FAILURES
from scanner.local_scan_api import build_server
from scanner.result_store import MemoryResultStore
from scripts.verify_local_scan_api import fixture_bundle, deletion_digest, request


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Backend:
    """Controlled authorization decisions, not storage/capability cryptography."""
    def __init__(self):
        self.calls = 0
    def delete(self, result_id, token):
        self.calls += 1
        return {'owner': 'deleted', 'pending-owner': 'pending',
                'retry-owner': 'retryable', 'unknown': 'not-found'}.get(token, 'forbidden')


def main():
    backend = Backend()
    service = LocalScanJobService(result_backend=backend, deletion_failure_history_limit=2)
    ids = ['r_' + digit * 32 for digit in ('1', '2', '3')]
    try:
        with patch('scanner.local_scan_api.time.monotonic', return_value=100):
            for identifier in ids[:2]:
                for index in range(100):
                    outcome, retry = service.delete_result(identifier, 'wrong')
                    require(outcome == ('forbidden' if index < MAX_DELETION_FAILURES - 1 else 'rate-limited'),
                            'existing wrong-token threshold changed')
                    require(len(service._deletion_failures[identifier]) <= MAX_DELETION_FAILURES,
                            'one result timestamp history exceeded cap')
            before = backend.calls
            outcome, retry = service.delete_result(ids[2], 'wrong')
            require(outcome == 'rate-limited' and retry == 60
                    and len(service._deletion_failures) == 2 and backend.calls == before + 1,
                    'global saturation bypassed authority check or allocated history')
            require(service.delete_result(ids[2], 'pending-owner') == ('pending', 5)
                    and service.delete_result(ids[2], 'retry-owner') == ('retryable', 5)
                    and service.delete_result(ids[2], 'unknown') == ('not-found', None),
                    'saturation replaced authorized pending or missing outcomes')
            require(service.delete_result(ids[0], 'owner') == ('deleted', None)
                    and ids[0] not in service._deletion_failures, 'attacker history blocked owner deletion')
            require(service.delete_result(ids[2], 'wrong') == ('forbidden', None)
                    and len(service._deletion_failures) == 2, 'owner cleanup did not release tracking capacity')
        with patch('scanner.local_scan_api.time.monotonic', return_value=120):
            for _ in range(20):
                require(service.delete_result(ids[1], 'wrong') == ('rate-limited', 40)
                        and service._deletion_failures[ids[1]] == [100] * MAX_DELETION_FAILURES,
                        'throttled guesses extended the retained window or timestamp cap')
        with patch('scanner.local_scan_api.time.monotonic', return_value=160):
            require(service.delete_result(ids[0], 'wrong') == ('forbidden', None)
                    and list(service._deletion_failures) == [ids[0]], 'expired records not pruned at exact window')
    finally:
        service.shutdown()
    for invalid in (0, -1, True, 1.5, '2', None):
        try:
            LocalScanJobService(deletion_failure_history_limit=invalid)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid deletion history limit accepted')
    verify_owner_http()
    print('Wrong-token history: per-result/global caps, threshold, cold-ID backpressure, exact expiry and controlled outcomes pass; real local HMAC backend/HTTP owner deletion survives saturation. Not distributed proof.')


def verify_owner_http():
    store = MemoryResultStore(keys=(b'D' * 32,))
    token = 'dxrd_' + 'a' * 64
    publications = [store.publish(fixture_bundle(name), deletion_digest(token))
                    for name in ('clean', 'image-heavy')]
    service = LocalScanJobService(result_backend=store, deletion_failure_history_limit=1)
    server = build_server('127.0.0.1', 0, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f'http://127.0.0.1:{server.server_port}'
    try:
        for index in range(10):
            status, headers, payload = request(base_url,
                f'/api/results/{publications[0].result_id}', method='DELETE',
                headers={'X-Deletion-Token': 'dxrd_' + '0' * 64})
            require(status == (403 if index < 4 else 429) and not payload
                    and headers.get('Cache-Control') == 'no-store',
                    'real backend wrong-token threshold or transport changed')
        status, headers, payload = request(base_url,
            f'/api/results/{publications[1].result_id}', method='DELETE',
            headers={'X-Deletion-Token': 'dxrd_' + '0' * 64})
        require(status == 429 and not payload and int(headers['Retry-After']) > 0
                and len(service._deletion_failures) == 1,
                'real backend cold-ID saturation allocated history')
        for publication in publications:
            status, headers, payload = request(base_url,
                f'/api/results/{publication.result_id}', method='DELETE',
                headers={'X-Deletion-Token': token})
            require(status == 204 and not payload and headers.get('Cache-Control') == 'no-store'
                    and store.get(publication.result_id) is None,
                    'local HMAC owner was blocked or result remained readable')
        require(not service._deletion_failures, 'owner deletion retained failure history')
    finally:
        server.shutdown()
        server.server_close()
        service.shutdown()
        thread.join(timeout=2)
        require(not thread.is_alive(), 'owned HTTP loop did not stop')


if __name__ == '__main__':
    main()
