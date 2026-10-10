"""Real HTTP/HMAC backend controls with a deliberately controlled executor."""
from pathlib import Path
import sys
import time
from threading import Event, Thread

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.admission_policy import ScanAdmissionGate
from scanner.local_scan_api import API_VERSION, LocalScanJobService, build_server
from scanner.result_store import MemoryResultStore
from scripts.verify_local_scan_api import fixture_bundle, deletion_digest, json_request, request, require


def wait_for_publication(base, job_id):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status, headers, job = json_request(base, f'/api/scans/{job_id}')
        require(status == 200 and headers['Cache-Control'] == 'no-store', 'HTTP polling failed')
        if job['state'] not in ('queued', 'running'):
            return job
        time.sleep(.02)
    raise AssertionError('controlled publication observation timed out')


class ControlledExecutor:
    def __init__(self, blocked=False):
        self.started, self.release = Event(), Event()
        self.calls = []
        if not blocked:
            self.release.set()
    def supports(self, target):
        return target in ('https://clean.example/', 'https://gallery.example/')
    def execute(self, target, progress):
        self.calls.append(target)
        self.started.set()
        require(self.release.wait(5), 'owned executor release timed out')
        return fixture_bundle('clean' if target == 'https://clean.example/' else 'image-heavy')


def main():
    owner = 'dxrd_' + 'a' * 64
    now = [100.0]
    for blocked in (False, True):
        gate = ScanAdmissionGate(duplicate_window_seconds=30, origin_cooling_seconds=10,
            clock=lambda: now[0], max_target_reservations=1, max_origin_reservations=1)
        store = MemoryResultStore(keys=(b'A' * 32,))
        executor = ControlledExecutor(blocked)
        if not blocked:
            publication = store.publish(fixture_bundle('clean'), deletion_digest(owner))
            require(gate.reserve('https://clean.example/').action == 'scan', 'reuse setup failed')
            gate.complete('https://clean.example/', publication.result_id)
        service = LocalScanJobService(executor, admission_gate=gate, result_backend=store)
        server = build_server('127.0.0.1', 0, service)
        host = Thread(target=server.serve_forever, daemon=True)
        base = f'http://127.0.0.1:{server.server_port}'
        def submit(target):
            return json_request(base, '/api/scans', method='POST',
                value={'apiVersion': API_VERSION, 'url': target},
                headers={'X-Deletion-Token-Digest': 'sha256=' + deletion_digest(owner)})
        try:
            host.start()
            status, _, job = submit('https://clean.example/')
            require(status == (202 if blocked else 200), 'active/reuse admission changed')
            if blocked:
                require(executor.started.wait(2), 'controlled scan did not start')
                now[0] += 31
                status, headers, duplicate = submit('https://clean.example/')
                require(status == 429 and headers['Retry-After'] == '1'
                        and duplicate['error']['code'] == 'rate-limited', 'expired active target duplicated')
            for _ in range(24):
                status, headers, overflow = submit('https://gallery.example/')
                require(status == 429 and overflow['error']['code'] == 'rate-limited'
                        and headers['Cache-Control'] == 'no-store'
                        and int(headers['Retry-After']) >= 1
                        and len(gate._targets) == 1 and len(gate._origins) <= 1,
                        'capacity flood grew maps or changed HTTP contract')
            require(executor.calls == (['https://clean.example/'] if blocked else []),
                    'overflow/reuse reached executor')
            if blocked:
                executor.release.set()
                job = wait_for_publication(base, job['jobId'])
                require(job['state'] == 'ready', 'late completion lost original reservation')
            result_id = job['result']['resultId']
            status, _, payload = request(base, f'/api/results/{result_id}')
            before = store.get(result_id)
            require(status == 200 and before is not None and payload == before.payload,
                    'admission cap changed stored result')
            status, headers, body = request(base, f'/api/results/{result_id}', method='DELETE',
                headers={'X-Deletion-Token': owner})
            require(status == 204 and not body and headers['Cache-Control'] == 'no-store'
                    and store.get(result_id) is None and not gate._targets,
                    'map saturation prevented original HMAC owner deletion')
            if not blocked:
                status, headers, _ = submit('https://gallery.example/')
                require(status == 429 and headers['Retry-After'] == '10',
                        'owner deletion bypassed origin capacity/cooling')
                now[0] += 10
            status, _, new_job = submit('https://gallery.example/')
            require(status == 202 and wait_for_publication(base, new_job['jobId'])['state'] == 'ready',
                    'expiry/release did not restore actual API admission')
        finally:
            executor.release.set()
            if host.is_alive():
                server.shutdown()
            server.server_close()
            service.shutdown()
            host.join(timeout=2)
            require(not host.is_alive(), 'owned server did not stop')
    print('API admission capacity: 429/no-store without execution, reuse at saturation, '
          'active TTL survival/late publication, real HMAC owner deletion and cooling recovery pass. '
          'Controlled capture, not renderer/public-egress/distributed proof.')


if __name__ == '__main__':
    main()
