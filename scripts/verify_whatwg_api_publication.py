"""Pinned API parser through seeded supervised execution and real publication.

No public DNS/origin contact or deployed public scanner is established.
"""

import sys
import time
from pathlib import Path
from threading import Event, Thread
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.api_contract import API_VERSION, validate_viewer_bundle
from scanner.local_scan_api import FixtureScanExecutor, LocalScanJobService, build_server
from scanner.result_store import MemoryResultStore
from scripts.verify_local_scan_api import json_request, require, verify_artifact_route, wait_for_terminal
from scripts.verify_whatwg_api_admission import fixture_parser


class RecordingFixtureExecutor(FixtureScanExecutor):
    execution = None

    def execute(self, target, progress):
        self.execution = super().execute(target, progress)
        return self.execution


class ReplayExecutor:
    """Negative-control seam replays one real schema-valid fixture execution."""
    def __init__(self, execution):
        self.execution = execution
        self.started, self.release = Event(), Event()

    def supports(self, target):
        return target in ('https://clean.example/', 'https://gallery.example/')

    def execute(self, target, progress):
        self.started.set()
        require(self.release.wait(5), 'replay release timed out')
        return self.execution


def wait_for_publication(service, job_id):
    # Observation budget only; no executor or renderer deadline is modified.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        job = service.get_job(job_id)
        require(job is not None, 'publication job disappeared')
        if job['state'] not in ('queued', 'running'):
            return job
        time.sleep(0.02)
    raise AssertionError('publication observation remained nonterminal')


def main():
    parser = fixture_parser()
    executor = RecordingFixtureExecutor()
    store = MemoryResultStore()
    service = LocalScanJobService(executor, target_parser=parser, result_backend=store)
    server = build_server('127.0.0.1', 0, service, static_root=None)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = 'http://127.0.0.1:' + str(server.server_port)
    digest = 'a' * 64
    try:
        status, _, submitted = json_request(base, '/api/scans', method='POST',
            value={'apiVersion': API_VERSION, 'url': 'https://gallery.example:443/path/../'},
            headers={'X-Deletion-Token-Digest': 'sha256=' + digest})
        require(status == 202, 'canonical supported request not queued')
        terminal = wait_for_publication(service, submitted['jobId'])
        require(terminal['state'] == 'ready', 'configured parser publication failed')
        status, headers, bundle = json_request(base, terminal['result']['bundleUrl'])
        require(status == 200 and headers['Cache-Control'] == 'no-store', 'published bundle route failed')
        validate_viewer_bundle(bundle)
        require(bundle['record']['requestedUrl'] == 'https://gallery.example/', 'published canonical identity changed')
        result_id = bundle['result']['resultId']
        verify_artifact_route(base, '/api/results/' + result_id + '/poster.png',
            bundle['result']['exports']['poster'], label='configured-parser poster',
            media_type='image/png', signature=b'\x89PNG\r\n\x1a\n')
        verify_artifact_route(base, '/api/results/' + result_id + '/video.mp4',
            bundle['result']['exports']['video'], label='configured-parser video',
            media_type='video/mp4', signature=b'\x00\x00\x00')
        status, _, reused = json_request(base, '/api/scans', method='POST',
            value={'apiVersion': API_VERSION, 'url': 'https://gallery.example/'},
            headers={'X-Deletion-Token-Digest': 'sha256=' + digest})
        require(status == 200 and reused['result']['resultId'] == result_id, 'canonical result reuse drifted')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        service.shutdown()
    execution = executor.execution
    require(execution is not None, 'real execution not retained for controls')
    validate_viewer_bundle(execution.bundle)
    for target, broken_parser in (('https://clean.example/', False), ('https://gallery.example/', True)):
        replay, backend = ReplayExecutor(execution), MemoryResultStore()
        controlled = LocalScanJobService(replay, target_parser=parser, result_backend=backend)
        try:
            with patch.object(backend, 'publish', wraps=backend.publish) as publish:
                job, status, _ = controlled.submit(target, digest)
                require(status == 202 and replay.started.wait(2), 'negative control not queued')
                if broken_parser:
                    with patch.object(parser, '_guard', side_effect=OSError('private-result-parser-canary')):
                        replay.release.set()
                        failed = wait_for_terminal(controlled, job['jobId'])
                else:
                    replay.release.set()
                    failed = wait_for_terminal(controlled, job['jobId'])
                require(failed['state'] == 'failed' and failed['error']['code'] == 'internal-error'
                        and not publish.called and backend.get(result_id) is None
                        and 'private-result-parser-canary' not in str(failed),
                        'wrong target or parser fault crossed publication boundary')
        finally:
            replay.release.set()
            controlled.shutdown()
    print('Configured pinned parser: real seeded HTTP publication, exact bundle/poster/video routes and canonical reuse passed; valid wrong-target and result-time parser-fault controls published nothing. Public scanner remains disabled.')


if __name__ == '__main__':
    main()
