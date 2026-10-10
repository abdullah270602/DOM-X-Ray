"""Bounded terminal metadata, active preservation and real stored-result survival."""

import hashlib
from pathlib import Path
import sys
from threading import Event, Thread

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.local_scan_api import LocalScanJobService, ScanExecutionError, build_server
from scripts.verify_local_scan_api import request, require, wait_for_terminal
from scripts.verify_whatwg_api_publication import wait_for_publication


class Blocking:
    def __init__(self):
        self.started, self.release = Event(), Event()
    def supports(self, target):
        return target in ('https://clean.example/', 'https://gallery.example/')
    def execute(self, target, progress):
        progress('capturing')
        self.started.set()
        require(self.release.wait(5), 'history fixture release timed out')
        raise ScanExecutionError('capture-failed')


def main():
    block = Blocking()
    service = LocalScanJobService(block, max_workers=1, max_active_jobs=2, terminal_job_history_limit=3)
    digest = 'a' * 64
    try:
        first, status, _ = service.submit('https://clean.example/', digest)
        require(status == 202 and block.started.wait(2), 'first job not running')
        second, status, _ = service.submit('https://gallery.example/', digest)
        require(status == 202, 'second job not queued')
        oldest = None
        for _ in range(64):
            rejected = service.reject_submission()
            oldest = oldest or rejected['jobId']
            require(len(service._jobs) <= 5 and len(service._terminal_jobs) <= 3
                    and service.get_job(first['jobId'])['state'] == 'running'
                    and service.get_job(second['jobId'])['state'] == 'queued',
                    'history cap evicted active work or exceeded bound')
        require(service.get_job(oldest) is None and service.get_job(rejected['jobId']) is not None,
                'oldest terminal history not evicted')
        block.release.set()
        require(wait_for_terminal(service, first['jobId'])['state'] == 'failed'
                and wait_for_terminal(service, second['jobId'])['state'] == 'failed',
                'old active jobs did not become recently retained terminal history')
        for _ in range(5):
            service.reject_submission()
        require(service.get_job(first['jobId']) is None, 'completed history not evicted')
        service._set_progress(first['jobId'], 'capturing')
        service._fail(first['jobId'], 'internal-error')
        require(len(service._jobs) == len(service._terminal_jobs) == 3, 'late callback recreated evicted job')
    finally:
        block.release.set()
        service.shutdown()

    # Real seeded result storage is a separate authority from transient jobs.
    service = LocalScanJobService(terminal_job_history_limit=1)
    server = build_server('127.0.0.1', 0, service, static_root=None)
    host = Thread(target=server.serve_forever, daemon=True)
    host.start()
    token = 'dxrd_' + 'c' * 64
    owner = hashlib.sha256(token.encode()).hexdigest()
    try:
        job, status, _ = service.submit('https://gallery.example/', owner)
        require(status == 202, 'stored-result proof not queued')
        ready = wait_for_publication(service, job['jobId'])
        require(ready['state'] == 'ready', 'real stored result not published')
        result_id = ready['result']['resultId']
        before_bundle, before_poster = service.get_bundle(result_id), service.get_artifact(result_id)
        require(before_bundle is not None and before_poster is not None, 'stored artifacts missing')
        for _ in range(5):
            service.reject_submission()
        status, headers, body = request('http://127.0.0.1:' + str(server.server_port),
                                        '/api/scans/' + job['jobId'])
        require(status == 404 and headers['Cache-Control'] == 'no-store'
                and job['jobId'].encode() not in body, 'evicted job not a content-free HTTP miss')
        require(service.get_bundle(result_id) == before_bundle and service.get_artifact(result_id) == before_poster,
                'job eviction changed stored bundle or artifact')
        reused, status, _ = service.submit('https://gallery.example/', 'b' * 64)
        require(status == 200 and reused['result']['resultId'] == result_id and len(service._jobs) == 1,
                'result reuse lost independent authority or history bound')
        require(service.delete_result(result_id, token)[0] == 'deleted' and service.get_bundle(result_id) is None,
                'original owner deletion authority did not survive job eviction/reuse')
    finally:
        server.shutdown()
        server.server_close()
        host.join(timeout=2)
        service.shutdown()
    for invalid in (0, -1, True, 1.5, '3', None):
        try:
            LocalScanJobService(terminal_job_history_limit=invalid)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid history limit accepted')
    print('Terminal count cap, queued/running preservation, completion order, late callbacks, HTTP eviction miss, byte-identical stored result/artifact, reuse and original-owner deletion passed. No whole-memory or distributed-abuse bound.')


if __name__ == '__main__':
    main()
