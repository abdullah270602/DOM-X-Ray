"""Real pinned parser at local API admission; no public DNS/origin contact."""

import hashlib
from pathlib import Path
import shutil
import sys
from threading import Event, Thread
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.api_contract import API_VERSION
from scanner.local_scan_api import LocalScanJobService, ScanExecutionError, build_server
from scanner.whatwg_url import WhatwgUrlParser
from scripts.verify_local_scan_api import json_request, require, wait_for_terminal


class Executor:
    def __init__(self):
        self.checked, self.executed = [], []
        self.enabled = False
        self.started, self.release = Event(), Event()

    def supports(self, target):
        self.checked.append(target)
        return self.enabled

    def execute(self, target, progress):
        self.executed.append(target)
        self.started.set()
        require(self.release.wait(5), 'fixture release timed out')
        raise ScanExecutionError('capture-failed')


def fixture_parser():
    # Test-only pins derived from selected files, never deployment defaults.
    node = Path(shutil.which('node')).resolve(strict=True)
    return WhatwgUrlParser(node, **{key: hashlib.sha256(path.read_bytes()).hexdigest()
        for key, path in [('node_sha256', node), ('module_sha256', ROOT / 'shared/public_url.mjs'),
                          ('worker_sha256', ROOT / 'scanner/public_url_worker.mjs')]})


def main():
    parser = fixture_parser()
    executor = Executor()
    service = LocalScanJobService(executor, target_parser=parser, max_workers=1)
    server = build_server('127.0.0.1', 0, service, static_root=None)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = 'http://127.0.0.1:' + str(server.server_port)
    digest = 'a' * 64
    try:
        def submit(url):
            return json_request(base, '/api/scans', method='POST',
                value={'apiVersion': API_VERSION, 'url': url},
                headers={'X-Deletion-Token-Digest': 'sha256=' + digest})
        status, headers, job = submit('https://bücher.example:443/a/../😀')
        canonical = 'https://xn--bcher-kva.example/%F0%9F%98%80'
        require(status == 503 and job['error']['code'] == 'scanner-disabled'
                and executor.checked == [canonical] and not executor.executed,
                'unsupported canonical URL enabled scanner or lost identity')
        require(headers['Cache-Control'] == 'no-store', 'admission rejection is cacheable')
        for bad in ('https://user:private-canary@example.com/', 'https://example.com/?',
                    'https://example.com/#', 'http://0127.0.0.1/', 'https://example.com:8443/'):
            before = len(executor.checked)
            status, _, job = submit(bad)
            require(status == 403 and job['error']['code'] == 'invalid-target'
                    and len(executor.checked) == before and not executor.executed,
                    'bad URL reached executor or wrong rejection')
        with patch.object(parser, '_guard', side_effect=OSError('private-parser-canary')):
            before = len(executor.checked)
            status, _, job = submit('https://clean.example/')
            require(status == 503 and job['error']['code'] == 'internal-error'
                    and job['state'] == 'failed'
                    and 'private-parser-canary' not in str(job)
                    and len(executor.checked) == before, 'parser failure reached executor or leaked details')
        executor.enabled = True
        status, _, first = submit('https://clean.example:443/a/../')
        require(status == 202 and executor.started.wait(2)
                and executor.executed == ['https://clean.example/'], 'queue lost canonical target')
        status, _, duplicate = submit('https://clean.example/')
        require(status == 429 and duplicate['error']['code'] == 'rate-limited'
                and len(executor.executed) == 1, 'canonical duplicate bypassed admission')
        require(service._requested_target_matches(canonical, canonical), 'canonical result identity rejected')
        require(not service._requested_target_matches('https://bücher.example/😀', canonical),
                'noncanonical result identity admitted')
        require(not service._requested_target_matches('https://other.example/', canonical),
                'wrong result target admitted')
        executor.release.set()
        require(wait_for_terminal(service, first['jobId'])['state'] == 'failed', 'fake executor failure drifted')
    finally:
        executor.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        service.shutdown()
    try:
        LocalScanJobService(target_parser=object())
    except ValueError:
        pass
    else:
        raise AssertionError('unconfigured parser accepted')
    print('Real loopback API: pinned canonical admission, duplicate key, fixed failures and result identity checks passed. No public scanner or publication proof.')


if __name__ == '__main__':
    main()
