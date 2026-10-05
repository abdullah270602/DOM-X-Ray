"""Trusted baked fixture modes, not a visitor-selectable scanner entrypoint."""

import json
from dataclasses import replace
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), '/opt/runtime/python']

from scanner.container_capture_entry import emit_record, read_request, runtime
from scanner.egress_capture_worker import capture_granted_page
from scanner.worker_supervisor import MAX_WORKER_RESULT_BYTES
from scripts.verify_browser_egress_proxy import FixtureOrigin


def main():
    mode = sys.argv[1]
    grant, nonce = read_request()
    with tempfile.TemporaryDirectory(prefix='dxr-stdio-fixture-', dir='/tmp') as temporary:
        os.environ.clear()
        os.environ.update(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8',
                          HOME=temporary, TMPDIR=temporary)
        if mode in ('capture-broker', 'capture-broker-hang'):
            from fixtures.worker.broker_capture_fixture import capture_through_broker
            def broker_after_capture(_probe, _home, browser):
                if mode == 'capture-broker-hang':
                    witness = browser.new_context()
                    page = witness.new_page()
                    page.set_content('<div>Offline RPC timeout witness</div>')
                    if page.evaluate('1 + 1') != 2:
                        raise AssertionError('offline broker witness failure')
                    time.sleep(60)
            emit_record(capture_through_broker(grant, runtime(), after_capture=broker_after_capture), nonce)
            return
        if mode in ('capture', 'capture-hang', 'capture-wrong-pin'):
            requests, contacts = [], []
            def connector(destination, **_kwargs):
                contacts.append(destination)
                return FixtureOrigin(destination, requests)
            def after_capture(_probe, _home, browser):
                if mode == 'capture-hang':
                    context = browser.new_context()
                    page = context.new_page()
                    page.set_content('<div>Offline timeout witness</div>')
                    if page.evaluate('1 + 1') != 2:
                        raise AssertionError('offline renderer failure')
                    time.sleep(60)
            configured = runtime()
            if mode == 'capture-wrong-pin':
                configured = replace(configured, expected_chromium_version='0.0.0.0')
            try:
                record = capture_granted_page(grant, configured,
                    resolver=lambda _h, _p: ['1.0.0.1'],
                    connector=connector,
                    after_capture=after_capture)
            except ValueError as error:
                if (mode == 'capture-wrong-pin' and str(error) == 'capture-worker-browser-version'
                        and not requests and not contacts):
                    raise SystemExit(7) from None
                raise
            emit_record(record, nonce)
        elif mode == 'crash':
            raise SystemExit(7)
        elif mode == 'oversize':
            sys.stdout.buffer.write(b'x' * (MAX_WORKER_RESULT_BYTES + 1))
            sys.stdout.buffer.flush()
            time.sleep(60)
        elif mode == 'duplicate-key':
            sys.stdout.buffer.write(json.dumps({'supervisorNonce': nonce, 'result': {'record': {}}}).encode()[:-1]
                                    + b',"result":{"record":{}}}')
            sys.stdout.buffer.flush()
        elif mode in ('valid', 'wrong-nonce', 'trailing', 'stderr-flood'):
            record = json.loads((ROOT / 'fixtures/scan/clean.json').read_text())
            if mode == 'stderr-flood':
                sys.stderr.buffer.write(b'x' * 4_000_000)
                sys.stderr.buffer.flush()
            emit_record(record, '0' * 32 if mode == 'wrong-nonce' else nonce)
            if mode == 'trailing':
                sys.stdout.buffer.write(b'{}')
                sys.stdout.buffer.flush()
        else:
            raise ValueError('unknown-trusted-fixture-mode')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit(2) from None
