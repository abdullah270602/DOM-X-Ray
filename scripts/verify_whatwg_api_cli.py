"""Actual isolated Windows CLI process over loopback; seeded-only proof."""

from pathlib import Path
import re
import sys
import tempfile
from threading import Event, Thread
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.api_contract import API_VERSION, validate_viewer_bundle
from scanner.local_scan_api import main as api_main
from scripts.verify_local_scan_api import json_request, require
from scripts.verify_native_recovery_poller import host_interpreter_flags, spawn_job, stop_job
from scripts.verify_whatwg_api_admission import fixture_parser


def main():
    require(sys.platform == 'win32', 'fixture requires Windows Jobs')
    parser = fixture_parser()
    flags = host_interpreter_flags(sys.flags.optimize)
    prefix = [*flags, Path(__file__).resolve(), '--serve-child', str(sys.flags.optimize)]
    pins = ['--url-parser-node', parser.node, '--url-parser-node-sha256', parser.pins[0],
            '--url-parser-module-sha256', parser.pins[1], '--url-parser-worker-sha256', parser.pins[2]]
    with tempfile.TemporaryDirectory(prefix='dxr-cli-parser-') as temporary:
        data = Path(temporary) / 'valid'
        process, job = spawn_job([*prefix, '--host', '127.0.0.1', '--port', '0', '--data-dir', data, *pins])
        ready, lines = Event(), []
        def read():
            line = process.stdout.readline(513)
            if len(line) <= 512:
                lines.append(line)
            ready.set()
        reader = Thread(target=read, daemon=True)
        reader.start()
        try:
            require(ready.wait(10) and process.poll() is None and len(lines) == 1, 'CLI did not start')
            matched = re.fullmatch(rb'DOM X-Ray local scan API listening on http://127\.0\.0\.1:([0-9]{1,5}) '
                rb'\(seeded fixtures only; arbitrary public scanning disabled\)\r?\n', lines[0])
            require(matched is not None and 0 < int(matched[1]) <= 65535, 'CLI startup frame invalid')
            base = 'http://127.0.0.1:' + matched[1].decode('ascii')
            status, _, health = json_request(base, '/api/health')
            require(status == 200 and health['arbitraryPublicScanning'] is False, 'CLI health overstated mode')
            def submit(url):
                return json_request(base, '/api/scans', method='POST',
                    value={'apiVersion': API_VERSION, 'url': url},
                    headers={'X-Deletion-Token-Digest': 'sha256=' + 'a' * 64})
            status, _, rejected = submit('https://example.com/?')
            require(status == 403 and rejected['error']['code'] == 'invalid-target', 'CLI parser not active')
            status, _, disabled = submit('https://example.com/')
            require(status == 503 and disabled['error']['code'] == 'scanner-disabled', 'CLI enabled public scanning')
            status, _, submitted = submit('https://gallery.example:443/path/../')
            require(status == 202, 'CLI canonical seeded URL not queued')
            deadline = time.monotonic() + 30
            while True:
                status, _, terminal = json_request(base, '/api/scans/' + submitted['jobId'])
                require(status == 200 and process.poll() is None, 'CLI job/server disappeared')
                if terminal['state'] not in ('queued', 'running'):
                    break
                require(time.monotonic() < deadline, 'CLI publication observation timed out')
                time.sleep(0.05)
            require(terminal['state'] == 'ready', 'CLI seeded publication failed')
            status, _, bundle = json_request(base, terminal['result']['bundleUrl'])
            require(status == 200 and bundle['record']['requestedUrl'] == 'https://gallery.example/',
                    'CLI publication identity drifted')
            validate_viewer_bundle(bundle)
        finally:
            stop_job(process, job)
            reader.join(timeout=2)
            require(not reader.is_alive(), 'CLI startup reader survived owned Job stop')
            process.stdout.close()
        invalid_data = Path(temporary) / 'invalid'
        wrong_pins = pins.copy()
        wrong_pins[3] = '0' * 64
        rejected, rejected_job = spawn_job([*prefix, '--host', '127.0.0.1', '--port', '0',
            '--data-dir', invalid_data, *wrong_pins])
        try:
            require(rejected.wait(timeout=10) == 2 and rejected.stdout.read(513) == b''
                    and not invalid_data.exists(), 'invalid CLI pin started hosting/storage')
        finally:
            stop_job(rejected, rejected_job)
            rejected.stdout.close()
    print('Actual isolated CLI: pinned admission, canonical seeded publication, disabled public scanning, startup pin failure before data creation, and owned Windows Jobs empty. No public deployment or Linux containment proof.')


if __name__ == '__main__':
    if len(sys.argv) > 2 and sys.argv[1] == '--serve-child':
        require(sys.flags.isolated == 1 and sys.flags.optimize == int(sys.argv[2]), 'CLI child flags differ')
        sys.argv = [sys.argv[0], *sys.argv[3:]]
        api_main()
    else:
        main()
