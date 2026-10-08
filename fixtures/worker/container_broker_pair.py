"""Baked reserved-origin cross-container fixtures; never the public entrypoint."""

import json
import os
from pathlib import Path
import re
import select
import socket
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), '/opt/runtime/python']

from scanner.container_capture_entry import emit_record, runtime
from scanner.destination_policy import DestinationPolicy
from scanner.egress_capture_worker import capture_granted_page
from scanner.origin_broker import OriginBroker, RemoteOriginExchange
from scanner.origin_exchange import OriginExchange, OriginExchangeError
from scanner.scan_transport import decode_public_scan_grant
from scanner.docker_worker_supervisor import _pairs, _invalid_constant
from scripts.verify_browser_egress_proxy import FixtureOrigin

DIRECTORY = Path('/run/dxr-broker')
SOCKET = DIRECTORY / 'origin.sock'


def install_profile():
    """Reserved fixture diagnostics only; prefixed stdout is never an artifact."""
    import scanner.egress_capture_worker as capture
    import scanner.browser_probe as probe
    import scanner.namespace_bridge as bridge
    from playwright.sync_api import BrowserType, Browser, Page
    started = time.monotonic()
    def wrap(owner, name, label):
        original = getattr(owner, name)
        def measured(*args, **kwargs):
            before = time.monotonic()
            print(f'profile {label}-begin 0', flush=True)
            try:
                return original(*args, **kwargs)
            except Exception:
                print(f'profile {label}-error 1', flush=True)
                raise
            finally:
                print(f'profile {label}-end {int((time.monotonic() - before) * 1000)}', flush=True)
        setattr(owner, name, measured)
    wrap(capture.ScanCertificateIssuer, '__init__', 'issuer')
    wrap(capture.ScanCertificateIssuer, '__exit__', 'issuer-cleanup')
    wrap(capture.LinuxBrowserTrust, '__init__', 'trust')
    wrap(capture.LinuxBrowserTrust, '__exit__', 'trust-cleanup')
    wrap(bridge.NamespaceBridge, '__init__', 'bridge')
    wrap(bridge.NamespaceBridge, '__exit__', 'bridge-cleanup')
    wrap(bridge.NamespaceBridge, 'shutdown', 'bridge-listener-stop')
    wrap(bridge._BoundedHandlers, 'close_handlers', 'bridge-handlers-stop')
    wrap(BrowserType, 'launch', 'browser')
    wrap(Browser, 'close', 'browser-cleanup')
    wrap(Page, 'goto', 'navigation')
    wrap(probe, 'probe_page', 'probe')
    print(f'profile installed {int((time.monotonic() - started) * 1000)}', flush=True)


def require(value):
    if not value:
        raise ValueError('container-broker-fixture')


def request():
    raw = sys.stdin.buffer.readline(16385)
    require(raw.endswith(b'\n') and len(raw) <= 16384)
    payload = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
    require(isinstance(payload, dict) and set(payload) == {'grant', 'nonce', 'capability'})
    require(isinstance(payload['nonce'], str) and re.fullmatch('[0-9a-f]{32}', payload['nonce']))
    require(isinstance(payload['capability'], str) and re.fullmatch('[0-9a-f]{64}', payload['capability']))
    grant = decode_public_scan_grant(payload['grant'])
    require(grant.destination.hostname.endswith('.test'))
    return grant, payload['nonce'], payload['capability']


def denied(callback):
    try:
        callback()
    except OSError:
        return
    raise ValueError('container-broker-access-not-denied')


def main():
    mode = sys.argv[1]
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    require(int(status['CapEff'].strip(), 16) == (1 if mode == 'initialize' else 0)
            and status['NoNewPrivs'].strip() == '1' and status['Seccomp'].strip() == '2')
    if mode == 'initialize':
        require(os.getuid() == 0 and not list(DIRECTORY.iterdir()))
        DIRECTORY.chmod(0o710)
        os.chown(DIRECTORY, 10002, 10001)
        return
    grant, nonce, capability = request()
    if mode in ('broker', 'broker-wrong-uid'):
        require(os.getuid() == 10002 and os.getgid() == 10001)
        private = DIRECTORY / 'broker-private'
        descriptor = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        contacts, dns = [], []
        exchange = OriginExchange(DestinationPolicy(lambda h, p: dns.append((h, p)) or ['1.0.0.1']),
            user_agent='DOM-X-Ray-Container-Broker-Fixture/0.1', initial_grant=grant,
            connector=lambda destination, **_kwargs: contacts.append(destination) or FixtureOrigin(destination, []))
        with OriginBroker(SOCKET, grant=grant, exchange=exchange, capability=capability,
                          worker_uid=10003 if mode == 'broker-wrong-uid' else 10001, socket_gid=10001):
            print('ready', flush=True)
            ready, _, _ = select.select([sys.stdin.buffer], [], [], 15)
            if ready:
                require(sys.stdin.buffer.read(1) == b'')
        private.unlink()
        print(json.dumps({'uid': os.getuid(), 'contacts': len(contacts), 'lookups': len(dns),
            'initialPinned': bool(contacts) and contacts[0] == grant.destination,
            'laterPinned': all(value.addresses == ('1.0.0.1',) for value in contacts[1:]),
            'socketRemoved': not SOCKET.exists(), 'empty': not list(DIRECTORY.iterdir())}), flush=True)
        return
    require(os.getuid() == 10001 and os.getgid() == (10003 if mode == 'worker-wrong-gid' else 10001))
    require(sys.stdin.buffer.read(1) == b'')
    if mode == 'worker-wrong-gid':
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            denied(lambda: connection.connect(str(SOCKET)))
        print('denied', flush=True)
        return
    if mode != 'worker-no-volume':
        denied(lambda: list(DIRECTORY.iterdir()))
        denied(lambda: (DIRECTORY / 'broker-private').read_bytes())
        denied(lambda: SOCKET.chmod(0o666))
        denied(lambda: SOCKET.unlink())
        denied(lambda: (DIRECTORY / 'forged').write_bytes(b'forged'))
        denied(lambda: os.chown(SOCKET, 10001, 10001))
    client = RemoteOriginExchange(SOCKET, grant=grant,
        capability='0' * 64 if mode == 'worker-wrong-capability' else capability,
        broker_uid=10002, socket_gid=10001)
    if mode in ('worker-wrong-capability', 'worker-wrong-uid', 'worker-no-volume'):
        try:
            client.validate_initial_target(grant.target_url)
        except OriginExchangeError:
            print('denied', flush=True)
            return
        raise ValueError('container-broker-auth-not-denied')
    require(mode in ('worker', 'worker-hang', 'worker-profile'))
    if mode == 'worker-profile':
        install_profile()
    with tempfile.TemporaryDirectory(prefix='dxr-container-pair-', dir='/tmp') as temporary:
        os.environ.clear()
        os.environ.update(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8', HOME=temporary, TMPDIR=temporary)
        def after_capture(_probe, _home, browser):
            if mode == 'worker-hang':
                page = browser.new_context().new_page()
                page.set_content('<div>Offline cross-container timeout witness</div>')
                require(page.evaluate('1 + 1') == 2)
                print('renderer-live', flush=True)
                time.sleep(60)
        record = capture_granted_page(grant, runtime(), origin_exchange=client, after_capture=after_capture)
        emit_record(record, nonce)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit(2) from None
