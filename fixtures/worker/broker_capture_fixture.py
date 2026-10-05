"""Real RPC process pair inside one fixture container; same UID, not identity isolation."""

import json
import os
from pathlib import Path
import secrets
import select
import signal
import time

from scanner.destination_policy import DestinationPolicy
from scanner.egress_capture_worker import capture_granted_page
from scanner.origin_broker import OriginBroker, RemoteOriginExchange
from scanner.origin_exchange import OriginExchange
from scripts.verify_browser_egress_proxy import FixtureOrigin


def capture_through_broker(grant, runtime, *, after_capture=None):
    path = Path(os.environ['TMPDIR']) / 'broker.sock'
    capability = secrets.token_hex(32)
    control_read, control_write = os.pipe()
    report_read, report_write = os.pipe()
    pid = os.fork()  # Before capture creates Playwright/proxy/bridge threads.
    if pid == 0:
        os.close(control_write)
        os.close(report_read)
        null = os.open('/dev/null', os.O_RDWR)
        for descriptor in (0, 1, 2):
            os.dup2(null, descriptor)
        if null > 2:
            os.close(null)
        try:
            contacts, requests, dns = [], [], []
            def connector(destination, **_kwargs):
                contacts.append(destination)
                return FixtureOrigin(destination, requests)
            policy = DestinationPolicy(lambda h, p: dns.append((h, p)) or ['1.0.0.1'])
            exchange = OriginExchange(policy, user_agent='DOM-X-Ray-RPC-Capture-Fixture/0.1',
                                      initial_grant=grant, connector=connector)
            with OriginBroker(path, grant=grant, exchange=exchange, capability=capability, worker_uid=os.getuid()):
                os.write(report_write, b'ready\n')
                os.read(control_read, 1)  # Owner closes pipe after capture or whole container is destroyed.
            report = {'pid': os.getpid(), 'uid': os.getuid(), 'contactCount': len(contacts),
                'requestCount': len(requests), 'lookupCount': len(dns),
                'initialPinned': bool(contacts) and contacts[0] == grant.destination,
                'laterPinned': all(value.addresses == ('1.0.0.1',) for value in contacts[1:])}
            os.write(report_write, json.dumps(report).encode())
            os._exit(0)
        except Exception:
            os._exit(2)
    os.close(control_read)
    os.close(report_write)
    try:
        ready, _, _ = select.select([report_read], [], [], 3)
        if not ready or os.read(report_read, 6) != b'ready\n':
            raise RuntimeError('fixture-broker-startup')
        client = RemoteOriginExchange(path, grant=grant, capability=capability, broker_uid=os.getuid())
        record = capture_granted_page(grant, runtime, origin_exchange=client, after_capture=after_capture)
    finally:
        os.close(control_write)
        deadline = time.monotonic() + 2
        while True:
            finished, status = os.waitpid(pid, os.WNOHANG)
            if finished == pid:
                break
            if time.monotonic() >= deadline:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                os.close(report_read)
                raise RuntimeError('fixture-broker-stop')
            time.sleep(0.01)
        raw = os.read(report_read, 4097)
        os.close(report_read)
        if status != 0 or len(raw) > 4096 or path.exists():
            raise RuntimeError('fixture-broker-teardown')
    report = json.loads(raw)
    if (report['pid'] == os.getpid() or report['uid'] != os.getuid()
            or not report['initialPinned'] or not report['laterPinned']
            or report['requestCount'] < 3 or report['lookupCount'] < 1):
        raise RuntimeError('fixture-broker-origin-observations')
    return record
