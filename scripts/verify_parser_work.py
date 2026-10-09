"""Count actual pinned parser invocations at trusted backend phase boundaries."""

import hashlib
from pathlib import Path
import shutil
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.whatwg_url import WhatwgUrlParser, WhatwgDestinationPolicy
from scanner.origin_exchange import OriginExchange
from scanner.scan_transport import PublicScanGrant
from scripts.verify_origin_exchange import Socket, response


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    node = Path(shutil.which('node')).resolve(strict=True)
    parser = WhatwgUrlParser(node, **{name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in (('node_sha256', node), ('module_sha256', ROOT / 'shared/public_url.mjs'),
                           ('worker_sha256', ROOT / 'scanner/public_url_worker.mjs'))})
    dns = []
    policy = WhatwgDestinationPolicy(lambda h, p: dns.append((h, p)) or ['8.8.8.8'], parser=parser)
    target = 'https://xn--bcher-kva.example/target'
    grant = PublicScanGrant(target, policy.validate(target, purpose='initial'))
    sockets = [Socket(response()), Socket(response()), Socket(response()),
               Socket(response(headers=b'Location: ../next\r\n', status=b'302 Found'))]
    connected = []
    def connect(destination, **_options):
        connected.append(destination)
        return sockets[len(connected) - 1]
    exchange = OriginExchange(policy, user_agent='DOM-X-Ray-Parser-Work/0.1',
        connector=connect, initial_grant=grant)
    calls = []
    invoke = parser._invoke
    def counted(*args, **kwargs):
        calls.append(kwargs.get('base') is not None)
        return invoke(*args, **kwargs)
    timings = {}
    with patch.object(parser, '_invoke', side_effect=counted):
        phases = [
            ('initial-purpose', lambda: exchange.request_purpose('https://bücher.example/target', target)),
            ('initial-fetch', lambda: exchange.fetch('https://bücher.example/target', purpose='initial')),
            ('repeat-fetch', lambda: exchange.fetch(target, purpose='initial')),
            ('subresource-fetch', lambda: exchange.fetch('https://bücher.example/asset?q=1', purpose='subresource')),
            ('redirect-fetch', lambda: exchange.fetch('https://bücher.example/dir/page', purpose='subresource')),
        ]
        for name, action in phases:
            before = len(calls)
            started = time.monotonic()
            action()
            timings[name] = {'parserInvocations': len(calls) - before,
                             'elapsedMs': round((time.monotonic() - started) * 1000, 2)}
    require(len(dns) == 5 and len(connected) == 4 and all(s.closed for s in sockets),
            'work reduction changed fresh authorization or cleanup')
    print(timings)
    require([v['parserInvocations'] for v in timings.values()] == [1, 1, 1, 1, 2],
            'backend phase reparsed already canonical input')
    print('Actual per-phase parser work measured; not a public-corpus latency benchmark.')


if __name__ == '__main__':
    main()
