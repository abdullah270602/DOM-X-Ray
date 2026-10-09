"""Real pinned Node parser through trusted policy/transport/origin seams.

Resolver and HTTP sockets are deterministic, with no public origin contact.
Transport admission uses the existing actual supervised fixture subprocess.
"""

import hashlib
from pathlib import Path
import shutil
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.destination_policy import DestinationPolicyError
from scanner.browser_egress_proxy import _Handler
from scanner.egress_ledger import EgressLedger
from scanner.origin_exchange import OriginExchange, OriginExchangeError
from scanner.scan_transport import check_public_scan_grant, run_public_scan_transport
from scanner.whatwg_url import WhatwgDestinationPolicy, WhatwgUrlParser
from scripts.verify_origin_exchange import Socket, response
from scripts.verify_scan_transport import LaunchLedger, validators


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
    raw = 'https://bücher.example:443/old/../😀'
    canonical = 'https://xn--bcher-kva.example/%F0%9F%98%80'
    schema, semantics = validators()
    launch = LaunchLedger('rewrite-requested-url')
    result = run_public_scan_transport(raw, policy=policy, launch_worker=launch,
        schema_validator=schema, semantic_validator=semantics)
    require(result.admitted and result.record['requestedUrl'] == canonical, 'canonical transport record not admitted')
    require(len(launch.grants) == 1 and launch.grants[0].target_url == canonical,
            'worker did not receive canonical target')
    grant = launch.grants[0]
    check_public_scan_grant(grant)
    require(dns == [('xn--bcher-kva.example', 443)], 'initial transport DNS changed')
    print('Actual supervised fixture admission: canonical target, schema/semantics and launch grant agree.')

    sockets = [Socket(response()), Socket(response()), Socket(response())]
    connected = []
    def connect(destination, *, timeout_seconds):
        require(timeout_seconds > 0, 'expired connector contact')
        connected.append(destination)
        return sockets[len(connected) - 1]
    exchange = OriginExchange(policy, user_agent='DOM-X-Ray-Parser-Proof/0.1',
        connector=connect, initial_grant=grant)
    before = len(dns)
    require(exchange.validate_initial_target(raw) == grant.destination, 'canonical bind lost grant')
    require(exchange.request_purpose(raw, raw) == 'initial', 'canonical request purpose changed')
    tunnel = exchange.validate_browser_tunnel('https://bücher.example/')
    require((tunnel.scheme, tunnel.hostname, tunnel.port, tunnel.addresses) ==
            (grant.destination.scheme, grant.destination.hostname, grant.destination.port, grant.destination.addresses)
            and tunnel.purpose == 'subresource', 'Unicode tunnel did not bind pending authority')
    require(len(dns) == before and not exchange.initial_grant_consumed, 'setup consumed/resolved initial grant')
    exchange.fetch(raw, purpose='initial')
    require(exchange.initial_grant_consumed and len(dns) == before, 'first GET did not consume exact pin once')
    require(sockets[0].request.startswith(b'GET /%F0%9F%98%80 HTTP/1.1\r\nHost: xn--bcher-kva.example\r\n'),
            'canonical Host/path not serialized')
    exchange.fetch(raw, purpose='initial')
    require(len(dns) == before + 1, 'repeat initial request reused DNS pin')
    exchange.fetch('https://bücher.example/a/../asset?q=1#local', purpose='subresource')
    require(sockets[2].request.startswith(b'GET /asset?q=1 HTTP/1.1\r\n'), 'query/path/fragment serialization drift')
    require(all(s.closed for s in sockets), 'origin socket leaked')
    print('Bind/tunnel purpose and one-shot pin: canonical wire path/Host, repeat DNS and query serialization verified.')

    for bad in ('https://example.com/?', 'https://user:secret-canary@example.com/', 'http://１２７.０.０.１/'):
        before = len(dns), len(connected), len(launch.grants)
        try:
            run_public_scan_transport(bad, policy=policy, launch_worker=launch,
                schema_validator=schema, semantic_validator=semantics)
        except DestinationPolicyError:
            pass
        else:
            raise AssertionError('bad target reached worker')
        try:
            OriginExchange(policy, user_agent='DOM-X-Ray-Parser-Proof/0.1', connector=connect).fetch(bad, purpose='initial')
        except OriginExchangeError as error:
            require(str(error) == 'destination-policy', 'parser rejection leaked provider detail')
        else:
            raise AssertionError('bad target reached connector')
        require(before == (len(dns), len(connected), len(launch.grants)), 'bad target reached side effects')
    with patch.object(parser, '_guard', side_effect=OSError('private-configuration-canary')):
        before = len(dns), len(connected), len(launch.grants)
        try:
            pending = OriginExchange(policy, user_agent='DOM-X-Ray-Parser-Proof/0.1',
                connector=connect, initial_grant=grant)
            pending.fetch(canonical, purpose='initial')
        except OriginExchangeError as error:
            require(str(error) == 'destination-policy', 'parser fault did not become fixed exchange failure')
        else:
            raise AssertionError('broken parser borrowed already bound pin')
        require(before == (len(dns), len(connected), len(launch.grants)), 'broken parser reached side effects')
        require(not pending.initial_grant_consumed, 'parser fault consumed pending grant')
    print('Invalid target and parser fault: no DNS/connector/worker launch, including bound initial grant.')

    for location, accepted in ((b'//b\xfccher.example/new/../target', True),
                               (b'http://127.0.0.1/', False)):
        socket = Socket(response(headers=b'Location: ' + location + b'\r\n', status=b'302 Found'))
        redirected = OriginExchange(policy, user_agent='DOM-X-Ray-Parser-Proof/0.1',
            connector=lambda _grant, **_options: socket)
        before = len(dns)
        try:
            redirected.fetch('https://example.com/base', purpose='initial')
        except OriginExchangeError as error:
            require(not accepted and str(error) == 'destination-policy', 'redirect preflight failed unexpectedly')
        else:
            require(accepted and dns[-1] == ('xn--bcher-kva.example', 443), 'Unicode redirect was not revalidated')
        require(len(dns) == before + (2 if accepted else 1) and socket.closed,
                'redirect contacted forbidden DNS or leaked origin socket')
    print('Redirect preflight uses shared policy: Unicode host accepted, private literal denied before destination DNS.')

    # Real parsing can exceed a deliberately tiny request budget. It must not
    # receive a connector grant after that budget expires; this is no hard-kill proof.
    before = len(dns), len(connected)
    actual_parse = parser.parse
    parsed = []
    def delayed_parse(*args, **kwargs):
        value = actual_parse(*args, **kwargs)
        parsed.append(True)
        time.sleep(0.02)
        return value
    with patch.object(parser, 'parse', side_effect=delayed_parse):
        try:
            exchange.fetch(canonical, purpose='initial', timeout_seconds=0.01)
        except OriginExchangeError as error:
            require(str(error) == 'timeout', 'expired parser budget did not time out')
        else:
            raise AssertionError('expired request reached connector')
    require(parsed == [True], 'expiry test did not complete actual parser work')
    require(before == (len(dns), len(connected)), 'expired request had origin side effects')
    clock = [0.0]
    events = []
    class Browser:
        def __init__(self):
            self.payload = b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n'
            self.reply = b''
            self.closed = False
        def recv(self, limit):
            value, self.payload = self.payload[:limit], self.payload[limit:]
            return value
        def settimeout(self, _value):
            pass
        def sendall(self, reply):
            self.reply += reply
        def close(self):
            self.closed = True
    def late_purpose(url, initial_url):
        value = exchange.request_purpose(url, initial_url)
        clock[0] = 16.0
        return value
    def forbidden_fetch(*_args, **_kwargs):
        raise AssertionError('proxy refreshed expired budget after purpose parsing')
    handler = object.__new__(_Handler)
    handler.request = Browser()
    handler.server = SimpleNamespace(initial_url='http://example.com/', ledger=EgressLedger(),
        exchange=SimpleNamespace(request_purpose=late_purpose, fetch=forbidden_fetch),
        forget_connection=lambda _connection: None, event=lambda **event: events.append(event))
    with patch('scanner.browser_egress_proxy.time', SimpleNamespace(monotonic=lambda: clock[0])):
        handler.handle()
    require(handler.request.closed and handler.request.reply.startswith(b'HTTP/1.1 403')
            and events[-1]['reason'] == 'timeout', 'proxy purpose work extended outer budget')
    print('Expired exchange budget cannot contact DNS/connector. Production image/API/broker deployment remains open.')


if __name__ == '__main__':
    main()
