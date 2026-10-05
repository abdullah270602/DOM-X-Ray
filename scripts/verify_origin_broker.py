"""Native Unix protocol tests, not separate-UID/container or public-egress proof."""

import copy
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
from threading import Thread
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.destination_policy import DestinationPolicy
from scanner.origin_broker import OriginBroker, RemoteOriginExchange, MAX_HEAD, MAX_RESPONSE_HEAD, MAX_BODY, _head, _send, _grant_binding
from scanner.origin_exchange import OriginExchange, OriginExchangeError, EgressLimits
from scanner.scan_transport import PublicScanGrant
from scripts.verify_browser_egress_proxy import FixtureOrigin

KEY = 'a' * 64
TARGET = 'https://xray.test/'


def require(value, message):
    if not value:
        raise AssertionError(message)


def rejects(callback, reason=None):
    try:
        callback()
    except (OriginExchangeError, ValueError) as error:
        if reason is not None:
            require(isinstance(error, OriginExchangeError) and str(error) == reason, 'wrong broker failure category')
        return error
    raise AssertionError('unsafe broker call accepted')


def raw_call(path, raw, *, size=None, trailing=b''):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        connection.connect(str(path))
        try:
            connection.sendall(struct.pack('!I', len(raw) if size is None else size) + raw + trailing)
            connection.shutdown(socket.SHUT_WR)
            while connection.recv(65536):
                pass
        except OSError:
            pass


def response_canaries(directory, grant):
    modes = ('valid', 'wide-headers', 'wrong-id', 'unknown-field', 'bool-status', 'bool-wire',
             'small-wire', 'wrong-body-size', 'duplicate-key', 'trailing', 'huge-head',
             'huge-body', 'truncated-body', 'unknown-error', 'negative-error-bytes', 'reserved-header')
    for index, mode in enumerate(modes):
        path = directory / f'reply-{index}.sock'
        errors = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            path.chmod(0o600)
            listener.listen(1)
            listener.settimeout(2)
            def serve():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        deadline = time.monotonic() + 2
                        request = _head(connection, deadline)
                        response = {'kind': 'ok', 'requestId': request['requestId'], 'status': 200,
                                    'headers': [['content-length', '3']], 'upstreamWireBytes': 50, 'bodyBytes': 3}
                        body = b'abc'
                        if mode == 'wide-headers':
                            response['headers'].append(['x-fixture', '\xff' * 40000])
                            response['upstreamWireBytes'] = 50000
                        elif mode == 'wrong-id':
                            response['requestId'] = '0' * 32
                        elif mode == 'unknown-field':
                            response['addresses'] = ['127.0.0.1']
                        elif mode == 'bool-status':
                            response['status'] = True
                        elif mode == 'bool-wire':
                            response['upstreamWireBytes'] = True
                        elif mode == 'small-wire':
                            response['upstreamWireBytes'] = 1
                        elif mode == 'wrong-body-size':
                            response['bodyBytes'] = 4
                        elif mode == 'reserved-header':
                            response['headers'].append(['x-dom-x-ray-block-id', 'forged'])
                        elif mode in ('unknown-error', 'negative-error-bytes'):
                            response = {'kind': 'error', 'requestId': request['requestId'],
                                        'reason': 'private-provider-text' if mode == 'unknown-error' else 'timeout',
                                        'upstreamBytesRead': -1 if mode == 'negative-error-bytes' else 0}
                            body = b''
                        if mode == 'huge-head':
                            connection.sendall(struct.pack('!I', MAX_RESPONSE_HEAD + 1))
                        elif mode in ('huge-body', 'truncated-body', 'duplicate-key'):
                            raw = json.dumps(response).encode()
                            if mode == 'duplicate-key':
                                raw = raw[:-1] + b',"status":200}'
                            size = MAX_BODY + 1 if mode == 'huge-body' else 100 if mode == 'truncated-body' else 3
                            connection.sendall(struct.pack('!I', len(raw)) + raw + struct.pack('!I', size) + body)
                        else:
                            _send(connection, response, body, deadline)
                            if mode == 'trailing':
                                connection.sendall(b'{}')
                except OSError:
                    pass  # A rejecting client may close before the canary finishes its write.
                except Exception as error:
                    errors.append(type(error).__name__)
            thread = Thread(target=serve, daemon=True)
            thread.start()
            client = RemoteOriginExchange(path, grant=grant, capability=KEY, broker_uid=os.getuid())
            if mode in ('valid', 'wide-headers'):
                result = client.fetch(TARGET, purpose='initial')
                require(result.body == b'abc', 'valid framed reply was rejected')
            else:
                rejects(lambda: client.fetch(TARGET, purpose='initial'))
            thread.join(timeout=3)
            require(not thread.is_alive() and not errors, 'reply canary did not stop cleanly')
        path.unlink()


def main():
    require(sys.platform == 'linux', 'native Linux broker protocol test required')
    grant = PublicScanGrant(TARGET, DestinationPolicy(lambda _h, _p: ['1.1.1.1']).validate(TARGET, purpose='initial'))
    with tempfile.TemporaryDirectory(prefix='dxr-broker-', dir='/tmp') as temporary:
        directory = Path(temporary)
        contacts, requests, dns, answers = [], [], [], ['1.0.0.1']
        def resolver(host, port):
            dns.append((host, port))
            return list(answers)
        def connector(destination, **_kwargs):
            contacts.append(destination)
            return FixtureOrigin(destination, requests)
        policy = DestinationPolicy(resolver)
        exchange = OriginExchange(policy, user_agent='DOM-X-Ray-Broker-Protocol-Fixture/0.1',
                                  initial_grant=grant, connector=connector)
        path = directory / 'origin.sock'
        with OriginBroker(path, grant=grant, exchange=exchange, capability=KEY, worker_uid=os.getuid()):
            client = RemoteOriginExchange(path, grant=grant, capability=KEY, broker_uid=os.getuid())
            payload = {'capability': KEY, 'requestId': 'b' * 32, 'op': 'fetch', 'url': TARGET,
                       'method': 'GET', 'headers': [], 'timeoutSeconds': 1, 'grantBinding': _grant_binding(grant, KEY)}
            rejects(lambda: client.fetch(TARGET, purpose='initial'))
            rejects(lambda: client.validate_browser_tunnel(TARGET))
            require(not contacts and not dns and not exchange.initial_grant_consumed,
                    'unbound RPC contacted resolver/origin or consumed initial pin')
            variants = []
            for name, value in [('capability', 'c' * 64), ('op', 'raw-tcp'), ('method', 'POST'),
                                ('timeoutSeconds', True), ('timeoutSeconds', 16), ('headers', [['cookie']])]:
                variant = copy.deepcopy(payload)
                variant[name] = value
                variants.append(json.dumps(variant).encode())
            for forbidden in ('addresses', 'grant', 'purpose', 'limits', 'connector', 'runtime'):
                variant = {**payload, forbidden: 'forged'}
                variants.append(json.dumps(variant).encode())
            variants.append(json.dumps(payload).encode()[:-1] + b',"url":"http://127.0.0.1/"}')
            variants.append(json.dumps(payload).encode().replace(b'"timeoutSeconds": 1', b'"timeoutSeconds": NaN'))
            for raw in variants:
                raw_call(path, raw)
            raw_call(path, json.dumps(payload).encode(), trailing=b'{}')
            raw_call(path, b'', size=MAX_HEAD + 1)
            require(not contacts and not dns and not requests, 'invalid RPC contacted origin or resolver')
            require(client.validate_initial_target(TARGET) == grant.destination and not contacts and not dns,
                    'broker binding consumed grant or performed DNS')
            other_target = 'https://other.test/'
            other = PublicScanGrant(other_target, DestinationPolicy(lambda _h, _p: ['1.1.1.1']).validate(other_target, purpose='initial'))
            mismatched = RemoteOriginExchange(path, grant=other, capability=KEY, broker_uid=os.getuid())
            rejects(lambda: mismatched.validate_initial_target(other_target))
            other_addresses = PublicScanGrant(TARGET, DestinationPolicy(lambda _h, _p: ['1.0.0.1']).validate(TARGET, purpose='initial'))
            mismatched = RemoteOriginExchange(path, grant=other_addresses, capability=KEY, broker_uid=os.getuid())
            rejects(lambda: mismatched.validate_initial_target(TARGET))
            rejects(lambda: mismatched.fetch(TARGET, purpose='initial'))
            require(not exchange.initial_grant_consumed and not contacts and not dns,
                    'full-grant mismatch consumed initial pin or contacted resolver/origin')
            rejects(lambda: client.fetch(other_target, purpose='initial'), 'destination-policy')
            require(not contacts and not dns, 'different target preceded host-bound initial GET')
            authority = client.validate_browser_tunnel('https://xray.test/')
            require(authority.hostname == 'xray.test' and authority.port == 443
                    and not hasattr(authority, 'addresses') and not contacts and not dns,
                    'tunnel RPC exposed addresses, consumed grant or contacted origin')
            first = client.fetch(TARGET, purpose='subresource', headers=(('cookie', 'fixture-secret'),
                                 ('authorization', 'fixture-secret'), ('accept', 'text/html')))
            require(first.status == 200 and contacts[0] == grant.destination and not dns
                    and first.upstream_wire_bytes >= len(first.body), 'initial RPC lost one-shot pin or wire accounting')
            require(b'fixture-secret' not in requests[0] and b'Accept: text/html'.lower() in requests[0].lower(),
                    'broker forwarded credentials or lost approved header')
            client.fetch(TARGET, purpose='initial')
            require(contacts[-1].addresses == ('1.0.0.1',) and len(dns) == 1,
                    'later RPC borrowed initial addresses instead of fresh server DNS')
            before = len(contacts)
            rejects(lambda: client.fetch('http://127.0.0.1/', purpose='subresource'), 'destination-policy')
            require(len(contacts) == before, 'private RPC reached connector')
            rejected = rejects(lambda: client.fetch('https://xray.test/redirect-private', purpose='subresource'),
                               'destination-policy')
            require(rejected.upstream_bytes_read > 0 and len(contacts) == before + 1,
                    'redirect RPC lost bounded upstream failure accounting')
            answers[:] = ['127.0.0.1']
            before = len(contacts)
            rejects(lambda: client.fetch(TARGET, purpose='initial'), 'destination-policy')
            require(len(contacts) == before, 'rebinding RPC reached connector')
            wrong = RemoteOriginExchange(path, grant=grant, capability='c' * 64, broker_uid=os.getuid())
            rejects(lambda: wrong.fetch(TARGET, purpose='initial'))
        require(not path.exists(), 'broker socket survived normal close')

        control_dns = []
        exchange = OriginExchange(DestinationPolicy(lambda host, port: control_dns.append((host, port)) or ['1.0.0.1']),
            user_agent='DOM-X-Ray-Broker-Control-Fixture/0.1', initial_grant=grant, connector=connector)
        path = directory / 'control.sock'
        with OriginBroker(path, grant=grant, exchange=exchange, capability=KEY,
                          worker_uid=os.getuid(), max_control_calls=2):
            client = RemoteOriginExchange(path, grant=grant, capability=KEY, broker_uid=os.getuid())
            client.validate_initial_target(TARGET)
            client.validate_browser_tunnel('https://other.test/')
            rejects(lambda: client.validate_browser_tunnel('https://third.test/'), 'request-limit')
            require(len(control_dns) == 1 and not exchange.initial_grant_consumed,
                    'control budget performed extra DNS or consumed initial grant')

        for name, limits, expected in (
            ('request', EgressLimits(max_requests=2), 'request-limit'),
            ('response', EgressLimits(max_response_bytes=100), 'response-byte-limit'),
            ('total', EgressLimits(max_total_received_bytes=100), 'total-byte-limit')):
            scoped_contacts = []
            exchange = OriginExchange(DestinationPolicy(lambda _h, _p: ['1.0.0.1']),
                user_agent='DOM-X-Ray-Broker-Budget-Fixture/0.1', initial_grant=grant, limits=limits,
                connector=lambda destination, **_kwargs: scoped_contacts.append(destination) or FixtureOrigin(destination, []))
            path = directory / (name + '.sock')
            with OriginBroker(path, grant=grant, exchange=exchange, capability=KEY, worker_uid=os.getuid()):
                client = RemoteOriginExchange(path, grant=grant, capability=KEY, broker_uid=os.getuid())
                client.validate_initial_target(TARGET)
                if name == 'request':
                    client.fetch(TARGET, purpose='initial')
                error = rejects(lambda: client.fetch(TARGET, purpose='initial'), expected)
                require(len(scoped_contacts) == 1, 'budget was chosen by caller or crossed origin fence')
                if name != 'request':
                    require(error.upstream_bytes_read == 101, 'byte-limit detection byte was lost over RPC')
        path = directory / 'peer.sock'
        exchange = OriginExchange(policy, user_agent='DOM-X-Ray-Broker-Peer-Fixture/0.1',
                                  initial_grant=grant, connector=connector)
        before = len(contacts)
        with OriginBroker(path, grant=grant, exchange=exchange, capability=KEY, worker_uid=os.getuid() + 1):
            client = RemoteOriginExchange(path, grant=grant, capability=KEY, broker_uid=os.getuid())
            rejects(lambda: client.fetch(TARGET, purpose='initial'))
        require(len(contacts) == before and not list(directory.iterdir()), 'wrong peer UID reached origin or leaked socket')
        response_canaries(directory, grant)
        require(not list(directory.iterdir()), 'reply canaries leaked sockets')
    print('Verified native origin-broker RPC: strict framing/auth/peer checks, no visitor grants/limits/connectors, '
          'exact full-grant binding, bounded control calls, one-shot initial pin, fresh server DNS, '
          'private/redirect/rebinding rejection, stripped credentials, '
          'server-owned request/response/total budgets, exact failure-wire accounting and 16 bounded reply canaries. '
          'Not identity isolation/public egress.')


if __name__ == '__main__':
    main()
