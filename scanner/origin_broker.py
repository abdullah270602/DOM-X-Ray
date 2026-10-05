"""Per-scan Unix RPC around OriginExchange, never a raw origin tunnel.

Deployment owns both endpoint and capability. This protocol does not itself
establish separate container identities, a socket mount, or public API adoption.
"""

import hmac
import hashlib
from functools import wraps
import json
import math
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import stat
import struct
import sys
from threading import Condition, Lock, Semaphore, Thread
import time

from scanner.destination_policy import DestinationPolicy, DestinationPolicyError
from scanner.origin_exchange import OriginExchange, OriginExchangeError, OriginResponse, _header
from scanner.scan_transport import check_public_scan_grant, public_scan_target_matches

MAX_HEAD = 65536
MAX_RESPONSE_HEAD = 400000  # JSON escaping of an admitted 64 KiB Latin-1 HTTP head.
MAX_BODY = 20_000_000
REASONS = frozenset({'method', 'invalid-headers', 'invalid-response', 'invalid-request-target',
    'destination-policy', 'request-limit', 'response-byte-limit', 'total-byte-limit', 'timeout', 'upstream-failed'})
_UnixBase = getattr(socketserver, 'ThreadingUnixStreamServer', socketserver.ThreadingTCPServer)


def _require(value):
    if not value:
        raise ValueError('origin-broker-protocol')


def _pairs(values):
    result = {}
    for key, value in values:
        _require(key not in result)
        result[key] = value
    return result


def _constant(_value):
    raise ValueError('origin-broker-protocol')


def _grant_binding(grant, capability):
    """Keyed, exact full-grant identity; never return resolver answers over RPC."""
    check_public_scan_grant(grant)
    destination = grant.destination
    raw = json.dumps([grant.target_url, destination.purpose, destination.scheme,
        destination.hostname, destination.port, destination.addresses],
        separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
    return hmac.new(bytes.fromhex(capability), b'DOM-X-Ray-origin-grant-v1\0' + raw,
                    hashlib.sha256).hexdigest()


def _seconds(value):
    _require(not isinstance(value, bool) and isinstance(value, (int, float))
             and 0 < value <= 15 and math.isfinite(value))
    return float(value)


def _integer(value, ceiling):
    _require(not isinstance(value, bool) and isinstance(value, int) and 0 <= value <= ceiling)
    return value


def _remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError('origin-broker-deadline')
    return value


def _read(connection, size, deadline):
    result = bytearray()
    while len(result) < size:
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(min(65536, size - len(result)))
        _require(bool(chunk))
        result.extend(chunk)
    return bytes(result)


def _head(connection, deadline, ceiling=MAX_HEAD):
    size = struct.unpack('!I', _read(connection, 4, deadline))[0]
    _require(0 < size <= ceiling)
    return json.loads(_read(connection, size, deadline), object_pairs_hook=_pairs, parse_constant=_constant)


def _send(connection, payload, body, deadline):
    raw = json.dumps(payload, separators=(',', ':'), allow_nan=False).encode()
    _require(0 < len(raw) <= MAX_RESPONSE_HEAD and isinstance(body, bytes) and len(body) <= MAX_BODY)
    connection.settimeout(_remaining(deadline))
    connection.sendall(struct.pack('!I', len(raw)) + raw + struct.pack('!I', len(body)))
    for offset in range(0, len(body), 65536):
        connection.settimeout(_remaining(deadline))
        connection.sendall(body[offset:offset + 65536])


def _credentials(connection):
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))


def _response_guard(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except TimeoutError:
            raise OriginExchangeError('timeout') from None
        except (ValueError, TypeError, OSError, RecursionError):
            raise OriginExchangeError('upstream-failed') from None
    return checked


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        accepted = time.monotonic()
        deadline = min(self.server.deadline, accepted + 15)
        request_id = None
        try:
            _require(_credentials(self.request)[1] == self.server.worker_uid)
            payload = _head(self.request, min(deadline, accepted + 2))
            _require(isinstance(payload, dict) and isinstance(payload.get('capability'), str)
                     and hmac.compare_digest(payload['capability'], self.server.capability))
            request_id = payload.get('requestId')
            _require(isinstance(request_id, str) and re.fullmatch(r'[0-9a-f]{32}', request_id))
            fields = {'capability', 'requestId', 'op', 'url', 'method', 'headers', 'timeoutSeconds', 'grantBinding'}
            _require(set(payload) == fields)
            binding = payload['grantBinding']
            _require(isinstance(binding, str) and re.fullmatch(r'[0-9a-f]{64}', binding)
                     and hmac.compare_digest(binding, self.server.grant_binding))
            _require(isinstance(payload['url'], str) and len(payload['url']) <= 8192)
            deadline = min(deadline, accepted + _seconds(payload['timeoutSeconds']))
            self.request.settimeout(_remaining(min(deadline, accepted + 2)))
            _require(not self.request.recv(1))  # Exactly one frame; no body, trailing bytes or pipelining.
            _require(payload['op'] in ('bind', 'tunnel', 'fetch') and isinstance(payload['headers'], list)
                     and len(payload['headers']) <= 100)
            headers = []
            for pair in payload['headers']:
                _require(isinstance(pair, list) and len(pair) == 2)
                headers.append(_header(*pair))
            with self.server._control_lock:
                _require(payload['op'] == 'bind' or self.server._bound)
            if payload['op'] in ('bind', 'tunnel'):
                _require(payload['method'] == ('BIND' if payload['op'] == 'bind' else 'CONNECT') and not headers)
                with self.server._control_lock:
                    if self.server._control_calls >= self.server.max_control_calls:
                        raise OriginExchangeError('request-limit')
                    self.server._control_calls += 1
                authority = (self.server.exchange.validate_initial_target(payload['url']) if payload['op'] == 'bind'
                             else self.server.exchange.validate_browser_tunnel(payload['url']))
                if payload['op'] == 'bind':
                    with self.server._control_lock:
                        self.server._bound = True
                response = {'kind': 'ok', 'requestId': request_id,
                            'authority': {'hostname': authority.hostname, 'port': authority.port}}
                body = b''
            else:
                _require(payload['method'] in ('GET', 'HEAD', 'OPTIONS'))
                if not self.server._fetch_lock.acquire(timeout=_remaining(deadline)):
                    raise OriginExchangeError('timeout')
                try:
                    if (not self.server.exchange.initial_grant_consumed
                            and not public_scan_target_matches(payload['url'], self.server.grant)):
                        raise OriginExchangeError('destination-policy')
                    result = self.server.exchange.fetch(payload['url'], method=payload['method'],
                        purpose=self.server.exchange.request_purpose(payload['url'], self.server.grant.target_url),
                        headers=tuple(headers), timeout_seconds=_remaining(deadline))
                finally:
                    self.server._fetch_lock.release()
                response = {'kind': 'ok', 'requestId': request_id, 'status': result.status,
                            'headers': result.headers, 'upstreamWireBytes': result.upstream_wire_bytes,
                            'bodyBytes': len(result.body)}
                body = result.body
            _send(self.request, response, body, deadline)
        except (OriginExchangeError, DestinationPolicyError, ValueError, TypeError, OSError, RecursionError) as error:
            if request_id is not None:
                reason = str(error) if isinstance(error, OriginExchangeError) else (
                    'destination-policy' if isinstance(error, DestinationPolicyError) else
                    'timeout' if isinstance(error, TimeoutError) else 'upstream-failed')
                if reason not in REASONS:
                    reason = 'upstream-failed'
                count = getattr(error, 'upstream_bytes_read', 0)
                try:
                    _integer(count, MAX_BODY + 1)
                    _send(self.request, {'kind': 'error', 'requestId': request_id, 'reason': reason,
                        'upstreamBytesRead': count}, b'', deadline)
                except (ValueError, OSError):
                    pass


class OriginBroker(_UnixBase):
    """One host-configured grant and budgets; no request can replace either."""

    daemon_threads = True

    def __init__(self, path, *, grant, exchange, capability, worker_uid, lifetime_seconds=15,
                 max_control_calls=1000, socket_gid=None):
        _require(sys.platform == 'linux' and hasattr(socket, 'SO_PEERCRED'))
        check_public_scan_grant(grant)
        _require(type(exchange) is OriginExchange and exchange.initial_grant == grant
                 and exchange.validate_initial_target(grant.target_url) == grant.destination)
        _require(isinstance(capability, str) and re.fullmatch(r'[0-9a-f]{64}', capability))
        _integer(worker_uid, 2**31 - 1)
        _require(0 < _integer(max_control_calls, 1000))
        path = Path(path)
        parent_mode = 0o700 if socket_gid is None else 0o710
        if socket_gid is not None:
            _integer(socket_gid, 2**31 - 1)
            _require(path.parent.stat().st_gid == socket_gid and os.getgid() == socket_gid)
        _require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent
                 and path.parent.is_dir() and path.parent.stat().st_uid == os.getuid()
                 and stat.S_IMODE(path.parent.stat().st_mode) == parent_mode
                 and not path.exists() and not path.is_symlink()
                 and len(os.fsencode(path)) <= 107)
        self.grant, self.exchange, self.capability, self.worker_uid = grant, exchange, capability, worker_uid
        self.grant_binding = _grant_binding(grant, capability)
        self.socket_gid = socket_gid
        self.deadline = time.monotonic() + _seconds(lifetime_seconds)
        self.path = path
        self._slots, self._activity, self._active = Semaphore(16), Condition(), set()
        self._fetch_lock = Lock()
        self._control_lock, self._control_calls, self.max_control_calls = Lock(), 0, max_control_calls
        self._bound = False
        super().__init__(str(path), _Handler)
        if socket_gid is not None:
            _require(path.stat().st_gid == socket_gid)
        path.chmod(0o600 if socket_gid is None else 0o620)
        self._identity = (path.stat().st_dev, path.stat().st_ino)
        self._thread = Thread(target=self.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        self._thread.start()

    def process_request(self, request, client_address):
        if time.monotonic() >= self.deadline or not self._slots.acquire(blocking=False):
            request.close()
            return
        with self._activity:
            self._active.add(request)
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._activity:
                self._active.discard(request)
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._activity:
                self._active.discard(request)
                self._activity.notify_all()
            self._slots.release()

    def handle_error(self, *_args):
        pass  # Never emit request, capability, URL or provider traceback text.

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.shutdown()
        self.server_close()
        self._thread.join(timeout=1)
        deadline = time.monotonic() + 5
        with self._activity:
            for connection in tuple(self._active):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
            while self._active:
                self._activity.wait(_remaining(deadline))
        _require(not self._thread.is_alive())
        metadata = self.path.lstat()
        _require(stat.S_ISSOCK(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == self._identity
                 and metadata.st_uid == os.getuid()
                 and stat.S_IMODE(metadata.st_mode) == (0o600 if self.socket_gid is None else 0o620)
                 and (self.socket_gid is None or metadata.st_gid == self.socket_gid))
        self.path.unlink()


class TunnelAuthority:
    def __init__(self, hostname, port):
        _require(isinstance(hostname, str) and 0 < len(hostname) <= 253)
        _integer(port, 65535)
        _require(port in (80, 443))
        self.hostname, self.port = hostname, port


class RemoteOriginExchange(OriginExchange):
    """Client has no origin connector or resolver; server owns their decisions."""

    def __init__(self, path, *, grant, capability, broker_uid, socket_gid=None):
        check_public_scan_grant(grant)
        _require(isinstance(capability, str) and re.fullmatch(r'[0-9a-f]{64}', capability))
        _integer(broker_uid, 2**31 - 1)
        if socket_gid is not None:
            _integer(socket_gid, 2**31 - 1)
            _require(os.getgid() == socket_gid and broker_uid != os.getuid())
        self.socket_gid = socket_gid
        self.path, self.capability, self.broker_uid = Path(path), capability, broker_uid
        _require(self.path.is_absolute() and len(os.fsencode(self.path)) <= 107)
        def no_dns(_host, _port):
            raise ValueError('origin-broker-required')
        def no_origin(*_args, **_kwargs):
            raise OriginExchangeError('upstream-failed')
        super().__init__(DestinationPolicy(no_dns), user_agent='DOM-X-Ray-Remote-Client/0.1',
                         initial_grant=grant, connector=no_origin)

    def _rpc(self, op, url, method, headers, seconds):
        deadline = time.monotonic() + _seconds(seconds)
        request_id = secrets.token_hex(16)
        payload = {'capability': self.capability, 'requestId': request_id, 'op': op,
            'url': url, 'method': method, 'headers': headers, 'timeoutSeconds': seconds,
            'grantBinding': _grant_binding(self.initial_grant, self.capability)}
        raw = json.dumps(payload,
            separators=(',', ':'), allow_nan=False).encode()
        _require(len(raw) <= MAX_HEAD and sys.platform == 'linux')
        try:
            metadata = self.path.lstat()
            parent = self.path.parent.stat()
            _require(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == self.broker_uid
                     and stat.S_IMODE(metadata.st_mode) == (0o600 if self.socket_gid is None else 0o620)
                     and (self.socket_gid is None or metadata.st_gid == self.socket_gid)
                     and (self.socket_gid is None or (parent.st_uid == self.broker_uid
                          and parent.st_gid == self.socket_gid and stat.S_IMODE(parent.st_mode) == 0o710))
                     and self.path.parent.resolve() == self.path.parent)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(_remaining(deadline))
                connection.connect(str(self.path))
                _require(_credentials(connection)[1] == self.broker_uid)
                connection.sendall(struct.pack('!I', len(raw)) + raw)
                connection.shutdown(socket.SHUT_WR)
                response = _head(connection, deadline, MAX_RESPONSE_HEAD)
                _require(isinstance(response, dict) and response.get('requestId') == request_id)
                count = struct.unpack('!I', _read(connection, 4, deadline))[0]
                _require(count <= MAX_BODY)
                body = _read(connection, count, deadline)
                connection.settimeout(_remaining(deadline))
                _require(not connection.recv(1))
        except TimeoutError:
            raise OriginExchangeError('timeout') from None
        except (OSError, ValueError, TypeError, RecursionError):
            raise OriginExchangeError('upstream-failed') from None
        if response.get('kind') == 'error':
            _require(set(response) == {'kind', 'requestId', 'reason', 'upstreamBytesRead'} and not body
                     and response['reason'] in REASONS)
            raise OriginExchangeError(response['reason'],
                upstream_bytes_read=_integer(response['upstreamBytesRead'], MAX_BODY + 1))
        _require(response.get('kind') == 'ok')
        return response, body

    @_response_guard
    def validate_browser_tunnel(self, url):
        response, body = self._rpc('tunnel', url, 'CONNECT', (), 10)
        _require(set(response) == {'kind', 'requestId', 'authority'} and not body
                 and isinstance(response['authority'], dict) and set(response['authority']) == {'hostname', 'port'})
        return TunnelAuthority(**response['authority'])

    @_response_guard
    def validate_initial_target(self, url):
        destination = super().validate_initial_target(url)
        response, body = self._rpc('bind', url, 'BIND', (), 10)
        _require(set(response) == {'kind', 'requestId', 'authority'} and not body
                 and response['authority'] == {'hostname': destination.hostname, 'port': destination.port})
        return destination

    @_response_guard
    def fetch(self, url, *, method='GET', purpose, headers=(), timeout_seconds=10):
        _require(purpose in ('initial', 'redirect', 'subresource'))
        response, body = self._rpc('fetch', url, method, headers, timeout_seconds)
        _require(set(response) == {'kind', 'requestId', 'status', 'headers', 'upstreamWireBytes', 'bodyBytes'}
                 and isinstance(response['headers'], list) and len(response['headers']) <= 100)
        status = _integer(response['status'], 599)
        _require(status >= 200 and _integer(response['bodyBytes'], MAX_BODY) == len(body))
        wire = _integer(response['upstreamWireBytes'], MAX_BODY)
        _require(wire > 0 and wire >= len(body))
        pairs = []
        for pair in response['headers']:
            _require(isinstance(pair, list) and len(pair) == 2)
            pair = _header(*pair)
            _require(pair[0] not in {'set-cookie', 'x-dom-x-ray-block-id', 'transfer-encoding',
                                    'connection', 'proxy-authenticate', 'proxy-authorization'})
            pairs.append(pair)
        return OriginResponse(status, tuple(pairs), body, wire)
