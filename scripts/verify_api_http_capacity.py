"""Real idle sockets and overflow before HTTP parsing; no hard total deadline."""

from pathlib import Path
import socket
import sys
from threading import Event, Lock, Thread, current_thread
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.local_scan_api import LocalScanJobService, build_server
from scripts.verify_local_scan_api import json_request, request, require


def main():
    service = LocalScanJobService()
    server = build_server('127.0.0.1', 0, service, max_http_handlers=2, http_idle_timeout_seconds=0.4)
    mutex, occupied, drained = Lock(), Event(), Event()
    active, peak = 0, 0
    handlers, peers = [], []
    original = server.process_request_thread
    def counted(*args):
        nonlocal active, peak
        with mutex:
            handlers.append(current_thread())
            active += 1
            peak = max(peak, active)
            if active == 2:
                occupied.set()
        try:
            original(*args)
        finally:
            with mutex:
                active -= 1
                if active == 0:
                    drained.set()
    host = Thread(target=server.serve_forever, daemon=True)
    base = 'http://127.0.0.1:' + str(server.server_port)
    try:
        with patch.object(server, 'process_request_thread', side_effect=counted), \
                patch.object(service, 'submit', wraps=service.submit) as submit, \
                patch.object(service, 'reject_submission', wraps=service.reject_submission) as reject:
            host.start()
            for _ in range(2):
                peer = socket.create_connection(('127.0.0.1', server.server_port), timeout=2)
                peer.settimeout(3)
                peers.append(peer)
            require(occupied.wait(2), 'two idle handlers not occupied')
            status, headers, body = request(base, '/api/health')
            require(status == 503 and body == b'' and headers['Retry-After'] == '1'
                    and headers['Cache-Control'] == 'no-store' and headers['Connection'] == 'close'
                    and not submit.called and not reject.called and not service._jobs,
                    'HTTP overflow invoked job logic or returned wrong response')
            for peer in peers:
                require(peer.recv(1) == b'', 'idle handler did not close socket')
            require(drained.wait(2) and peak == 2, 'handler permits did not drain within observed idle test')
            status, _, health = json_request(base, '/api/health')
            require(status == 200 and health['arbitraryPublicScanning'] is False,
                    'capacity not restored for health request')
    finally:
        for peer in peers:
            peer.close()
        if host.is_alive():
            server.shutdown()
        server.server_close()
        if host.ident is not None:
            host.join(timeout=2)
        for handler in handlers:
            handler.join(timeout=2)
        service.shutdown()
    require(not host.is_alive() and all(not handler.is_alive() for handler in handlers), 'owned HTTP threads survived')
    with patch('scanner.local_scan_api.ThreadingHTTPServer.process_request', side_effect=RuntimeError('fixture-start')):
        try:
            server.process_request(Mock(), ('127.0.0.1', 0))
        except RuntimeError:
            pass
        else:
            raise AssertionError('controlled thread-start failure missing')
    require(server._http_slots.acquire(blocking=False) and server._http_slots.acquire(blocking=False)
            and not server._http_slots.acquire(blocking=False), 'start failure leaked or over-released slot')
    try:
        peer = Mock()
        peer.recv.side_effect = TimeoutError()
        peer.sendall.side_effect = BrokenPipeError()
        with patch.object(server, 'shutdown_request') as close:
            server.process_request(peer, ('127.0.0.1', 0))
            require(close.call_count == 1 and not server._http_slots.acquire(blocking=False),
                    'overflow I/O failure leaked thread or skipped closure')
    finally:
        server._http_slots.release()
        server._http_slots.release()
    for count, timeout in ((0, 1), (-1, 1), (True, 1), (1.5, 1), (2, 0), (2, -1),
                           (2, float('nan')), (2, float('inf')), (2, True), (2, None)):
        with patch('scanner.local_scan_api.ThreadingHTTPServer.__init__') as bind:
            try:
                build_server('127.0.0.1', 0, service, max_http_handlers=count,
                             http_idle_timeout_seconds=timeout)
            except ValueError:
                pass
            else:
                raise AssertionError('invalid HTTP limits accepted')
            require(not bind.called, 'invalid HTTP limits reached listener construction')
    print('Actual loopback: two idle handlers, overflow empty no-store 503 without jobs, idle socket closure, capacity recovery and owned threads joined. Idle timeout is not a slow-drip/whole-request deadline.')


if __name__ == '__main__':
    main()
