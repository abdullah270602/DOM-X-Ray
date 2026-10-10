"""Slow-drip header/body reads end before the independent idle timeout."""
from pathlib import Path
import socket
import sys
import time
from threading import Event, Thread, current_thread
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.local_scan_api import LocalScanJobService, LocalScanHttpServer, _IngressSocketReader, build_server
from scripts.verify_local_scan_api import json_request, require


def main():
    connection = Mock()
    connection.recv_into.return_value = 1
    reader = _IngressSocketReader(connection, 2)
    reader.deadline = 100.5
    with patch('scanner.local_scan_api.time.monotonic', return_value=100.3):
        require(reader.readinto(bytearray(1)) == 1, 'reader changed receive result')
    require(abs(connection.settimeout.call_args_list[0].args[0] - .2) < .0001
            and connection.settimeout.call_args_list[-1].args == (2,),
            'remaining ingress budget or independent idle timeout changed')
    connection.reset_mock()
    with patch('scanner.local_scan_api.time.monotonic', return_value=100.5):
        try:
            reader.readinto(bytearray(1))
        except TimeoutError:
            pass
        else:
            raise AssertionError('exactly exhausted deadline allowed another receive')
    require(not connection.recv_into.called, 'exhausted ingress touched socket')
    with patch('scanner.local_scan_api.time.monotonic', side_effect=[100.3, 100.5]):
        try:
            reader.readinto(bytearray(1))
        except TimeoutError:
            pass
        else:
            raise AssertionError('receive completing at deadline delivered bytes')
    require(connection.recv_into.call_count == 1 and connection.settimeout.call_args.args == (2,),
            'late receive did not restore idle timeout')
    reader.close()

    service = LocalScanJobService()
    server = build_server('127.0.0.1', 0, service, max_http_handlers=1,
                         http_idle_timeout_seconds=2, http_ingress_timeout_seconds=.5)
    handlers = []
    finished = Event()
    original = server.process_request_thread
    def counted(*args):
        handlers.append(current_thread())
        try:
            original(*args)
        finally:
            finished.set()
    host = Thread(target=server.serve_forever, daemon=True)
    base = f'http://127.0.0.1:{server.server_port}'
    try:
        with patch.object(server, 'process_request_thread', side_effect=counted), \
                patch.object(service, 'submit', wraps=service.submit) as submit, \
                patch.object(service, 'reject_submission', wraps=service.reject_submission) as reject:
            host.start()
            for label, initial in (
                ('headers', b'GET /api/health HTTP/1.1\r\nHost: local\r\nX-Slow: '),
                ('body', b'POST /api/scans HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: 80\r\n\r\n{')):
                finished.clear()
                stop = Event()
                peer = socket.create_connection(('127.0.0.1', server.server_port), timeout=2)
                peer.settimeout(1.5)
                sender = None
                sent = []
                try:
                    started = time.monotonic()
                    peer.sendall(initial)
                    def drip():
                        while not stop.wait(.05):
                            try:
                                peer.sendall(b' ')
                                sent.append(time.monotonic())
                            except OSError:
                                return
                    sender = Thread(target=drip, daemon=True)
                    sender.start()
                    try:
                        closed = peer.recv(1) == b''
                    except (ConnectionResetError, ConnectionAbortedError):
                        closed = True  # A timeout close may race unread drip bytes.
                    require(closed, f'{label} slow drip did not close without response')
                    elapsed = time.monotonic() - started
                    require(.3 <= elapsed < 1.5 and len(sent) >= 3,
                            f'{label} closure did not demonstrate ingress before 2s idle timeout')
                    require(finished.wait(1), f'{label} handler did not release capacity')
                finally:
                    stop.set()
                    if sender is not None:
                        sender.join(timeout=2)
                        require(not sender.is_alive(), 'owned sender did not stop')
                    peer.close()
                require(not submit.called and not reject.called and not service._jobs,
                        f'{label} partial ingress touched job admission')
                status, _, health = json_request(base, '/api/health')
                require(status == 200 and health['arbitraryPublicScanning'] is False,
                        'capacity did not recover for ordinary request')
                for handler in handlers:
                    handler.join(timeout=2)
                    require(not handler.is_alive(), 'owned handler did not finish')
            for invalid in (0, -1, True, float('nan'), float('inf'), '1', None):
                with patch.object(LocalScanHttpServer, 'server_bind') as bind:
                    try:
                        build_server('127.0.0.1', 0, service, http_ingress_timeout_seconds=invalid)
                    except ValueError:
                        pass
                    else:
                        raise AssertionError('invalid ingress deadline accepted')
                    require(not bind.called, 'invalid deadline bound listener')
    finally:
        if host.is_alive():
            server.shutdown()
        server.server_close()
        service.shutdown()
        host.join(timeout=2)
        require(not host.is_alive(), 'owned server did not stop')
    print('Absolute ingress: slow-drip headers and body close before idle timeout; '
          'no admission, capacity recovery, exact budget and pre-bind configuration controls pass. '
          'Not a whole-request/backend/response deadline.')


if __name__ == '__main__':
    main()
