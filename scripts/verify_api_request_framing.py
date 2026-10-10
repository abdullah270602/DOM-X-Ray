"""Raw loopback framing controls; no claim about a deployed proxy chain."""
import json
from pathlib import Path
import socket
import sys
from threading import Thread, current_thread
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.local_scan_api import API_VERSION, LocalScanJobService, MAX_REQUEST_BODY_BYTES, build_server
from scanner.api_contract import validate_job
from scripts.verify_local_scan_api import require


def exchange(port, wire, *, half_close=False):
    response = bytearray()
    with socket.create_connection(('127.0.0.1', port), timeout=2) as peer:
        peer.settimeout(2)
        peer.sendall(wire)
        if half_close:
            peer.shutdown(socket.SHUT_WR)
        while True:
            try:
                chunk = peer.recv(4096)
            except (ConnectionResetError, ConnectionAbortedError):
                break
            if not chunk:
                break
            response.extend(chunk)
            require(len(response) < 16384, 'test response exceeded fixed envelope')
    require(response.count(b'HTTP/1.') == 1, 'no single complete response or a second request was served')
    header_bytes, payload = bytes(response).split(b'\r\n\r\n', 1)
    lines = header_bytes.decode('ascii').split('\r\n')
    status = int(lines[0].split()[1])
    headers = dict(line.split(': ', 1) for line in lines[1:])
    require(len(payload) == int(headers['Content-Length']), 'response body was truncated')
    return status, headers, payload


def main():
    executor = Mock()
    executor.supports.return_value = False
    service = LocalScanJobService(executor)
    server = build_server('127.0.0.1', 0, service)
    host = Thread(target=server.serve_forever, daemon=True)
    handlers = []
    original = server.process_request_thread
    def counted(*args):
        handlers.append(current_thread())
        original(*args)
    body = json.dumps({'apiVersion': API_VERSION, 'url': 'https://disabled.example/'}).encode()
    canary = b'FRAMING_PRIVATE_CANARY'
    tail = b'GET /api/health HTTP/1.1\r\nHost: local\r\n\r\n'
    def wire(fields, *, path='/api/scans', data=body, pipeline=True):
        return (f'POST {path} HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\n'.encode()
            + b'X-Deletion-Token-Digest: sha256=' + b'a' * 64 + b'\r\nX-Private: ' + canary + b'\r\n'
            + fields + b'\r\n' + data + (tail if pipeline else b''))
    cases = [
        ('missing', b'', 400),
        ('duplicate equal', f'Content-Length: {len(body)}\r\nContent-Length: {len(body)}\r\n'.encode(), 400),
        ('duplicate conflict', f'Content-Length: {len(body)}\r\nContent-Length: 1\r\n'.encode(), 400),
        ('comma equal', f'Content-Length: {len(body)}, {len(body)}\r\n'.encode(), 400),
        ('comma conflict', b'Content-Length: 1, 2\r\n', 400),
        ('transfer plus length', f'Transfer-Encoding: chunked\r\nContent-Length: {len(body)}\r\n'.encode(), 400),
        ('transfer only', b'Transfer-Encoding: chunked\r\n', 400),
        ('empty transfer', f'Transfer-Encoding:\r\nContent-Length: {len(body)}\r\n'.encode(), 400),
        ('duplicate transfer', b'Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n', 400),
        ('unknown transfer', b'Transfer-Encoding: canary\r\n', 400),
        ('plus sign', f'Content-Length: +{len(body)}\r\n'.encode(), 400),
        ('negative', b'Content-Length: -1\r\n', 400),
        ('internal space', b'Content-Length: 1 2\r\n', 400),
        ('empty length', b'Content-Length:\r\n', 400),
        ('hexadecimal', b'Content-Length: 0x40\r\n', 400),
        ('over limit', f'Content-Length: {MAX_REQUEST_BODY_BYTES + 1}\r\n'.encode(), 413),
        ('huge decimal', b'Content-Length: ' + b'9' * 5000 + b'\r\n', 413),
    ]
    try:
        with patch.object(server, 'process_request_thread', side_effect=counted), \
                patch.object(service, 'submit', wraps=service.submit) as submit:
            host.start()
            for label, fields, expected in cases:
                status, headers, payload = exchange(server.server_port, wire(fields))
                require(status == expected and headers['Connection'] == 'close'
                        and headers['Cache-Control'] == 'no-store' and canary not in payload
                        and not submit.called and not executor.supports.called and not executor.execute.called,
                        f'{label} framing reached admission or wrong response')
                validate_job(json.loads(payload))
            status, headers, payload = exchange(server.server_port,
                wire(f'Content-Length: {len(body) + 1}\r\n'.encode(), pipeline=False), half_close=True)
            require(status == 400 and headers['Connection'] == 'close'
                    and headers['Cache-Control'] == 'no-store' and not submit.called
                    and not executor.supports.called and canary not in payload,
                    'EOF-short but valid JSON body reached admission')
            validate_job(json.loads(payload))
            media_wire = wire(f'Content-Length: {len(body)}\r\n'.encode()).replace(
                b'Content-Type: application/json', b'Content-Type: text/plain')
            status, headers, payload = exchange(server.server_port, media_wire)
            require(status == 415 and headers['Connection'] == 'close'
                    and headers['Cache-Control'] == 'no-store' and not submit.called,
                    'unsupported media left unread body reusable')
            status, headers, payload = exchange(server.server_port,
                wire(f'Content-Length: {len(body)}\r\n'.encode(), path='/unknown'))
            require(status == 404 and headers['Connection'] == 'close'
                    and headers['Cache-Control'] == 'no-store' and not submit.called,
                    'unknown POST left unread body reusable')
            for fields in (cases[1][1], cases[5][1], cases[-1][1]):
                status, headers, payload = exchange(server.server_port,
                    wire(fields, path='/api/results/r_' + '0' * 32 + '/poster.png'))
                require(status == 405 and not payload and headers['Connection'] == 'close'
                        and headers['Cache-Control'] == 'no-store' and not submit.called,
                        'artifact upload rejection tried ambiguous body drain')
            for value in (str(len(body)), '000' + str(len(body)), '\t' + str(len(body)) + '\t'):
                status, headers, payload = exchange(server.server_port,
                    wire(f'Content-Length: {value}\r\n'.encode(), pipeline=False))
                require(status == 503 and json.loads(payload)['error']['code'] == 'scanner-disabled'
                        and headers['Cache-Control'] == 'no-store', 'valid fixed-length framing changed')
            require(submit.call_count == executor.supports.call_count == 3
                    and not executor.execute.called, 'valid controls did not cross admission exactly once')
            for handler in handlers:
                handler.join(timeout=2)
                require(not handler.is_alive(), 'owned framing handler did not finish')
    finally:
        if host.is_alive():
            server.shutdown()
        server.server_close()
        service.shutdown()
        host.join(timeout=2)
        require(not host.is_alive(), 'owned framing server did not stop')
    print('Raw HTTP framing: ambiguous/unsupported/invalid lengths rejected before admission; '
          'oversize integers bounded, upload drain fail-closed, no pipelined response/canary echo; '
          'valid decimal/zeros/OWS controls pass. Not deployed proxy interoperability proof.')


if __name__ == '__main__':
    main()
