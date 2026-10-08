"""Native idle/active listener teardown; no public origin contacts."""

from pathlib import Path
import socket
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.namespace_bridge import NamespaceBridge
from scanner.browser_egress_proxy import run_browser_egress_proxy
from scanner.destination_policy import DestinationPolicy
from scanner.origin_exchange import OriginExchange
from scripts.verify_browser_egress_proxy import FixtureOrigin


def require(value, message):
    if not value:
        raise AssertionError(message)


def wait_handlers(server):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        with server._activity:
            if server._handlers:
                return
        time.sleep(0.01)
    raise AssertionError('idle client was never handled')


def empty(server):
    with server._activity:
        require(not server._active and not server._handlers, 'tracked handlers or sockets survived')
    require(server.socket.fileno() == -1, 'listening socket survived')


def main():
    require(sys.platform == 'linux', 'native Linux listener evidence required')
    for active in (False, True):
        policy = DestinationPolicy(lambda _h, _p: ['1.1.1.1'])
        exchange = OriginExchange(policy, user_agent='DOM-X-Ray-Listener-Fixture/0.1',
                                  connector=lambda grant, **_kw: FixtureOrigin(grant, []))
        client = None
        try:
            with run_browser_egress_proxy(initial_url='http://xray.test/', policy=policy,
                                         exchange=exchange, tls_context=lambda _h: None) as proxy:
                if active:
                    client = socket.create_connection(proxy.server_address, timeout=1)
                    wait_handlers(proxy)
                started = time.monotonic()
            duration = time.monotonic() - started
            empty(proxy)
            require(duration < 2, 'proxy listener/idle handler teardown exceeded fixture bound')
            print(f'proxy active={active}: stopped and empty in {duration * 1000:.0f} ms')
        finally:
            if client is not None:
                client.close()
        with tempfile.TemporaryDirectory(prefix='dxr-listener-', dir='/tmp') as temporary:
            parent = Path(temporary)
            parent.chmod(0o700)
            client = None
            # A local fixed upstream accepts but never sends data, keeping the
            # relay handler active until explicit cleanup closes its sockets.
            with socket.socket() as upstream:
                upstream.bind(('127.0.0.1', 0))
                upstream.listen()
                try:
                    with NamespaceBridge(upstream.getsockname()[1], temporary_parent=parent) as bridge:
                        path = bridge.path
                        if active:
                            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                            client.connect(str(path))
                            wait_handlers(bridge)
                        started = time.monotonic()
                    duration = time.monotonic() - started
                    empty(bridge)
                    require(not bridge._thread.is_alive() and not path.parent.exists(),
                            'bridge listener thread/private socket directory survived')
                    require(duration < 2, 'bridge listener/idle handler teardown exceeded fixture bound')
                    print(f'bridge active={active}: stopped and empty in {duration * 1000:.0f} ms')
                finally:
                    if client is not None:
                        client.close()
    print('Verified native idle/active listener termination, tracked socket/handler emptiness and private directory cleanup.')


if __name__ == '__main__':
    main()
