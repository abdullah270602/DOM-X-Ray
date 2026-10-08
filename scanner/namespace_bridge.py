"""Fixed proxy bridge across a browser network namespace, not a container.

No arbitrary target selection or descriptor passing. Filesystem/other pathname
Unix sockets remain outside this network-only proof and require deployment isolation.
"""

import os
from pathlib import Path
import select
import socket
from socketserver import BaseRequestHandler, ThreadingTCPServer, ThreadingUnixStreamServer
import struct
import tempfile
from threading import Condition, Semaphore, Thread, current_thread
import time


def pump(first, second):
    """Two bounded buffers, partial writes, half-close and a shared 15 s ceiling."""
    deadline = time.monotonic() + 15
    sockets = (first, second)
    buffers = {first: bytearray(), second: bytearray()}
    readable = {first: True, second: True}
    shut = set()
    for connection in sockets:
        connection.setblocking(False)
    while True:
        for source, destination in ((first, second), (second, first)):
            if not readable[source] and not buffers[destination] and destination not in shut:
                destination.shutdown(socket.SHUT_WR)
                shut.add(destination)
        if not any(readable.values()) and not any(buffers.values()):
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("namespace-relay-timeout")
        reads = [source for source, destination in ((first, second), (second, first))
                 if readable[source] and len(buffers[destination]) < 65_536]
        writes = [connection for connection in sockets if buffers[connection]]
        ready_read, ready_write, errors = select.select(reads, writes, sockets, remaining)
        if errors:
            raise OSError("namespace-relay-socket")
        for source in ready_read:
            destination = second if source is first else first
            try:
                chunk = source.recv(65_536 - len(buffers[destination]))
            except BlockingIOError:
                continue
            if chunk:
                buffers[destination].extend(chunk)
            else:
                readable[source] = False
        for destination in ready_write:
            try:
                sent = destination.send(buffers[destination])
            except BlockingIOError:
                continue
            if not sent:
                raise OSError("namespace-relay-socket")
            del buffers[destination][:sent]


class _BoundedHandlers:
    daemon_threads = True

    def configure_handlers(self):
        self._slots = Semaphore(16)
        self._activity = Condition()
        self._active = set()
        self._handlers = set()

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
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
        with self._activity:
            self._handlers.add(current_thread())
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._activity:
                self._active.discard(request)
                self._handlers.discard(current_thread())
                self._activity.notify_all()
            self._slots.release()

    def track(self, connection):
        with self._activity:
            self._active.add(connection)

    def forget(self, connection):
        with self._activity:
            self._active.discard(connection)

    def close_handlers(self):
        deadline = time.monotonic() + 5
        with self._activity:
            for connection in tuple(self._active):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
            while self._active or self._handlers:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("namespace-relay-cleanup")
                self._activity.wait(remaining)

    def handle_error(self, *_args):
        pass


class _BridgeHandler(BaseRequestHandler):
    def handle(self):
        upstream = None
        try:
            credentials = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _pid, uid, _gid = struct.unpack("3i", credentials)
            if uid != self.server.owner_uid:
                return
            with self.server._activity:
                if len(self.server.peer_ids) < 16:
                    self.server.peer_ids.add(_pid)
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.track(upstream)
            upstream.settimeout(3)
            upstream.connect(("127.0.0.1", self.server.proxy_port))
            pump(self.request, upstream)
        except (OSError, ValueError):
            pass
        finally:
            if upstream is not None:
                upstream.close()
                self.server.forget(upstream)


class NamespaceBridge(_BoundedHandlers, ThreadingUnixStreamServer):
    """Private pathname socket that can reach only one fixed loopback proxy."""

    def __init__(self, proxy_port, *, temporary_parent=None):
        if (not isinstance(proxy_port, int) or isinstance(proxy_port, bool)
                or not 1 <= proxy_port <= 65_535 or not hasattr(socket, "SO_PEERCRED")):
            raise ValueError("namespace-bridge-configuration")
        if temporary_parent is not None:
            temporary_parent = Path(temporary_parent)
            if (not temporary_parent.is_absolute() or not temporary_parent.is_dir()
                    or temporary_parent.is_symlink() or temporary_parent.stat().st_mode & 0o077):
                raise ValueError("namespace-bridge-private-directory")
        self.proxy_port = proxy_port
        self.owner_uid = os.getuid()
        # Bounded scan-local process identities for namespace verification only;
        # never a public record, hostname, address, or authorization decision.
        self.peer_ids = set()
        self.configure_handlers()
        # A supervised worker supplies parent-owned storage, so hard termination
        # cannot orphan a socket directory outside transport cleanup. Long paths
        # fail closed; never silently fall back to unowned /tmp storage.
        self._temporary = tempfile.TemporaryDirectory(prefix="dxr-net-",
            dir="/tmp" if temporary_parent is None else str(temporary_parent))
        directory = Path(self._temporary.name)
        directory.chmod(0o700)
        self.path = directory / "proxy.sock"
        try:
            if len(os.fsencode(self.path)) > 107:
                raise ValueError("namespace-bridge-path-limit")
            super().__init__(str(self.path), _BridgeHandler)
            self.path.chmod(0o600)
            self._thread = Thread(target=self.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
            self._thread.start()
        except Exception:
            self._temporary.cleanup()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        try:
            self.shutdown()
            self.server_close()
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                raise RuntimeError("namespace-relay-listener-cleanup")
            self.close_handlers()
        finally:
            self._temporary.cleanup()


class _RelayHandler(BaseRequestHandler):
    def handle(self):
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.track(upstream)
        try:
            upstream.settimeout(3)
            upstream.connect(self.server.bridge_path)
            pump(self.request, upstream)
        except (OSError, ValueError):
            pass
        finally:
            upstream.close()
            self.server.forget(upstream)


class NamespaceRelay(_BoundedHandlers, ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, bridge_path, port):
        if (not Path(bridge_path).is_absolute() or not isinstance(port, int) or isinstance(port, bool)
                or not 1 <= port <= 65535):
            raise ValueError("namespace-relay-configuration")
        self.configure_handlers()
        self.bridge_path = str(bridge_path)
        super().__init__(("127.0.0.1", port), _RelayHandler)
