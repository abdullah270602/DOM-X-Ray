"""Loopback-only deterministic HTTP fixture server.

The browser sees reserved ``.test`` hosts through Chromium host-resolver rules.
Response bodies are padded to declared byte sizes so CDP transfer accounting can
be checked against a known payload without depending on checked-in binaries.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock, Thread
from typing import Iterator


ROOT = Path(__file__).resolve().parent / "site"


@dataclass(frozen=True)
class FixtureSpec:
    name: str
    host: str
    route: str
    expected_payload_bytes: int
    expected_request_count: int
    expected_rects: dict[str, tuple[float, float, float, float]]
    expected_excluded_markers: tuple[str, ...] = ()
    expected_omitted_markers: tuple[str, ...] = ()
    expected_exact_element_links: int = 0
    expected_rendered_count: int | None = None
    expected_aggregated_count: int = 0
    expected_redirect_count: int = 0
    expected_final_host: str | None = None
    cache_disabled: bool = True
    use_policy_proxy: bool = True
    trusted_loopback: bool = False
    expected_unobserved_paths: tuple[str, ...] = ()
    expected_missing_byte_count: int = 0
    hard_stop_seconds: float = 12.0
    expected_status: str = "complete"
    expected_failure_code: str | None = None
    expected_limits: tuple[str, ...] = ()


FIXTURES = {
    "clean": FixtureSpec(
        name="clean",
        host="clean.test",
        route="/clean/",
        expected_payload_bytes=180_000,
        expected_request_count=5,
        expected_rects={
            "n-root": (0, 0, 1440, 900),
            "n-header": (0, 0, 1440, 88),
            "n-main": (96, 120, 1248, 570),
            "n-card": (144, 176, 520, 320),
            "include-plain": (816, 200, 180, 80),
            "include-duplicate-image": (716, 480, 160, 90),
            "include-partial": (-24, 520, 40, 40),
            "n-footer": (0, 820, 1440, 80),
        },
        expected_excluded_markers=(
            "exclude-display",
            "exclude-hidden",
            "exclude-opacity",
            "exclude-tiny",
            "exclude-offscreen",
        ),
        expected_exact_element_links=2,
    ),
    "image-heavy": FixtureSpec(
        name="image-heavy",
        host="gallery.test",
        route="/image-heavy/",
        expected_payload_bytes=5_200_000,
        expected_request_count=7,
        expected_rects={
            "n-root": (0, 0, 1440, 900),
            "n-header": (0, 0, 1440, 88),
            "n-hero": (72, 120, 1296, 420),
            "n-gallery": (72, 570, 1296, 250),
            "n-card-1": (96, 600, 620, 190),
            "n-card-2": (724, 600, 620, 190),
            "n-caption": (96, 782, 1248, 24),
            "n-footer": (0, 840, 1440, 60),
        },
        expected_exact_element_links=3,
    ),
    "third-party": FixtureSpec(
        name="third-party",
        host="newsroom.test",
        route="/third-party/",
        expected_payload_bytes=1_160_000,
        expected_request_count=8,
        expected_rects={
            "n-root": (0, 0, 1440, 900),
            "n-header": (0, 0, 1440, 88),
            "n-article": (96, 120, 820, 620),
            "n-author": (128, 152, 220, 40),
            "n-share": (960, 140, 300, 180),
            "n-comments": (96, 770, 820, 100),
            "n-footer": (960, 800, 384, 70),
        },
        expected_exact_element_links=1,
    ),
    "aggregation": FixtureSpec(
        name="aggregation",
        host="aggregation.test",
        route="/aggregation/",
        expected_payload_bytes=100_000,
        expected_request_count=2,
        expected_rects={
            "agg-main": (20, 20, 1016, 812),
            "agg-tile-000": (20, 20, 30, 30),
            "agg-tile-646": (564, 734, 30, 30),
        },
        expected_omitted_markers=("agg-tile-647", "agg-tile-719"),
        expected_rendered_count=650,
        expected_aggregated_count=73,
    ),
    "redirect": FixtureSpec(
        name="redirect",
        host="redirect.test",
        route="/redirect/start",
        expected_payload_bytes=80_000,
        expected_request_count=6,
        expected_rects={
            "redirect-main": (120, 120, 1200, 600),
            "redirect-first-image": (180, 220, 420, 236.25),
            "redirect-third-image": (840, 220, 420, 236.25),
        },
        expected_exact_element_links=2,
        expected_redirect_count=2,
        expected_final_host="final.test",
    ),
    "cache": FixtureSpec(
        name="cache",
        host="cache.test",
        route="/cache/",
        expected_payload_bytes=130_000,
        expected_request_count=3,
        expected_rects={"cache-main": (120, 120, 1200, 600)},
        cache_disabled=False,
    ),
    "service-worker": FixtureSpec(
        name="service-worker",
        host="localhost",
        route="/service-worker/",
        expected_payload_bytes=75_000,
        expected_request_count=5,
        expected_rects={
            "worker-main": (120, 120, 1200, 600),
            "worker-image": (180, 220, 320, 180),
        },
        expected_exact_element_links=1,
        use_policy_proxy=False,
        trusted_loopback=True,
        expected_unobserved_paths=("/sw.js",),
        expected_missing_byte_count=1,
        expected_status="partial",
        expected_failure_code="measurement-unavailable",
    ),
    "never-settling": FixtureSpec(
        name="never-settling",
        host="unstable.test",
        route="/never-settling/",
        expected_payload_bytes=25_000,
        expected_request_count=1,
        expected_rects={"unstable-main": (120, 120, 1200, 600)},
        hard_stop_seconds=2.0,
        expected_status="partial",
        expected_failure_code="measurement-unavailable",
        expected_limits=("time",),
    ),
    "unknown-byte": FixtureSpec(
        name="unknown-byte",
        host="unfinished.test",
        route="/unknown-byte/",
        expected_payload_bytes=25_000,
        expected_request_count=2,
        expected_rects={"unknown-main": (120, 120, 1200, 600)},
        expected_unobserved_paths=("/stream/unfinished",),
        expected_missing_byte_count=1,
        hard_stop_seconds=2.0,
        expected_status="partial",
        expected_failure_code="measurement-unavailable",
        expected_limits=("time",),
    ),
}


PAGE_SPECS = {
    "/clean/": ("clean.html", 42_000, "text/html; charset=utf-8"),
    "/image-heavy/": ("image-heavy.html", 48_000, "text/html; charset=utf-8"),
    "/third-party/": ("third-party.html", 52_000, "text/html; charset=utf-8"),
    "/aggregation/": ("aggregation.html", 80_000, "text/html; charset=utf-8"),
    "/redirect/final": ("redirect-final.html", 40_000, "text/html; charset=utf-8"),
    "/cache/": ("cache.html", 30_000, "text/html; charset=utf-8"),
    "/service-worker/": ("service-worker.html", 35_000, "text/html; charset=utf-8"),
    "/never-settling/": ("never-settling.html", 25_000, "text/html; charset=utf-8"),
    "/unknown-byte/": ("unknown-byte.html", 25_000, "text/html; charset=utf-8"),
}


ASSET_SPECS = {
    "/assets/clean.css": ("assets/clean.css", 18_000, "text/css; charset=utf-8"),
    "/assets/clean.js": ("assets/clean.js", 32_000, "text/javascript; charset=utf-8"),
    "/assets/clean.woff2": (None, 24_000, "font/woff2"),
    "/media/clean.svg": (None, 64_000, "image/svg+xml"),
    "/assets/image-heavy.css": ("assets/image-heavy.css", 22_000, "text/css; charset=utf-8"),
    "/assets/image-heavy.js": ("assets/image-heavy.js", 430_000, "text/javascript; charset=utf-8"),
    "/assets/image-heavy.woff2": (None, 150_000, "font/woff2"),
    "/media/hero.svg": (None, 2_400_000, "image/svg+xml"),
    "/media/gallery.svg": (None, 1_650_000, "image/svg+xml"),
    "/media/thumb.svg": (None, 500_000, "image/svg+xml"),
    "/assets/third-party.css": ("assets/third-party.css", 36_000, "text/css; charset=utf-8"),
    "/assets/third-party.js": ("assets/third-party.js", 220_000, "text/javascript; charset=utf-8"),
    "/assets/third-party.woff2": (None, 180_000, "font/woff2"),
    "/assets/metrics.js": ("assets/metrics.js", 90_000, "text/javascript; charset=utf-8"),
    "/assets/comments.js": ("assets/comments.js", 210_000, "text/javascript; charset=utf-8"),
    "/media/lead.svg": (None, 310_000, "image/svg+xml"),
    "/api/thread": (None, 62_000, "application/octet-stream"),
    "/assets/aggregation.css": ("assets/aggregation.css", 20_000, "text/css; charset=utf-8"),
    "/assets/redirect.css": ("assets/redirect.css", 10_000, "text/css; charset=utf-8"),
    "/media/redirect-first.svg": (None, 15_000, "image/svg+xml"),
    "/media/redirect-third.svg": (None, 15_000, "image/svg+xml"),
    "/assets/cache-payload.bin": (None, 100_000, "application/octet-stream"),
    "/media/worker-payload.svg": (None, 20_000, "image/svg+xml"),
    "/sw.js": ("sw.js", 10_000, "text/javascript; charset=utf-8"),
}


def _pad_text(source: bytes, target_size: int, content_type: str) -> bytes:
    if content_type.startswith("text/html"):
        marker = b"</body>"
        wrapper = (b"<!--", b"-->")
    elif content_type.startswith("image/svg"):
        marker = b"</svg>"
        wrapper = (b"<!--", b"-->")
    else:
        marker = b""
        wrapper = (b"/*", b"*/")

    insertion = source.rfind(marker) if marker else len(source)
    if insertion < 0:
        insertion = len(source)
    overhead = len(wrapper[0]) + len(wrapper[1])
    fill_size = target_size - len(source) - overhead
    if fill_size < 0:
        raise ValueError(f"fixture source exceeds declared size {target_size}")
    padding = wrapper[0] + (b"x" * fill_size) + wrapper[1]
    return source[:insertion] + padding + source[insertion:]


def _svg_body(target_size: int) -> bytes:
    source = (
        b'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="9" viewBox="0 0 16 9">'
        b'<rect width="16" height="9" fill="#c7c0b2"/></svg>'
    )
    return _pad_text(source, target_size, "image/svg+xml")


def _binary_body(target_size: int, content_type: str) -> bytes:
    if content_type == "font/woff2":
        prefix = b"wOF2" + (b"\x00" * 44)
    else:
        prefix = b"DOMXRAY\x00"
    return prefix + (b"\x00" * (target_size - len(prefix)))


class FixtureHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), FixtureRequestHandler)
        self.ledger: list[dict[str, object]] = []
        self.ledger_lock = Lock()

    def record(self, item: dict[str, object]) -> None:
        with self.ledger_lock:
            self.ledger.append(item)

    def clear_ledger(self) -> None:
        with self.ledger_lock:
            self.ledger.clear()


class FixtureRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    @property
    def fixture_server(self) -> FixtureHTTPServer:
        return self.server  # type: ignore[return-value]

    def _write_response(
        self,
        status: int,
        content_type: str,
        body: bytes,
        *,
        extra_headers: tuple[tuple[str, str], ...] = (),
        cache_control: str = "no-store",
    ) -> None:
        reason = {
            200: "OK",
            302: "Found",
            307: "Temporary Redirect",
            404: "Not Found",
        }.get(status, "Fixture")
        extra = "".join(f"{name}: {value}\r\n" for name, value in extra_headers)
        header = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Cache-Control: {cache_control}\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            f"{extra}"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        self.wfile.write(header)
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True
        self.fixture_server.record(
            {
                "host": self.headers.get("Host", ""),
                "method": self.command,
                "path": self.path.split("?", 1)[0],
                "status": status,
                "bodyBytes": len(body) if self.command != "HEAD" else 0,
                "wireBytes": len(header) + (len(body) if self.command != "HEAD" else 0),
            }
        )

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_OPTIONS(self) -> None:
        self._write_response(200, "text/plain", b"")

    def do_GET(self) -> None:
        route = self.path.split("?", 1)[0]
        port = self.server.server_port
        if route == "/stream/unfinished":
            declared_size = 100_000
            partial_body = b"u" * 4_096
            header = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/octet-stream\r\n"
                f"Content-Length: {declared_size}\r\n"
                "Cache-Control: no-store\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            self.wfile.write(header)
            self.wfile.write(partial_body)
            self.wfile.flush()
            self.fixture_server.record(
                {
                    "host": self.headers.get("Host", ""),
                    "method": self.command,
                    "path": route,
                    "status": 200,
                    "bodyBytes": len(partial_body),
                    "wireBytes": len(header) + len(partial_body),
                }
            )
            self.close_connection = True
            time.sleep(5)
            return

        redirect_specs = {
            "/redirect/start": (302, f"http://middle.test:{port}/redirect/middle"),
            "/redirect/middle": (
                307,
                f"http://final.test:{port}/redirect/final?token=redirect-secret-1234567890",
            ),
            "/redirect/private": (302, f"http://127.0.0.1:{port}/private-hit"),
            "/redirect/credentials": (302, f"http://user:secret@final.test:{port}/private-hit"),
            "/redirect/scheme": (302, "file:///fixture-secret"),
            "/redirect/loop/a": (302, f"http://redirect.test:{port}/redirect/loop/b"),
            "/redirect/loop/b": (302, f"http://redirect.test:{port}/redirect/loop/a"),
        }
        if route.startswith("/redirect/cap/"):
            try:
                index = int(route.rsplit("/", 1)[1])
            except ValueError:
                index = -1
            if 0 <= index <= 10:
                redirect_specs[route] = (
                    302,
                    f"http://redirect.test:{port}/redirect/cap/{index + 1}",
                )
        if route in redirect_specs:
            status, location = redirect_specs[route]
            self._write_response(
                status,
                "text/plain; charset=utf-8",
                b"",
                extra_headers=(("Location", location),),
            )
            return

        if route in PAGE_SPECS:
            relative_path, target_size, content_type = PAGE_SPECS[route]
            source = (ROOT / relative_path).read_text(encoding="utf-8")
            source = source.replace("{{PORT}}", str(port)).encode("utf-8")
            if b"{{TILES}}" in source:
                tiles = "".join(
                    f'<div data-xray-id="agg-tile-{index:03d}"></div>'
                    for index in range(720)
                ).encode("utf-8")
                source = source.replace(b"{{TILES}}", tiles)
            body = _pad_text(source, target_size, content_type)
            self._write_response(200, content_type, body)
            return

        if route in ASSET_SPECS:
            relative_path, target_size, content_type = ASSET_SPECS[route]
            if relative_path is not None:
                source = (ROOT / relative_path).read_bytes()
                body = _pad_text(source, target_size, content_type)
            elif content_type == "image/svg+xml":
                body = _svg_body(target_size)
            else:
                body = _binary_body(target_size, content_type)
            self._write_response(
                200,
                content_type,
                body,
                cache_control=(
                    "public, max-age=3600, immutable"
                    if route == "/assets/cache-payload.bin"
                    else "no-store"
                ),
            )
            return

        self._write_response(404, "text/plain; charset=utf-8", b"not found")


@contextmanager
def run_fixture_server() -> Iterator[FixtureHTTPServer]:
    server = FixtureHTTPServer()
    thread = Thread(target=server.serve_forever, name="dom-xray-fixtures", daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
