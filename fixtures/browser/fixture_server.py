"""Loopback-only deterministic HTTP fixture server.

The browser sees reserved ``.test`` hosts through Chromium host-resolver rules.
Response bodies are padded to declared byte sizes so CDP transfer accounting can
be checked against a known payload without depending on checked-in binaries.
"""

from __future__ import annotations

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
}


PAGE_SPECS = {
    "/clean/": ("clean.html", 42_000, "text/html; charset=utf-8"),
    "/image-heavy/": ("image-heavy.html", 48_000, "text/html; charset=utf-8"),
    "/third-party/": ("third-party.html", 52_000, "text/html; charset=utf-8"),
    "/aggregation/": ("aggregation.html", 80_000, "text/html; charset=utf-8"),
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

    def _write_response(self, status: int, content_type: str, body: bytes) -> None:
        reason = {200: "OK", 404: "Not Found"}.get(status, "Fixture")
        header = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Cache-Control: no-store\r\n"
            "Access-Control-Allow-Origin: *\r\n"
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
                "path": self.path,
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
        if route in PAGE_SPECS:
            relative_path, target_size, content_type = PAGE_SPECS[route]
            source = (ROOT / relative_path).read_text(encoding="utf-8")
            source = source.replace("{{PORT}}", str(self.server.server_port)).encode("utf-8")
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
            self._write_response(200, content_type, body)
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
