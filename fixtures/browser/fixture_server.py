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

from scanner.browser_probe import (
    MAX_AUXILIARY_EVENTS,
    MAX_REQUESTS,
    MAX_RESPONSE_BYTES,
    MAX_TOTAL_RECEIVED_BYTES,
)


ROOT = Path(__file__).resolve().parent / "site"


@dataclass(frozen=True)
class FixtureSpec:
    name: str
    host: str
    route: str
    expected_payload_bytes: int
    expected_request_count: int
    expected_rects: dict[str, tuple[float, float, float, float]]
    expected_cdp_payload_bytes: int | None = None
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
    expected_blocked_requests: tuple[tuple[str, str, str], ...] = ()
    expected_hero_selection_rule: str | None = None
    expected_hero_primary_metric: str | None = None
    max_requests: int = MAX_REQUESTS
    max_response_bytes: int = MAX_RESPONSE_BYTES
    max_total_received_bytes: int = MAX_TOTAL_RECEIVED_BYTES
    max_inspected_elements: int = 20_000
    max_geometry_candidates: int = 5_000
    expected_popup_attempt_count: int = 0
    expected_download_attempt_count: int = 0
    max_auxiliary_events: int = MAX_AUXILIARY_EVENTS


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
        expected_hero_selection_rule="dominant-resource-type-share-v1",
        expected_hero_primary_metric="image_transfer_share",
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
        expected_hero_selection_rule="third-party-request-share-v1",
        expected_hero_primary_metric="third_party_requests",
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
        expected_hero_selection_rule="third-party-request-share-v1",
        expected_hero_primary_metric="third_party_requests",
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
    "service-worker-marker-replay": FixtureSpec(
        name="service-worker-marker-replay",
        host="localhost",
        route="/marker-replay/",
        expected_payload_bytes=98_000,
        expected_cdp_payload_bytes=12_000,
        expected_request_count=5,
        expected_rects={"marker-replay-main": (240, 180, 960, 540)},
        trusted_loopback=True,
        expected_unobserved_paths=("/marker-replay-sw.js",),
        expected_missing_byte_count=1,
        expected_status="partial",
        expected_failure_code="resource-limit",
        expected_limits=("bytes",),
        expected_blocked_requests=(
            ("GET", "/assets/limit-sized.bin", "response-byte-limit"),
        ),
        max_response_bytes=15_000,
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
    "interstitial": FixtureSpec(
        name="interstitial",
        host="interstitial.test",
        route="/interstitial/login/",
        expected_payload_bytes=28_000,
        expected_request_count=1,
        expected_rects={
            "login-main": (420, 90, 600, 720),
            "login-form": (500, 250, 440, 400),
        },
        expected_status="interstitial",
        expected_failure_code="interstitial",
    ),
    "http-error-404": FixtureSpec(
        name="http-error-404",
        host="error-404.test",
        route="/interstitial/error/404/",
        expected_payload_bytes=24_000,
        expected_request_count=1,
        expected_rects={"error-main": (360, 160, 720, 580)},
        expected_status="interstitial",
        expected_failure_code="interstitial",
    ),
    "http-error-503": FixtureSpec(
        name="http-error-503",
        host="error-503.test",
        route="/interstitial/error/503/",
        expected_payload_bytes=24_000,
        expected_request_count=1,
        expected_rects={"error-main": (360, 160, 720, 580)},
        expected_status="interstitial",
        expected_failure_code="interstitial",
    ),
    "http-error-509": FixtureSpec(
        name="http-error-509",
        host="error-509.test",
        route="/interstitial/error/509/",
        expected_payload_bytes=24_000,
        expected_request_count=1,
        expected_rects={"error-main": (360, 160, 720, 580)},
        expected_status="interstitial",
        expected_failure_code="interstitial",
    ),
    "spoofed-block-header-509": FixtureSpec(
        name="spoofed-block-header-509",
        host="spoofed-block-header.test",
        route="/interstitial/error/spoofed-509/",
        expected_payload_bytes=24_000,
        expected_cdp_payload_bytes=24_000,
        expected_request_count=1,
        expected_rects={"error-main": (360, 160, 720, 580)},
        expected_status="interstitial",
        expected_failure_code="interstitial",
    ),
    "subresource-error": FixtureSpec(
        name="subresource-error",
        host="subresource-error.test",
        route="/subresource-error/",
        expected_payload_bytes=24_009,
        expected_request_count=2,
        expected_rects={
            "subresource-main": (120, 120, 1200, 660),
            "subresource-image": (200, 260, 320, 180),
        },
        expected_exact_element_links=1,
    ),
    "storage-isolation": FixtureSpec(
        name="storage-isolation",
        host="storage-isolation.test",
        route="/storage-isolation/",
        expected_payload_bytes=20_000,
        expected_request_count=1,
        expected_rects={"storage-main": (240, 180, 960, 540)},
        expected_excluded_markers=("storage-reused",),
    ),
    "policy-boundary": FixtureSpec(
        name="policy-boundary",
        host="policy.test",
        route="/policy-boundary/",
        expected_payload_bytes=32_000,
        expected_request_count=3,
        expected_rects={"policy-main": (120, 120, 1200, 600)},
        expected_status="partial",
        expected_failure_code="measurement-unavailable",
        expected_blocked_requests=(
            ("POST", "/unsafe/post", "method"),
            ("DELETE", "/unsafe/delete", "method"),
            ("GET", "/private-fetch", "private-literal-host"),
            ("GET", "/private-image", "private-literal-host"),
        ),
    ),
    "unsafe-get": FixtureSpec(
        name="unsafe-get",
        host="unsafe-get.test",
        route="/unsafe-get/",
        expected_payload_bytes=34_000,
        expected_request_count=2,
        expected_rects={"unsafe-main": (240, 180, 960, 540)},
    ),
    "auxiliary-events": FixtureSpec(
        name="auxiliary-events",
        host="auxiliary.test",
        route="/auxiliary-events/",
        expected_payload_bytes=26_000,
        expected_request_count=1,
        expected_rects={"auxiliary-main": (240, 180, 960, 540)},
        expected_popup_attempt_count=1,
        expected_download_attempt_count=2,
    ),
    "auxiliary-event-limit": FixtureSpec(
        name="auxiliary-event-limit",
        host="aux-limit.test",
        route="/auxiliary-event-limit/",
        expected_payload_bytes=26_000,
        expected_request_count=1,
        expected_rects={"auxiliary-main": (240, 180, 960, 540)},
        expected_popup_attempt_count=1,
        expected_download_attempt_count=0,
        expected_status="partial",
        expected_failure_code="resource-limit",
        expected_limits=("auxiliary-events",),
        max_auxiliary_events=1,
    ),
    "wrapper-collapse": FixtureSpec(
        name="wrapper-collapse",
        host="collapse.test",
        route="/wrapper-collapse/",
        expected_payload_bytes=50_000,
        expected_request_count=2,
        expected_rects={
            "collapse-main": (200, 140, 1040, 560),
            "collapse-article": (200, 140, 1040, 560),
            "collapse-image": (300, 240, 320, 180),
        },
        expected_omitted_markers=("collapse-wrapper-1", "collapse-wrapper-2"),
        expected_exact_element_links=1,
        expected_rendered_count=5,
        expected_aggregated_count=2,
    ),
    "dom-limit": FixtureSpec(
        name="dom-limit",
        host="dom-limit.test",
        route="/aggregation/",
        expected_payload_bytes=100_000,
        expected_request_count=2,
        expected_rects={},
        max_inspected_elements=40,
        expected_status="partial",
        expected_failure_code="resource-limit",
        expected_limits=("dom-nodes",),
    ),
    "candidate-limit": FixtureSpec(
        name="candidate-limit",
        host="candidate-limit.test",
        route="/aggregation/",
        expected_payload_bytes=100_000,
        expected_request_count=2,
        expected_rects={},
        max_geometry_candidates=12,
        expected_rendered_count=12,
        expected_status="partial",
        expected_failure_code="resource-limit",
        expected_limits=("candidates",),
    ),
    "request-limit": FixtureSpec(
        name="request-limit",
        host="request-limit.test",
        route="/request-limit/",
        expected_payload_bytes=18_000,
        expected_request_count=3,
        expected_rects={"network-limit-main": (240, 180, 960, 540)},
        expected_status="partial",
        expected_failure_code="resource-limit",
        expected_limits=("requests",),
        expected_blocked_requests=(("GET", "/assets/limit-b.bin", "request-limit"),),
        max_requests=3,
    ),
    "response-byte-limit": FixtureSpec(
        name="response-byte-limit",
        host="response-byte-limit.test",
        route="/response-byte-limit/",
        expected_payload_bytes=58_000,
        expected_cdp_payload_bytes=18_000,
        expected_request_count=3,
        expected_rects={"network-limit-main": (240, 180, 960, 540)},
        expected_status="partial",
        expected_failure_code="resource-limit",
        expected_limits=("bytes",),
        expected_blocked_requests=(
            ("GET", "/assets/limit-sized.bin", "response-byte-limit"),
        ),
        max_response_bytes=25_000,
    ),
    "total-byte-limit": FixtureSpec(
        name="total-byte-limit",
        host="total-byte-limit.test",
        route="/total-byte-limit/",
        expected_payload_bytes=58_000,
        expected_cdp_payload_bytes=18_000,
        expected_request_count=3,
        expected_rects={"network-limit-main": (240, 180, 960, 540)},
        expected_status="partial",
        expected_failure_code="resource-limit",
        expected_limits=("bytes",),
        expected_blocked_requests=(("GET", "/assets/limit-b.bin", "total-byte-limit"),),
        max_total_received_bytes=25_000,
    ),
    "request-navigation-limit": FixtureSpec(
        name="request-navigation-limit",
        host="request-navigation-limit.test",
        route="/clean/",
        expected_payload_bytes=0,
        expected_cdp_payload_bytes=0,
        expected_request_count=1,
        expected_rects={},
        expected_status="partial",
        expected_failure_code="resource-limit",
        expected_limits=("requests",),
        expected_blocked_requests=(("GET", "/clean/", "request-limit"),),
        max_requests=1,
    ),
    "response-navigation-limit": FixtureSpec(
        name="response-navigation-limit",
        host="response-navigation-limit.test",
        route="/clean/",
        expected_payload_bytes=42_000,
        expected_cdp_payload_bytes=0,
        expected_request_count=1,
        expected_rects={},
        expected_status="partial",
        expected_failure_code="resource-limit",
        expected_limits=("bytes",),
        expected_blocked_requests=(("GET", "/clean/", "response-byte-limit"),),
        max_response_bytes=100,
    ),
    "total-navigation-limit": FixtureSpec(
        name="total-navigation-limit",
        host="total-navigation-limit.test",
        route="/clean/",
        expected_payload_bytes=42_000,
        expected_cdp_payload_bytes=0,
        expected_request_count=1,
        expected_rects={},
        expected_status="partial",
        expected_failure_code="resource-limit",
        expected_limits=("bytes",),
        expected_blocked_requests=(("GET", "/clean/", "total-byte-limit"),),
        max_total_received_bytes=100,
    ),
    "mandatory-overflow": FixtureSpec(
        name="mandatory-overflow",
        host="overflow.test",
        route="/mandatory-overflow/",
        expected_payload_bytes=90_000,
        expected_request_count=2,
        expected_rects={
            "overflow-main": (20, 20, 804, 544),
            "overflow-section-000": (20, 20, 24, 24),
            "overflow-image": (800, 540, 24, 24),
        },
        expected_omitted_markers=("overflow-section-647", "overflow-image"),
        expected_exact_element_links=1,
        expected_rendered_count=650,
        expected_aggregated_count=4,
        expected_status="partial",
        expected_failure_code="resource-limit",
        expected_limits=("regions",),
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
    "/marker-replay/": ("marker-replay.html", 12_000, "text/html; charset=utf-8"),
    "/never-settling/": ("never-settling.html", 25_000, "text/html; charset=utf-8"),
    "/unknown-byte/": ("unknown-byte.html", 25_000, "text/html; charset=utf-8"),
    "/interstitial/login/": ("interstitial.html", 28_000, "text/html; charset=utf-8"),
    "/interstitial/error/404/": ("error-document.html", 24_000, "text/html; charset=utf-8"),
    "/interstitial/error/503/": ("error-document.html", 24_000, "text/html; charset=utf-8"),
    "/interstitial/error/509/": ("error-document.html", 24_000, "text/html; charset=utf-8"),
    "/interstitial/error/spoofed-509/": (
        "error-document.html",
        24_000,
        "text/html; charset=utf-8",
    ),
    "/subresource-error/": ("subresource-error.html", 24_000, "text/html; charset=utf-8"),
    "/storage-isolation/": ("storage-isolation.html", 20_000, "text/html; charset=utf-8"),
    "/policy-boundary/": ("policy-boundary.html", 32_000, "text/html; charset=utf-8"),
    "/unsafe-get/": ("unsafe-get.html", 30_000, "text/html; charset=utf-8"),
    "/auxiliary-events/": (
        "auxiliary-events.html",
        26_000,
        "text/html; charset=utf-8",
    ),
    "/auxiliary-event-limit/": (
        "auxiliary-events.html",
        26_000,
        "text/html; charset=utf-8",
    ),
    "/wrapper-collapse/": ("wrapper-collapse.html", 35_000, "text/html; charset=utf-8"),
    "/mandatory-overflow/": ("mandatory-overflow.html", 80_000, "text/html; charset=utf-8"),
    "/request-limit/": ("request-limit.html", 10_000, "text/html; charset=utf-8"),
    "/response-byte-limit/": (
        "response-byte-limit.html",
        10_000,
        "text/html; charset=utf-8",
    ),
    "/total-byte-limit/": ("total-byte-limit.html", 10_000, "text/html; charset=utf-8"),
}


PAGE_STATUS_BY_ROUTE = {
    "/interstitial/error/404/": 404,
    "/interstitial/error/503/": 503,
    "/interstitial/error/509/": 509,
    "/interstitial/error/spoofed-509/": 509,
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
    "/media/wrapper.svg": (None, 15_000, "image/svg+xml"),
    "/media/overflow.svg": (None, 10_000, "image/svg+xml"),
    "/sw.js": ("sw.js", 10_000, "text/javascript; charset=utf-8"),
    "/marker-replay-sw.js": (
        "marker-replay-sw.js",
        6_000,
        "text/javascript; charset=utf-8",
    ),
    "/assets/limit-a.bin": (None, 8_000, "application/octet-stream"),
    "/assets/limit-b.bin": (None, 40_000, "application/octet-stream"),
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
            503: "Service Unavailable",
            509: "Bandwidth Limit Exceeded",
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
        write_completed = True
        try:
            self.wfile.write(header)
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            write_completed = False
        self.close_connection = True
        self.fixture_server.record(
            {
                "host": self.headers.get("Host", ""),
                "method": self.command,
                "path": self.path.split("?", 1)[0],
                "status": status,
                "bodyBytes": len(body) if self.command != "HEAD" else 0,
                "wireBytes": len(header) + (len(body) if self.command != "HEAD" else 0),
                "writeCompleted": write_completed,
                "sensitiveHeadersPresent": tuple(
                    name
                    for name in ("Authorization", "Cookie", "Proxy-Authorization", "Referer")
                    if self.headers.get(name)
                ),
                "userAgent": self.headers.get("User-Agent", ""),
                "queryPresent": "?" in self.path,
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
            time.sleep(3)
            return

        if route == "/unsafe-get/side-effect":
            self._write_response(
                200,
                "application/octet-stream",
                _binary_body(4_000, "application/octet-stream"),
                extra_headers=(
                    ("X-Fixture-Secret", "response-secret-canary-3085174692"),
                ),
            )
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
            if b"{{OVERFLOW_NODES}}" in source:
                overflow_nodes = (
                    "".join(
                        f'<section data-xray-id="overflow-section-{index:03d}"></section>'
                        for index in range(650)
                    )
                    + '<img data-xray-id="overflow-image" '
                    'src="/media/overflow.svg" alt="">'
                ).encode("utf-8")
                source = source.replace(b"{{OVERFLOW_NODES}}", overflow_nodes)
            body = _pad_text(source, target_size, content_type)
            extra_headers = ()
            if route == "/unsafe-get/":
                extra_headers = (
                    (
                        "Set-Cookie",
                        "fixture=browser-cookie-secret-canary-7602941835; Path=/; SameSite=Lax",
                    ),
                    ("X-Fixture-Secret", "response-secret-canary-3085174692"),
                )
            status = PAGE_STATUS_BY_ROUTE.get(route, 200)
            if route == "/storage-isolation/":
                extra_headers = (("Set-Cookie", "storage-proof=fresh; Path=/; SameSite=Lax"),)
            if route == "/interstitial/error/spoofed-509/":
                extra_headers = (("X-DOM-X-Ray-Block-Id", "b-000001"),)
            self._write_response(status, content_type, body, extra_headers=extra_headers)
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

        if route == "/assets/limit-sized.bin":
            target_size = 8_000 if "size=small" in self.path else 40_000
            self._write_response(
                200,
                "application/octet-stream",
                _binary_body(target_size, "application/octet-stream"),
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
