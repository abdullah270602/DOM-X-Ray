"""Run the real Gate 0 browser probe inside one supervised fixture worker."""

from __future__ import annotations

import json
import math
import os
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from fixtures.browser.policy_proxy import run_policy_proxy
from scanner.browser_probe import (
    MAX_AUXILIARY_EVENTS,
    MAX_REQUESTS,
    MAX_RESPONSE_BYTES,
    MAX_TOTAL_RECEIVED_BYTES,
    probe_page,
)
from scanner.worker_supervisor import RESULT_NONCE_ENV


ALLOWED_CONFIG_KEYS = frozenset(
    {
        "url",
        "fixtureUpstreamPort",
        "usePolicyProxy",
        "trustedLoopback",
        "cacheDisabled",
        "hardStopSeconds",
        "maxRequests",
        "maxResponseBytes",
        "maxTotalReceivedBytes",
        "maxAuxiliaryEvents",
        "postCaptureDelaySeconds",
        "postCaptureMarkerPath",
    }
)


def _boolean(config: dict[str, object], name: str, default: bool) -> bool:
    value = config.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a JSON boolean")
    return value


def _integer(
    config: dict[str, object],
    name: str,
    default: int | None,
    maximum: int,
) -> int:
    value = config.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a JSON integer")
    if value <= 0 or value > maximum:
        raise ValueError(f"{name} must be within [1, {maximum}]")
    return value


def _number(
    config: dict[str, object],
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    value = config.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a JSON number")
    normalized = float(value)
    if not math.isfinite(normalized) or not minimum <= normalized <= maximum:
        raise ValueError(f"{name} must be within [{minimum}, {maximum}]")
    return normalized


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: capture_worker_fixture.py CONFIG RESULT")
    config_path = Path(sys.argv[1])
    result_path = Path(sys.argv[2])
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("worker config must be a JSON object")
    unknown_keys = set(config) - ALLOWED_CONFIG_KEYS
    if unknown_keys:
        raise ValueError(f"unknown worker config keys: {sorted(unknown_keys)}")
    nonce = os.environ.get(RESULT_NONCE_ENV)
    if not nonce:
        raise SystemExit("missing supervisor result nonce")

    url_value = config.get("url")
    if not isinstance(url_value, str) or not url_value:
        raise ValueError("url must be a non-empty JSON string")
    url = url_value
    use_policy_proxy = _boolean(config, "usePolicyProxy", True)
    trusted_loopback = _boolean(config, "trustedLoopback", False)
    cache_disabled = _boolean(config, "cacheDisabled", True)
    max_requests = _integer(config, "maxRequests", MAX_REQUESTS, MAX_REQUESTS)
    max_response_bytes = _integer(
        config,
        "maxResponseBytes",
        MAX_RESPONSE_BYTES,
        MAX_RESPONSE_BYTES,
    )
    max_total_received_bytes = _integer(
        config,
        "maxTotalReceivedBytes",
        MAX_TOTAL_RECEIVED_BYTES,
        MAX_TOTAL_RECEIVED_BYTES,
    )
    max_auxiliary_events = _integer(
        config,
        "maxAuxiliaryEvents",
        MAX_AUXILIARY_EVENTS,
        MAX_AUXILIARY_EVENTS,
    )
    hard_stop_seconds = _number(
        config,
        "hardStopSeconds",
        12.0,
        minimum=0.1,
        maximum=12.0,
    )
    post_capture_delay_seconds = _number(
        config,
        "postCaptureDelaySeconds",
        0.0,
        minimum=0.0,
        maximum=60.0,
    )
    marker_value = config.get("postCaptureMarkerPath")
    if marker_value is not None and (
        not isinstance(marker_value, str) or not marker_value
    ):
        raise ValueError("postCaptureMarkerPath must be a non-empty JSON string")
    upstream_port = None
    if "fixtureUpstreamPort" in config:
        upstream_port = _integer(
            config,
            "fixtureUpstreamPort",
            None,
            65_535,
        )
    if not use_policy_proxy and not trusted_loopback:
        raise ValueError("direct fixture capture requires explicit trusted loopback")
    if use_policy_proxy and upstream_port is None:
        raise ValueError("fixtureUpstreamPort is required with the policy proxy")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            args=["--proxy-bypass-list=<-loopback>"],
        )
        try:
            if use_policy_proxy:
                assert upstream_port is not None
                with run_policy_proxy(upstream_port) as proxy:
                    proxy.configure_limits(
                        max_requests=max_requests,
                        max_response_bytes=max_response_bytes,
                        max_total_received_bytes=max_total_received_bytes,
                        allow_trusted_loopback=trusted_loopback,
                    )
                    probe = probe_page(
                        browser,
                        url,
                        proxy_server=proxy.url,
                        policy_block_log=proxy.blocked,
                        egress_observation_snapshot=proxy.snapshot_observations,
                        egress_correlation_key=proxy.correlation_key,
                        trusted_loopback_fixture=trusted_loopback,
                        cache_disabled=cache_disabled,
                        hard_stop_seconds=hard_stop_seconds,
                        max_requests=max_requests,
                        max_response_bytes=max_response_bytes,
                        max_total_received_bytes=max_total_received_bytes,
                        max_auxiliary_events=max_auxiliary_events,
                    )
            else:
                probe = probe_page(
                    browser,
                    url,
                    trusted_loopback_fixture=trusted_loopback,
                    cache_disabled=cache_disabled,
                    hard_stop_seconds=hard_stop_seconds,
                    max_requests=max_requests,
                    max_response_bytes=max_response_bytes,
                    max_total_received_bytes=max_total_received_bytes,
                    max_auxiliary_events=max_auxiliary_events,
                )
            if marker_value is not None:
                Path(marker_value).write_text("capture-complete", encoding="utf-8")
            if post_capture_delay_seconds:
                time.sleep(post_capture_delay_seconds)
        finally:
            browser.close()

    _atomic_json(
        result_path,
        {
            "supervisorNonce": nonce,
            "result": {"record": probe.record},
        },
    )


if __name__ == "__main__":
    main()
