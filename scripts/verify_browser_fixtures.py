"""Run the Gate 0 deterministic pages through controlled Chromium."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fixtures.browser.fixture_server import FIXTURES, run_fixture_server
from scanner.browser_probe import probe_page, request_block_reason, validate_fixture_target
from scripts.validate_fixtures import validate_semantics


SCHEMA = json.loads((ROOT / "docs" / "SCAN_RECORD.schema.json").read_text(encoding="utf-8"))
GEOMETRY_TOLERANCE_PX = 1.0
TRANSFER_TOLERANCE = 0.02
EXPECTED_CHROMIUM_VERSION = "140.0.7339.16"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def assert_rects(record: dict, expected: dict[str, tuple[float, float, float, float]]) -> None:
    actual = {item["id"]: item["rect"] for item in record["nodes"]}
    require(set(actual) == set(expected), f"geometry IDs differ: {sorted(actual)} != {sorted(expected)}")
    for node_id, target in expected.items():
        observed = actual[node_id]
        for key, value in zip(("x", "y", "width", "height"), target, strict=True):
            delta = abs(float(observed[key]) - value)
            require(delta <= GEOMETRY_TOLERANCE_PX, f"{node_id}.{key} drifted by {delta:.3f}px")


def assert_transfer(record: dict, expected_payload_bytes: int) -> int:
    known = [item["transferredBytes"] for item in record["resources"] if item["transferredBytes"] is not None]
    require(len(known) == len(record["resources"]), "fixture has missing CDP byte data")
    total = int(sum(known))
    delta = abs(total - expected_payload_bytes) / expected_payload_bytes
    require(
        delta <= TRANSFER_TOLERANCE,
        f"CDP total {total} differs from payload {expected_payload_bytes} by {delta:.2%}",
    )
    return total


def assert_request_policy() -> None:
    cases = [
        ("GET", "https://public.example/page", None),
        ("HEAD", "https://public.example/page", None),
        ("OPTIONS", "https://public.example/page", None),
        ("POST", "https://public.example/write", "method"),
        ("DELETE", "https://public.example/item", "method"),
        ("GET", "http://127.0.0.1/secret", "private-literal-host"),
        ("GET", "http://[::1]/secret", "private-literal-host"),
        ("GET", "http://localhost/secret", "private-literal-host"),
        ("GET", "https://user:secret@public.example/page", "credentials"),
        ("GET", "file:///etc/passwd", "scheme"),
    ]
    for method, url, expected in cases:
        actual = request_block_reason(method, url)
        require(actual == expected, f"policy mismatch for {method} {url}: {actual!r} != {expected!r}")

    validate_fixture_target("http://clean.test:8080/clean/")
    invalid_targets = [
        "https://public.example/page",
        "http://user:secret@clean.test:8080/clean/",
        "http://clean.test:8080/clean/?token=secret",
        "file:///tmp/fixture.html",
    ]
    for target in invalid_targets:
        try:
            validate_fixture_target(target)
        except ValueError:
            continue
        raise AssertionError(f"fixture-only target boundary accepted {target}")


def main() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    assert_request_policy()
    summaries = []

    with run_fixture_server() as server, sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            args=[
                "--host-resolver-rules=MAP *.test 127.0.0.1",
                "--no-proxy-server",
            ],
        )
        try:
            require(
                browser.version == EXPECTED_CHROMIUM_VERSION,
                f"Chromium version {browser.version} != pinned proof version {EXPECTED_CHROMIUM_VERSION}",
            )
            for name, fixture in FIXTURES.items():
                server.clear_ledger()
                url = f"http://{fixture.host}:{server.server_port}{fixture.route}"
                result = probe_page(browser, url)
                record = result.record
                validate_semantics(record, f"browser fixture {name}", validator)
                require(record["status"] == "complete", f"{name} did not settle")
                require(not result.blocked_requests, f"{name} unexpectedly blocked requests")
                require(
                    record["capture"]["requestCount"] == fixture.expected_request_count,
                    f"{name} request count is {record['capture']['requestCount']}",
                )
                assert_rects(record, fixture.expected_rects)
                cdp_total = assert_transfer(record, fixture.expected_payload_bytes)

                if name == "clean":
                    require(not record["layoutShifts"], "clean fixture recorded a layout shift")
                elif name == "image-heavy":
                    require(result.layout_shift_supported, "layout-shift API unavailable in pinned Chromium")
                    require(record["layoutShifts"], "image-heavy fixture did not record its displacement")
                    require(
                        any(not shift["hadRecentInput"] for shift in record["layoutShifts"]),
                        "image-heavy displacement was not eligible evidence",
                    )
                    require(
                        record["capture"]["stabilizationMs"] >= 1_300,
                        "capture did not honor the mutation-reset quiet interval",
                    )
                elif name == "third-party":
                    third_party = [item for item in record["resources"] if item["party"] == "third"]
                    domains = {item["registrableDomain"] for item in third_party}
                    require(len(third_party) == 4, f"expected 4 third-party requests, found {len(third_party)}")
                    require(len(domains) == 3, f"expected 3 external hubs, found {len(domains)}")

                served_payload = sum(int(item["bodyBytes"]) for item in server.ledger if item["status"] == 200)
                served_wire = sum(int(item["wireBytes"]) for item in server.ledger if item["status"] == 200)
                require(
                    served_payload == fixture.expected_payload_bytes,
                    f"{name} server payload ledger drifted: {served_payload}",
                )
                require(
                    cdp_total == served_wire,
                    f"{name} CDP total {cdp_total} does not equal emitted wire bytes {served_wire}",
                )
                summaries.append(
                    f"{name}: {len(record['nodes'])} rects, {len(record['resources'])} requests, "
                    f"{cdp_total} exact CDP/wire bytes"
                )
        finally:
            browser.close()

    print(
        f"Validated controlled Chromium {EXPECTED_CHROMIUM_VERSION} "
        "against 3 deterministic browser fixtures."
    )
    for summary in summaries:
        print(f"  {summary}")
    print("Validated 10 request-policy cases and 5 fixture-boundary cases.")


if __name__ == "__main__":
    main()
