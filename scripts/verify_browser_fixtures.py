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
from scanner.aggregation import MandatoryOverflowError, aggregate_nodes
from scanner.browser_probe import probe_page, request_block_reason, validate_fixture_target
from scripts.validate_fixtures import validate_semantics


SCHEMA = json.loads((ROOT / "docs" / "SCAN_RECORD.schema.json").read_text(encoding="utf-8"))
GEOMETRY_TOLERANCE_PX = 1.0
TRANSFER_TOLERANCE = 0.02
EXPECTED_CHROMIUM_VERSION = "140.0.7339.16"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def assert_rects(
    record: dict,
    expected: dict[str, tuple[float, float, float, float]],
    fixture_node_ids: dict[str, str],
) -> None:
    actual = {item["id"]: item["rect"] for item in record["nodes"]}
    for marker, target in expected.items():
        require(marker in fixture_node_ids, f"expected candidate marker was excluded: {marker}")
        node_id = fixture_node_ids[marker]
        observed = actual[node_id]
        for key, value in zip(("x", "y", "width", "height"), target, strict=True):
            delta = abs(float(observed[key]) - value)
            require(delta <= GEOMETRY_TOLERANCE_PX, f"{marker}/{node_id}.{key} drifted by {delta:.3f}px")


def assert_exact_attribution(record: dict) -> int:
    images = [item for item in record["resources"] if item["type"] == "image"]
    require(
        all(item["attributionScope"] == "exact-element" and item["attributedNodeIds"] for item in images),
        "an image resource lacks exact element attribution",
    )
    require(
        all(
            item["attributionScope"] == "page-level" and not item["attributedNodeIds"]
            for item in record["resources"]
            if item["type"] in {"stylesheet", "font", "script", "fetch", "xhr"}
        ),
        "a stylesheet, font, script, fetch, or XHR was incorrectly blamed on a DOM candidate",
    )
    return sum(len(item["attributedNodeIds"]) for item in images)


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


def assert_aggregation_guards() -> None:
    def node(node_id: str, parent_id: str | None = None) -> dict:
        return {
            "id": node_id,
            "parentId": parent_id,
            "tag": "div",
            "selector": "div",
            "rect": {"x": 0, "y": 0, "width": 100, "height": 100},
            "domDepth": 0 if parent_id is None else 1,
            "stackingContext": {"creates": False, "rule": None},
            "memberNodeIds": [],
            "aggregationRule": None,
            "resourceIds": [],
        }

    def metadata(*, mandatory: bool, preorder: int) -> dict:
        return {
            "preorderIndex": preorder,
            "clippedRect": {"x": 0, "y": 0, "width": 100, "height": 100},
            "mandatory": mandatory,
            "semanticDistinctness": 0,
            "hasDistinctPaint": True,
        }

    resource_node = node("resource")
    resource_node["resourceIds"] = ["res-1"]
    try:
        aggregate_nodes([resource_node], {"resource": metadata(mandatory=False, preorder=0)}, [])
    except ValueError as error:
        require("resource-bearing" in str(error), "resource mandatory guard raised the wrong error")
    else:
        raise AssertionError("aggregation accepted a nonmandatory resource-bearing candidate")

    stacking_node = node("stacking")
    stacking_node["stackingContext"] = {"creates": True, "rule": "positioned-z-index"}
    try:
        aggregate_nodes([stacking_node], {"stacking": metadata(mandatory=False, preorder=0)}, [])
    except ValueError as error:
        require("stacking-context" in str(error), "stacking mandatory guard raised the wrong error")
    else:
        raise AssertionError("aggregation accepted a nonmandatory stacking-context candidate")

    mandatory_nodes = [node("root"), node("child", "root")]
    mandatory_metadata = {
        "root": metadata(mandatory=True, preorder=0),
        "child": metadata(mandatory=True, preorder=1),
    }
    try:
        aggregate_nodes(mandatory_nodes, mandatory_metadata, [], max_scene_objects=1)
    except MandatoryOverflowError:
        pass
    else:
        raise AssertionError("aggregation emitted an over-budget mandatory scene")


def deterministic_fingerprint(record: dict) -> tuple:
    nodes = tuple(
        (
            item["id"],
            item["parentId"],
            item["tag"],
            item["selector"],
            tuple(item["rect"].items()),
            item["domDepth"],
            tuple(item["stackingContext"].items()),
            tuple(item["resourceIds"]),
            tuple(item["memberNodeIds"]),
            item["aggregationRule"],
        )
        for item in record["nodes"]
    )
    links = tuple(
        sorted(
            (item["displayUrl"], item["attributionScope"], tuple(item["attributedNodeIds"]))
            for item in record["resources"]
        )
    )
    counts = (
        record["page"]["rawDomNodeCount"],
        record["page"]["maxDomDepth"],
        record["capture"]["inspectedNodeCount"],
        record["capture"]["candidateNodeCount"],
        record["capture"]["aggregatedNodeCount"],
        record["capture"]["renderedRegionCount"],
    )
    return nodes, links, counts


def main() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    assert_request_policy()
    assert_aggregation_guards()
    summaries = []
    clean_fingerprint = None

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
                assert_rects(record, fixture.expected_rects, result.fixture_node_ids)
                for marker in fixture.expected_excluded_markers:
                    require(marker not in result.fixture_node_ids, f"excluded candidate survived: {marker}")
                require(
                    record["page"]["rawDomNodeCount"] == record["capture"]["inspectedNodeCount"],
                    f"{name} did not inspect every raw element",
                )
                require(
                    record["capture"]["candidateNodeCount"]
                    == len(record["nodes"]) + record["capture"]["aggregatedNodeCount"],
                    f"{name} candidate/aggregation counts drifted",
                )
                require(
                    record["capture"]["renderedRegionCount"] == len(record["nodes"]),
                    f"{name} rendered-region count drifted",
                )
                require(
                    record["capture"]["candidateNodeCount"] < record["capture"]["inspectedNodeCount"],
                    f"{name} candidate filtering excluded nothing",
                )
                require(
                    record["capture"]["aggregatedNodeCount"] == fixture.expected_aggregated_count,
                    f"{name} aggregated {record['capture']['aggregatedNodeCount']} candidates",
                )
                if fixture.expected_rendered_count is not None:
                    require(
                        record["capture"]["renderedRegionCount"] == fixture.expected_rendered_count,
                        f"{name} rendered {record['capture']['renderedRegionCount']} regions",
                    )

                rendered_ids = {item["id"] for item in record["nodes"]}
                member_ids = [
                    member_id
                    for item in record["nodes"]
                    for member_id in item["memberNodeIds"]
                ]
                for marker in fixture.expected_omitted_markers:
                    require(marker in result.fixture_node_ids, f"omitted marker was not a candidate: {marker}")
                    node_id = result.fixture_node_ids[marker]
                    require(node_id not in rendered_ids, f"omitted marker was rendered: {marker}")
                    require(member_ids.count(node_id) == 1, f"omitted marker lost or duplicated: {marker}")
                serialized_record = json.dumps(record, sort_keys=True)
                require("data-xray-id" not in serialized_record, f"{name} leaked fixture attributes")
                require(
                    "secret-123456789012345678901234" not in serialized_record,
                    f"{name} leaked a high-entropy selector token",
                )
                require(
                    "abcdefghijklmnopqrstuvwxyzabcdef" not in serialized_record,
                    f"{name} leaked a long alphabetic selector token",
                )
                if name == "clean":
                    require("xray-redacted" in serialized_record, "selector redaction marker is missing")
                exact_image_links = assert_exact_attribution(record)
                require(
                    exact_image_links == fixture.expected_exact_element_links,
                    f"{name} has {exact_image_links} exact element links",
                )
                cdp_total = assert_transfer(record, fixture.expected_payload_bytes)

                if name == "clean":
                    require(not record["layoutShifts"], "clean fixture recorded a layout shift")
                    require(exact_image_links == 2, "duplicate image URL did not link to both exact elements")
                    clean_fingerprint = deterministic_fingerprint(record)
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
                elif name == "aggregation":
                    require(record["capture"]["candidateNodeCount"] == 723, "aggregation candidate count drifted")
                    require(record["capture"]["renderedRegionCount"] == 650, "aggregation budget drifted")
                    require(record["capture"]["aggregatedNodeCount"] == 73, "aggregation omission count drifted")
                    kept_id = result.fixture_node_ids["agg-tile-646"]
                    omitted_id = result.fixture_node_ids["agg-tile-647"]
                    require(kept_id in rendered_ids, "preorder boundary tile 646 was omitted")
                    require(omitted_id not in rendered_ids, "preorder boundary tile 647 was rendered")
                    main_id = result.fixture_node_ids["agg-main"]
                    main_node = next(item for item in record["nodes"] if item["id"] == main_id)
                    require(len(main_node["memberNodeIds"]) == 73, "aggregation members were not attached to main")
                    expected_members = {
                        result.fixture_node_ids[f"agg-tile-{index:03d}"]
                        for index in range(647, 720)
                    }
                    require(set(member_ids) == expected_members, "aggregation member set is incomplete or extraneous")
                    third_party_hubs = {
                        item["registrableDomain"]
                        for item in record["resources"]
                        if item["party"] == "third" and item["registrableDomain"] is not None
                    }
                    require(
                        len(record["nodes"]) + len(third_party_hubs) <= 650,
                        "rendered nodes and external hubs exceed the scene budget",
                    )

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
                    f"{name}: {record['capture']['candidateNodeCount']} candidates -> "
                    f"{record['capture']['renderedRegionCount']} regions "
                    f"({record['capture']['aggregatedNodeCount']} aggregated), "
                    f"{exact_image_links} exact element links, {len(record['resources'])} requests, "
                    f"{cdp_total} exact CDP/wire bytes"
                )

            clean = FIXTURES["clean"]
            repeat_url = f"http://{clean.host}:{server.server_port}{clean.route}"
            repeated = probe_page(browser, repeat_url).record
            require(
                clean_fingerprint == deterministic_fingerprint(repeated),
                "clean fixture node IDs, parents, geometry, selectors, or attribution changed on repeat",
            )
        finally:
            browser.close()

    print(
        f"Validated controlled Chromium {EXPECTED_CHROMIUM_VERSION} "
        "against 4 deterministic browser fixtures."
    )
    for summary in summaries:
        print(f"  {summary}")
    print("Validated deterministic node and attribution fingerprints across a repeated capture.")
    print("Validated 10 request-policy cases and 5 fixture-boundary cases.")
    print("Validated 3 aggregation safety guards.")


if __name__ == "__main__":
    main()
