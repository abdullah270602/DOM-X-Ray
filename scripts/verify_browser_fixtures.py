"""Run the Gate 0 deterministic pages through controlled Chromium."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fixtures.browser.fixture_server import FIXTURES, run_fixture_server
from fixtures.browser.policy_proxy import run_policy_proxy
from scanner.aggregation import MandatoryOverflowError, aggregate_nodes
from scanner.browser_probe import (
    INTERSTITIAL_CLASSIFIER_VERSION,
    classify_interstitial_v1,
    classify_transfer_source,
    probe_navigation_policy,
    probe_page,
    request_block_reason,
    validate_fixture_target,
)
from scripts.validate_fixtures import ContractError, validate_semantics


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


def assert_transfer(
    record: dict,
    expected_payload_bytes: int,
    expected_missing_byte_count: int = 0,
    excluded_wire_bytes: int = 0,
) -> int:
    known = [item["transferredBytes"] for item in record["resources"] if item["transferredBytes"] is not None]
    missing_count = len(record["resources"]) - len(known)
    require(
        missing_count == expected_missing_byte_count,
        f"fixture has {missing_count} resources with missing CDP byte data",
    )
    total = int(sum(known))
    comparable_total = total - excluded_wire_bytes
    delta = abs(comparable_total - expected_payload_bytes) / expected_payload_bytes
    require(
        delta <= TRANSFER_TOLERANCE,
        f"CDP comparable total {comparable_total} differs from payload "
        f"{expected_payload_bytes} by {delta:.2%}",
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

    try:
        validate_fixture_target("http://localhost:8080/service-worker/")
    except ValueError:
        pass
    else:
        raise AssertionError("fixture-only target boundary accepted localhost without explicit trust")
    validate_fixture_target(
        "http://localhost:8080/service-worker/",
        allow_trusted_loopback=True,
    )
    require(
        [name for name, fixture in FIXTURES.items() if fixture.trusted_loopback]
        == ["service-worker"],
        "trusted-loopback fixture scope expanded beyond the service-worker proof",
    )


def assert_transfer_source_priority() -> None:
    cases = [
        (True, True, 100, "service-worker"),
        (False, True, 100, "cache"),
        (False, False, 0, "network"),
        (False, False, None, "unknown"),
    ]
    for from_worker, from_cache, transferred_bytes, expected in cases:
        actual = classify_transfer_source(
            from_service_worker=from_worker,
            from_cache=from_cache,
            transferred_bytes=transferred_bytes,
        )
        require(actual == expected, f"transfer source priority produced {actual} instead of {expected}")


def assert_interstitial_classifier_guards() -> None:
    strong_login_wall = {
        "visibleFormCount": 1,
        "visibleCredentialFormCount": 1,
        "visiblePasswordInputCount": 1,
        "visibleIdentityInputCount": 1,
        "visibleSubmitControlCount": 1,
        "visibleCompetingContentCount": 0,
    }
    require(
        classify_interstitial_v1(strong_login_wall) == "login-wall",
        "strong credential gate was not classified",
    )
    for signal in (
        "visiblePasswordInputCount",
        "visibleIdentityInputCount",
        "visibleSubmitControlCount",
    ):
        weakened = dict(strong_login_wall)
        weakened[signal] = 0
        require(
            classify_interstitial_v1(weakened) is None,
            f"classifier accepted a credential form without {signal}",
        )
    with_competing_content = dict(strong_login_wall)
    with_competing_content["visibleCompetingContentCount"] = 1
    require(
        classify_interstitial_v1(with_competing_content) is None,
        "classifier ignored competing visible page content",
    )
    with_second_form = dict(strong_login_wall)
    with_second_form["visibleFormCount"] = 2
    require(
        classify_interstitial_v1(with_second_form) is None,
        "classifier ignored a second visible form",
    )


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


def assert_redirect_policy(browser, server, proxy) -> None:
    cases = [
        ("private", "/redirect/private", "private-literal-host", ["/redirect/private"]),
        ("credentials", "/redirect/credentials", "credentials", ["/redirect/credentials"]),
        ("scheme", "/redirect/scheme", "scheme", ["/redirect/scheme"]),
        ("loop", "/redirect/loop/a", "redirect-loop", ["/redirect/loop/a", "/redirect/loop/b"]),
        ("limit", "/redirect/cap/0", "redirect-limit", [f"/redirect/cap/{index}" for index in range(11)]),
    ]
    for label, route, reason, expected_paths in cases:
        server.clear_ledger()
        proxy.clear_state()
        result = probe_navigation_policy(
            browser,
            f"http://redirect.test:{server.server_port}{route}",
            proxy_server=proxy.url,
        )
        require(result.response_status == 403, f"{label} redirect did not become a bounded block response")
        require(not result.blocked_requests, f"{label} unexpectedly relied on the route-only guard")
        require(len(proxy.blocked) == 1, f"{label} redirect was not blocked exactly once")
        blocked = proxy.blocked[0]
        require(blocked["reason"] == reason, f"{label} redirect used block reason {blocked['reason']}")
        require(blocked["redirect"] == "true", f"{label} rejection was not identified as a redirect")
        require("user:secret" not in blocked["url"], f"{label} block evidence leaked credentials")
        observed_paths = [str(item["path"]) for item in server.ledger]
        require(observed_paths == expected_paths, f"{label} server reachability drifted: {observed_paths}")


def assert_redirect_chain_guard(record: dict, validator: Draft202012Validator) -> None:
    reordered = copy.deepcopy(record)
    reordered["resources"].reverse()
    validate_semantics(reordered, "reordered valid redirect chain", validator)

    malformed = copy.deepcopy(record)
    document_hops = [item for item in malformed["resources"] if item["type"] == "document"]
    first_id = document_hops[0]["id"]
    malformed["resources"] = [item for item in malformed["resources"] if item["id"] != first_id]
    malformed["capture"]["requestCount"] -= 1
    next(item for item in malformed["resources"] if item["type"] == "document")[
        "redirectedFromResourceId"
    ] = None
    try:
        validate_semantics(malformed, "missing redirect predecessor", validator)
    except ContractError as error:
        require("skips a hop" in str(error), "redirect-chain guard rejected for the wrong reason")
    else:
        raise AssertionError("semantic validation accepted a redirect chain with its first hop removed")


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
            (
                item["displayUrl"],
                item.get("requestChainId"),
                item.get("redirectHopIndex"),
                item.get("redirectedFromResourceId"),
                item.get("responseStatus"),
                item.get("requestOwner"),
                item["transferSource"],
                item["transferredBytes"],
                item["attributionScope"],
                tuple(item["attributedNodeIds"]),
            )
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
        record["capture"].get("redirectCount"),
        tuple(
            (
                item["hopIndex"],
                item["fromUrl"],
                item["toUrl"],
                item["status"],
                item["followed"],
                item["rejectionCode"],
            )
            for item in record["capture"].get("redirects", [])
        ),
    )
    return nodes, links, counts


def main() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    assert_request_policy()
    assert_transfer_source_priority()
    assert_interstitial_classifier_guards()
    assert_aggregation_guards()
    summaries = []
    clean_fingerprint = None
    redirect_fingerprint = None
    cache_fingerprint = None
    worker_fingerprint = None
    interstitial_fingerprint = None
    policy_fingerprint = None

    with (
        run_fixture_server() as server,
        run_policy_proxy(server.server_port) as proxy,
        sync_playwright() as playwright,
    ):
        browser = playwright.chromium.launch(
            headless=True,
        )
        try:
            require(
                browser.version == EXPECTED_CHROMIUM_VERSION,
                f"Chromium version {browser.version} != pinned proof version {EXPECTED_CHROMIUM_VERSION}",
            )
            for name, fixture in FIXTURES.items():
                server.clear_ledger()
                proxy.clear_state()
                url = f"http://{fixture.host}:{server.server_port}{fixture.route}"
                result = probe_page(
                    browser,
                    url,
                    hard_stop_seconds=fixture.hard_stop_seconds,
                    proxy_server=proxy.url if fixture.use_policy_proxy else None,
                    cache_disabled=fixture.cache_disabled,
                    trusted_loopback_fixture=fixture.trusted_loopback,
                    policy_block_log=proxy.blocked if fixture.use_policy_proxy else None,
                )
                record = result.record
                validate_semantics(
                    record,
                    f"browser fixture {name}",
                    validator,
                    allow_trusted_loopback=fixture.trusted_loopback,
                )
                require(
                    record["status"] == fixture.expected_status,
                    f"{name} has unexpected status {record['status']}",
                )
                require(
                    record["failureCode"] == fixture.expected_failure_code,
                    f"{name} has unexpected failure code {record['failureCode']}",
                )
                require(
                    tuple(record["capture"]["limitsReached"]) == fixture.expected_limits,
                    f"{name} has unexpected capture limits",
                )
                actual_blocks = {
                    (
                        str(item["method"]),
                        urlsplit(str(item["url"])).path,
                        str(item["reason"]),
                    )
                    for item in result.blocked_requests
                }
                require(
                    actual_blocks == set(fixture.expected_blocked_requests),
                    f"{name} policy blocks drifted: {sorted(actual_blocks)}",
                )
                require(
                    all(str(item["redirect"]) == "false" for item in result.blocked_requests),
                    f"{name} subresource block was mislabeled as a redirect",
                )
                require(
                    record["capture"]["requestCount"] == fixture.expected_request_count,
                    f"{name} request count is {record['capture']['requestCount']}",
                )
                require(
                    record["capture"]["redirectCount"] == fixture.expected_redirect_count,
                    f"{name} redirect count is {record['capture']['redirectCount']}",
                )
                require(
                    record["capture"]["cachePolicy"] == ("cold" if fixture.cache_disabled else "mixed"),
                    f"{name} cache policy is mislabeled",
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
                require(
                    "redirect-secret-1234567890" not in serialized_record,
                    f"{name} leaked a redirect query value",
                )
                if name == "clean":
                    require("xray-redacted" in serialized_record, "selector redaction marker is missing")
                exact_image_links = assert_exact_attribution(record)
                require(
                    exact_image_links == fixture.expected_exact_element_links,
                    f"{name} has {exact_image_links} exact element links",
                )
                recorded_resource_urls = {
                    item["displayUrl"] for item in record["resources"]
                }
                blocked_wire = sum(
                    int(item["wireBytes"])
                    for item in result.blocked_requests
                    if str(item["url"]) in recorded_resource_urls
                )
                cdp_total = assert_transfer(
                    record,
                    fixture.expected_payload_bytes,
                    fixture.expected_missing_byte_count,
                    blocked_wire,
                )

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
                elif name == "redirect":
                    require(fixture.expected_final_host is not None, "redirect fixture lacks final host")
                    require(
                        urlsplit(record["finalUrl"]).hostname == fixture.expected_final_host,
                        "redirect final URL does not identify the final host",
                    )
                    require(
                        record["page"]["registrableDomain"] == fixture.expected_final_host,
                        "page party basis did not move to the final host",
                    )
                    hops = record["capture"]["redirects"]
                    require([hop["hopIndex"] for hop in hops] == [1, 2], "redirect hop order drifted")
                    require([hop["status"] for hop in hops] == [302, 307], "redirect statuses drifted")
                    require(
                        [urlsplit(hop["toUrl"]).hostname for hop in hops] == ["middle.test", "final.test"],
                        "redirect targets drifted",
                    )
                    require(
                        all(not urlsplit(hop["toUrl"]).query for hop in hops)
                        and not urlsplit(record["finalUrl"]).query,
                        "redirect query values were persisted",
                    )
                    first_party = [item for item in record["resources"] if item["party"] == "first"]
                    third_party = [item for item in record["resources"] if item["party"] == "third"]
                    require(len(first_party) == 3, f"redirect fixture has {len(first_party)} first-party resources")
                    require(len(third_party) == 3, f"redirect fixture has {len(third_party)} third-party resources")
                    document_hops = [item for item in record["resources"] if item["type"] == "document"]
                    require(
                        [item["redirectHopIndex"] for item in document_hops] == [0, 1, 2],
                        "document redirect hops were collapsed or reordered",
                    )
                    require(
                        [item["responseStatus"] for item in document_hops] == [302, 307, 200],
                        "document redirect response status drifted",
                    )
                    require(
                        [item["redirectedFromResourceId"] for item in document_hops]
                        == [None, document_hops[0]["id"], document_hops[1]["id"]],
                        "document redirect predecessor links drifted",
                    )
                    resources_by_path = {
                        urlsplit(item["displayUrl"]).path: item
                        for item in record["resources"]
                    }
                    require(
                        resources_by_path["/media/redirect-first.svg"]["party"] == "first",
                        "final-host image was not first party",
                    )
                    require(
                        resources_by_path["/media/redirect-third.svg"]["party"] == "third",
                        "redirect-origin image was not third party",
                    )
                    require(
                        "redirect-secret-1234567890" not in json.dumps(proxy.ledger, sort_keys=True),
                        "redirect query value leaked into the proxy ledger",
                    )
                    require(
                        "redirect-secret-1234567890" not in json.dumps(server.ledger, sort_keys=True),
                        "redirect query value leaked into the server ledger",
                    )
                    assert_redirect_chain_guard(record, validator)
                    redirect_fingerprint = deterministic_fingerprint(record)
                elif name == "cache":
                    payload_rows = [
                        item
                        for item in record["resources"]
                        if urlsplit(item["displayUrl"]).path == "/assets/cache-payload.bin"
                    ]
                    require(len(payload_rows) == 2, "cache fixture did not observe both fetches")
                    require(
                        [item["transferSource"] for item in payload_rows] == ["network", "cache"],
                        "cache fixture did not preserve network/cache source order",
                    )
                    require(
                        payload_rows[1]["transferredBytes"] == 0,
                        "cache hit was not preserved as measured zero bytes",
                    )
                    require(
                        sum(item["path"] == "/assets/cache-payload.bin" for item in server.ledger) == 1,
                        "cache payload reached the server more than once",
                    )
                    cache_fingerprint = deterministic_fingerprint(record)
                elif name == "service-worker":
                    worker_rows = [
                        item
                        for item in record["resources"]
                        if urlsplit(item["displayUrl"]).path == "/sw/worker-data"
                    ]
                    require(len(worker_rows) == 1, "service-worker response was not observed exactly once")
                    require(
                        worker_rows[0]["transferSource"] == "service-worker",
                        "worker-produced response was not classified as service-worker",
                    )
                    require(
                        worker_rows[0]["transferredBytes"] == 0,
                        "worker-produced response did not preserve measured zero transfer bytes",
                    )
                    require(
                        worker_rows[0]["requestOwner"] == "page",
                        "worker-produced client response lost page ownership",
                    )
                    shared_asset_rows = [
                        item
                        for item in record["resources"]
                        if urlsplit(item["displayUrl"]).path
                        == "/media/worker-payload.svg"
                    ]
                    require(
                        len(shared_asset_rows) == 2,
                        "same-URL page and worker requests were collapsed or duplicated",
                    )
                    page_asset_rows = [
                        item for item in shared_asset_rows if item["requestOwner"] == "page"
                    ]
                    worker_fetch_rows = [
                        item
                        for item in shared_asset_rows
                        if item["requestOwner"] == "service-worker"
                    ]
                    require(
                        len(page_asset_rows) == 1
                        and page_asset_rows[0]["type"] == "image"
                        and page_asset_rows[0]["attributionScope"] == "exact-element"
                        and page_asset_rows[0]["attributedNodeIds"],
                        "same-URL page image lost its exact element attribution",
                    )
                    require(len(worker_fetch_rows) == 1, "worker-owned fetch was not observed once")
                    require(
                        worker_fetch_rows[0]["requestOwner"] == "service-worker"
                        and worker_fetch_rows[0]["transferSource"] == "network"
                        and worker_fetch_rows[0]["transferredBytes"] is not None,
                        "worker-owned fetch lacks measured worker/network evidence",
                    )
                    require(
                        worker_fetch_rows[0]["attributionScope"] == "page-level"
                        and not worker_fetch_rows[0]["attributedNodeIds"],
                        "worker-owned fetch was incorrectly attributed to an element",
                    )
                    bootstrap_rows = [
                        item
                        for item in record["resources"]
                        if urlsplit(item["displayUrl"]).path == "/sw.js"
                    ]
                    require(len(bootstrap_rows) == 1, "worker bootstrap request was not represented once")
                    require(
                        bootstrap_rows[0]["requestOwner"] == "service-worker"
                        and bootstrap_rows[0]["transferSource"] == "unknown"
                        and bootstrap_rows[0]["transferredBytes"] is None,
                        "worker bootstrap did not preserve its unknown-byte boundary",
                    )
                    require(
                        record["capture"]["requestsWithoutByteData"] == 1,
                        "worker bootstrap missing-byte count drifted",
                    )
                    require(
                        record["capture"]["transferAccountingRule"]
                        == "cdp-page-worker-target-loading-finished-v1",
                        "worker target capture did not select its accounting rule",
                    )
                    require(
                        all(item["path"] != "/sw/worker-data" for item in server.ledger),
                        "worker-produced response unexpectedly reached the origin server",
                    )
                    require(
                        sum(item["path"] == "/sw.js" for item in server.ledger) == 1,
                        "worker script did not reach the origin exactly once",
                    )
                    require(
                        sum(
                            item["path"] == "/media/worker-payload.svg"
                            for item in server.ledger
                        )
                        == 2,
                        "same-URL page and worker requests did not reach the origin twice",
                    )
                    require(
                        record["failureCode"] == "measurement-unavailable",
                        "worker target gap did not mark byte completeness unavailable",
                    )
                    worker_limitations = {
                        item["code"]: item for item in record["limitations"]
                    }
                    require(
                        "service-worker-bootstrap-bytes-unavailable" in worker_limitations,
                        "worker bootstrap byte gap was not disclosed",
                    )
                    require(
                        set(
                            worker_limitations["service-worker-bootstrap-bytes-unavailable"][
                                "invalidatesMetrics"
                            ]
                        )
                        == {"request_count", "total_transferred_bytes"},
                        "worker target gap does not invalidate the affected metrics",
                    )
                    worker_fingerprint = deterministic_fingerprint(record)
                elif name == "never-settling":
                    limitations = {item["code"]: item for item in record["limitations"]}
                    require(
                        set(limitations) == {"settle-timeout"},
                        "DOM churn did not produce only the expected settle timeout",
                    )
                    require(
                        record["capture"]["durationMs"]
                        >= fixture.hard_stop_seconds * 1_000 - 150,
                        "never-settling capture stopped before its hard limit",
                    )
                    require(record["nodes"], "never-settling partial record lost useful geometry")
                    require(
                        sum(item["path"] == "/never-settling/" for item in server.ledger) == 1,
                        "never-settling page was retried",
                    )
                elif name == "unknown-byte":
                    unknown_rows = [
                        item
                        for item in record["resources"]
                        if urlsplit(item["displayUrl"]).path == "/stream/unfinished"
                    ]
                    require(len(unknown_rows) == 1, "unfinished request was not represented once")
                    unknown_row = unknown_rows[0]
                    require(
                        unknown_row["requestOwner"] == "page"
                        and unknown_row["transferSource"] == "unknown"
                        and unknown_row["transferredBytes"] is None,
                        "unfinished request was converted into known or zero-byte evidence",
                    )
                    require(
                        record["capture"]["requestsWithoutByteData"] == 1,
                        "unfinished request missing-byte count drifted",
                    )
                    limitations = {item["code"]: item for item in record["limitations"]}
                    limitation = limitations.get(
                        f"resource-bytes-unavailable-{unknown_row['id']}"
                    )
                    require(limitation is not None, "unfinished request lacks a byte limitation")
                    require(
                        set(limitations)
                        == {
                            "settle-timeout",
                            f"resource-bytes-unavailable-{unknown_row['id']}",
                        },
                        "unfinished request produced an unexpected limitation set",
                    )
                    require(
                        limitation["scope"] == "resource"
                        and limitation["targetId"] == unknown_row["id"]
                        and set(limitation["invalidatesMetrics"])
                        == {"request_count", "resource_mass", "total_transferred_bytes"},
                        "unfinished request limitation has the wrong scope or invalidations",
                    )
                    require(
                        record["capture"]["durationMs"]
                        >= fixture.hard_stop_seconds * 1_000 - 150,
                        "active unfinished request did not hold capture to the hard limit",
                    )
                    require(
                        sum(item["path"] == "/stream/unfinished" for item in server.ledger) == 1,
                        "unfinished request was retried",
                    )
                elif name == "interstitial":
                    serialized = json.dumps(record, sort_keys=True)
                    require(not record["insights"], "interstitial emitted a hero or other insight")
                    limitations = {item["code"]: item for item in record["limitations"]}
                    require(
                        set(limitations) == {INTERSTITIAL_CLASSIFIER_VERSION},
                        "login wall produced an unexpected limitation set",
                    )
                    limitation = limitations[INTERSTITIAL_CLASSIFIER_VERSION]
                    require(
                        limitation["scope"] == "scan"
                        and limitation["targetId"] is None
                        and set(limitation["invalidatesMetrics"])
                        == {"hero_insight", "intended_page_content"},
                        "login-wall limitation has the wrong scope or invalidations",
                    )
                    require(
                        record["requestedUrl"] == record["finalUrl"],
                        "login wall changed the intended destination URL",
                    )
                    require(
                        "form-secret-canary-9472051863" not in serialized
                        and "password-secret-canary-6301847295" not in serialized,
                        "form value leaked into normalized evidence",
                    )
                    require(
                        [(item["method"], item["path"]) for item in server.ledger]
                        == [("GET", "/interstitial/login/")],
                        "login-wall form was submitted or navigation was retried",
                    )
                    interstitial_fingerprint = (
                        record["status"],
                        record["failureCode"],
                        tuple(item["code"] for item in record["limitations"]),
                        deterministic_fingerprint(record),
                    )
                elif name == "policy-boundary":
                    serialized_policy_evidence = json.dumps(
                        {
                            "record": record,
                            "proxyBlocked": result.blocked_requests,
                            "proxyLedger": proxy.ledger,
                            "serverLedger": server.ledger,
                        },
                        sort_keys=True,
                    )
                    require(
                        "unsafe-body-secret-canary-5814072963"
                        not in serialized_policy_evidence,
                        "blocked request body leaked into policy evidence",
                    )
                    require(
                        [(item["method"], item["path"]) for item in server.ledger]
                        == [("GET", "/policy-boundary/")],
                        "a blocked method/private request reached the fixture server",
                    )
                    require(
                        {
                            (
                                str(item["method"]),
                                urlsplit(str(item["url"])).path,
                            )
                            for item in proxy.ledger
                        }
                        == {
                            ("GET", "/policy-boundary/"),
                            ("POST", "/unsafe/post"),
                            ("DELETE", "/unsafe/delete"),
                            ("GET", "/private-fetch"),
                            ("GET", "/private-image"),
                        },
                        "proxy did not observe exactly the allowed page and four blocked attempts",
                    )
                    blocked_resources = [
                        item for item in record["resources"] if item["responseStatus"] == 403
                    ]
                    require(
                        len(blocked_resources) == 2
                        and all(
                            item["transferSource"] == "network"
                            and item["transferredBytes"] is not None
                            for item in blocked_resources
                        ),
                        "proxy block responses lost their completed wire evidence",
                    )
                    blocked_resource_ids = {item["id"] for item in blocked_resources}
                    block_limitations = [
                        item
                        for item in record["limitations"]
                        if item["code"].startswith("blocked-request-")
                    ]
                    require(
                        len(block_limitations) == 4,
                        "policy fixture did not disclose all four blocked attempts",
                    )
                    targeted_block_limitations = [
                        item for item in block_limitations if item["targetId"] is not None
                    ]
                    scan_block_limitations = [
                        item for item in block_limitations if item["targetId"] is None
                    ]
                    require(
                        len(targeted_block_limitations) == 2
                        and {item["targetId"] for item in targeted_block_limitations}
                        == blocked_resource_ids
                        and all(
                            item["scope"] == "resource"
                            and set(item["invalidatesMetrics"])
                            == {
                                "page_behavior",
                                "resource_mass",
                                "total_transferred_bytes",
                            }
                            for item in targeted_block_limitations
                        ),
                        "unsafe-method limitations are not targeted at their resources",
                    )
                    require(
                        len(scan_block_limitations) == 2
                        and all(
                            item["scope"] == "scan"
                            and set(item["invalidatesMetrics"])
                            == {
                                "page_behavior",
                                "request_count",
                                "total_transferred_bytes",
                            }
                            for item in scan_block_limitations
                        ),
                        "private-target limitations do not invalidate omitted request evidence",
                    )
                    require(
                        "127.0.0.1" not in json.dumps(record, sort_keys=True)
                        and "/private-fetch" not in json.dumps(record, sort_keys=True)
                        and "/private-image" not in json.dumps(record, sort_keys=True),
                        "private target provenance leaked into the normalized record",
                    )
                    require(
                        not record["insights"],
                        "blocked policy responses produced an insight",
                    )
                    policy_fingerprint = (
                        record["status"],
                        record["failureCode"],
                        tuple(
                            (
                                item["code"],
                                item["scope"],
                                item["targetId"],
                                tuple(item["invalidatesMetrics"]),
                            )
                            for item in record["limitations"]
                        ),
                        deterministic_fingerprint(record),
                    )

                unobserved_paths = set(fixture.expected_unobserved_paths)
                observed_ledger = [
                    item
                    for item in server.ledger
                    if str(item["path"]) not in unobserved_paths
                ]
                require(
                    {
                        str(item["path"])
                        for item in server.ledger
                        if str(item["path"]) in unobserved_paths
                    }
                    == unobserved_paths,
                    f"{name} unobserved worker-target paths drifted",
                )
                served_payload = sum(
                    int(item["bodyBytes"])
                    for item in observed_ledger
                    if item["status"] == 200
                )
                served_wire = sum(
                    int(item["wireBytes"])
                    for item in observed_ledger
                    if 200 <= int(item["status"]) < 400
                ) + blocked_wire
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
                    f"{cdp_total} known CDP/wire bytes, "
                    f"{record['capture']['requestsWithoutByteData']} missing-byte requests"
                )

            clean = FIXTURES["clean"]
            repeat_url = f"http://{clean.host}:{server.server_port}{clean.route}"
            proxy.clear_state()
            repeated = probe_page(
                browser,
                repeat_url,
                proxy_server=proxy.url,
                policy_block_log=proxy.blocked,
            ).record
            require(
                clean_fingerprint == deterministic_fingerprint(repeated),
                "clean fixture node IDs, parents, geometry, selectors, or attribution changed on repeat",
            )
            redirect = FIXTURES["redirect"]
            redirect_url = f"http://{redirect.host}:{server.server_port}{redirect.route}"
            server.clear_ledger()
            proxy.clear_state()
            repeated_redirect = probe_page(
                browser,
                redirect_url,
                proxy_server=proxy.url,
                policy_block_log=proxy.blocked,
            ).record
            require(
                redirect_fingerprint == deterministic_fingerprint(repeated_redirect),
                "redirect hop IDs, predecessors, URLs, statuses, or attribution changed on repeat",
            )
            cache = FIXTURES["cache"]
            cache_url = f"http://{cache.host}:{server.server_port}{cache.route}"
            server.clear_ledger()
            proxy.clear_state()
            repeated_cache = probe_page(
                browser,
                cache_url,
                proxy_server=proxy.url,
                cache_disabled=False,
                policy_block_log=proxy.blocked,
            ).record
            require(
                cache_fingerprint == deterministic_fingerprint(repeated_cache),
                "cache request order, sources, bytes, or geometry changed on repeat",
            )
            worker = FIXTURES["service-worker"]
            worker_url = f"http://{worker.host}:{server.server_port}{worker.route}"
            server.clear_ledger()
            repeated_worker = probe_page(
                browser,
                worker_url,
                trusted_loopback_fixture=True,
            ).record
            require(
                worker_fingerprint == deterministic_fingerprint(repeated_worker),
                "worker target attachment, ownership, sources, bytes, or geometry changed on repeat",
            )
            interstitial = FIXTURES["interstitial"]
            interstitial_url = (
                f"http://{interstitial.host}:{server.server_port}{interstitial.route}"
            )
            server.clear_ledger()
            proxy.clear_state()
            repeated_interstitial = probe_page(
                browser,
                interstitial_url,
                proxy_server=proxy.url,
                policy_block_log=proxy.blocked,
            ).record
            repeated_interstitial_fingerprint = (
                repeated_interstitial["status"],
                repeated_interstitial["failureCode"],
                tuple(item["code"] for item in repeated_interstitial["limitations"]),
                deterministic_fingerprint(repeated_interstitial),
            )
            require(
                interstitial_fingerprint == repeated_interstitial_fingerprint,
                "interstitial classification, limitation, or geometry changed on repeat",
            )
            policy = FIXTURES["policy-boundary"]
            policy_url = f"http://{policy.host}:{server.server_port}{policy.route}"
            server.clear_ledger()
            proxy.clear_state()
            repeated_policy = probe_page(
                browser,
                policy_url,
                proxy_server=proxy.url,
                policy_block_log=proxy.blocked,
            ).record
            repeated_policy_fingerprint = (
                repeated_policy["status"],
                repeated_policy["failureCode"],
                tuple(
                    (
                        item["code"],
                        item["scope"],
                        item["targetId"],
                        tuple(item["invalidatesMetrics"]),
                    )
                    for item in repeated_policy["limitations"]
                ),
                deterministic_fingerprint(repeated_policy),
            )
            require(
                policy_fingerprint == repeated_policy_fingerprint,
                "policy block resources, limitations, or geometry changed on repeat",
            )
            assert_redirect_policy(browser, server, proxy)
        finally:
            browser.close()

    print(
        f"Validated controlled Chromium {EXPECTED_CHROMIUM_VERSION} "
        f"against {len(FIXTURES)} deterministic browser fixtures."
    )
    for summary in summaries:
        print(f"  {summary}")
    print(
        "Validated deterministic node, redirect, attribution, source, interstitial, and policy fingerprints "
        "across repeated captures."
    )
    print("Validated 10 request-policy cases and 5 fixture-boundary cases.")
    print("Validated 4 transfer-source priority cases.")
    print("Validated 6 interstitial-classifier safety guards.")
    print("Validated 3 aggregation safety guards.")
    print("Validated 5 browser-enforced redirect rejection cases.")
    print("Validated 4 live unsafe-method/private-subresource blocks.")
    print("Validated 1 redirect-chain negative control.")


if __name__ == "__main__":
    main()
