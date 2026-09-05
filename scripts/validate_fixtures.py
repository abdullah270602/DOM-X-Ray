"""Validate DOM X-Ray Gate 0 scan fixtures.

This is contract tooling, not an application-stack decision. It combines JSON
Schema Draft 2020-12 validation with cross-record invariants that JSON Schema
cannot express reliably (foreign keys, counts, provenance, and claim rules).
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs" / "SCAN_RECORD.schema.json"
FIXTURE_DIR = ROOT / "fixtures" / "scan"
FIXTURE_NAMES = ("clean.json", "image-heavy.json", "third-party-heavy.json")


class ContractError(AssertionError):
    """Raised when a fixture violates a DOM X-Ray semantic invariant."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def unique_index(items: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        item_id = item["id"]
        require(item_id not in result, f"duplicate {label} id: {item_id}")
        result[item_id] = item
    return result


def resolve_pointer(document: Any, reference: str) -> Any:
    require(reference.startswith("#/"), f"evidence reference is not a JSON Pointer: {reference}")
    current = document
    for token in reference[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            require(token.isdigit(), f"array pointer token is not an index: {reference}")
            index = int(token)
            require(index < len(current), f"array pointer is out of range: {reference}")
            current = current[index]
        else:
            require(isinstance(current, dict) and token in current, f"unresolved evidence pointer: {reference}")
            current = current[token]
    return current


def validate_public_url(
    value: str,
    label: str,
    *,
    origin_only: bool = False,
    allow_trusted_loopback: bool = False,
) -> None:
    parsed = urlsplit(value)
    require(parsed.scheme in {"http", "https"}, f"{label} is not HTTP(S): {value}")
    require(bool(parsed.hostname), f"{label} has no hostname: {value}")
    require(parsed.username is None and parsed.password is None, f"{label} contains credentials")
    require(not parsed.query and not parsed.fragment, f"{label} contains query or fragment data")

    if origin_only:
        normalized = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        require(value == normalized, f"{label} is not an origin: {value}")

    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None

    if address is not None:
        require(address.is_global, f"{label} points to a non-public address: {value}")

    hostname = parsed.hostname.lower()
    forbidden_hosts = {"localhost", "metadata.google.internal"}
    require(
        hostname not in forbidden_hosts or (allow_trusted_loopback and hostname == "localhost"),
        f"{label} uses a forbidden host",
    )


def validate_semantics(
    record: dict[str, Any],
    label: str,
    validator: Draft202012Validator,
    *,
    allow_trusted_loopback: bool = False,
) -> None:
    schema_errors = sorted(validator.iter_errors(record), key=lambda error: list(error.path))
    if schema_errors:
        details = "; ".join(
            f"/{'/'.join(str(part) for part in error.path)}: {error.message}"
            for error in schema_errors[:8]
        )
        raise ContractError(f"{label} failed JSON Schema: {details}")

    nodes = unique_index(record["nodes"], "node")
    resources = unique_index(record["resources"], "resource")
    shifts = unique_index(record["layoutShifts"], "layout shift")
    insights = unique_index(record["insights"], "insight")
    limitations: dict[str, dict[str, Any]] = {}
    for limitation in record["limitations"]:
        code = limitation["code"]
        require(code not in limitations, f"duplicate limitation code: {code}")
        limitations[code] = limitation

    require(record["schemaVersion"] == "0.1.0", f"{label} uses an unexpected schema version")
    require(record["capture"]["requestCount"] == len(resources), f"{label} request count mismatch")
    require(record["capture"]["renderedRegionCount"] == len(nodes), f"{label} rendered-region count mismatch")

    capture = record["capture"]
    if "redirects" in capture:
        redirects = capture["redirects"]
        require(capture["redirectCount"] == len(redirects), f"{label} redirect count mismatch")
        require(
            capture["redirectCount"] <= capture["redirectLimit"] or "redirects" in capture["limitsReached"],
            f"{label} exceeds its redirect limit without recording the limit",
        )
        require(
            [hop["hopIndex"] for hop in redirects] == list(range(1, len(redirects) + 1)),
            f"{label} redirect hops are not contiguous and ordered",
        )
        for hop in redirects:
            validate_public_url(
                hop["fromUrl"],
                f"{label} redirect source",
                allow_trusted_loopback=allow_trusted_loopback,
            )
            validate_public_url(
                hop["toUrl"],
                f"{label} redirect target",
                allow_trusted_loopback=allow_trusted_loopback,
            )
            if hop["followed"]:
                require(hop["rejectionCode"] is None, f"{label} followed a rejected redirect")
            else:
                require(bool(hop["rejectionCode"]), f"{label} rejected redirect lacks a reason")

    member_ids = [member for node in nodes.values() for member in node["memberNodeIds"]]
    require(len(member_ids) == len(set(member_ids)), f"{label} repeats an aggregated member id")
    require(not (set(member_ids) & set(nodes)), f"{label} exposes an aggregated member as a rendered node")
    require(
        record["capture"]["aggregatedNodeCount"] == len(member_ids),
        f"{label} aggregated-node count mismatch",
    )
    require(
        record["capture"]["candidateNodeCount"] == len(nodes) + len(member_ids),
        f"{label} candidate-node count mismatch",
    )
    require(
        record["page"]["rawDomNodeCount"] >= record["capture"]["inspectedNodeCount"],
        f"{label} inspected-node count exceeds raw DOM count",
    )
    require(
        record["capture"]["inspectedNodeCount"] >= record["capture"]["candidateNodeCount"],
        f"{label} candidate-node count exceeds inspected-node count",
    )

    for node in nodes.values():
        if node["parentId"] is not None:
            require(node["parentId"] in nodes, f"{label} has orphan parent {node['parentId']}")
            require(node["parentId"] != node["id"], f"{label} has a self-parented node {node['id']}")
        if node["memberNodeIds"]:
            require(bool(node.get("aggregationRule")), f"{label} aggregated node lacks a rule: {node['id']}")
        for resource_id in node["resourceIds"]:
            require(resource_id in resources, f"{label} node links unknown resource {resource_id}")
            require(
                node["id"] in resources[resource_id]["attributedNodeIds"],
                f"{label} node/resource link is not symmetric: {node['id']} -> {resource_id}",
            )

    for node_id in nodes:
        seen: set[str] = set()
        current_id: str | None = node_id
        while current_id is not None:
            require(current_id not in seen, f"{label} has a parent cycle at {current_id}")
            seen.add(current_id)
            current_id = nodes[current_id]["parentId"]

    redirect_hops_by_chain: dict[tuple[str, int], str] = {}
    for resource in resources.values():
        if "requestChainId" not in resource:
            continue
        chain_key = (resource["requestChainId"], resource["redirectHopIndex"])
        require(chain_key not in redirect_hops_by_chain, f"{label} repeats request-chain hop {chain_key}")
        redirect_hops_by_chain[chain_key] = resource["id"]

    missing_byte_count = 0
    for resource in resources.values():
        validate_public_url(
            resource["displayUrl"],
            f"{label} resource URL",
            allow_trusted_loopback=allow_trusted_loopback,
        )
        validate_public_url(
            resource["origin"],
            f"{label} resource origin",
            origin_only=True,
            allow_trusted_loopback=allow_trusted_loopback,
        )
        require(bool(resource["partyRule"]), f"{label} resource has no party rule: {resource['id']}")
        registrable_domain = resource["registrableDomain"]
        if registrable_domain is None:
            require(resource["party"] == "unknown", f"{label} null registrable domain has known party")
        elif registrable_domain == record["page"]["registrableDomain"]:
            require(resource["party"] == "first", f"{label} same-site resource is not first party")
        else:
            require(resource["party"] == "third", f"{label} external site resource is not third party")
        if resource["transferredBytes"] is None:
            missing_byte_count += 1
        scope = resource["attributionScope"]
        targets = resource["attributedNodeIds"]
        if scope in {"exact-element", "exact-resource-link"}:
            require(bool(targets), f"{label} exact attribution has no node: {resource['id']}")
        if scope in {"page-level", "unknown"}:
            require(not targets, f"{label} page-level attribution names a node: {resource['id']}")
        for node_id in targets:
            require(node_id in nodes, f"{label} resource links unknown node {node_id}")
            require(
                resource["id"] in nodes[node_id]["resourceIds"],
                f"{label} resource/node link is not symmetric: {resource['id']} -> {node_id}",
            )

        if "requestChainId" in resource:
            previous_id = resource["redirectedFromResourceId"]
            if resource["redirectHopIndex"] == 0:
                require(previous_id is None, f"{label} initial request hop has a predecessor")
            else:
                previous_key = (
                    resource["requestChainId"],
                    resource["redirectHopIndex"] - 1,
                )
                require(previous_key in redirect_hops_by_chain, f"{label} redirect chain skips a hop")
                expected_previous = redirect_hops_by_chain[previous_key]
                require(
                    previous_id == expected_previous,
                    f"{label} redirect predecessor does not match its chain",
                )

    require(
        record["capture"]["requestsWithoutByteData"] == missing_byte_count,
        f"{label} missing-byte count mismatch",
    )

    for shift in shifts.values():
        for source in shift["sources"]:
            if source["nodeId"] is not None:
                require(source["nodeId"] in nodes, f"{label} layout shift links an unknown node")

    hero_insights = [insight for insight in insights.values() if insight["hero"]]
    require(len(hero_insights) <= 1, f"{label} has more than one hero insight")
    banned_claim = re.compile(r"\b(trackers?|spying|bloated|carbon|gpu layer|always)\b", re.IGNORECASE)

    for insight in insights.values():
        require(not banned_claim.search(insight["statement"]), f"{label} contains prohibited claim language")
        require("captured" in insight["statement"].lower(), f"{label} claim is not scoped to the capture")
        primary = [evidence for evidence in insight["evidence"] if evidence["role"] == "primary"]
        require(len(primary) == 1, f"{label} insight needs exactly one primary metric")
        require(len(insight["evidence"]) - 1 <= 3, f"{label} insight has too many support metrics")
        if insight["hero"]:
            require(primary[0]["level"] in {"observed", "derived"}, f"{label} hero uses classified evidence")
            require(isinstance(primary[0]["value"], (int, float)), f"{label} hero primary is not numeric")
        for evidence in insight["evidence"]:
            require(bool(evidence["unit"]), f"{label} evidence has an empty unit")
            if evidence["level"] == "classified":
                require("classifier" in evidence, f"{label} classified evidence lacks classifier metadata")
            for reference in evidence["sourceRefs"]:
                resolve_pointer(record, reference)
        for limitation_code in insight["limitationCodes"]:
            require(limitation_code in limitations, f"{label} insight names unknown limitation {limitation_code}")

    target_indexes = {
        "node": nodes,
        "resource": resources,
        "layout-shift": shifts,
        "insight": insights,
    }
    for limitation in limitations.values():
        scope = limitation["scope"]
        target_id = limitation.get("targetId")
        if scope in target_indexes:
            require(target_id in target_indexes[scope], f"{label} limitation has an unknown target")
        else:
            require(target_id is None, f"{label} scan/page limitation must not name an object")

    if record["status"] == "complete":
        require(record["failureCode"] is None, f"{label} complete scan has a failure code")
    if record["status"] in {"partial", "interstitial", "blocked", "failed"}:
        require(record["failureCode"] is not None, f"{label} non-complete scan lacks a failure code")
        require(bool(limitations), f"{label} non-complete scan lacks a limitation")
    if record["status"] in {"blocked", "failed"}:
        require(not nodes and not insights, f"{label} blocked/failed scan contains a simulated scene")
    if record["status"] == "interstitial":
        require(not insights, f"{label} interstitial capture contains a hero claim")

    validate_public_url(
        record["requestedUrl"],
        f"{label} requested URL",
        allow_trusted_loopback=allow_trusted_loopback,
    )
    if record["finalUrl"] is not None:
        validate_public_url(
            record["finalUrl"],
            f"{label} final URL",
            allow_trusted_loopback=allow_trusted_loopback,
        )

    screenshot_status = record["page"]["screenshotStatus"]
    screenshot_ref = record["page"]["screenshotRef"]
    require(
        (screenshot_status == "captured" and isinstance(screenshot_ref, str) and bool(screenshot_ref))
        or (screenshot_status in {"unavailable", "omitted"} and screenshot_ref is None),
        f"{label} screenshot status/reference mismatch",
    )

    if record["scanId"] == "fixture-clean":
        hero = hero_insights[0]
        require(hero["evidence"][0]["value"] == record["page"]["rawDomNodeCount"], "clean hero mismatch")
    elif record["scanId"] == "fixture-image-heavy":
        known = [resource for resource in resources.values() if resource["transferredBytes"] is not None]
        total = sum(resource["transferredBytes"] for resource in known)
        image_total = sum(resource["transferredBytes"] for resource in known if resource["type"] == "image")
        expected_share = round(image_total * 1000 / total) / 10
        require(total == 5_200_000, "image-heavy total changed unexpectedly")
        require(hero_insights[0]["evidence"][0]["value"] == expected_share, "image share hero mismatch")
    elif record["scanId"] == "fixture-third-party-heavy":
        third_party = sum(resource["party"] == "third" for resource in resources.values())
        require(third_party == 4, "third-party fixture count changed unexpectedly")
        require(hero_insights[0]["evidence"][0]["value"] == third_party, "third-party hero mismatch")
        require(
            any("total_transferred_bytes" in item["invalidatesMetrics"] for item in limitations.values()),
            "unknown bytes do not suppress byte-total claims",
        )


def expect_failure(
    name: str,
    baseline: dict[str, Any],
    mutate: Callable[[dict[str, Any]], None],
    validator: Draft202012Validator,
) -> None:
    candidate = copy.deepcopy(baseline)
    mutate(candidate)
    try:
        validate_semantics(candidate, f"negative control {name}", validator)
    except ContractError:
        return
    raise ContractError(f"negative control was not rejected: {name}")


def main() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    records: dict[str, dict[str, Any]] = {}
    for fixture_name in FIXTURE_NAMES:
        path = FIXTURE_DIR / fixture_name
        record = json.loads(path.read_text(encoding="utf-8"))
        validate_semantics(record, fixture_name, validator)
        records[fixture_name] = record

    clean = records["clean.json"]

    expect_failure("duplicate node id", clean, lambda item: item["nodes"].append(copy.deepcopy(item["nodes"][0])), validator)
    expect_failure("orphan evidence pointer", clean, lambda item: item["insights"][0]["evidence"][0]["sourceRefs"].append("#/missing/value"), validator)
    expect_failure("two hero insights", clean, lambda item: item["insights"].append(copy.deepcopy(item["insights"][0])), validator)
    expect_failure("missing aggregation rule", clean, lambda item: item["nodes"][1].update({"aggregationRule": None}), validator)
    expect_failure("missing-byte count drift", clean, lambda item: item["resources"][0].update({"transferredBytes": None}), validator)
    expect_failure("prohibited tracker claim", clean, lambda item: item["insights"][0].update({"statement": "4 trackers in this captured load."}), validator)
    expect_failure("blocked scene", clean, lambda item: item.update({"status": "blocked", "failureCode": "blocked-by-policy"}), validator)
    expect_failure("page-level element blame", clean, lambda item: item["resources"][0].update({"attributedNodeIds": ["n-body"]}), validator)
    expect_failure("party/domain mismatch", clean, lambda item: item["resources"][0].update({"registrableDomain": "other.example"}), validator)
    expect_failure("candidate count drift", clean, lambda item: item["capture"].update({"candidateNodeCount": 10}), validator)
    expect_failure("inspected count exceeds raw DOM", clean, lambda item: item["page"].update({"rawDomNodeCount": 10}), validator)
    expect_failure("parent cycle", clean, lambda item: item["nodes"][0].update({"parentId": "n-logo"}), validator)

    print(f"Validated {len(records)} fixtures and 12 negative controls against Gate 0.")


if __name__ == "__main__":
    main()
