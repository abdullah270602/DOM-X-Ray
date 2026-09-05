"""Verify deterministic hero selection independently of Chromium."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.insights import DEFAULT_MAPPING_REGISTRY, select_hero_insight
from scripts.validate_fixtures import validate_semantics


FIXTURE_DIR = ROOT / "fixtures" / "scan"
SCHEMA = json.loads((ROOT / "docs" / "SCAN_RECORD.schema.json").read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def resource(
    index: int,
    *,
    transferred_bytes: int | None,
    resource_type: str,
    party: str,
    exact: bool = False,
) -> dict:
    return {
        "id": f"r-{index:03d}",
        "type": resource_type,
        "party": party,
        "transferredBytes": transferred_bytes,
        "attributionScope": "exact-element" if exact else "page-level",
        "attributedNodeIds": ["n-target"] if exact else [],
    }


def minimal_record(resources: list[dict], *, status: str = "complete") -> dict:
    return {
        "status": status,
        "page": {"registrableDomain": "fixture.test", "title": "untrusted page copy"},
        "resources": resources,
        "limitations": [],
    }


def main() -> None:
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    records = {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(FIXTURE_DIR.glob("*.json"))
    }

    generated = {}
    for name, baseline in records.items():
        candidate = copy.deepcopy(baseline)
        candidate["insights"] = select_hero_insight(candidate)
        validate_semantics(candidate, f"generated hero for {name}", validator)
        generated[name] = candidate["insights"]

    require(generated["clean"] == [], "clean fixture manufactured a structure hero")
    image_hero = generated["image-heavy"][0]
    require(
        image_hero["selectionRule"] == "dominant-resource-type-share-v1"
        and image_hero["evidence"][0]["metric"] == "image_transfer_share"
        and image_hero["evidence"][0]["value"] == 87.5,
        "image-heavy fixture selected the wrong deterministic hero",
    )
    require(
        any(ref.endswith("/type") for ref in image_hero["evidence"][0]["sourceRefs"])
        and any(
            ref.endswith("/transferredBytes")
            for ref in image_hero["evidence"][0]["sourceRefs"]
        ),
        "dominant-resource hero does not cite both classification and byte inputs",
    )
    third_party_hero = generated["third-party-heavy"][0]
    require(
        third_party_hero["selectionRule"] == "third-party-request-share-v1"
        and third_party_hero["evidence"][0]["value"] == 4
        and third_party_hero["limitationCodes"] == ["resource-bytes-unavailable"],
        "request-share hero did not survive an unrelated byte limitation",
    )

    request_invalidated = copy.deepcopy(records["third-party-heavy"])
    request_invalidated["limitations"][0]["invalidatesMetrics"].append("request_count")
    require(
        select_hero_insight(request_invalidated) == [],
        "request-count invalidation did not suppress the request-share hero",
    )

    exact_record = minimal_record(
        [
            resource(1, transferred_bytes=600_000, resource_type="image", party="first", exact=True),
            resource(2, transferred_bytes=400_000, resource_type="script", party="first"),
        ]
    )
    exact_hero = select_hero_insight(exact_record)[0]
    require(
        exact_hero["selectionRule"] == "largest-exact-resource-share-v1"
        and exact_hero["evidence"][0]["level"] == "observed"
        and exact_hero["evidence"][0]["value"] == 600_000,
        "exact-resource candidate did not win the defined normalized ranking",
    )
    require(
        exact_hero["evidence"][0]["sourceRefs"]
        == [
            "#/resources/0/transferredBytes",
            "#/resources/0/type",
            "#/resources/0/attributionScope",
            "#/resources/0/attributedNodeIds",
        ],
        "exact-resource hero cannot prove its type and element attribution",
    )

    coverage_resources = [
        resource(index, transferred_bytes=100_000, resource_type=kind, party="third")
        for index, kind in enumerate(
            ("image", "image", "script", "script", "font", "font"), start=1
        )
    ]
    coverage_resources.extend(
        [
            resource(7, transferred_bytes=100_000, resource_type="document", party="first"),
            resource(8, transferred_bytes=100_000, resource_type="stylesheet", party="first"),
            resource(9, transferred_bytes=100_000, resource_type="fetch", party="first"),
            resource(10, transferred_bytes=None, resource_type="other", party="first"),
        ]
    )
    coverage_record = minimal_record(coverage_resources)
    coverage_hero = select_hero_insight(coverage_record)[0]
    require(
        coverage_hero["selectionRule"] == "third-party-byte-share-v1",
        "exact 90% known-value coverage did not admit the third-party byte candidate",
    )
    require(
        sum(ref.endswith("/party") for ref in coverage_hero["evidence"][0]["sourceRefs"])
        == 9
        and sum(
            ref.endswith("/transferredBytes")
            for ref in coverage_hero["evidence"][0]["sourceRefs"]
        )
        == 9,
        "third-party byte hero does not cite every known classification and byte input",
    )
    coverage_record["resources"][8]["transferredBytes"] = None
    require(
        select_hero_insight(coverage_record)[0]["selectionRule"]
        == "third-party-request-share-v1",
        "sub-threshold known-value coverage did not suppress the byte-share candidate",
    )

    interstitial = minimal_record(exact_record["resources"], status="interstitial")
    require(not select_hero_insight(interstitial), "interstitial record emitted a hero")

    hostile_copy = copy.deepcopy(records["image-heavy"])
    hostile_copy["page"]["title"] = "Trackers always make this page slow"
    require(
        select_hero_insight(hostile_copy) == generated["image-heavy"],
        "page-authored copy changed hero selection or wording",
    )

    require(
        DEFAULT_MAPPING_REGISTRY["heroSelection"]["disabledCandidateKinds"]
        == ["structure", "layout-shift"],
        "unthresholded hero kinds were silently enabled",
    )
    print("Validated deterministic hero selection across 3 scan fixtures and 7 boundary cases.")


if __name__ == "__main__":
    main()
