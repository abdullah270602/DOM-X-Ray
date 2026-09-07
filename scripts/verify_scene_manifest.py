"""Verify deterministic renderer-neutral scene manifests without WebGL."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.scene_manifest import (  # noqa: E402
    DEFAULT_MAPPING_REGISTRY,
    SceneManifestError,
    build_scene_manifest,
    stable_manifest_json,
)


FIXTURE_DIR = ROOT / "fixtures" / "scan"
FIXTURE_NAMES = ("clean.json", "image-heavy.json", "third-party-heavy.json")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {row["id"]: row for row in rows}


def resource_copy(
    template: dict[str, Any],
    *,
    resource_id: str,
    party: str = "first",
    domain: str | None = "clean.example",
    source: str = "network",
    transferred_bytes: int | None = 100,
    scope: str = "page-level",
    targets: list[str] | None = None,
    response_status: int | None | object = ...,
) -> dict[str, Any]:
    result = copy.deepcopy(template)
    result.update(
        {
            "id": resource_id,
            "displayUrl": f"https://{domain or 'unknown.example'}/{resource_id}",
            "origin": f"https://{domain or 'unknown.example'}",
            "registrableDomain": domain,
            "party": party,
            "transferSource": source,
            "transferredBytes": transferred_bytes,
            "decodedBodyBytes": transferred_bytes,
            "attributionScope": scope,
            "attributedNodeIds": targets or [],
        }
    )
    if response_status is ...:
        result.pop("responseStatus", None)
    else:
        result["responseStatus"] = response_status
    return result


def exercise_transfer_and_endpoint_matrix() -> None:
    record = load_fixture("clean.json")
    template = record["resources"][0]
    record["nodes"].append(
        {
            "id": "n-evidence-only",
            "parentId": "n-body",
            "tag": "img",
            "selector": "[data-evidence-only]",
            "rect": {"x": 20, "y": 20, "width": 40, "height": 40},
            "domDepth": 2,
            "stackingContext": {"creates": False, "rule": None},
            "memberNodeIds": [],
            "aggregationRule": None,
            "resourceIds": ["r-evidence-only"],
            "sceneIncluded": False,
        }
    )
    additions = [
        resource_copy(
            template,
            resource_id="r-cache-zero",
            source="cache",
            transferred_bytes=0,
            scope="exact-element",
            targets=["n-logo"],
            response_status=200,
        ),
        resource_copy(
            template,
            resource_id="r-worker-zero",
            source="service-worker",
            transferred_bytes=0,
            scope="exact-element",
            targets=["n-logo"],
            response_status=200,
        ),
        resource_copy(
            template,
            resource_id="r-network-zero",
            source="network",
            transferred_bytes=0,
            scope="exact-element",
            targets=["n-logo"],
            response_status=200,
        ),
        resource_copy(
            template,
            resource_id="r-unknown",
            source="unknown",
            transferred_bytes=None,
            scope="probable-link",
            targets=["n-main"],
        ),
        resource_copy(
            template,
            resource_id="r-blocked",
            party="third",
            domain="blocked.example",
            source="unknown",
            transferred_bytes=1_100,
            scope="exact-element",
            targets=["n-logo"],
            response_status=None,
        ),
        resource_copy(
            template,
            resource_id="r-third-exact",
            party="third",
            domain="cdn.example",
            transferred_bytes=500,
            scope="exact-resource-link",
            targets=["n-logo"],
            response_status=200,
        ),
        resource_copy(
            template,
            resource_id="r-third-probable",
            party="third",
            domain="api.example",
            transferred_bytes=300,
            scope="probable-link",
            targets=["n-main"],
            response_status=200,
        ),
        resource_copy(
            template,
            resource_id="r-mass-invalid",
            party="third",
            domain="cdn.example",
            transferred_bytes=900,
            scope="exact-element",
            targets=["n-logo"],
            response_status=200,
        ),
        resource_copy(
            template,
            resource_id="r-evidence-only",
            transferred_bytes=700,
            scope="exact-element",
            targets=["n-evidence-only"],
            response_status=200,
        ),
        resource_copy(
            template,
            resource_id="r-party-unknown",
            party="unknown",
            domain=None,
            transferred_bytes=None,
            scope="unknown",
        ),
        resource_copy(
            template,
            resource_id="r-incomplete",
            source="unknown",
            transferred_bytes=None,
            response_status=None,
        ),
    ]
    record["resources"].extend(additions)
    record["nodes"][2]["resourceIds"].extend(
        [
            "r-cache-zero",
            "r-worker-zero",
            "r-network-zero",
            "r-blocked",
            "r-third-exact",
            "r-mass-invalid",
        ]
    )
    record["nodes"][3]["resourceIds"].extend(["r-unknown", "r-third-probable"])
    record["limitations"].append(
        {
            "code": "blocked-request-1",
            "scope": "resource",
            "targetId": "r-blocked",
            "message": "Synthetic blocked request.",
            "invalidatesMetrics": ["resource_mass"],
        }
    )
    record["limitations"].append(
        {
            "code": "synthetic-resource-mass-invalid",
            "scope": "resource",
            "targetId": "r-mass-invalid",
            "message": "Synthetic targeted mass invalidation.",
            "invalidatesMetrics": ["resource_mass"],
        }
    )
    record["limitations"].append(
        {
            "code": "synthetic-scan-partial",
            "scope": "scan",
            "targetId": None,
            "message": "Synthetic scan-level incompleteness.",
            "invalidatesMetrics": ["resource_mass", "total_transferred_bytes"],
        }
    )

    manifest = build_scene_manifest(record)
    connections = by_id(manifest["connections"])
    require(connections["connection:r-cache-zero"]["visualState"] == "cached-hollow", "cache zero collapsed")
    require(connections["connection:r-worker-zero"]["visualState"] == "service-worker-hollow", "worker zero collapsed")
    require(connections["connection:r-network-zero"]["visualState"] == "measured-zero-hollow", "network zero collapsed")
    require(connections["connection:r-unknown"]["visualState"] == "hatched-hollow", "unknown bytes collapsed")
    require(connections["connection:r-blocked"]["visualState"] == "broken-outline", "blocked response collapsed")
    require(connections["connection:r-incomplete"]["visualState"] == "broken-outline", "incomplete response collapsed")
    require(connections["connection:r-third-exact"]["visualState"] == "solid", "known response lost mass")
    require(connections["connection:r-mass-invalid"]["visualState"] == "limitation-hatched", "targeted mass invalidation remained solid")
    require(connections["connection:r-mass-invalid"]["measurement"]["mass"] is None, "targeted invalid mass survived")

    exact = connections["connection:r-third-exact"]
    require(exact["sourceObjectId"] == "hub:cdn.example", "third-party source did not use its hub")
    require(exact["targetObjectIds"] == ["region:n-logo"], "exact endpoint did not use its region")
    probable = connections["connection:r-unknown"]
    require(probable["targetObjectIds"] == ["bus:page"], "probable link escaped the page bus")
    require(probable["sourceObjectId"] == "bus:page", "first-party source escaped the page bus")
    third_probable = connections["connection:r-third-probable"]
    require(third_probable["sourceObjectId"] == "hub:api.example", "probable third-party source missed its hub")
    require(third_probable["targetObjectIds"] == ["bus:page"], "probable third-party target escaped the bus")
    evidence_only = connections["connection:r-evidence-only"]
    require(not evidence_only["targetObjectIds"], "evidence-only node became a scene endpoint")
    require(evidence_only["fallbackObjectId"] == "bus:page", "evidence-only exact link lacks display fallback")
    require(
        evidence_only["evidenceOnlyTargetNodeIds"] == ["n-evidence-only"],
        "evidence-only exact identity was lost",
    )
    unknown_party = connections["connection:r-party-unknown"]
    require(unknown_party["sourceObjectId"] == "bus:page", "unknown party invented an external hub")

    objects = by_id(manifest["objects"])
    logo_weight = objects["region:n-logo"]["weight"]
    require(logo_weight["knownTransferredBytes"] == 24_500, "region exact-byte sum drifted")
    require("r-unknown" not in logo_weight["knownResourceIds"], "probable bytes entered region mass")
    require(logo_weight["blockedResourceIds"] == ["r-blocked"], "blocked exact resource entered mass")
    require(
        logo_weight["massSuppressedResourceIds"] == ["r-blocked", "r-mass-invalid"],
        "targeted mass suppression did not reach the region",
    )
    require(
        connections["connection:r-logo"]["measurement"]["mass"] is not None,
        "scan-level partiality erased a valid observed resource",
    )
    require(objects["region:n-main"]["weight"]["knownTransferredBytes"] is None, "probable link created region mass")
    require("region:n-evidence-only" not in objects, "evidence-only node became a scene object")
    require(manifest["budget"]["countedObjectCount"] == 7, "synthetic hub budget drifted")


def expect_manifest_failure(
    name: str,
    record: dict[str, Any],
    registry: dict[str, Any],
    mutate: Callable[[dict[str, Any], dict[str, Any]], None],
) -> None:
    candidate_record = copy.deepcopy(record)
    candidate_registry = copy.deepcopy(registry)
    mutate(candidate_record, candidate_registry)
    try:
        build_scene_manifest(candidate_record, candidate_registry)
    except (SceneManifestError, KeyError, TypeError, ValueError, ZeroDivisionError):
        return
    raise AssertionError(f"negative control was not rejected: {name}")


def main() -> None:
    fixtures = [load_fixture(name) for name in FIXTURE_NAMES]
    manifests = [build_scene_manifest(record) for record in fixtures]
    summaries = [
        (
            manifest["scanId"],
            manifest["budget"]["regionCount"],
            manifest["budget"]["hubCount"],
            manifest["budget"]["countedObjectCount"],
            manifest["hero"] is not None,
        )
        for manifest in manifests
    ]
    require(
        summaries
        == [
            ("fixture-clean", 4, 0, 4, False),
            ("fixture-image-heavy", 4, 0, 4, True),
            ("fixture-third-party-heavy", 5, 3, 8, True),
        ],
        "fixture scene summaries drifted",
    )

    for record, manifest in zip(fixtures, manifests):
        region_ids = {
            item["id"].removeprefix("region:")
            for item in manifest["objects"]
            if item["kind"] in {"region", "aggregate"}
        }
        require(
            region_ids
            == {node["id"] for node in record["nodes"] if node.get("sceneIncluded", True)},
            f"{record['scanId']} scene node membership drifted",
        )
        require(len(manifest["connections"]) == len(record["resources"]), "resource path count drifted")
        require(
            stable_manifest_json(manifest) == stable_manifest_json(build_scene_manifest(record)),
            f"{record['scanId']} serialization is not deterministic",
        )
        require(manifest["budget"]["pageBusCounted"] is False, "page bus budget became implicit")

    clean_objects = by_id(manifests[0]["objects"])
    logo = clean_objects["region:n-logo"]
    require(logo["weight"]["knownTransferredBytes"] == 24_000, "clean logo mass drifted")
    require(logo["positionWorld"] == {"x": -4.533333, "y": 2.816667, "z": 0.84}, "clean logo geometry drifted")
    clean_connections = by_id(manifests[0]["connections"])
    require(clean_connections["connection:r-logo"]["targetObjectIds"] == ["region:n-logo"], "clean exact link drifted")
    require(clean_connections["connection:r-style"]["targetObjectIds"] == ["bus:page"], "clean page-level link drifted")

    third_hubs = [item for item in manifests[2]["objects"] if item["kind"] == "third-party-hub"]
    require(
        [(item["domain"], item["evidence"]["angleDegrees"]) for item in third_hubs]
        == [("cdn.example", -22.0), ("service.example", 0.0), ("vendor.example", 22.0)],
        "third-party hub ordering or angles drifted",
    )
    third_connections = by_id(manifests[2]["connections"])
    comments = third_connections["connection:r-comments-api"]
    require(comments["sourceObjectId"] == "hub:service.example", "probable third-party source drifted")
    require(comments["targetObjectIds"] == ["bus:page"], "probable third-party target drifted")
    require(comments["evidenceOnlyTargetNodeIds"] == [], "represented probable target was mislabeled")
    require(third_connections["connection:r-metrics"]["visualState"] == "hatched-hollow", "fixture unknown state drifted")

    exercise_transfer_and_endpoint_matrix()

    clean = fixtures[0]
    expect_manifest_failure("mapping mismatch", clean, DEFAULT_MAPPING_REGISTRY, lambda record, _mapping: record.update({"mappingVersion": "other"}))
    expect_manifest_failure("duplicate resource", clean, DEFAULT_MAPPING_REGISTRY, lambda record, _mapping: record["resources"].append(copy.deepcopy(record["resources"][0])))
    expect_manifest_failure("region count mismatch", clean, DEFAULT_MAPPING_REGISTRY, lambda record, _mapping: record["capture"].update({"renderedRegionCount": 3}))
    expect_manifest_failure("node parent cycle", clean, DEFAULT_MAPPING_REGISTRY, lambda record, _mapping: record["nodes"][0].update({"parentId": "n-logo"}))
    expect_manifest_failure("unknown exact target", clean, DEFAULT_MAPPING_REGISTRY, lambda record, _mapping: record["resources"][3].update({"attributedNodeIds": ["n-missing"]}))
    expect_manifest_failure("scene budget", clean, DEFAULT_MAPPING_REGISTRY, lambda _record, mapping: mapping["scene"].update({"maxSceneObjects": 3}))
    expect_manifest_failure("zero-duration reveal", clean, DEFAULT_MAPPING_REGISTRY, lambda _record, mapping: mapping["reveal"][2].update({"endSeconds": 1.7}))

    fingerprints = {
        manifest["scanId"]: hashlib.sha256(stable_manifest_json(manifest).encode("utf-8")).hexdigest()[:16]
        for manifest in manifests
    }
    require(
        fingerprints
        == {
            "fixture-clean": "264c19fe87d40ace",
            "fixture-image-heavy": "b79c3f7b136df4e4",
            "fixture-third-party-heavy": "f209bed602212d37",
        },
        "fixture manifest fingerprints drifted",
    )
    print(
        "Verified scene-manifest-v0.1.0 across 3 fixtures, one transfer/endpoint matrix, "
        f"and 7 negative controls; fingerprints: {fingerprints}."
    )


if __name__ == "__main__":
    main()
