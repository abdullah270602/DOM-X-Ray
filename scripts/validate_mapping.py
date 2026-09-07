"""Validate the prototype DOM X-Ray mapping registry against Gate 0 fixtures."""

from __future__ import annotations

import copy
import json
import math
import sys
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.scene_manifest import resource_mass, scene_rect, structure_depth  # noqa: E402


REGISTRY_PATH = ROOT / "docs" / "MAPPING_REGISTRY.v0.1.json"
FIXTURE_DIR = ROOT / "fixtures" / "scan"
FIXTURE_NAMES = ("clean.json", "image-heavy.json", "third-party-heavy.json")


class MappingError(AssertionError):
    """Raised when the prototype mapping violates a deterministic invariant."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MappingError(message)


def validate_registry(registry: dict[str, Any], fixtures: list[dict[str, Any]]) -> None:
    require(registry["version"] == "mapping-v0.1.0", "unexpected mapping version")
    require(registry["status"] == "prototype", "Gate 1 registry must remain explicitly provisional")
    require(1 <= registry["scene"]["maxSceneObjects"] <= 650, "scene object budget exceeds Gate 1")
    require(registry["scene"]["viewportPlaneWidthWorld"] > 0, "viewport plane width must be positive")
    require(
        registry["scene"]["objectBudgetRule"]
        == "scene-included-regions-plus-third-party-hubs-v1",
        "scene object budget rule drifted",
    )
    require(
        registry["scene"]["pageBusCountsTowardObjectBudget"] is False,
        "page bus budget treatment drifted",
    )

    depths = [structure_depth(registry, depth) for depth in range(0, 201)]
    require(depths == sorted(depths), "structure depth mapping is not monotonic")
    require(all(0 <= value <= registry["structure"]["maxWorld"] for value in depths), "depth cap failed")

    byte_samples = [0, 1, 1024, 10_000, 100_000, 1_000_000, 5_000_000, 50_000_000]
    masses = [resource_mass(registry, value) for value in byte_samples]
    require(masses == sorted(masses), "resource mass mapping is not monotonic")
    require(masses[0] == 0, "a measured zero must map to zero mass")
    require(all(0 <= value <= 1 for value in masses), "resource mass escaped normalized range")
    require(
        registry["weight"]["unknownTransferredBytesStyle"]
        != registry["weight"]["zeroTransferredBytesStyle"],
        "unknown and measured-zero bytes use the same visual state",
    )

    reveal = registry["reveal"]
    require([stage["id"] for stage in reveal] == ["flat", "structure", "weight", "party", "hero"], "reveal order drifted")
    require(reveal[0]["startSeconds"] == 0, "reveal does not start at zero")
    for previous, current in zip(reveal, reveal[1:]):
        require(previous["endSeconds"] > previous["startSeconds"], "reveal stage has no duration")
        require(previous["endSeconds"] == current["startSeconds"], "reveal contains a gap or overlap")
    require(reveal[-1]["endSeconds"] > reveal[-1]["startSeconds"], "final reveal stage has no duration")
    require(abs(reveal[-1]["endSeconds"] - 5) < 1e-9, "reveal is not exactly five seconds")

    party = registry["party"]
    require(party["hubPlacementRule"] == "right-edge-arc-even-v1", "hub placement rule drifted")
    require(
        -90 < party["hubAngleStartDegrees"] <= party["hubAngleEndDegrees"] < 90,
        "hub arc must remain on the external right edge",
    )
    require(party["hubRadiusWorld"] > registry["scene"]["viewportPlaneWidthWorld"] / 2, "hubs overlap the page center")
    require(party["hubNodeRadiusWorld"] > 0, "hub node radius must be positive")
    outer_angle = max(abs(party["hubAngleStartDegrees"]), abs(party["hubAngleEndDegrees"]))
    inner_hub_x = (
        party["hubRadiusWorld"] * math.cos(math.radians(outer_angle))
        - party["hubNodeRadiusWorld"]
    )
    require(
        inner_hub_x > registry["scene"]["viewportPlaneWidthWorld"] / 2,
        "external hub geometry overlaps the page plinth",
    )
    require(party["pageBusInsetWorld"] >= 0, "page bus inset must be non-negative")
    require(
        party["pageBusInsetWorld"] <= registry["scene"]["viewportPlaneWidthWorld"] / 2,
        "page bus escaped the page plinth",
    )
    require(party["cableThicknessBaseWorld"] > 0, "cable base thickness must be positive")
    require(party["cableThicknessRangeWorld"] > 0, "cable thickness range must be positive")

    hero = registry["heroSelection"]
    for key, value in hero.items():
        if key.endswith("Minimum") and "Bytes" not in key:
            require(0 <= value <= 1, f"hero threshold {key} is outside 0–1")
    require(hero["supportMetricMaximum"] == 3, "support metric limit drifted")
    require(hero["fallbackShareEligible"] is False, "neutral fallback must not masquerade as share-worthy")
    require(hero["eligibleStatuses"] == ["complete", "partial"], "hero status boundary drifted")
    require(
        hero["knownByteCoverageRule"]
        == "count(resources where transferredBytes is known) / count(resources)",
        "known-value coverage proxy is ambiguous",
    )
    require(
        hero["rankingOrder"]
        == [
            "effect-strength-desc",
            "measurement-coverage-desc",
            "exact-attribution-desc",
            "visual-share-desc",
            "observed-evidence-desc",
            "source-order-asc",
            "candidate-id-asc",
        ],
        "hero comparator is not fully deterministic",
    )
    require(
        hero["disabledCandidateKinds"] == ["structure", "layout-shift"],
        "an unthresholded hero kind was enabled",
    )
    require(
        hero["enabledCandidates"]
        == [
            "dominant-resource-type-share-v1",
            "third-party-request-share-v1",
            "third-party-byte-share-v1",
            "largest-exact-resource-share-v1",
        ],
        "hero candidate set drifted",
    )

    for fixture in fixtures:
        require(fixture["mappingVersion"] == registry["version"], f"{fixture['scanId']} mapping version mismatch")
        viewport = fixture["capture"]["viewport"]
        mapped = [
            scene_rect(registry, node["rect"], viewport)
            for node in fixture["nodes"]
            if node.get("sceneIncluded", True)
        ]
        mapped = [rect for rect in mapped if rect is not None]
        require(
            len(mapped) <= fixture["capture"]["renderedRegionCount"],
            f"{fixture['scanId']} mapped more nodes than its rendered-region count",
        )
        require(len(mapped) <= registry["scene"]["maxSceneObjects"], f"{fixture['scanId']} exceeds object budget")
        for rect in mapped:
            require(all(math.isfinite(value) for value in rect.values()), f"{fixture['scanId']} produced non-finite geometry")
            require(rect["width"] > 0 and rect["height"] > 0, f"{fixture['scanId']} produced empty geometry")
            require(rect["width"] <= registry["scene"]["viewportPlaneWidthWorld"], f"{fixture['scanId']} escaped plane width")

        for resource in fixture["resources"]:
            if resource["transferredBytes"] is None:
                require(
                    registry["weight"]["unknownTransferredBytesStyle"] == "hatched-hollow",
                    "unknown transfer bytes lost their explicit state",
                )
            else:
                first = resource_mass(registry, resource["transferredBytes"])
                second = resource_mass(registry, resource["transferredBytes"])
                require(first == second, f"{fixture['scanId']} resource mapping is not deterministic")

        third_party_origins = {item["origin"] for item in fixture["resources"] if item["party"] == "third"}
        third_party_domains = {
            item["registrableDomain"]
            for item in fixture["resources"]
            if item["party"] == "third" and item["registrableDomain"] is not None
        }
        scene_object_count = len(mapped) + len(third_party_domains)
        require(scene_object_count <= registry["scene"]["maxSceneObjects"], "combined scene objects exceed budget")
        if fixture["scanId"] == "fixture-third-party-heavy":
            require(len(third_party_origins) == 4, "subdomain origin control drifted")
            require(len(third_party_domains) == 3, "registrable-domain hubs were not collapsed")


def expect_failure(
    name: str,
    registry: dict[str, Any],
    fixtures: list[dict[str, Any]],
    mutate: Callable[[dict[str, Any], list[dict[str, Any]]], None],
) -> None:
    candidate_registry = copy.deepcopy(registry)
    candidate_fixtures = copy.deepcopy(fixtures)
    mutate(candidate_registry, candidate_fixtures)
    try:
        validate_registry(candidate_registry, candidate_fixtures)
    except (MappingError, KeyError, TypeError, ValueError, ZeroDivisionError):
        return
    raise MappingError(f"negative control was not rejected: {name}")


def main() -> None:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    fixtures = [json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8")) for name in FIXTURE_NAMES]
    validate_registry(registry, fixtures)

    expect_failure("mapping version drift", registry, fixtures, lambda _r, f: f[0].update({"mappingVersion": "other"}))
    expect_failure("non-monotonic depth", registry, fixtures, lambda r, _f: r["structure"].update({"coefficient": -1}))
    expect_failure("zero byte base", registry, fixtures, lambda r, _f: r["weight"].update({"baseBytes": 0}))
    expect_failure("unknown equals zero", registry, fixtures, lambda r, _f: r["weight"].update({"unknownTransferredBytesStyle": "cached-hollow"}))
    expect_failure("timeline gap", registry, fixtures, lambda r, _f: r["reveal"][2].update({"startSeconds": 1.8}))
    expect_failure("zero-duration stage", registry, fixtures, lambda r, _f: r["reveal"][2].update({"endSeconds": 1.7}))
    expect_failure("shareable neutral fallback", registry, fixtures, lambda r, _f: r["heroSelection"].update({"fallbackShareEligible": True}))

    print("Validated mapping-v0.1.0 against 3 fixtures and 7 negative controls; reveal duration is 5.0 seconds.")


if __name__ == "__main__":
    main()
