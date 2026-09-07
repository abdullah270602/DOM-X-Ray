"""Deterministic scan-record to renderer-neutral scene-manifest mapping."""

from __future__ import annotations

import copy
import json
import math
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAPPING_REGISTRY = json.loads(
    (ROOT / "docs" / "MAPPING_REGISTRY.v0.1.json").read_text(encoding="utf-8")
)
MANIFEST_VERSION = "scene-manifest-v0.1.0"
EXACT_ATTRIBUTION = {"exact-element", "exact-resource-link"}


class SceneManifestError(ValueError):
    """Raised when a record cannot produce one truthful deterministic scene."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SceneManifestError(message)


def _number(value: float) -> float:
    """Keep generated JSON stable without leaking binary-float noise."""

    rounded = round(float(value), 6)
    return 0.0 if rounded == 0 else rounded


def clamp(value: float, minimum: float, maximum: float) -> float:
    return min(maximum, max(minimum, value))


def structure_depth(registry: dict[str, Any], dom_depth: int) -> float:
    config = registry["structure"]
    return min(config["maxWorld"], config["coefficient"] * math.log2(1 + dom_depth))


def resource_mass(registry: dict[str, Any], transferred_bytes: int) -> float:
    config = registry["weight"]
    return clamp(
        math.log2(1 + transferred_bytes / config["baseBytes"]) / config["normalizer"],
        0,
        1,
    )


def clipped_rect(
    rect: dict[str, float], viewport: dict[str, float]
) -> dict[str, float] | None:
    left = max(0, rect["x"])
    top = max(0, rect["y"])
    right = min(viewport["width"], rect["x"] + rect["width"])
    bottom = min(viewport["height"], rect["y"] + rect["height"])
    if right <= left or bottom <= top:
        return None
    return {"x": left, "y": top, "width": right - left, "height": bottom - top}


def scene_rect(
    registry: dict[str, Any],
    rect: dict[str, float],
    viewport: dict[str, float],
) -> dict[str, float] | None:
    clipped = clipped_rect(rect, viewport)
    if clipped is None:
        return None
    plane_width = registry["scene"]["viewportPlaneWidthWorld"]
    scale = plane_width / viewport["width"]
    return {
        "x": _number((clipped["x"] + clipped["width"] / 2 - viewport["width"] / 2) * scale),
        "y": _number(-(clipped["y"] + clipped["height"] / 2 - viewport["height"] / 2) * scale),
        "width": _number(clipped["width"] * scale),
        "height": _number(clipped["height"] * scale),
    }


def _limitations_by_target(record: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for index, limitation in enumerate(record.get("limitations", [])):
        target_id = limitation.get("targetId")
        if target_id is None:
            continue
        result.setdefault(str(target_id), []).append(
            {
                "code": limitation["code"],
                "recordRef": f"#/limitations/{index}",
                "invalidatesMetrics": list(limitation.get("invalidatesMetrics", [])),
            }
        )
    return result


def _resource_outcome(
    resource: dict[str, Any],
    limitations: list[dict[str, Any]],
) -> str:
    codes = {item["code"] for item in limitations}
    if any(code.startswith("blocked-request-") or code.startswith("response-byte-limit-") for code in codes):
        return "blocked"
    if "responseStatus" not in resource:
        return "not-recorded"
    if resource["responseStatus"] is None:
        return "no-completed-response"
    return "http-response"


def _resource_visual_state(
    resource: dict[str, Any],
    outcome: str,
) -> str:
    source = resource["transferSource"]
    value = resource["transferredBytes"]
    if outcome == "blocked":
        return "broken-outline"
    if value is None:
        if source == "service-worker":
            return "service-worker-hollow"
        if outcome == "no-completed-response":
            return "broken-outline"
        return "hatched-hollow"
    if value == 0:
        if source == "cache":
            return "cached-hollow"
        if source == "service-worker":
            return "service-worker-hollow"
        return "measured-zero-hollow"
    return "solid"


def _connection_measurement(
    registry: dict[str, Any],
    resource: dict[str, Any],
    outcome: str,
    limitations: list[dict[str, Any]],
) -> dict[str, Any]:
    value = resource["transferredBytes"]
    mass_suppressed = any(
        "resource_mass" in limitation["invalidatesMetrics"]
        for limitation in limitations
    )
    if value is None or outcome == "blocked" or mass_suppressed:
        return {
            "transferredBytes": value,
            "mass": None,
            "cableThicknessWorld": None,
            "massSuppressedByLimitation": mass_suppressed,
        }
    mass = resource_mass(registry, value)
    party = registry["party"]
    return {
        "transferredBytes": value,
        "mass": _number(mass),
        "cableThicknessWorld": _number(
            party["cableThicknessBaseWorld"] + mass * party["cableThicknessRangeWorld"]
        ),
        "massSuppressedByLimitation": False,
    }


def _region_weight(
    registry: dict[str, Any],
    resource_ids: list[str],
    resources_by_id: dict[str, dict[str, Any]],
    limitations_by_target: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    rows = [resources_by_id[resource_id] for resource_id in resource_ids]
    mass_suppressed_rows = [
        row
        for row in rows
        if any(
            "resource_mass" in limitation["invalidatesMetrics"]
            for limitation in limitations_by_target.get(row["id"], [])
        )
    ]
    mass_suppressed_ids = {row["id"] for row in mass_suppressed_rows}
    blocked_rows = [
        row
        for row in rows
        if _resource_outcome(row, limitations_by_target.get(row["id"], [])) == "blocked"
    ]
    blocked_ids = {row["id"] for row in blocked_rows}
    known_rows = [
        row
        for row in rows
        if row["id"] not in mass_suppressed_ids
        and row["id"] not in blocked_ids
        and row["transferredBytes"] is not None
    ]
    unknown_rows = [
        row
        for row in rows
        if row["id"] not in blocked_ids and row["transferredBytes"] is None
    ]
    known_bytes = (
        sum(int(row["transferredBytes"]) for row in known_rows)
        if known_rows
        else None
    )
    if known_bytes is None:
        mass = None
        thickness = None
        plate_style = "none"
    else:
        mass_value = resource_mass(registry, known_bytes)
        mass = _number(mass_value)
        weight = registry["weight"]
        thickness = _number(
            weight["plateThicknessBaseWorld"]
            + mass_value * weight["plateThicknessRangeWorld"]
        )
        sources = {row["transferSource"] for row in known_rows}
        if known_bytes > 0:
            plate_style = "solid"
        elif sources == {"cache"}:
            plate_style = "cached-hollow"
        elif sources == {"service-worker"}:
            plate_style = "service-worker-hollow"
        elif len(sources) > 1:
            plate_style = "mixed-zero-sources-hollow"
        else:
            plate_style = "measured-zero-hollow"

    return {
        "knownTransferredBytes": known_bytes,
        "mass": mass,
        "plateThicknessWorld": thickness,
        "plateStyle": plate_style,
        "knownResourceIds": [row["id"] for row in known_rows],
        "unknownResourceIds": [row["id"] for row in unknown_rows],
        "unknownMarkers": [
            {
                "resourceId": row["id"],
                "visualState": _resource_visual_state(
                    row,
                    _resource_outcome(row, limitations_by_target.get(row["id"], [])),
                ),
            }
            for row in unknown_rows
        ],
        "blockedResourceIds": [row["id"] for row in blocked_rows],
        "blockedMarkerStyle": "broken-outline" if blocked_rows else "none",
        "massSuppressedResourceIds": [row["id"] for row in mass_suppressed_rows],
        "unknownMarkerStyle": "hatched-hollow" if unknown_rows else "none",
        "limitationCodes": sorted(
            {
                limitation["code"]
                for row in rows
                for limitation in limitations_by_target.get(row["id"], [])
            }
        ),
    }


def _nearest_scene_parent(
    node: dict[str, Any],
    nodes_by_id: dict[str, dict[str, Any]],
    scene_node_ids: set[str],
) -> str | None:
    parent_id = node["parentId"]
    visited: set[str] = set()
    while parent_id is not None:
        _require(parent_id not in visited, f"node parent cycle at {parent_id}")
        visited.add(parent_id)
        _require(parent_id in nodes_by_id, f"node has unknown parent {parent_id}")
        if parent_id in scene_node_ids:
            return f"region:{parent_id}"
        parent_id = nodes_by_id[parent_id]["parentId"]
    return None


def _validate_node_tree(nodes: list[dict[str, Any]]) -> None:
    nodes_by_id = {node["id"]: node for node in nodes}
    _require(len(nodes_by_id) == len(nodes), "node IDs must be unique")
    for node in nodes:
        current_id: str | None = node["id"]
        visited: set[str] = set()
        while current_id is not None:
            _require(current_id not in visited, f"node parent cycle at {current_id}")
            visited.add(current_id)
            _require(current_id in nodes_by_id, f"node has unknown parent {current_id}")
            current_id = nodes_by_id[current_id]["parentId"]


def _region_objects(
    record: dict[str, Any],
    registry: dict[str, Any],
    resources_by_id: dict[str, dict[str, Any]],
    limitations_by_target: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    viewport = record["capture"]["viewport"]
    nodes = record["nodes"]
    nodes_by_id = {node["id"]: node for node in nodes}
    _require(len(nodes_by_id) == len(nodes), "node IDs must be unique")
    scene_nodes = [node for node in nodes if node.get("sceneIncluded", True)]
    _require(
        len(scene_nodes) == record["capture"]["renderedRegionCount"],
        "renderedRegionCount does not match scene-included nodes",
    )
    scene_node_ids = {node["id"] for node in scene_nodes}

    result = []
    for node in scene_nodes:
        mapped = scene_rect(registry, node["rect"], viewport)
        _require(mapped is not None, f"scene node {node['id']} does not intersect the viewport")
        linked_resource_ids = list(node["resourceIds"])
        _require(
            all(resource_id in resources_by_id for resource_id in linked_resource_ids),
            f"scene node {node['id']} references an unknown resource",
        )
        exact_resource_ids = [
            resource_id
            for resource_id in linked_resource_ids
            if resources_by_id[resource_id]["attributionScope"] in EXACT_ATTRIBUTION
        ]
        separation = structure_depth(registry, int(node["domDepth"]))
        seam = (
            registry["structure"]["stackingContextSeamWorld"]
            if node["stackingContext"]["creates"]
            else 0
        )
        record_index = record["nodes"].index(node)
        result.append(
            {
                "id": f"region:{node['id']}",
                "kind": "aggregate" if node["aggregationRule"] is not None else "region",
                "parentId": _nearest_scene_parent(node, nodes_by_id, scene_node_ids),
                "positionWorld": {
                    "x": mapped["x"],
                    "y": mapped["y"],
                    "z": _number(separation + seam),
                },
                "sizeWorld": {"width": mapped["width"], "height": mapped["height"]},
                "structure": {
                    "domDepth": node["domDepth"],
                    "separationWorld": _number(separation),
                    "stackingSeamWorld": _number(seam),
                    "stackingRule": node["stackingContext"]["rule"],
                },
                "weight": _region_weight(
                    registry,
                    exact_resource_ids,
                    resources_by_id,
                    limitations_by_target,
                ),
                "evidence": {
                    "recordRefs": [
                        f"#/nodes/{record_index}",
                        "#/mappingVersion",
                    ],
                    "memberNodeIds": list(node["memberNodeIds"]),
                    "linkedResourceIds": linked_resource_ids,
                    "aggregationRule": node["aggregationRule"],
                },
                "documentOrder": record_index,
            }
        )
    return result


def _hub_objects(
    record: dict[str, Any],
    registry: dict[str, Any],
) -> list[dict[str, Any]]:
    resources = record["resources"]
    domains = sorted(
        {
            resource["registrableDomain"]
            for resource in resources
            if resource["party"] == "third" and resource["registrableDomain"] is not None
        },
        key=lambda value: (value.casefold(), value),
    )
    party = registry["party"]
    start = float(party["hubAngleStartDegrees"])
    end = float(party["hubAngleEndDegrees"])
    angles = (
        [(start + end) / 2]
        if len(domains) == 1
        else [start + (end - start) * index / (len(domains) - 1) for index in range(len(domains))]
    )
    result = []
    for domain, angle in zip(domains, angles):
        radians = math.radians(angle)
        resource_indices = [
            index
            for index, resource in enumerate(resources)
            if resource["party"] == "third" and resource["registrableDomain"] == domain
        ]
        result.append(
            {
                "id": f"hub:{domain}",
                "kind": "third-party-hub",
                "parentId": None,
                "domain": domain,
                "positionWorld": {
                    "x": _number(party["hubRadiusWorld"] * math.cos(radians)),
                    "y": _number(party["hubRadiusWorld"] * math.sin(radians)),
                    "z": _number(party["hubZWorld"]),
                },
                "radiusWorld": _number(party["hubNodeRadiusWorld"]),
                "resourceIds": [resources[index]["id"] for index in resource_indices],
                "evidence": {
                    "recordRefs": [
                        ref
                        for index in resource_indices
                        for ref in (
                            f"#/resources/{index}/registrableDomain",
                            f"#/resources/{index}/party",
                        )
                    ],
                    "groupingRule": party["classificationRule"],
                    "placementRule": party["hubPlacementRule"],
                    "angleDegrees": _number(angle),
                },
            }
        )
    return result


def _page_bus_object(record: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
    scene = registry["scene"]
    party = registry["party"]
    plane_half_width = scene["viewportPlaneWidthWorld"] / 2
    return {
        "id": "bus:page",
        "kind": "page-bus",
        "parentId": None,
        "positionWorld": {
            "x": _number(plane_half_width - party["pageBusInsetWorld"]),
            "y": 0.0,
            "z": _number(party["pageBusZWorld"]),
        },
        "resourceIds": [resource["id"] for resource in record["resources"]],
        "evidence": {
            "recordRefs": ["#/page/registrableDomain", "#/resources"],
            "placementRule": party["pageBusPlacementRule"],
        },
    }


def _connection_objects(
    record: dict[str, Any],
    registry: dict[str, Any],
    scene_node_ids: set[str],
    all_node_ids: set[str],
    hub_ids: set[str],
    limitations_by_target: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    result = []
    for index, resource in enumerate(record["resources"]):
        resource_id = resource["id"]
        resource_limitations = limitations_by_target.get(resource_id, [])
        outcome = _resource_outcome(resource, resource_limitations)
        mass_suppressed = any(
            "resource_mass" in limitation["invalidatesMetrics"]
            for limitation in resource_limitations
        )
        if resource["party"] == "third":
            domain = resource["registrableDomain"]
            _require(domain is not None, f"third-party resource {resource_id} has no domain")
            source_id = f"hub:{domain}"
            _require(source_id in hub_ids, f"resource {resource_id} has no domain hub")
        else:
            source_id = "bus:page"

        exact = resource["attributionScope"] in EXACT_ATTRIBUTION
        _require(
            all(node_id in all_node_ids for node_id in resource["attributedNodeIds"]),
            f"resource {resource_id} references an unknown node",
        )
        represented_targets = [
            f"region:{node_id}"
            for node_id in resource["attributedNodeIds"]
            if node_id in scene_node_ids
        ]
        evidence_only_targets = [
            node_id
            for node_id in resource["attributedNodeIds"]
            if node_id not in scene_node_ids
        ]
        if exact:
            _require(resource["attributedNodeIds"], f"exact resource {resource_id} has no target")
            target_ids = represented_targets
            fallback_id = "bus:page" if evidence_only_targets else None
            endpoint_rule = "exact-visible-region-with-evidence-only-bus-fallback-v1"
        else:
            target_ids = ["bus:page"]
            fallback_id = None
            endpoint_rule = "page-bus-for-non-exact-attribution-v1"

        result.append(
            {
                "id": f"connection:{resource_id}",
                "kind": "resource-path",
                "resourceId": resource_id,
                "sourceObjectId": source_id,
                "targetObjectIds": target_ids,
                "fallbackObjectId": fallback_id,
                "evidenceOnlyTargetNodeIds": evidence_only_targets,
                "attributionScope": resource["attributionScope"],
                "endpointRule": endpoint_rule,
                "transferSource": resource["transferSource"],
                "outcome": outcome,
                "visualState": (
                    "limitation-hatched"
                    if mass_suppressed and outcome != "blocked"
                    else _resource_visual_state(resource, outcome)
                ),
                "measurement": _connection_measurement(
                    registry,
                    resource,
                    outcome,
                    resource_limitations,
                ),
                "evidence": {
                    "recordRefs": [
                        f"#/resources/{index}",
                        "#/mappingVersion",
                    ],
                    "limitationRefs": [item["recordRef"] for item in resource_limitations],
                },
            }
        )
    return result


def _hero(record: dict[str, Any]) -> dict[str, Any] | None:
    rows = [
        (index, insight)
        for index, insight in enumerate(record.get("insights", []))
        if insight.get("hero") is True
    ]
    _require(len(rows) <= 1, "record contains more than one hero insight")
    if not rows:
        return None
    index, insight = rows[0]
    source_refs = list(
        dict.fromkeys(
            ref
            for evidence in insight["evidence"]
            for ref in evidence["sourceRefs"]
        )
    )
    return {
        "insightId": insight["id"],
        "kind": insight["kind"],
        "statement": insight["statement"],
        "shareEligible": True,
        "recordRef": f"#/insights/{index}",
        "sourceRefs": source_refs,
        "limitationCodes": list(insight["limitationCodes"]),
    }


def _manifest_limitations(record: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "code": limitation["code"],
            "scope": limitation["scope"],
            "targetId": limitation.get("targetId"),
            "invalidatesMetrics": list(limitation["invalidatesMetrics"]),
            "recordRef": f"#/limitations/{index}",
        }
        for index, limitation in enumerate(record.get("limitations", []))
    ]


def _validate_mapping_for_manifest(mapping: dict[str, Any]) -> None:
    scene = mapping["scene"]
    _require(
        scene["objectBudgetRule"] == "scene-included-regions-plus-third-party-hubs-v1",
        "unsupported object budget rule",
    )
    _require(scene["pageBusCountsTowardObjectBudget"] is False, "unsupported page bus budget rule")
    reveal = mapping["reveal"]
    _require([stage["id"] for stage in reveal] == ["flat", "structure", "weight", "party", "hero"], "unsupported reveal order")
    _require(reveal[0]["startSeconds"] == 0, "reveal must start at zero")
    for index, stage in enumerate(reveal):
        _require(stage["endSeconds"] > stage["startSeconds"], f"reveal stage {stage['id']} has no duration")
        if index:
            _require(
                reveal[index - 1]["endSeconds"] == stage["startSeconds"],
                "reveal contains a gap or overlap",
            )
    _require(reveal[-1]["endSeconds"] == 5, "reveal must end at five seconds")


def build_scene_manifest(
    record: dict[str, Any],
    registry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create the sole deterministic rendering input for a normalized scan."""

    mapping = registry or DEFAULT_MAPPING_REGISTRY
    _validate_mapping_for_manifest(mapping)
    _require(record["mappingVersion"] == mapping["version"], "mapping version mismatch")
    viewport = record["capture"]["viewport"]
    _require(viewport["width"] > 0 and viewport["height"] > 0, "viewport must be positive")
    resources = record["resources"]
    resources_by_id = {resource["id"]: resource for resource in resources}
    _require(len(resources_by_id) == len(resources), "resource IDs must be unique")
    _validate_node_tree(record["nodes"])
    limitations_by_target = _limitations_by_target(record)

    regions = _region_objects(
        record,
        mapping,
        resources_by_id,
        limitations_by_target,
    )
    hubs = _hub_objects(record, mapping)
    counted_object_count = len(regions) + len(hubs)
    budget_limit = int(mapping["scene"]["maxSceneObjects"])
    _require(counted_object_count <= budget_limit, "scene object budget exceeded")
    scene_node_ids = {item["id"].removeprefix("region:") for item in regions}
    all_node_ids = {item["id"] for item in record["nodes"]}
    hub_ids = {item["id"] for item in hubs}
    connections = _connection_objects(
        record,
        mapping,
        scene_node_ids,
        all_node_ids,
        hub_ids,
        limitations_by_target,
    )
    bus_needed = any(
        connection["sourceObjectId"] == "bus:page"
        or "bus:page" in connection["targetObjectIds"]
        or connection["fallbackObjectId"] == "bus:page"
        for connection in connections
    )
    bus = [_page_bus_object(record, mapping)] if bus_needed else []

    scale = mapping["scene"]["viewportPlaneWidthWorld"] / viewport["width"]
    return {
        "manifestVersion": MANIFEST_VERSION,
        "scanId": record["scanId"],
        "mappingVersion": record["mappingVersion"],
        "status": record["status"],
        "failureCode": record["failureCode"],
        "frame": {
            "coordinateSpace": "captured-viewport-css-px",
            "viewport": {
                "width": viewport["width"],
                "height": viewport["height"],
            },
            "planeWorld": {
                "width": _number(mapping["scene"]["viewportPlaneWidthWorld"]),
                "height": _number(viewport["height"] * scale),
            },
            "scaleCssPxToWorld": _number(scale),
            "origin": "viewport-center",
            "axes": {"x": "right", "y": "up", "z": "structure-separation"},
        },
        "budget": {
            "limit": budget_limit,
            "countedKinds": ["region", "aggregate", "third-party-hub"],
            "regionCount": len(regions),
            "hubCount": len(hubs),
            "countedObjectCount": counted_object_count,
            "pageBusCounted": bool(mapping["scene"]["pageBusCountsTowardObjectBudget"]),
        },
        "objects": regions + bus + hubs,
        "connections": connections,
        "nonSceneNodes": [
            {
                "nodeId": node["id"],
                "reason": "object-budget-evidence-only",
                "recordRef": f"#/nodes/{index}",
            }
            for index, node in enumerate(record["nodes"])
            if not node.get("sceneIncluded", True)
        ],
        "hero": _hero(record),
        "reveal": copy.deepcopy(mapping["reveal"]),
        "reducedMotion": copy.deepcopy(mapping["reducedMotion"]),
        "limitations": _manifest_limitations(record),
    }


def stable_manifest_json(manifest: dict[str, Any]) -> str:
    """Serialize a manifest for immutable storage or regression fingerprints."""

    return json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
