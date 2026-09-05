"""Deterministic candidate reduction for ``perceptual-region-v1``."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any


AGGREGATION_RULE = "perceptual-region-v1"


class MandatoryOverflowError(ValueError):
    """Raised until the truthful region-level overflow fallback is implemented."""


@dataclass(frozen=True)
class AggregationResult:
    nodes: list[dict[str, Any]]
    candidate_count: int
    aggregated_count: int
    rendered_count: int
    available_node_budget: int
    external_hub_count: int


def _rect_matches(left: dict[str, float], right: dict[str, float], tolerance: float = 1.0) -> bool:
    return all(abs(float(left[key]) - float(right[key])) <= tolerance for key in ("x", "y", "width", "height"))


def aggregate_nodes(
    nodes: list[dict[str, Any]],
    metadata: dict[str, dict[str, Any]],
    resources: list[dict[str, Any]],
    *,
    max_scene_objects: int = 650,
    external_hub_count: int = 0,
) -> AggregationResult:
    """Reduce candidates without losing membership or exact evidence.

    ``metadata`` is scanner-internal and keyed by candidate node ID. It must
    contain ``preorderIndex``, ``clippedRect``, ``mandatory``,
    ``semanticDistinctness``, and ``hasDistinctPaint``.
    """

    if len({node["id"] for node in nodes}) != len(nodes):
        raise ValueError("candidate node IDs must be unique")
    if set(metadata) != {node["id"] for node in nodes}:
        raise ValueError("aggregation metadata must cover every candidate exactly")
    if not 0 <= external_hub_count <= max_scene_objects:
        raise ValueError("external hub count exceeds the scene budget")

    ordered = [node["id"] for node in nodes]
    node_map = {node["id"]: copy.deepcopy(node) for node in nodes}
    parent_map = {node["id"]: node["parentId"] for node in nodes}
    active = set(ordered)

    for node in nodes:
        item = metadata[node["id"]]
        if node["resourceIds"] and not item["mandatory"]:
            raise ValueError(f"resource-bearing candidate is not mandatory: {node['id']}")
        if node["stackingContext"]["creates"] and not item["mandatory"]:
            raise ValueError(f"stacking-context candidate is not mandatory: {node['id']}")

    def nearest_ancestor(node_id: str, represented: set[str]) -> str | None:
        parent_id = parent_map[node_id]
        visited: set[str] = set()
        while parent_id is not None:
            if parent_id in visited:
                raise ValueError(f"candidate parent cycle at {parent_id}")
            visited.add(parent_id)
            if parent_id in represented:
                return parent_id
            if parent_id not in parent_map:
                raise ValueError(f"candidate has unknown parent {parent_id}")
            parent_id = parent_map[parent_id]
        return None

    # First collapse evidence-free wrappers whose clipped footprint duplicates
    # the nearest still-represented ancestor. Mandatory nodes never collapse.
    for node_id in ordered:
        item = metadata[node_id]
        if item["mandatory"]:
            continue
        parent_id = nearest_ancestor(node_id, active)
        if parent_id is None:
            continue
        node = node_map[node_id]
        if (
            _rect_matches(item["clippedRect"], metadata[parent_id]["clippedRect"])
            and not node["resourceIds"]
            and not node["stackingContext"]["creates"]
            and not item["semanticDistinctness"]
            and not item["hasDistinctPaint"]
        ):
            active.remove(node_id)

    available = max_scene_objects - external_hub_count
    mandatory_ids = [node_id for node_id in ordered if node_id in active and metadata[node_id]["mandatory"]]
    if len(mandatory_ids) > available:
        raise MandatoryOverflowError(
            f"{len(mandatory_ids)} mandatory candidates exceed the available scene budget of {available}"
        )

    if len(active) > available:
        known_bytes_by_node: dict[str, int] = {}
        for resource in resources:
            value = resource["transferredBytes"]
            if value is None:
                continue
            for node_id in resource["attributedNodeIds"]:
                known_bytes_by_node[node_id] = known_bytes_by_node.get(node_id, 0) + int(value)

        nonmandatory = [node_id for node_id in active if not metadata[node_id]["mandatory"]]
        nonmandatory.sort(
            key=lambda node_id: (
                -float(metadata[node_id]["clippedRect"]["width"])
                * float(metadata[node_id]["clippedRect"]["height"]),
                -known_bytes_by_node.get(node_id, 0),
                -int(metadata[node_id]["semanticDistinctness"]),
                int(metadata[node_id]["preorderIndex"]),
            )
        )
        retained = set(mandatory_ids)
        retained.update(nonmandatory[: available - len(mandatory_ids)])
    else:
        retained = set(active)

    if not retained and ordered:
        raise ValueError("aggregation produced no represented root")

    omitted = [node_id for node_id in ordered if node_id not in retained]
    for node_id in retained:
        node_map[node_id]["parentId"] = nearest_ancestor(node_id, retained)
        node_map[node_id]["memberNodeIds"] = []
        node_map[node_id]["aggregationRule"] = None

    fallback_root = next((node_id for node_id in ordered if node_id in retained), None)
    for node_id in omitted:
        target_id = nearest_ancestor(node_id, retained) or fallback_root
        if target_id is None:
            raise ValueError(f"omitted candidate {node_id} has no represented ancestor")
        node_map[target_id]["memberNodeIds"].append(node_id)
        node_map[target_id]["aggregationRule"] = AGGREGATION_RULE

    rendered = [node_map[node_id] for node_id in ordered if node_id in retained]
    return AggregationResult(
        nodes=rendered,
        candidate_count=len(nodes),
        aggregated_count=len(omitted),
        rendered_count=len(rendered),
        available_node_budget=available,
        external_hub_count=external_hub_count,
    )
