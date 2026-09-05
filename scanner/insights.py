"""Deterministic hero-fact selection from normalized scan evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAPPING_REGISTRY = json.loads(
    (ROOT / "docs" / "MAPPING_REGISTRY.v0.1.json").read_text(encoding="utf-8")
)


@dataclass(frozen=True)
class HeroCandidate:
    candidate_id: str
    insight: dict[str, Any]
    effect_strength: float
    measurement_coverage: float
    attribution_rank: int
    visual_consequence: float
    evidence_rank: int
    source_order: int


def _percentage(share: float) -> float:
    return round(share * 1_000) / 10


def _human_bytes(value: int) -> str:
    if value >= 1_000_000:
        rendered = f"{value / 1_000_000:.1f}".rstrip("0").rstrip(".")
        return f"{rendered} MB"
    if value >= 1_000:
        rendered = f"{value / 1_000:.1f}".rstrip("0").rstrip(".")
        return f"{rendered} KB"
    return f"{value} bytes"


def _effect_strength(share: float, minimum: float) -> float:
    if minimum >= 1:
        return 1.0 if share >= minimum else 0.0
    return max(0.0, min(1.0, (share - minimum) / (1 - minimum)))


def _resource_type_label(resource_type: str) -> str:
    return {
        "document": "Documents",
        "stylesheet": "Stylesheets",
        "image": "Images",
        "media": "Media",
        "font": "Fonts",
        "script": "Scripts",
        "fetch": "Fetch responses",
        "xhr": "XHR responses",
        "other": "Other responses",
    }.get(resource_type, "Responses")


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _insight(
    *,
    insight_id: str,
    kind: str,
    statement: str,
    evidence: list[dict[str, Any]],
    selection_rule: str,
    limitation_codes: list[str],
) -> dict[str, Any]:
    return {
        "id": insight_id,
        "kind": kind,
        "hero": True,
        "statement": statement,
        "evidence": evidence,
        "selectionRule": selection_rule,
        "limitationCodes": limitation_codes,
    }


def _invalidated_metrics(record: dict[str, Any]) -> set[str]:
    return {
        metric
        for limitation in record.get("limitations", [])
        for metric in limitation.get("invalidatesMetrics", [])
    }


def select_hero_insight(
    record: dict[str, Any],
    registry: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return zero or one reproducible hero insight for a normalized scan record."""

    mapping = registry or DEFAULT_MAPPING_REGISTRY
    thresholds = mapping["heroSelection"]
    if record.get("status") not in set(thresholds["eligibleStatuses"]):
        return []
    enabled = set(thresholds["enabledCandidates"])
    resources = record.get("resources", [])
    if not resources:
        return []

    invalidated = _invalidated_metrics(record)
    if "hero_insight" in invalidated:
        return []

    limitation_codes = [item["code"] for item in record.get("limitations", [])]
    known = [
        (index, resource)
        for index, resource in enumerate(resources)
        if isinstance(resource.get("transferredBytes"), int)
        and not isinstance(resource.get("transferredBytes"), bool)
        and resource["transferredBytes"] >= 0
    ]
    known_total = int(sum(resource["transferredBytes"] for _, resource in known))
    known_coverage = len(known) / len(resources)
    all_byte_refs = [f"#/resources/{index}/transferredBytes" for index, _ in known]
    all_type_refs = [f"#/resources/{index}/type" for index, _ in known]
    all_party_refs = [f"#/resources/{index}/party" for index, _ in known]
    candidates: list[HeroCandidate] = []

    byte_metrics_invalid = bool(
        invalidated
        & {"total_transferred_bytes", "resource_type_transferred_bytes", "resource_mass"}
    )
    if known_total > 0 and not byte_metrics_invalid:
        resources_by_type: dict[str, list[tuple[int, dict[str, Any]]]] = {}
        for index, resource in known:
            resources_by_type.setdefault(resource["type"], []).append((index, resource))

        share_minimum = float(thresholds["dominantResourceTypeShareMinimum"])
        bytes_minimum = int(thresholds["dominantResourceTypeBytesMinimum"])
        for resource_type, rows in resources_by_type.items():
            type_bytes = int(sum(resource["transferredBytes"] for _, resource in rows))
            share = type_bytes / known_total
            if (
                "dominant-resource-type-share-v1" not in enabled
                or share < share_minimum
                or type_bytes < bytes_minimum
            ):
                continue
            type_refs = [
                value
                for index, _ in rows
                for value in (
                    f"#/resources/{index}/type",
                    f"#/resources/{index}/transferredBytes",
                )
            ]
            share_percent = _percentage(share)
            insight_id = f"i-dominant-{resource_type}"
            candidates.append(
                HeroCandidate(
                    candidate_id=insight_id,
                    insight=_insight(
                        insight_id=insight_id,
                        kind="weight",
                        statement=(
                            f"{_resource_type_label(resource_type)} accounted for {share_percent:g}% "
                            f"of {_human_bytes(known_total)} received in this captured load."
                        ),
                        evidence=[
                            {
                                "role": "primary",
                                "level": "derived",
                                "attributionScope": "page-level",
                                "metric": f"{resource_type}_transfer_share",
                                "value": share_percent,
                                "unit": "percent",
                                "sourceRefs": _unique(all_type_refs + all_byte_refs),
                                "rule": "round(typeBytes * 1000 / totalKnownBytes) / 10",
                            },
                            {
                                "role": "support",
                                "level": "derived",
                                "attributionScope": "page-level",
                                "metric": f"{resource_type}_transferred_bytes",
                                "value": type_bytes,
                                "unit": "bytes",
                                "sourceRefs": type_refs,
                                "rule": "sum(known transferredBytes for resource type)",
                            },
                            {
                                "role": "support",
                                "level": "derived",
                                "attributionScope": "page-level",
                                "metric": "total_known_transferred_bytes",
                                "value": known_total,
                                "unit": "bytes",
                                "sourceRefs": all_byte_refs,
                                "rule": "sum(known transferredBytes)",
                            },
                        ],
                        selection_rule="dominant-resource-type-share-v1",
                        limitation_codes=limitation_codes,
                    ),
                    effect_strength=_effect_strength(share, share_minimum),
                    measurement_coverage=known_coverage,
                    attribution_rank=0,
                    visual_consequence=share,
                    evidence_rank=0,
                    source_order=min(index for index, _ in rows),
                )
            )

        third_byte_metrics_invalid = bool(
            invalidated & {"total_transferred_bytes", "third_party_transferred_bytes"}
        )
        third_rows = [
            (index, resource)
            for index, resource in known
            if resource.get("party") == "third"
        ]
        third_bytes = int(sum(resource["transferredBytes"] for _, resource in third_rows))
        third_share = third_bytes / known_total
        third_share_minimum = float(thresholds["thirdPartyByteShareMinimum"])
        coverage_minimum = float(thresholds["knownByteCoverageMinimum"])
        if (
            third_rows
            and "third-party-byte-share-v1" in enabled
            and not third_byte_metrics_invalid
            and known_coverage >= coverage_minimum
            and third_share >= third_share_minimum
        ):
            third_refs = [
                value
                for index, _ in third_rows
                for value in (
                    f"#/resources/{index}/party",
                    f"#/resources/{index}/transferredBytes",
                )
            ]
            share_percent = _percentage(third_share)
            insight_id = "i-third-party-bytes"
            candidates.append(
                HeroCandidate(
                    candidate_id=insight_id,
                    insight=_insight(
                        insight_id=insight_id,
                        kind="third-party",
                        statement=(
                            "Responses from domains different from "
                            f"{record['page']['registrableDomain']} accounted for {share_percent:g}% "
                            f"of {_human_bytes(known_total)} received in this captured load."
                        ),
                        evidence=[
                            {
                                "role": "primary",
                                "level": "derived",
                                "attributionScope": "page-level",
                                "metric": "third_party_transfer_share",
                                "value": share_percent,
                                "unit": "percent",
                                "sourceRefs": _unique(all_party_refs + all_byte_refs),
                                "rule": "round(thirdPartyBytes * 1000 / totalKnownBytes) / 10",
                            },
                            {
                                "role": "support",
                                "level": "derived",
                                "attributionScope": "page-level",
                                "metric": "third_party_transferred_bytes",
                                "value": third_bytes,
                                "unit": "bytes",
                                "sourceRefs": _unique(all_party_refs + all_byte_refs),
                                "rule": "sum(known transferredBytes where party is third)",
                            },
                            {
                                "role": "support",
                                "level": "derived",
                                "attributionScope": "page-level",
                                "metric": "total_known_transferred_bytes",
                                "value": known_total,
                                "unit": "bytes",
                                "sourceRefs": all_byte_refs,
                                "rule": "sum(known transferredBytes)",
                            },
                        ],
                        selection_rule="third-party-byte-share-v1",
                        limitation_codes=limitation_codes,
                    ),
                    effect_strength=_effect_strength(third_share, third_share_minimum),
                    measurement_coverage=known_coverage,
                    attribution_rank=0,
                    visual_consequence=third_share,
                    evidence_rank=0,
                    source_order=min(index for index, _ in third_rows),
                )
            )

        exact_rows = [
            (index, resource)
            for index, resource in known
            if resource.get("attributionScope") in {"exact-element", "exact-resource-link"}
            and resource.get("attributedNodeIds")
        ]
        if exact_rows:
            exact_index, exact_resource = min(
                exact_rows,
                key=lambda item: (-float(item[1]["transferredBytes"]), item[0]),
            )
            exact_bytes = int(exact_resource["transferredBytes"])
            exact_share = exact_bytes / known_total
            exact_share_minimum = float(thresholds["largestExactResourceShareMinimum"])
            exact_bytes_minimum = int(thresholds["largestExactResourceBytesMinimum"])
            if (
                "largest-exact-resource-share-v1" in enabled
                and exact_share >= exact_share_minimum
                and exact_bytes >= exact_bytes_minimum
            ):
                share_percent = _percentage(exact_share)
                insight_id = "i-largest-exact-resource"
                candidates.append(
                    HeroCandidate(
                        candidate_id=insight_id,
                        insight=_insight(
                            insight_id=insight_id,
                            kind="weight",
                            statement=(
                                f"One exactly linked {exact_resource['type']} response contributed "
                                f"{_human_bytes(exact_bytes)}—{share_percent:g}% of the bytes received "
                                "in this captured load."
                            ),
                            evidence=[
                                {
                                    "role": "primary",
                                    "level": "observed",
                                    "attributionScope": exact_resource["attributionScope"],
                                    "metric": "largest_exact_resource_transferred_bytes",
                                    "value": exact_bytes,
                                    "unit": "bytes",
                                    "sourceRefs": [
                                        f"#/resources/{exact_index}/transferredBytes",
                                        f"#/resources/{exact_index}/type",
                                        f"#/resources/{exact_index}/attributionScope",
                                        f"#/resources/{exact_index}/attributedNodeIds",
                                    ],
                                    "rule": "max(known transferredBytes for exactly linked resources)",
                                },
                                {
                                    "role": "support",
                                    "level": "derived",
                                    "attributionScope": "page-level",
                                    "metric": "largest_exact_resource_transfer_share",
                                    "value": share_percent,
                                    "unit": "percent",
                                    "sourceRefs": all_byte_refs,
                                    "rule": "round(resourceBytes * 1000 / totalKnownBytes) / 10",
                                },
                                {
                                    "role": "support",
                                    "level": "derived",
                                    "attributionScope": "page-level",
                                    "metric": "total_known_transferred_bytes",
                                    "value": known_total,
                                    "unit": "bytes",
                                    "sourceRefs": all_byte_refs,
                                    "rule": "sum(known transferredBytes)",
                                },
                            ],
                            selection_rule="largest-exact-resource-share-v1",
                            limitation_codes=limitation_codes,
                        ),
                        effect_strength=_effect_strength(exact_share, exact_share_minimum),
                        measurement_coverage=known_coverage,
                        attribution_rank=1,
                        visual_consequence=exact_share,
                        evidence_rank=1,
                        source_order=exact_index,
                    )
                )

    classified = [
        (index, resource)
        for index, resource in enumerate(resources)
        if resource.get("party") in {"first", "third"}
    ]
    third_classified = [
        (index, resource) for index, resource in classified if resource["party"] == "third"
    ]
    if (
        classified
        and "third-party-request-share-v1" in enabled
        and "request_count" not in invalidated
    ):
        request_share = len(third_classified) / len(classified)
        request_share_minimum = float(thresholds["thirdPartyRequestShareMinimum"])
        if third_classified and request_share >= request_share_minimum:
            third_party_refs = [f"#/resources/{index}/party" for index, _ in third_classified]
            classified_refs = [f"#/resources/{index}/party" for index, _ in classified]
            insight_id = "i-third-party-requests"
            candidates.append(
                HeroCandidate(
                    candidate_id=insight_id,
                    insight=_insight(
                        insight_id=insight_id,
                        kind="third-party",
                        statement=(
                            f"{len(third_classified)} of {len(classified)} classified requests used "
                            f"domains different from {record['page']['registrableDomain']} "
                            "in this captured load."
                        ),
                        evidence=[
                            {
                                "role": "primary",
                                "level": "derived",
                                "attributionScope": "page-level",
                                "metric": "third_party_requests",
                                "value": len(third_classified),
                                "unit": "requests",
                                "sourceRefs": _unique(
                                    third_party_refs + ["#/page/registrableDomain"]
                                ),
                                "rule": "count(resources where party is third)",
                            },
                            {
                                "role": "support",
                                "level": "derived",
                                "attributionScope": "page-level",
                                "metric": "party_classified_requests",
                                "value": len(classified),
                                "unit": "requests",
                                "sourceRefs": classified_refs,
                                "rule": "count(resources where party is first or third)",
                            },
                        ],
                        selection_rule="third-party-request-share-v1",
                        limitation_codes=limitation_codes,
                    ),
                    effect_strength=_effect_strength(request_share, request_share_minimum),
                    measurement_coverage=len(classified) / len(resources),
                    attribution_rank=0,
                    visual_consequence=request_share,
                    evidence_rank=0,
                    source_order=min(index for index, _ in third_classified),
                )
            )

    if not candidates:
        return []
    candidates.sort(
        key=lambda candidate: (
            -candidate.effect_strength,
            -candidate.measurement_coverage,
            -candidate.attribution_rank,
            -candidate.visual_consequence,
            -candidate.evidence_rank,
            candidate.source_order,
            candidate.candidate_id,
        )
    )
    return [candidates[0].insight]
