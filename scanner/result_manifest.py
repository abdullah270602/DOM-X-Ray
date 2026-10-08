"""Build immutable, renderer-neutral public-result bindings."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from scanner.scene_manifest import (
    DEFAULT_MAPPING_REGISTRY,
    build_scene_manifest,
    stable_manifest_json,
)


RESULT_MANIFEST_VERSION = "result-manifest-v0.1.0"
_RESULT_ID = re.compile(r"r_[a-f0-9]{32}\Z")
_UNSAFE_PUBLIC_TEXT = re.compile(r"[\x00-\x1f\x7f<>]")
_MAX_ARTIFACT_BYTES = {
    "poster": 5_000_000,
    "video": 8_000_000,
}
_STATUS_LABELS = {
    "complete": "COMPLETE CAPTURE",
    "partial": "PARTIAL CAPTURE",
    "interstitial": "CAPTURED INTERSTITIAL",
    "blocked": "CAPTURE BLOCKED",
    "failed": "CAPTURE FAILED",
}


class ResultManifestError(ValueError):
    """Raised when source identities or export bindings disagree."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ResultManifestError(message)


def stable_result_json(value: Any) -> str:
    """Return the canonical JSON used by every result-binding hash."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _json_hash(value: Any) -> str:
    return hashlib.sha256(stable_result_json(value).encode("utf-8")).hexdigest()


def _safe_public_text(value: Any, label: str) -> str:
    _require(
        isinstance(value, str) and bool(value) and not _UNSAFE_PUBLIC_TEXT.search(value),
        f"unsafe public {label}",
    )
    return value


def _artifact_target(
    kind: str,
    *,
    eligible: bool,
    result_binding_hash: str,
    scene_hash: str,
    hero_hash: str,
    payload: bytes | None,
) -> dict[str, Any]:
    _require(kind in {"poster", "video"}, "unknown artifact kind")
    max_byte_length = _MAX_ARTIFACT_BYTES[kind]
    if payload is not None:
        _require(eligible, f"ineligible {kind} cannot have artifact bytes")
        _require(isinstance(payload, bytes), f"{kind} artifact must be bytes")
        _require(0 < len(payload) <= max_byte_length, f"{kind} artifact size is invalid")
    return {
        "kind": kind,
        "eligible": eligible,
        "state": "ready" if payload is not None else ("not-generated" if eligible else "ineligible"),
        "mediaType": "image/png" if kind == "poster" else "video/mp4",
        "width": 1080,
        "height": 1080,
        "durationMs": None if kind == "poster" else 5_000,
        "maxByteLength": max_byte_length,
        "sourceResultBindingSha256": result_binding_hash,
        "sourceSceneSha256": scene_hash,
        "sourceHeroSha256": hero_hash,
        "artifact": (
            None
            if payload is None
            else {
                "sha256": hashlib.sha256(payload).hexdigest(),
                "byteLength": len(payload),
            }
        ),
    }


def _hero_binding(
    record: dict[str, Any],
    scene: dict[str, Any],
    mapping: dict[str, Any],
) -> dict[str, Any] | None:
    scene_hero = scene["hero"]
    if scene_hero is None:
        _require(not [item for item in record["insights"] if item["hero"]], "scene omitted record hero")
        return None

    matches = [
        (index, insight)
        for index, insight in enumerate(record["insights"])
        if insight["id"] == scene_hero["insightId"] and insight["hero"]
    ]
    _require(len(matches) == 1, "scene hero does not resolve to one record insight")
    index, insight = matches[0]
    limitation_codes = [item["code"] for item in record["limitations"]]
    _require(
        list(insight["limitationCodes"]) == limitation_codes,
        "hero limitation codes drifted from scan limitations",
    )
    selection_rule = insight["selectionRule"]
    _require(
        selection_rule in set(mapping["heroSelection"]["enabledCandidates"]),
        "hero selection rule is not enabled by the mapping",
    )
    invalidated_metrics = {
        metric
        for limitation in record["limitations"]
        for metric in limitation["invalidatesMetrics"]
    }
    invalidated_by_rule = {
        "dominant-resource-type-share-v1": {
            "total_transferred_bytes",
            "resource_type_transferred_bytes",
            "resource_mass",
        },
        "third-party-byte-share-v1": {
            "total_transferred_bytes",
            "resource_type_transferred_bytes",
            "third_party_transferred_bytes",
            "resource_mass",
        },
        "largest-exact-resource-share-v1": {
            "total_transferred_bytes",
            "resource_type_transferred_bytes",
            "resource_mass",
        },
        "third-party-request-share-v1": {"request_count"},
    }
    _require("hero_insight" not in invalidated_metrics, "hero insight is invalidated")
    _require(
        not invalidated_metrics & invalidated_by_rule[selection_rule],
        "hero evidence metric is invalidated",
    )
    _safe_public_text(insight["statement"], "hero statement")
    _safe_public_text(selection_rule, "hero selection rule")
    for evidence_index, evidence in enumerate(insight["evidence"]):
        _safe_public_text(evidence["metric"], f"hero evidence {evidence_index} metric")
        _safe_public_text(evidence["unit"], f"hero evidence {evidence_index} unit")
        _safe_public_text(evidence["rule"], f"hero evidence {evidence_index} rule")
        if isinstance(evidence["value"], str):
            _safe_public_text(evidence["value"], f"hero evidence {evidence_index} value")
        classifier = evidence.get("classifier")
        if classifier is not None:
            for field in ("id", "version", "basis"):
                _safe_public_text(
                    classifier[field],
                    f"hero evidence {evidence_index} classifier {field}",
                )
    source_refs = list(
        dict.fromkeys(
            ref
            for evidence in insight["evidence"]
            for ref in evidence["sourceRefs"]
        )
    )
    expected_scene_fields = {
        "insightId": insight["id"],
        "kind": insight["kind"],
        "statement": insight["statement"],
        "shareEligible": True,
        "recordRef": f"#/insights/{index}",
        "sourceRefs": source_refs,
        "limitationCodes": list(insight["limitationCodes"]),
    }
    _require(scene_hero == expected_scene_fields, "scene hero drifted from record insight")
    return {
        **copy.deepcopy(expected_scene_fields),
        "evidence": copy.deepcopy(insight["evidence"]),
        "selectionRule": selection_rule,
    }


def build_result_manifest(
    record: dict[str, Any],
    *,
    result_id: str,
    scene_manifest: dict[str, Any] | None = None,
    mapping_registry: dict[str, Any] | None = None,
    artifact_payloads: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    """Bind one immutable scan, scene, hero, result route, and export targets."""

    _require(isinstance(result_id, str) and bool(_RESULT_ID.fullmatch(result_id)), "invalid result ID")
    mapping = mapping_registry or DEFAULT_MAPPING_REGISTRY
    expected_scene = build_scene_manifest(record, mapping)
    scene = expected_scene if scene_manifest is None else scene_manifest
    _require(
        stable_manifest_json(scene) == stable_manifest_json(expected_scene),
        "scene manifest does not match scan record and mapping",
    )
    _require(scene["scanId"] == record["scanId"], "scene scan identity mismatch")
    _require(scene["mappingVersion"] == mapping["version"], "scene mapping identity mismatch")

    payloads = dict(artifact_payloads or {})
    _require(set(payloads) <= {"poster", "video"}, "unknown artifact payload kind")
    hero = _hero_binding(record, scene, mapping)
    artifact_eligible = hero is not None and record["status"] in {"complete", "partial"}
    share_state = (
        "artifact-eligible"
        if artifact_eligible
        else ("link-only" if record["status"] in {"complete", "partial"} else "unavailable")
    )
    result_path = f"/r/{result_id}"
    scene_hash = _json_hash(scene)
    hero_hash = _json_hash(hero)
    source_hashes = {
        "scanRecordSha256": _json_hash(record),
        "sceneManifestSha256": scene_hash,
        "mappingRegistrySha256": _json_hash(mapping),
        "heroSha256": hero_hash,
    }
    result_binding_hash = _json_hash(
        {
            "resultManifestVersion": RESULT_MANIFEST_VERSION,
            "resultId": result_id,
            "resultPath": result_path,
            "scanId": record["scanId"],
            "scanRecordSchemaVersion": record["schemaVersion"],
            "mappingVersion": record["mappingVersion"],
            "sceneManifestVersion": scene["manifestVersion"],
            "sourceHashes": source_hashes,
        }
    )
    source_hashes["resultBindingSha256"] = result_binding_hash
    limitations = [
        {
            "code": _safe_public_text(limitation["code"], f"limitation {index} code"),
            "scope": limitation["scope"],
            "targetId": (
                None
                if limitation.get("targetId") is None
                else _safe_public_text(
                    limitation["targetId"],
                    f"limitation {index} target ID",
                )
            ),
            "message": _safe_public_text(
                limitation["message"],
                f"limitation {index} message",
            ),
            "invalidatesMetrics": [
                _safe_public_text(metric, f"limitation {index} invalidated metric")
                for metric in limitation["invalidatesMetrics"]
            ],
            "recordRef": f"#/limitations/{index}",
        }
        for index, limitation in enumerate(record["limitations"])
    ]
    if share_state == "unavailable":
        required_layers = ["page-identity", "capture-status", "product-identity", "new-scan-cta"]
    elif hero is None:
        required_layers = [
            "page-identity",
            "scene",
            "neutral-summary",
            "product-identity",
            "new-scan-cta",
        ]
    else:
        required_layers = [
            "page-identity",
            "scene",
            "hero-fact",
            "product-identity",
            "new-scan-cta",
        ]
    if record["status"] == "partial":
        required_layers.append("partial-status")
        required_layers.append("limitation-disclosure")

    page_identity = {'recordRef': '#/page/registrableDomain'}
    page_domain = record['page']['registrableDomain']
    if page_domain is None:
        page_domain = urlsplit(record['finalUrl']).hostname
        page_identity = {'recordRef': '#/finalUrl', 'derivation': 'url-hostname-v1'}
    page_label = _safe_public_text(page_domain, "page identity")
    _require(
        len(page_label) <= 253 and not re.search(r"[\s/?#]", page_label),
        "invalid public page identity",
    )

    return {
        "resultManifestVersion": RESULT_MANIFEST_VERSION,
        "resultId": result_id,
        "resultPath": result_path,
        "scanId": record["scanId"],
        "scanRecordSchemaVersion": record["schemaVersion"],
        "mappingVersion": record["mappingVersion"],
        "sceneManifestVersion": scene["manifestVersion"],
        "sourceHashes": source_hashes,
        "pageIdentity": {
            "label": page_label,
            **page_identity,
        },
        "status": record["status"],
        "failureCode": record["failureCode"],
        "statusPresentation": {
            "label": _STATUS_LABELS[record["status"]],
            "partialLabelRequired": record["status"] == "partial",
        },
        "shareState": share_state,
        "hero": hero,
        "content": {
            "productName": "DOM X-Ray",
            "finalFrameCta": "X-RAY ANOTHER SITE",
            "requiredLayers": required_layers,
        },
        "exports": {
            "poster": _artifact_target(
                "poster",
                eligible=artifact_eligible,
                result_binding_hash=result_binding_hash,
                scene_hash=scene_hash,
                hero_hash=hero_hash,
                payload=payloads.get("poster"),
            ),
            "video": _artifact_target(
                "video",
                eligible=artifact_eligible,
                result_binding_hash=result_binding_hash,
                scene_hash=scene_hash,
                hero_hash=hero_hash,
                payload=payloads.get("video"),
            ),
        },
        "limitations": limitations,
    }
