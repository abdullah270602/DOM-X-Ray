"""Renderer-neutral viewer model and deterministic interaction reducer."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

from scanner.result_manifest import build_result_manifest, stable_result_json
from scanner.scene_manifest import (
    DEFAULT_MAPPING_REGISTRY,
    build_scene_manifest,
    stable_manifest_json,
)


VIEWER_RUNTIME_VERSION = "viewer-runtime-v0.1.0"
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_UNSAFE_RUNTIME_TEXT = re.compile(r"[\x00-\x1f\x7f<>]")
_MODES = ("structure", "weight", "origins")
_STAGE_TARGETS = {
    "flat": {"page": 1.0, "structure": 0.0, "weight": 0.0, "origins": 0.0, "finding": 0.0},
    "structure": {"page": 1.0, "structure": 1.0, "weight": 0.0, "origins": 0.0, "finding": 0.0},
    "weight": {"page": 1.0, "structure": 1.0, "weight": 1.0, "origins": 0.0, "finding": 0.0},
    "party": {"page": 1.0, "structure": 1.0, "weight": 1.0, "origins": 1.0, "finding": 0.0},
    "hero": {"page": 1.0, "structure": 1.0, "weight": 1.0, "origins": 1.0, "finding": 1.0},
}
_STATUS_FALLBACKS = {
    "interstitial": "The captured page was an interstitial, so no page finding is presented.",
    "blocked": "The capture was blocked, so no page finding is presented.",
    "failed": "The capture failed, so no page finding is presented.",
}


class ViewerRuntimeError(ValueError):
    """Raised when viewer sources, state, or events disagree with the contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ViewerRuntimeError(message)


def stable_viewer_json(value: Any) -> str:
    """Return canonical JSON for runtime fixtures and source fingerprints."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _json_hash(value: Any) -> str:
    return hashlib.sha256(stable_viewer_json(value).encode("utf-8")).hexdigest()


def _safe_runtime_text(value: Any, label: str) -> str:
    _require(
        isinstance(value, str) and bool(value) and not _UNSAFE_RUNTIME_TEXT.search(value),
        f"unsafe viewer {label}",
    )
    return value


def resolve_pointer(document: Any, pointer: str) -> Any:
    """Resolve a local RFC 6901 pointer, failing closed on absent data."""

    _require(isinstance(pointer, str) and pointer.startswith("#/"), "invalid local JSON Pointer")
    current = document
    for encoded in pointer[2:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            _require(token.isdigit(), f"non-numeric array pointer token: {pointer}")
            index = int(token)
            _require(0 <= index < len(current), f"array pointer is out of range: {pointer}")
            current = current[index]
        else:
            _require(isinstance(current, dict) and token in current, f"unresolved pointer: {pointer}")
            current = current[token]
    return current


def _verify_result_source(
    record: dict[str, Any],
    scene: dict[str, Any],
    result: dict[str, Any],
    mapping: dict[str, Any],
) -> None:
    """Verify a result while allowing already-registered artifact byte metadata."""

    expected = build_result_manifest(
        record,
        result_id=result["resultId"],
        scene_manifest=scene,
        mapping_registry=mapping,
    )
    candidate = copy.deepcopy(result)
    _require(set(candidate.get("exports", {})) == {"poster", "video"}, "result exports drifted")
    for kind in ("poster", "video"):
        target = candidate["exports"][kind]
        expected_target = expected["exports"][kind]
        _require(target.get("eligible") == expected_target["eligible"], f"{kind} eligibility drifted")
        state = target.get("state")
        artifact = target.get("artifact")
        if state == "ready":
            _require(target["eligible"], f"ineligible {kind} became ready")
            _require(isinstance(artifact, dict) and set(artifact) == {"sha256", "byteLength"}, f"invalid ready {kind} metadata")
            _require(
                isinstance(artifact["sha256"], str) and bool(_SHA256.fullmatch(artifact["sha256"])),
                f"invalid ready {kind} hash",
            )
            _require(
                isinstance(artifact["byteLength"], int)
                and not isinstance(artifact["byteLength"], bool)
                and 0 < artifact["byteLength"] <= target["maxByteLength"],
                f"invalid ready {kind} byte length",
            )
        else:
            _require(
                state == expected_target["state"] and artifact is None,
                f"invalid {kind} generation state",
            )
        target["state"] = expected_target["state"]
        target["artifact"] = None
    _require(
        stable_result_json(candidate) == stable_result_json(expected),
        "result manifest does not match scan, scene, mapping, and route",
    )


def _mapping_refs_for_object(item: dict[str, Any]) -> list[str]:
    if item["kind"] in {"region", "aggregate"}:
        refs = ["#/scene/coordinateRule", "#/structure/depthRule", "#/structure/zRule"]
        if item["kind"] == "aggregate":
            refs.append("#/structure/aggregationRule")
        weight = item["weight"]
        if (
            weight["knownResourceIds"]
            or weight["unknownResourceIds"]
            or weight["blockedResourceIds"]
            or weight["massSuppressedResourceIds"]
        ):
            refs.append("#/weight")
        return refs
    if item["kind"] == "page-bus":
        return ["#/party/pageBusPlacementRule"]
    return [
        "#/party/classificationRule",
        "#/party/groupField",
        "#/party/hubPlacementRule",
    ]


def _object_selectable(
    item: dict[str, Any],
    index: int,
    limitation_refs: dict[str, str],
) -> dict[str, Any]:
    if item["kind"] in {"region", "aggregate"}:
        channels = ["structure"]
        weight = item["weight"]
        if (
            weight["knownResourceIds"]
            or weight["unknownResourceIds"]
            or weight["blockedResourceIds"]
            or weight["massSuppressedResourceIds"]
        ):
            channels.append("weight")
        label = "AGGREGATED REGION" if item["kind"] == "aggregate" else "PAGE REGION"
        codes = weight["limitationCodes"]
    elif item["kind"] == "page-bus":
        channels = ["origins"]
        label = "PAGE RESOURCE BUS"
        codes = []
    else:
        channels = ["origins"]
        label = "EXTERNAL DOMAIN HUB"
        codes = []
    return {
        "id": item["id"],
        "kind": item["kind"],
        "label": label,
        "renderable": True,
        "sceneRefs": [f"#/objects/{index}"],
        "recordRefs": list(item["evidence"]["recordRefs"]),
        "mappingRefs": _mapping_refs_for_object(item),
        "resultRefs": [],
        "limitationRefs": [limitation_refs[code] for code in codes],
        "emphasisChannels": channels,
    }


def _connection_selectable(item: dict[str, Any], index: int) -> dict[str, Any]:
    mapping_refs = ["#/party/classificationRule", "#/party/knownCableThicknessRule"]
    if item["measurement"]["transferredBytes"] is None:
        mapping_refs.append("#/party/unknownCableStyle")
    return {
        "id": item["id"],
        "kind": "resource-path",
        "label": "RESOURCE PATH",
        "renderable": True,
        "sceneRefs": [f"#/connections/{index}"],
        "recordRefs": list(item["evidence"]["recordRefs"]),
        "mappingRefs": mapping_refs,
        "resultRefs": [],
        "limitationRefs": list(item["evidence"]["limitationRefs"]),
        "emphasisChannels": ["weight", "origins"],
    }


def _evidence_only_selectable(item: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "id": f"evidence:{item['nodeId']}",
        "kind": "evidence-only-node",
        "label": "EVIDENCE-ONLY REGION",
        "renderable": False,
        "sceneRefs": [f"#/nonSceneNodes/{index}"],
        "recordRefs": [item["recordRef"]],
        "mappingRefs": ["#/scene/objectBudgetRule", "#/structure/aggregationRule"],
        "resultRefs": [],
        "limitationRefs": [],
        "emphasisChannels": ["structure"],
    }


def _finding_selectable(scene: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    if scene["hero"] is not None:
        return {
            "id": "finding:primary",
            "kind": "hero-finding",
            "label": "PRIMARY FINDING",
            "renderable": False,
            "sceneRefs": ["#/hero"],
            "recordRefs": [scene["hero"]["recordRef"], *scene["hero"]["sourceRefs"]],
            "mappingRefs": ["#/heroSelection"],
            "resultRefs": ["#/hero"],
            "limitationRefs": [
                item["recordRef"] for item in result["limitations"]
                if item["code"] in set(scene["hero"]["limitationCodes"])
            ],
            "emphasisChannels": ["finding"],
        }
    return {
        "id": "finding:summary",
        "kind": "neutral-summary",
        "label": "CAPTURE SUMMARY",
        "renderable": False,
        "sceneRefs": [],
        "recordRefs": ["#/capture", "#/page/registrableDomain"],
        "mappingRefs": ["#/heroSelection/fallback", "#/heroSelection/fallbackShareEligible"],
        "resultRefs": ["#/status", "#/failureCode", "#/shareState"],
        "limitationRefs": [item["recordRef"] for item in result["limitations"]],
        "emphasisChannels": ["finding"],
    }


def _status_selectable(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "status:capture",
        "kind": "capture-status",
        "label": "CAPTURE STATUS",
        "renderable": False,
        "sceneRefs": ["#/status", "#/failureCode", "#/limitations"],
        "recordRefs": ["#/status", "#/failureCode", "#/limitations"],
        "mappingRefs": [],
        "resultRefs": ["#/statusPresentation", "#/limitations"],
        "limitationRefs": [item["recordRef"] for item in result["limitations"]],
        "emphasisChannels": ["finding"],
    }


def _initial_state(motion: str) -> dict[str, Any]:
    return {
        "motion": motion,
        "phase": "revealing" if motion == "standard" else "stepping",
        "playback": "playing" if motion == "standard" else "paused",
        "elapsedMs": 0,
        "stageIndex": 0,
        "stageId": "flat",
        "mode": "structure",
        "selectedId": None,
        "isolatedId": None,
        "revision": 0,
    }


def build_viewer_runtime(
    record: dict[str, Any],
    scene: dict[str, Any],
    result: dict[str, Any],
    mapping: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the shared behavioral model for every viewer presentation path."""

    registry = mapping or DEFAULT_MAPPING_REGISTRY
    expected_scene = build_scene_manifest(record, registry)
    _require(
        stable_manifest_json(scene) == stable_manifest_json(expected_scene),
        "scene manifest does not match the admitted scan and mapping",
    )
    _verify_result_source(record, scene, result, registry)

    limitation_refs = {item["code"]: item["recordRef"] for item in result["limitations"]}
    selectables = [
        _object_selectable(item, index, limitation_refs)
        for index, item in enumerate(scene["objects"])
    ]
    selectables.extend(
        _connection_selectable(item, index)
        for index, item in enumerate(scene["connections"])
    )
    selectables.extend(
        _evidence_only_selectable(item, index)
        for index, item in enumerate(scene["nonSceneNodes"])
    )
    selectables.append(_finding_selectable(scene, result))
    selectables.append(_status_selectable(result))
    ids = [item["id"] for item in selectables]
    _require(len(ids) == len(set(ids)), "selectable IDs must be unique")
    _safe_runtime_text(record["scanId"], "scan ID")
    for selectable_id in ids:
        _safe_runtime_text(selectable_id, "selectable ID")

    documents = {
        "recordRefs": record,
        "sceneRefs": scene,
        "mappingRefs": registry,
        "resultRefs": result,
        "limitationRefs": record,
    }
    for selectable in selectables:
        for field, document in documents.items():
            for pointer in selectable[field]:
                resolve_pointer(document, pointer)

    stages = []
    for stage in scene["reveal"]:
        start_ms = round(stage["startSeconds"] * 1_000)
        end_ms = round(stage["endSeconds"] * 1_000)
        _require(end_ms > start_ms, f"reveal stage {stage['id']} has no duration")
        stages.append(
            {
                "id": stage["id"],
                "startMs": start_ms,
                "endMs": end_ms,
                "meaning": stage["meaning"],
                "targetChannels": copy.deepcopy(_STAGE_TARGETS[stage["id"]]),
            }
        )
    _require([stage["id"] for stage in stages] == list(_STAGE_TARGETS), "reveal order drifted")
    _require(stages[0]["startMs"] == 0 and stages[-1]["endMs"] == 5_000, "reveal duration drifted")
    for left, right in zip(stages, stages[1:]):
        _require(left["endMs"] == right["startMs"], "reveal stages are not contiguous")

    if result["hero"] is not None:
        finding = {
            "kind": "hero",
            "statement": result["hero"]["statement"],
            "shareEligible": True,
            "resultRef": "#/hero",
            "recordRef": result["hero"]["recordRef"],
        }
    elif result["status"] in {"complete", "partial"}:
        finding = {
            "kind": "neutral",
            "statement": "No standout finding was captured for this load.",
            "shareEligible": False,
            "resultRef": None,
            "recordRef": "#/capture",
        }
    else:
        finding = {
            "kind": "unavailable",
            "statement": _STATUS_FALLBACKS[result["status"]],
            "shareEligible": False,
            "resultRef": None,
            "recordRef": "#/status",
        }

    return {
        "viewerRuntimeVersion": VIEWER_RUNTIME_VERSION,
        "scanId": record["scanId"],
        "resultId": result["resultId"],
        "resultPath": result["resultPath"],
        "mappingVersion": registry["version"],
        "sourceHashes": {
            "scanRecordSha256": result["sourceHashes"]["scanRecordSha256"],
            "sceneManifestSha256": result["sourceHashes"]["sceneManifestSha256"],
            "mappingRegistrySha256": result["sourceHashes"]["mappingRegistrySha256"],
            "resultBindingSha256": result["sourceHashes"]["resultBindingSha256"],
            "resultManifestSha256": _json_hash(result),
        },
        "accessPaths": [
            {"id": "webgl", "requiresSceneRendering": True, "usesSameEvidence": True},
            {"id": "reduced-motion", "requiresSceneRendering": False, "usesSameEvidence": True},
            {"id": "text", "requiresSceneRendering": False, "usesSameEvidence": True},
        ],
        "presentation": {
            "pageLabel": result["pageIdentity"]["label"],
            "status": result["status"],
            "failureCode": result["failureCode"],
            "statusLabel": result["statusPresentation"]["label"],
            "partialLabelRequired": result["statusPresentation"]["partialLabelRequired"],
            "shareState": result["shareState"],
            "finding": finding,
            "limitationResultRefs": [
                f"#/limitations/{index}" for index in range(len(result["limitations"]))
            ],
        },
        "playback": {
            "durationMs": 5_000,
            "stages": stages,
            "reducedMotion": {
                "mode": scene["reducedMotion"]["mode"],
                "stepOrder": [stage["id"] for stage in stages],
                "cameraMotion": False,
                "continuousGeometryMotion": False,
            },
            "rendererOwned": ["camera-pose", "easing", "lighting", "material-interpolation"],
        },
        "modes": [
            {
                "id": "structure",
                "label": "STRUCTURE",
                "emphasizes": ["structure"],
                "preserves": ["object-membership", "geometry", "measurements", "endpoints"],
            },
            {
                "id": "weight",
                "label": "WEIGHT",
                "emphasizes": ["weight"],
                "preserves": ["object-membership", "geometry", "measurements", "endpoints"],
            },
            {
                "id": "origins",
                "label": "ORIGINS",
                "emphasizes": ["origins"],
                "preserves": ["object-membership", "geometry", "measurements", "endpoints"],
            },
        ],
        "selectables": selectables,
        "initialStates": {
            "standard": _initial_state("standard"),
            "reducedMotion": _initial_state("reduced"),
        },
    }


def _stage_for_elapsed(model: dict[str, Any], elapsed_ms: int) -> tuple[int, dict[str, Any]]:
    stages = model["playback"]["stages"]
    for index, stage in enumerate(stages):
        if elapsed_ms < stage["endMs"]:
            return index, stage
    return len(stages) - 1, stages[-1]


def _validate_state(model: dict[str, Any], state: dict[str, Any]) -> None:
    expected_fields = {
        "motion",
        "phase",
        "playback",
        "elapsedMs",
        "stageIndex",
        "stageId",
        "mode",
        "selectedId",
        "isolatedId",
        "revision",
    }
    _require(isinstance(state, dict) and set(state) == expected_fields, "viewer state fields drifted")
    _require(state["motion"] in {"standard", "reduced"}, "invalid motion preference")
    _require(state["mode"] in _MODES, "invalid viewer state mode")
    _require(
        isinstance(state["elapsedMs"], int)
        and not isinstance(state["elapsedMs"], bool)
        and 0 <= state["elapsedMs"] <= model["playback"]["durationMs"],
        "invalid viewer elapsed time",
    )
    _require(
        isinstance(state["revision"], int)
        and not isinstance(state["revision"], bool)
        and state["revision"] >= 0,
        "invalid viewer revision",
    )
    stage_index, stage = _stage_for_elapsed(model, state["elapsedMs"])
    _require(
        state["stageIndex"] == stage_index and state["stageId"] == stage["id"],
        "viewer stage does not match elapsed time",
    )
    at_end = state["elapsedMs"] == model["playback"]["durationMs"]
    expected_phase = "exploring" if at_end else (
        "stepping" if state["motion"] == "reduced" else "revealing"
    )
    _require(state["phase"] == expected_phase, "viewer phase does not match timeline")
    if at_end:
        _require(state["playback"] == "complete", "completed reveal has wrong playback state")
    elif state["motion"] == "reduced":
        _require(state["playback"] == "paused", "reduced-motion playback cannot run continuously")
    else:
        _require(state["playback"] in {"playing", "paused"}, "invalid standard playback state")

    selectable_by_id = {item["id"]: item for item in model["selectables"]}
    selected_id = state["selectedId"]
    isolated_id = state["isolatedId"]
    _require(selected_id is None or selected_id in selectable_by_id, "state selects an unknown ID")
    _require(isolated_id is None or isolated_id == selected_id, "isolation is not the active selection")
    if isolated_id is not None:
        _require(selectable_by_id[isolated_id]["renderable"], "state isolates non-renderable evidence")


def _updated_timeline_state(
    model: dict[str, Any],
    state: dict[str, Any],
    elapsed_ms: int,
    *,
    playback: str | None = None,
) -> dict[str, Any]:
    duration = model["playback"]["durationMs"]
    elapsed = max(0, min(duration, elapsed_ms))
    index, stage = _stage_for_elapsed(model, elapsed)
    result = copy.deepcopy(state)
    result["elapsedMs"] = elapsed
    result["stageIndex"] = index
    result["stageId"] = stage["id"]
    result["phase"] = "exploring" if elapsed == duration else (
        "stepping" if state["motion"] == "reduced" else "revealing"
    )
    result["playback"] = (
        "complete" if elapsed == duration else (playback if playback is not None else state["playback"])
    )
    return result


def reduce_viewer_state(
    model: dict[str, Any],
    state: dict[str, Any],
    event: dict[str, Any],
) -> dict[str, Any]:
    """Apply one explicit viewer event without network or renderer side effects."""

    _validate_state(model, state)
    _require(isinstance(event, dict) and isinstance(event.get("type"), str), "invalid viewer event")
    current = copy.deepcopy(state)
    event_type = event["type"]

    if event_type == "tick":
        _require(current["motion"] == "standard", "reduced motion does not accept tick")
        _require(set(event) == {"type", "deltaMs"}, "tick fields drifted")
        delta = event["deltaMs"]
        _require(isinstance(delta, int) and not isinstance(delta, bool) and delta >= 0, "invalid tick delta")
        if current["playback"] != "playing":
            return current
        updated = _updated_timeline_state(model, current, current["elapsedMs"] + delta)
    elif event_type == "seek":
        _require(current["motion"] == "standard", "reduced motion uses stage advance, not seek")
        _require(set(event) == {"type", "elapsedMs"}, "seek fields drifted")
        elapsed = event["elapsedMs"]
        _require(isinstance(elapsed, int) and not isinstance(elapsed, bool), "invalid seek time")
        updated = _updated_timeline_state(model, current, elapsed, playback="paused")
    elif event_type == "pause":
        _require(set(event) == {"type"} and current["motion"] == "standard", "invalid pause")
        updated = copy.deepcopy(current)
        if updated["playback"] == "playing":
            updated["playback"] = "paused"
    elif event_type == "play":
        _require(set(event) == {"type"} and current["motion"] == "standard", "invalid play")
        _require(current["elapsedMs"] < model["playback"]["durationMs"], "completed reveal requires replay")
        updated = copy.deepcopy(current)
        updated["playback"] = "playing"
    elif event_type == "skip-reveal":
        _require(
            set(event) == {"type"} and current["motion"] == "standard",
            "reduced motion preserves user-advanced stages",
        )
        updated = _updated_timeline_state(model, current, model["playback"]["durationMs"])
    elif event_type == "replay":
        _require(set(event) == {"type"}, "replay fields drifted")
        updated = _initial_state(current["motion"])
    elif event_type == "advance-stage":
        _require(set(event) == {"type"} and current["motion"] == "reduced", "invalid stage advance")
        stages = model["playback"]["stages"]
        next_index = min(len(stages) - 1, current["stageIndex"] + 1)
        elapsed = stages[next_index]["startMs"]
        if next_index == len(stages) - 1:
            elapsed = model["playback"]["durationMs"]
        updated = _updated_timeline_state(model, current, elapsed, playback="paused")
    elif event_type == "set-mode":
        _require(set(event) == {"type", "mode"} and event["mode"] in _MODES, "invalid viewer mode")
        updated = copy.deepcopy(current)
        updated["mode"] = event["mode"]
    elif event_type == "select":
        _require(set(event) == {"type", "id"} and isinstance(event["id"], str), "invalid selection")
        selectable_ids = {item["id"] for item in model["selectables"]}
        _require(event["id"] in selectable_ids, "unknown selectable ID")
        updated = copy.deepcopy(current)
        updated["selectedId"] = event["id"]
        if updated["isolatedId"] != event["id"]:
            updated["isolatedId"] = None
    elif event_type == "isolate-selected":
        _require(set(event) == {"type"} and current["selectedId"] is not None, "nothing selected to isolate")
        selectable = next(item for item in model["selectables"] if item["id"] == current["selectedId"])
        _require(selectable["renderable"], "non-renderable evidence cannot be isolated")
        updated = copy.deepcopy(current)
        updated["isolatedId"] = current["selectedId"]
    elif event_type == "clear-isolation":
        _require(set(event) == {"type"}, "clear-isolation fields drifted")
        updated = copy.deepcopy(current)
        updated["isolatedId"] = None
    elif event_type == "clear-selection":
        _require(set(event) == {"type"}, "clear-selection fields drifted")
        updated = copy.deepcopy(current)
        updated["selectedId"] = None
        updated["isolatedId"] = None
    else:
        raise ViewerRuntimeError(f"unknown viewer event: {event_type}")

    if stable_viewer_json(updated) != stable_viewer_json(current):
        updated["revision"] = current["revision"] + 1
    _validate_state(model, updated)
    return updated


def presentation_frame(model: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Derive renderer-independent reveal progress from the current state."""

    _validate_state(model, state)
    stages = model["playback"]["stages"]
    active = stages[state["stageIndex"]]
    channels = {name: 0.0 for name in _STAGE_TARGETS["flat"]}
    if state["motion"] == "reduced":
        channels = copy.deepcopy(active["targetChannels"])
        stage_progress = 1.0
    else:
        prior = _STAGE_TARGETS[stages[max(0, state["stageIndex"] - 1)]["id"]]
        if state["stageIndex"] == 0:
            prior = {"page": 1.0, "structure": 0.0, "weight": 0.0, "origins": 0.0, "finding": 0.0}
        duration = active["endMs"] - active["startMs"]
        stage_progress = min(1.0, max(0.0, (state["elapsedMs"] - active["startMs"]) / duration))
        for name, target in active["targetChannels"].items():
            channels[name] = round(prior[name] + (target - prior[name]) * stage_progress, 6)
    if state["elapsedMs"] == model["playback"]["durationMs"]:
        stage_progress = 1.0
        channels = copy.deepcopy(stages[-1]["targetChannels"])
    return {
        "stageId": state["stageId"],
        "stageProgress": round(stage_progress, 6),
        "channels": channels,
        "mode": state["mode"],
        "selectedId": state["selectedId"],
        "isolatedId": state["isolatedId"],
    }


def resolve_selection(
    model: dict[str, Any],
    selectable_id: str,
    *,
    record: dict[str, Any],
    scene: dict[str, Any],
    result: dict[str, Any],
    mapping: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve one selectable to its exact source and mapping evidence."""

    registry = mapping or DEFAULT_MAPPING_REGISTRY
    expected_model = build_viewer_runtime(record, scene, result, registry)
    _require(
        stable_viewer_json(model) == stable_viewer_json(expected_model),
        "viewer model does not match its bound sources",
    )
    matches = [item for item in model["selectables"] if item["id"] == selectable_id]
    _require(len(matches) == 1, "selection does not resolve to exactly one dossier")
    selectable = matches[0]
    documents = {
        "scene": (scene, selectable["sceneRefs"]),
        "record": (record, selectable["recordRefs"]),
        "mapping": (registry, selectable["mappingRefs"]),
        "result": (result, selectable["resultRefs"]),
        "limitations": (record, selectable["limitationRefs"]),
    }
    return {
        "selectableId": selectable_id,
        "kind": selectable["kind"],
        "label": selectable["label"],
        "renderable": selectable["renderable"],
        "sources": {
            name: [
                {"ref": pointer, "value": copy.deepcopy(resolve_pointer(document, pointer))}
                for pointer in pointers
            ]
            for name, (document, pointers) in documents.items()
        },
    }
