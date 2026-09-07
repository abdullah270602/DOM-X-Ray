"""Verify the renderer-neutral viewer model, evidence graph, and reducer."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.result_manifest import build_result_manifest  # noqa: E402
from scanner.scene_manifest import build_scene_manifest  # noqa: E402
from scanner.viewer_runtime import (  # noqa: E402
    ViewerRuntimeError,
    build_viewer_runtime,
    presentation_frame,
    reduce_viewer_state,
    resolve_selection,
    stable_viewer_json,
)
from scripts.export_result_fixtures import RESULT_IDS  # noqa: E402
from scripts.export_viewer_runtime_fixtures import FIXTURE_NAMES  # noqa: E402


SCAN_DIR = ROOT / "fixtures" / "scan"
SCENE_DIR = ROOT / "fixtures" / "scene-manifest"
RESULT_DIR = ROOT / "fixtures" / "result-manifest"
RUNTIME_DIR = ROOT / "fixtures" / "viewer-runtime"
SCHEMA = json.loads((ROOT / "docs" / "VIEWER_RUNTIME.schema.json").read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def expect_runtime_failure(name: str, action: Callable[[], object]) -> None:
    try:
        action()
    except (ViewerRuntimeError, KeyError, TypeError, ValueError):
        return
    raise AssertionError(f"viewer-runtime negative control was accepted: {name}")


def expect_schema_failure(
    name: str,
    model: dict[str, Any],
    validator: Draft202012Validator,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    candidate = copy.deepcopy(model)
    mutate(candidate)
    if list(validator.iter_errors(candidate)):
        return
    raise AssertionError(f"viewer-runtime schema control was accepted: {name}")


def build_sources(name: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    return (
        load_json(SCAN_DIR / name),
        load_json(SCENE_DIR / name),
        load_json(RESULT_DIR / name),
    )


def build_synthetic_runtime(
    record: dict[str, Any],
    result_id: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    scene = build_scene_manifest(record)
    result = build_result_manifest(record, result_id=result_id, scene_manifest=scene)
    return scene, result, build_viewer_runtime(record, scene, result)


def main() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    state_validator = Draft202012Validator(SCHEMA["$defs"]["viewerState"])
    sources = {name: build_sources(name) for name in FIXTURE_NAMES}
    models = {
        name: build_viewer_runtime(record, scene, result)
        for name, (record, scene, result) in sources.items()
    }

    for name, model in models.items():
        errors = sorted(validator.iter_errors(model), key=lambda error: list(error.path))
        require(
            not errors,
            f"{name} viewer runtime failed schema: "
            + "; ".join(error.message for error in errors),
        )
        golden_path = RUNTIME_DIR / name
        require(golden_path.is_file(), f"missing committed viewer-runtime fixture: {name}")
        require(golden_path.read_text(encoding="utf-8") == pretty_json(model), f"stale runtime: {name}")
        require(
            stable_viewer_json(model)
            == stable_viewer_json(build_viewer_runtime(*sources[name])),
            f"viewer runtime was not deterministic: {name}",
        )
        ids = [item["id"] for item in model["selectables"]]
        require(len(ids) == len(set(ids)), f"duplicate selectable ID: {name}")
        record, scene, result = sources[name]
        for selectable_id in ids:
            dossier = resolve_selection(
                model,
                selectable_id,
                record=record,
                scene=scene,
                result=result,
            )
            require(dossier["selectableId"] == selectable_id, f"wrong dossier: {selectable_id}")

        serialized = stable_viewer_json(model)
        require(record["page"]["title"] not in serialized, f"runtime leaked page title: {name}")
        for resource in record["resources"]:
            require(resource["displayUrl"] not in serialized, f"runtime leaked resource URL: {name}")
        for node in record["nodes"]:
            if len(node["selector"]) >= 8:
                require(node["selector"] not in serialized, f"runtime leaked selector: {name}")

    clean = models["clean.json"]
    image = models["image-heavy.json"]
    third = models["third-party-heavy.json"]
    require(
        clean["presentation"]["finding"]
        == {
            "kind": "neutral",
            "statement": "No standout finding was captured for this load.",
            "shareEligible": False,
            "resultRef": None,
            "recordRef": "#/capture",
        },
        "clean result manufactured a finding",
    )
    require(
        image["presentation"]["finding"]["kind"] == "hero"
        and image["presentation"]["finding"]["statement"]
        == sources["image-heavy.json"][2]["hero"]["statement"],
        "image hero did not bind exact result text",
    )
    require(
        third["presentation"]["partialLabelRequired"]
        and third["presentation"]["limitationResultRefs"] == ["#/limitations/0"]
        and third["presentation"]["finding"]["kind"] == "hero",
        "partial runtime hid status or limitations",
    )
    require(
        [item["id"] for item in third["accessPaths"]] == ["webgl", "reduced-motion", "text"]
        and all(item["usesSameEvidence"] for item in third["accessPaths"]),
        "fallback paths diverged from the shared evidence model",
    )

    record, scene, result = sources["image-heavy.json"]
    region_dossier = resolve_selection(
        image,
        "region:n-hero",
        record=record,
        scene=scene,
        result=result,
    )
    require(
        region_dossier["sources"]["record"][0]["value"]["id"] == "n-hero"
        and any(row["ref"] == "#/weight" for row in region_dossier["sources"]["mapping"]),
        "weighted region lost raw node or mapping evidence",
    )
    path_dossier = resolve_selection(
        image,
        "connection:r-hero",
        record=record,
        scene=scene,
        result=result,
    )
    require(
        path_dossier["sources"]["record"][0]["value"]["transferredBytes"] == 2_400_000,
        "resource path lost its exact transfer measurement",
    )
    third_hub = resolve_selection(
        third,
        "hub:service.example",
        record=sources["third-party-heavy.json"][0],
        scene=sources["third-party-heavy.json"][1],
        result=sources["third-party-heavy.json"][2],
    )
    require(
        len(third_hub["sources"]["record"]) == 4
        and third_hub["sources"]["mapping"][0]["value"] == "registrable-domain-v1",
        "external hub lost grouping evidence",
    )

    source_model_hash = hashlib.sha256(stable_viewer_json(image).encode("utf-8")).hexdigest()
    state = copy.deepcopy(image["initialStates"]["standard"])
    require(not list(state_validator.iter_errors(state)), "standard initial state failed schema")
    state = reduce_viewer_state(image, state, {"type": "tick", "deltaMs": 700})
    require(state["stageId"] == "structure" and state["elapsedMs"] == 700, "stage boundary drifted")
    state = reduce_viewer_state(image, state, {"type": "tick", "deltaMs": 500})
    frame = presentation_frame(image, state)
    require(
        frame["stageId"] == "structure"
        and frame["stageProgress"] == 0.5
        and frame["channels"]["structure"] == 0.5,
        "structure interpolation drifted",
    )
    state = reduce_viewer_state(image, state, {"type": "seek", "elapsedMs": 4_600})
    frame = presentation_frame(image, state)
    require(
        state["playback"] == "paused"
        and frame["stageId"] == "hero"
        and frame["channels"]["finding"] == 0.5,
        "hero scrub was not deterministic",
    )
    state = reduce_viewer_state(image, state, {"type": "set-mode", "mode": "weight"})
    state = reduce_viewer_state(image, state, {"type": "select", "id": "region:n-hero"})
    state = reduce_viewer_state(image, state, {"type": "isolate-selected"})
    require(
        state["mode"] == "weight"
        and state["selectedId"] == "region:n-hero"
        and state["isolatedId"] == "region:n-hero",
        "mode/selection/isolation state drifted",
    )
    require(
        hashlib.sha256(stable_viewer_json(image).encode("utf-8")).hexdigest() == source_model_hash,
        "interaction mutated the immutable viewer model",
    )
    replay_a = reduce_viewer_state(image, state, {"type": "replay"})
    replay_b = reduce_viewer_state(image, copy.deepcopy(state), {"type": "replay"})
    require(replay_a == replay_b, "replay was not deterministic")
    require(
        replay_a["elapsedMs"] == 0
        and replay_a["stageId"] == "flat"
        and replay_a["mode"] == "structure"
        and replay_a["selectedId"] is None
        and replay_a["isolatedId"] is None,
        "replay did not return to the authored start",
    )

    reduced = copy.deepcopy(image["initialStates"]["reducedMotion"])
    require(not list(state_validator.iter_errors(reduced)), "reduced initial state failed schema")
    reduced_frames = [presentation_frame(image, reduced)]
    for _ in range(4):
        reduced = reduce_viewer_state(image, reduced, {"type": "advance-stage"})
        reduced_frames.append(presentation_frame(image, reduced))
    require(
        [frame["stageId"] for frame in reduced_frames]
        == ["flat", "structure", "weight", "party", "hero"]
        and reduced["phase"] == "exploring"
        and reduced["playback"] == "complete"
        and reduced_frames[-1]["channels"]
        == {"page": 1.0, "structure": 1.0, "weight": 1.0, "origins": 1.0, "finding": 1.0},
        "reduced-motion steps did not preserve the five-stage story",
    )

    partial_no_hero_record = copy.deepcopy(sources["clean.json"][0])
    partial_no_hero_record["scanId"] = "synthetic-runtime-partial-no-hero"
    partial_no_hero_record["status"] = "partial"
    partial_no_hero_record["failureCode"] = "measurement-unavailable"
    partial_no_hero_record["limitations"] = [
        {
            "code": "hero-measurement-unavailable",
            "scope": "page",
            "message": "A defensible hero measurement was unavailable for this captured load.",
            "invalidatesMetrics": ["hero_insight"],
        }
    ]
    _, _, partial_no_hero = build_synthetic_runtime(
        partial_no_hero_record,
        "r_00000000000000000000000000000011",
    )
    require(
        partial_no_hero["presentation"]["finding"]["kind"] == "neutral"
        and partial_no_hero["presentation"]["partialLabelRequired"]
        and partial_no_hero["presentation"]["limitationResultRefs"] == ["#/limitations/0"],
        "partial no-hero fallback hid uncertainty",
    )

    interstitial_record = copy.deepcopy(sources["clean.json"][0])
    interstitial_record["scanId"] = "synthetic-runtime-interstitial"
    interstitial_record["status"] = "interstitial"
    interstitial_record["failureCode"] = "interstitial"
    interstitial_record["insights"] = []
    interstitial_record["limitations"] = [
        {
            "code": "captured-interstitial",
            "scope": "page",
            "message": "The captured document was an interstitial.",
            "invalidatesMetrics": ["hero_insight", "intended_page_content"],
        }
    ]
    _, _, interstitial = build_synthetic_runtime(
        interstitial_record,
        "r_00000000000000000000000000000012",
    )
    require(
        interstitial["presentation"]["finding"]["kind"] == "unavailable"
        and interstitial["presentation"]["shareState"] == "unavailable",
        "interstitial became a page finding",
    )

    evidence_only_record = copy.deepcopy(sources["clean.json"][0])
    evidence_only_record["scanId"] = "synthetic-runtime-evidence-only"
    hidden = copy.deepcopy(evidence_only_record["nodes"][-1])
    hidden.update(
        {
            "id": "n-evidence-only",
            "parentId": "n-body",
            "selector": "main > section:nth-of-type(2)",
            "sceneIncluded": False,
            "memberNodeIds": [],
            "aggregationRule": None,
            "resourceIds": [],
        }
    )
    evidence_only_record["nodes"].append(hidden)
    evidence_scene, evidence_result, evidence_model = build_synthetic_runtime(
        evidence_only_record,
        "r_00000000000000000000000000000013",
    )
    evidence_selectable = next(
        item for item in evidence_model["selectables"] if item["id"] == "evidence:n-evidence-only"
    )
    require(
        not evidence_selectable["renderable"]
        and not any(item["id"] == "region:n-evidence-only" for item in evidence_scene["objects"]),
        "evidence-only node became a scene object",
    )
    evidence_dossier = resolve_selection(
        evidence_model,
        evidence_selectable["id"],
        record=evidence_only_record,
        scene=evidence_scene,
        result=evidence_result,
    )
    require(
        evidence_dossier["sources"]["record"][0]["value"]["id"] == "n-evidence-only",
        "evidence-only node became unreachable",
    )

    visual_state_cases = (
        ("cached-hollow", "cache", 0, []),
        ("service-worker-hollow", "service-worker", 0, []),
        ("hatched-hollow", "unknown", None, []),
        (
            "broken-outline",
            "network",
            12_000,
            [
                {
                    "code": "blocked-request-synthetic",
                    "scope": "resource",
                    "targetId": "r-document",
                    "message": "The synthetic resource request was blocked.",
                    "invalidatesMetrics": ["resource_mass"],
                }
            ],
        ),
    )
    for index, (expected_state, transfer_source, value, limitations) in enumerate(visual_state_cases):
        case = copy.deepcopy(sources["clean.json"][0])
        case["scanId"] = f"synthetic-runtime-transfer-{index}"
        case["resources"][0]["transferSource"] = transfer_source
        case["resources"][0]["transferredBytes"] = value
        case["limitations"] = limitations
        if limitations:
            case["status"] = "partial"
            case["failureCode"] = "resource-limit"
        case_scene, case_result, case_model = build_synthetic_runtime(
            case,
            f"r_{index + 20:032x}",
        )
        dossier = resolve_selection(
            case_model,
            "connection:r-document",
            record=case,
            scene=case_scene,
            result=case_result,
        )
        require(
            dossier["sources"]["scene"][0]["value"]["visualState"] == expected_state,
            f"{expected_state} did not survive the shared evidence path",
        )

    ready_result = build_result_manifest(
        sources["image-heavy.json"][0],
        result_id=RESULT_IDS["image-heavy.json"],
        scene_manifest=sources["image-heavy.json"][1],
        artifact_payloads={"poster": b"poster-ready-envelope"},
    )
    ready_model = build_viewer_runtime(
        sources["image-heavy.json"][0],
        sources["image-heavy.json"][1],
        ready_result,
    )
    require(
        ready_model["sourceHashes"]["resultManifestSha256"]
        != image["sourceHashes"]["resultManifestSha256"],
        "ready artifact metadata did not change the exact result hash",
    )

    tampered_scene = copy.deepcopy(sources["image-heavy.json"][1])
    tampered_scene["objects"][0]["positionWorld"]["x"] += 1
    tampered_result = copy.deepcopy(sources["image-heavy.json"][2])
    tampered_result["sourceHashes"]["scanRecordSha256"] = "0" * 64
    coerced_unknown_scene = copy.deepcopy(sources["third-party-heavy.json"][1])
    unknown_connection = next(
        item for item in coerced_unknown_scene["connections"] if item["visualState"] == "hatched-hollow"
    )
    unknown_connection["measurement"]["transferredBytes"] = 0
    invalid_pointer_model = copy.deepcopy(image)
    invalid_pointer_model["selectables"][0]["recordRefs"] = ["#/nodes/999"]
    misbound_pointer_model = copy.deepcopy(image)
    misbound_pointer_model["selectables"][0]["recordRefs"] = ["#/nodes/1"]
    inconsistent_state = copy.deepcopy(image["initialStates"]["standard"])
    inconsistent_state["stageId"] = "hero"
    unsafe_id_record = copy.deepcopy(sources["clean.json"][0])
    unsafe_id_record["scanId"] = "synthetic-runtime-unsafe-id"
    unsafe_node = copy.deepcopy(unsafe_id_record["nodes"][-1])
    unsafe_node.update(
        {
            "id": "<bad>",
            "parentId": "n-body",
            "sceneIncluded": False,
            "memberNodeIds": [],
            "aggregationRule": None,
            "resourceIds": [],
        }
    )
    unsafe_id_record["nodes"].append(unsafe_node)

    runtime_controls = (
        (
            "tampered scene",
            lambda: build_viewer_runtime(
                sources["image-heavy.json"][0],
                tampered_scene,
                sources["image-heavy.json"][2],
            ),
        ),
        (
            "tampered result binding",
            lambda: build_viewer_runtime(
                sources["image-heavy.json"][0],
                sources["image-heavy.json"][1],
                tampered_result,
            ),
        ),
        (
            "unknown bytes coerced to zero",
            lambda: build_viewer_runtime(
                sources["third-party-heavy.json"][0],
                coerced_unknown_scene,
                sources["third-party-heavy.json"][2],
            ),
        ),
        (
            "unresolved evidence pointer",
            lambda: resolve_selection(
                invalid_pointer_model,
                invalid_pointer_model["selectables"][0]["id"],
                record=sources["image-heavy.json"][0],
                scene=sources["image-heavy.json"][1],
                result=sources["image-heavy.json"][2],
            ),
        ),
        (
            "valid but misbound evidence pointer",
            lambda: resolve_selection(
                misbound_pointer_model,
                misbound_pointer_model["selectables"][0]["id"],
                record=sources["image-heavy.json"][0],
                scene=sources["image-heavy.json"][1],
                result=sources["image-heavy.json"][2],
            ),
        ),
        (
            "unknown selectable",
            lambda: reduce_viewer_state(
                image,
                image["initialStates"]["standard"],
                {"type": "select", "id": "region:invented"},
            ),
        ),
        (
            "invalid mode",
            lambda: reduce_viewer_state(
                image,
                image["initialStates"]["standard"],
                {"type": "set-mode", "mode": "speed"},
            ),
        ),
        (
            "tick in reduced motion",
            lambda: reduce_viewer_state(
                image,
                image["initialStates"]["reducedMotion"],
                {"type": "tick", "deltaMs": 16},
            ),
        ),
        (
            "skip reduced-motion stages",
            lambda: reduce_viewer_state(
                image,
                image["initialStates"]["reducedMotion"],
                {"type": "skip-reveal"},
            ),
        ),
        (
            "isolate evidence-only node",
            lambda: reduce_viewer_state(
                evidence_model,
                reduce_viewer_state(
                    evidence_model,
                    evidence_model["initialStates"]["standard"],
                    {"type": "select", "id": "evidence:n-evidence-only"},
                ),
                {"type": "isolate-selected"},
            ),
        ),
        (
            "replay as rescan",
            lambda: reduce_viewer_state(
                image,
                image["initialStates"]["standard"],
                {"type": "rescan"},
            ),
        ),
        (
            "inconsistent incoming state",
            lambda: reduce_viewer_state(
                image,
                inconsistent_state,
                {"type": "pause"},
            ),
        ),
        (
            "inconsistent frame state",
            lambda: presentation_frame(image, inconsistent_state),
        ),
        (
            "unsafe source ID",
            lambda: build_synthetic_runtime(
                unsafe_id_record,
                "r_00000000000000000000000000000030",
            ),
        ),
    )
    for name, action in runtime_controls:
        expect_runtime_failure(name, action)

    schema_controls = (
        ("unexpected field", image, lambda row: row.update({"rendererGuess": True})),
        ("unsafe public label", image, lambda row: row["presentation"].update({"pageLabel": "<script>"})),
        ("fallback evidence split", image, lambda row: row["accessPaths"][2].update({"usesSameEvidence": False})),
        ("evidence-only made renderable", image, lambda row: row["selectables"][-3].update({"kind": "evidence-only-node", "renderable": True})),
        ("reveal order", image, lambda row: row["playback"]["stages"].reverse()),
        ("mode changes endpoints", image, lambda row: row["modes"][0]["preserves"].remove("endpoints")),
        ("source hash shape", image, lambda row: row["sourceHashes"].update({"resultManifestSha256": "short"})),
        ("neutral made eligible", clean, lambda row: row["presentation"].update({"shareState": "artifact-eligible"})),
        ("initial time drift", image, lambda row: row["initialStates"]["standard"].update({"elapsedMs": 1})),
    )
    for name, model, mutate in schema_controls:
        expect_schema_failure(name, model, validator, mutate)

    fingerprints = {
        model["scanId"]: hashlib.sha256(stable_viewer_json(model).encode("utf-8")).hexdigest()[:16]
        for model in models.values()
    }
    expected_fingerprints = {
        "fixture-clean": "ed1399af6e8f9514",
        "fixture-image-heavy": "6411737b22f10a3b",
        "fixture-third-party-heavy": "c107a80be4fe2f6c",
    }
    require(fingerprints == expected_fingerprints, f"viewer-runtime fingerprints drifted: {fingerprints}")
    print(
        "Verified viewer-runtime-v0.1.0 schema, 3 byte-identical models, shared WebGL/"
        "reduced-motion/text evidence, deterministic replay/scrub/modes/selection, partial/"
        "interstitial/evidence-only/transfer-state behavior, "
        f"{len(runtime_controls)} runtime controls, and {len(schema_controls)} schema controls; "
        f"fingerprints: {fingerprints}."
    )


if __name__ == "__main__":
    main()
