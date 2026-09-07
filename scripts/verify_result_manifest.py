"""Verify immutable public-result and export bindings without a UI or encoder."""

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

from scanner.result_manifest import (  # noqa: E402
    ResultManifestError,
    build_result_manifest,
    stable_result_json,
)
from scanner.scene_manifest import (  # noqa: E402
    DEFAULT_MAPPING_REGISTRY,
    build_scene_manifest,
)
from scripts.export_result_fixtures import RESULT_IDS  # noqa: E402


SCAN_DIR = ROOT / "fixtures" / "scan"
GOLDEN_DIR = ROOT / "fixtures" / "result-manifest"
SCHEMA = json.loads(
    (ROOT / "docs" / "RESULT_MANIFEST.schema.json").read_text(encoding="utf-8")
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_record(name: str) -> dict[str, Any]:
    return json.loads((SCAN_DIR / name).read_text(encoding="utf-8"))


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def resolve_pointer(record: dict[str, Any], pointer: str) -> Any:
    require(pointer.startswith("#/"), f"not a record JSON Pointer: {pointer}")
    current: Any = record
    for encoded in pointer[2:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            require(token.isdigit(), f"non-numeric record pointer token: {pointer}")
            index = int(token)
            require(0 <= index < len(current), f"record pointer index is absent: {pointer}")
            current = current[index]
        else:
            require(isinstance(current, dict) and token in current, f"unresolved pointer: {pointer}")
            current = current[token]
    return current


def verify_binding(
    record: dict[str, Any],
    manifest: dict[str, Any],
    *,
    artifact_payloads: dict[str, bytes] | None = None,
) -> None:
    expected = build_result_manifest(
        record,
        result_id=manifest["resultId"],
        artifact_payloads=artifact_payloads,
    )
    require(stable_result_json(manifest) == stable_result_json(expected), "result binding drifted")
    require(manifest["resultPath"] == f"/r/{manifest['resultId']}", "result path drifted")
    require(
        manifest["exports"]["poster"]["sourceSceneSha256"]
        == manifest["sourceHashes"]["sceneManifestSha256"]
        == manifest["exports"]["video"]["sourceSceneSha256"],
        "export target scene binding drifted",
    )
    require(
        manifest["exports"]["poster"]["sourceHeroSha256"]
        == manifest["sourceHashes"]["heroSha256"]
        == manifest["exports"]["video"]["sourceHeroSha256"],
        "export target hero binding drifted",
    )
    require(
        manifest["exports"]["poster"]["sourceResultBindingSha256"]
        == manifest["sourceHashes"]["resultBindingSha256"]
        == manifest["exports"]["video"]["sourceResultBindingSha256"],
        "export target result binding drifted",
    )
    pointers = [manifest["pageIdentity"]["recordRef"]]
    pointers.extend(item["recordRef"] for item in manifest["limitations"])
    if manifest["hero"] is not None:
        pointers.append(manifest["hero"]["recordRef"])
        pointers.extend(manifest["hero"]["sourceRefs"])
        for evidence in manifest["hero"]["evidence"]:
            pointers.extend(evidence["sourceRefs"])
    for pointer in pointers:
        resolve_pointer(record, pointer)


def expect_builder_failure(name: str, action: Callable[[], object]) -> None:
    try:
        action()
    except (ResultManifestError, KeyError, TypeError, ValueError):
        return
    raise AssertionError(f"result builder negative control was accepted: {name}")


def expect_schema_failure(
    name: str,
    manifest: dict[str, Any],
    validator: Draft202012Validator,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    candidate = copy.deepcopy(manifest)
    mutate(candidate)
    if list(validator.iter_errors(candidate)):
        return
    raise AssertionError(f"result schema negative control was accepted: {name}")


def expect_binding_failure(
    name: str,
    record: dict[str, Any],
    manifest: dict[str, Any],
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    candidate = copy.deepcopy(manifest)
    mutate(candidate)
    try:
        verify_binding(record, candidate)
    except AssertionError:
        return
    raise AssertionError(f"result binding negative control was accepted: {name}")


def main() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    records = {name: load_record(name) for name in RESULT_IDS}
    manifests = {
        name: build_result_manifest(record, result_id=RESULT_IDS[name])
        for name, record in records.items()
    }

    for name, manifest in manifests.items():
        errors = sorted(validator.iter_errors(manifest), key=lambda error: list(error.path))
        require(
            not errors,
            f"{name} result manifest failed JSON Schema: "
            + "; ".join(error.message for error in errors),
        )
        golden_path = GOLDEN_DIR / name
        require(golden_path.is_file(), f"missing committed result manifest: {name}")
        require(golden_path.read_text(encoding="utf-8") == pretty_json(manifest), f"stale result manifest: {name}")
        verify_binding(records[name], manifest)

        serialized = stable_result_json(manifest)
        record = records[name]
        require(record["page"]["title"] not in serialized, f"{name} leaked page title")
        for resource in record["resources"]:
            require(resource["displayUrl"] not in serialized, f"{name} leaked a resource URL")
        for node in record["nodes"]:
            if len(node["selector"]) >= 8:
                require(node["selector"] not in serialized, f"{name} leaked a selector")

    clean = manifests["clean.json"]
    image = manifests["image-heavy.json"]
    third = manifests["third-party-heavy.json"]
    require(
        clean["shareState"] == "link-only"
        and clean["hero"] is None
        and all(not target["eligible"] for target in clean["exports"].values()),
        "neutral clean result became artifact-eligible",
    )
    require(
        image["shareState"] == "artifact-eligible"
        and image["hero"]["evidence"][0]["value"] == 87.5,
        "image hero fact did not bind its exact number",
    )
    require(
        third["statusPresentation"]
        == {"label": "PARTIAL CAPTURE", "partialLabelRequired": True}
        and "partial-status" in third["content"]["requiredLayers"]
        and "limitation-disclosure" in third["content"]["requiredLayers"]
        and third["hero"]["limitationCodes"] == ["resource-bytes-unavailable"]
        and [item["code"] for item in third["limitations"]] == ["resource-bytes-unavailable"],
        "partial share result omitted its label or limitation",
    )

    partial_no_hero_record = copy.deepcopy(records["clean.json"])
    partial_no_hero_record["scanId"] = "synthetic-partial-no-hero"
    partial_no_hero_record["status"] = "partial"
    partial_no_hero_record["failureCode"] = "hero-measurement-unavailable"
    partial_no_hero_record["limitations"] = [
        {
            "code": "hero-measurement-unavailable",
            "scope": "page",
            "message": "A defensible hero measurement was unavailable for this captured load.",
            "invalidatesMetrics": ["hero_insight"],
        }
    ]
    partial_no_hero = build_result_manifest(
        partial_no_hero_record,
        result_id="r_00000000000000000000000000000001",
    )
    require(not list(validator.iter_errors(partial_no_hero)), "partial no-hero result failed schema")
    require(
        partial_no_hero["shareState"] == "link-only"
        and partial_no_hero["hero"] is None
        and "partial-status" in partial_no_hero["content"]["requiredLayers"]
        and "limitation-disclosure" in partial_no_hero["content"]["requiredLayers"]
        and all(not target["eligible"] for target in partial_no_hero["exports"].values()),
        "partial no-hero result lost its honest link-only disclosure",
    )

    ready_payloads = {
        "poster": b"deterministic-poster-byte-envelope-v0.1",
        "video": b"deterministic-video-byte-envelope-v0.1",
    }
    ready = build_result_manifest(
        records["image-heavy.json"],
        result_id=RESULT_IDS["image-heavy.json"],
        artifact_payloads=ready_payloads,
    )
    require(not list(validator.iter_errors(ready)), "ready artifact metadata failed schema")
    verify_binding(records["image-heavy.json"], ready, artifact_payloads=ready_payloads)
    for kind, payload in ready_payloads.items():
        artifact = ready["exports"][kind]["artifact"]
        require(
            ready["exports"][kind]["state"] == "ready"
            and artifact["byteLength"] == len(payload)
            and artifact["sha256"] == hashlib.sha256(payload).hexdigest(),
            f"{kind} byte envelope was not hashed exactly",
        )

    scene = build_scene_manifest(records["image-heavy.json"])
    mismatched_scene = copy.deepcopy(scene)
    mismatched_scene["objects"][0]["positionWorld"]["x"] += 0.5
    wrong_mapping = copy.deepcopy(DEFAULT_MAPPING_REGISTRY)
    wrong_mapping["version"] = "mapping-v0.1.1"
    made_up_limitation = copy.deepcopy(records["image-heavy.json"])
    made_up_limitation["insights"][0]["limitationCodes"] = ["made-up"]
    invalidated_hero = copy.deepcopy(records["image-heavy.json"])
    invalidated_hero["limitations"] = [
        {
            "code": "synthetic-byte-invalidation",
            "scope": "page",
            "message": "Byte-derived hero evidence is unavailable.",
            "invalidatesMetrics": ["resource_mass"],
        }
    ]
    invalidated_hero["insights"][0]["limitationCodes"] = ["synthetic-byte-invalidation"]
    unsafe_hero = copy.deepcopy(records["image-heavy.json"])
    unsafe_hero["insights"][0]["statement"] = "<script>alert(1)</script> captured"
    unsafe_limitation = copy.deepcopy(records["third-party-heavy.json"])
    unsafe_limitation["limitations"][0]["message"] = "<b>Untrusted limitation copy</b>"
    oversized_page_identity = copy.deepcopy(records["clean.json"])
    oversized_page_identity["page"]["registrableDomain"] = "a" * 254

    builder_controls = (
        (
            "scene mismatch",
            lambda: build_result_manifest(
                records["image-heavy.json"],
                result_id=RESULT_IDS["image-heavy.json"],
                scene_manifest=mismatched_scene,
            ),
        ),
        (
            "mapping mismatch",
            lambda: build_result_manifest(
                records["image-heavy.json"],
                result_id=RESULT_IDS["image-heavy.json"],
                mapping_registry=wrong_mapping,
            ),
        ),
        (
            "predictable result ID",
            lambda: build_result_manifest(
                records["image-heavy.json"],
                result_id="fixture-image-heavy",
            ),
        ),
        (
            "unknown artifact kind",
            lambda: build_result_manifest(
                records["image-heavy.json"],
                result_id=RESULT_IDS["image-heavy.json"],
                artifact_payloads={"html": b"<script>target()</script>"},
            ),
        ),
        (
            "artifact on neutral result",
            lambda: build_result_manifest(
                records["clean.json"],
                result_id=RESULT_IDS["clean.json"],
                artifact_payloads={"poster": b"not-eligible"},
            ),
        ),
        (
            "oversized artifact",
            lambda: build_result_manifest(
                records["image-heavy.json"],
                result_id=RESULT_IDS["image-heavy.json"],
                artifact_payloads={"poster": b"x" * 8_000_001},
            ),
        ),
        (
            "made-up hero limitation",
            lambda: build_result_manifest(
                made_up_limitation,
                result_id=RESULT_IDS["image-heavy.json"],
            ),
        ),
        (
            "invalidated hero metric",
            lambda: build_result_manifest(
                invalidated_hero,
                result_id=RESULT_IDS["image-heavy.json"],
            ),
        ),
        (
            "unsafe hero text",
            lambda: build_result_manifest(
                unsafe_hero,
                result_id=RESULT_IDS["image-heavy.json"],
            ),
        ),
        (
            "unsafe limitation text",
            lambda: build_result_manifest(
                unsafe_limitation,
                result_id=RESULT_IDS["third-party-heavy.json"],
            ),
        ),
        (
            "oversized page identity",
            lambda: build_result_manifest(
                oversized_page_identity,
                result_id=RESULT_IDS["clean.json"],
            ),
        ),
    )
    for name, action in builder_controls:
        expect_builder_failure(name, action)

    schema_controls = (
        ("target URL in result path", lambda row: row.update({"resultPath": "https://gallery.example/"})),
        ("deletion token", lambda row: row.update({"deletionToken": "secret"})),
        ("unsupported poster media", lambda row: row["exports"]["poster"].update({"mediaType": "image/svg+xml"})),
        ("wrong video duration", lambda row: row["exports"]["video"].update({"durationMs": 6_000})),
        ("partial label removed", lambda row: row["content"]["requiredLayers"].remove("partial-status")),
        (
            "partial limitation disclosure removed",
            lambda row: row["content"]["requiredLayers"].remove("limitation-disclosure"),
        ),
        ("partial hero made ineligible", lambda row: row.update({"shareState": "link-only"})),
        ("ready artifact missing metadata", lambda row: row["exports"]["poster"].update({"state": "ready"})),
        ("page identity trailing newline", lambda row: row["pageIdentity"].update({"label": "gallery.example\n"})),
        ("unsafe hero markup", lambda row: row["hero"].update({"statement": "<script>alert(1)</script>"})),
    )
    for name, mutate in schema_controls[:4]:
        expect_schema_failure(name, image, validator, mutate)
    for name, mutate in schema_controls[4:7]:
        expect_schema_failure(name, third, validator, mutate)
    expect_schema_failure(schema_controls[7][0], image, validator, schema_controls[7][1])
    for name, mutate in schema_controls[8:]:
        expect_schema_failure(name, image, validator, mutate)

    binding_controls = (
        ("scan identity", lambda row: row.update({"scanId": "other-scan"})),
        ("scan hash", lambda row: row["sourceHashes"].update({"scanRecordSha256": "0" * 64})),
        ("scene hash", lambda row: row["sourceHashes"].update({"sceneManifestSha256": "1" * 64})),
        ("mapping hash", lambda row: row["sourceHashes"].update({"mappingRegistrySha256": "2" * 64})),
        ("hero statement", lambda row: row["hero"].update({"statement": "Invented claim."})),
        ("hero value", lambda row: row["hero"]["evidence"][0].update({"value": 99.9})),
        ("hero limitations", lambda row: row["hero"].update({"limitationCodes": []})),
        ("result route identity", lambda row: row.update({"resultPath": "/r/r_00000000000000000000000000000000"})),
        (
            "result route pair",
            lambda row: row.update(
                {
                    "resultId": "r_00000000000000000000000000000000",
                    "resultPath": "/r/r_00000000000000000000000000000000",
                }
            ),
        ),
        (
            "result binding hash",
            lambda row: row["sourceHashes"].update({"resultBindingSha256": "3" * 64}),
        ),
    )
    for name, mutate in binding_controls[:6]:
        expect_binding_failure(name, records["image-heavy.json"], image, mutate)
    expect_binding_failure(
        binding_controls[6][0],
        records["third-party-heavy.json"],
        third,
        binding_controls[6][1],
    )
    expect_binding_failure(
        binding_controls[7][0],
        records["image-heavy.json"],
        image,
        binding_controls[7][1],
    )
    for name, mutate in binding_controls[8:]:
        expect_binding_failure(name, records["image-heavy.json"], image, mutate)

    fingerprints = {
        manifest["scanId"]: hashlib.sha256(stable_result_json(manifest).encode("utf-8")).hexdigest()[:16]
        for manifest in manifests.values()
    }
    require(
        fingerprints
        == {
            "fixture-clean": "f2f7a59371ef626d",
            "fixture-image-heavy": "196f3f9b59512b53",
            "fixture-third-party-heavy": "1d118979b467707b",
        },
        f"result manifest fingerprints drifted: {fingerprints}",
    )
    print(
        "Verified result-manifest-v0.1.0 schema, 3 golden result bindings, exact "
        "scan/scene/mapping/hero hashes, link-only and partial-share behavior, ready "
        f"artifact byte envelopes, {len(builder_controls)} builder controls, "
        f"{len(schema_controls)} schema controls, and {len(binding_controls)} "
        f"binding controls; fingerprints: {fingerprints}."
    )


if __name__ == "__main__":
    main()
