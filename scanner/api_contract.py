"""Validation helpers for the anonymous scan API and immutable viewer bundle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from scanner.viewer_runtime import resolve_pointer


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
API_VERSION = "scan-api-v0.1.0"
BUNDLE_VERSION = "viewer-bundle-v0.1.0"

_SCHEMA_NAMES = (
    "SCAN_SUBMISSION.schema.json",
    "SCAN_JOB.schema.json",
    "VIEWER_BUNDLE.schema.json",
    "SCAN_RECORD.schema.json",
    "SCENE_MANIFEST.schema.json",
    "RESULT_MANIFEST.schema.json",
    "VIEWER_RUNTIME.schema.json",
)


class ApiContractError(ValueError):
    """Raised when an API document is not safe to cross the public boundary."""


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ApiContractError(f"{path.name} must contain a JSON object")
    return value


def _build_validators() -> dict[str, Draft202012Validator]:
    schemas = {name: _load_json(DOCS / name) for name in _SCHEMA_NAMES}
    registry: Registry[dict[str, Any]] = Registry()
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return {
        name: Draft202012Validator(
            schema,
            registry=registry,
            format_checker=FormatChecker(),
        )
        for name, schema in schemas.items()
    }


_VALIDATORS = _build_validators()


def _validate(name: str, value: object) -> None:
    errors = sorted(
        _VALIDATORS[name].iter_errors(value),
        key=lambda error: list(error.path),
    )
    if errors:
        details = "; ".join(
            f"/{'/'.join(str(part) for part in error.path)}: {error.message}"
            for error in errors[:5]
        )
        raise ApiContractError(details)


def stable_json_bytes(value: object) -> bytes:
    """Return the byte representation used for immutable API documents."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(stable_json_bytes(value)).hexdigest()


def validate_submission(value: object) -> str:
    _validate("SCAN_SUBMISSION.schema.json", value)
    assert isinstance(value, dict)
    url = value["url"]
    assert isinstance(url, str)
    return url


def validate_job(value: object) -> None:
    _validate("SCAN_JOB.schema.json", value)


def validate_viewer_bundle(value: object) -> None:
    """Validate component schemas and the identities/hashes joining them."""

    _validate("VIEWER_BUNDLE.schema.json", value)
    assert isinstance(value, dict)
    record = value["record"]
    scene = value["scene"]
    result = value["result"]
    runtime = value["runtime"]
    mapping = value["mapping"]
    assert all(isinstance(item, dict) for item in (record, scene, result, runtime, mapping))

    scan_ids = {record["scanId"], scene["scanId"], result["scanId"], runtime["scanId"]}
    if len(scan_ids) != 1:
        raise ApiContractError("viewer bundle scan identities drifted")
    mapping_versions = {
        record["mappingVersion"],
        scene["mappingVersion"],
        result["mappingVersion"],
        runtime["mappingVersion"],
        mapping["version"],
    }
    if len(mapping_versions) != 1:
        raise ApiContractError("viewer bundle mapping identities drifted")
    if runtime["resultId"] != result["resultId"] or runtime["resultPath"] != result["resultPath"]:
        raise ApiContractError("viewer bundle result identities drifted")
    if result["sceneManifestVersion"] != scene["manifestVersion"]:
        raise ApiContractError("viewer bundle scene versions drifted")

    result_hashes = result["sourceHashes"]
    expected_hashes = {
        "scanRecordSha256": _sha256(record),
        "sceneManifestSha256": _sha256(scene),
        "mappingRegistrySha256": _sha256(mapping),
    }
    for key, expected in expected_hashes.items():
        if result_hashes[key] != expected or runtime["sourceHashes"][key] != expected:
            raise ApiContractError(f"viewer bundle source hash drifted: {key}")
    if runtime["sourceHashes"]["resultBindingSha256"] != result_hashes["resultBindingSha256"]:
        raise ApiContractError("viewer bundle result binding drifted")
    if runtime["sourceHashes"]["resultManifestSha256"] != _sha256(result):
        raise ApiContractError("viewer bundle result manifest hash drifted")

    object_ids = {item["id"] for item in scene["objects"]}
    for connection in scene["connections"]:
        endpoint_ids = [connection["sourceObjectId"], *connection["targetObjectIds"]]
        if connection["fallbackObjectId"] is not None:
            endpoint_ids.append(connection["fallbackObjectId"])
        if any(endpoint not in object_ids for endpoint in endpoint_ids):
            raise ApiContractError("viewer bundle connection endpoint is missing")

    reference_documents = {
        "recordRefs": record,
        "sceneRefs": scene,
        "mappingRefs": mapping,
        "resultRefs": result,
        "limitationRefs": record,
    }
    try:
        for selectable in runtime["selectables"]:
            for field, document in reference_documents.items():
                for pointer in selectable[field]:
                    resolve_pointer(document, pointer)
        for pointer in runtime["presentation"]["limitationResultRefs"]:
            resolve_pointer(result, pointer)
    except (KeyError, IndexError, TypeError, ValueError) as error:
        raise ApiContractError("viewer bundle contains an unresolved evidence pointer") from error
