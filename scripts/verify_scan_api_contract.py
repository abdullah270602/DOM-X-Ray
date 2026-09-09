"""Verify the anonymous scan job and immutable viewer-bundle contracts."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
FIXTURES = ROOT / "fixtures"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path.name} is not a JSON object")
    return value


def _validator(name: str, registry: Registry[dict[str, Any]]) -> Draft202012Validator:
    return Draft202012Validator(
        _load(DOCS / name),
        registry=registry,
        format_checker=FormatChecker(),
    )


def _assert_valid(validator: Draft202012Validator, value: object, label: str) -> None:
    errors = sorted(validator.iter_errors(value), key=lambda error: list(error.path))
    if errors:
        details = "; ".join(
            f"/{'/'.join(str(part) for part in error.path)}: {error.message}"
            for error in errors[:5]
        )
        raise AssertionError(f"{label} failed: {details}")


def _expect_invalid(
    validator: Draft202012Validator,
    baseline: dict[str, Any],
    mutate: Callable[[dict[str, Any]], None],
    label: str,
) -> None:
    candidate = copy.deepcopy(baseline)
    mutate(candidate)
    if not list(validator.iter_errors(candidate)):
        raise AssertionError(f"negative control was accepted: {label}")


def _sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _bundle(name: str) -> dict[str, Any]:
    return {
        "bundleVersion": "viewer-bundle-v0.1.0",
        "record": _load(FIXTURES / "scan" / f"{name}.json"),
        "scene": _load(FIXTURES / "scene-manifest" / f"{name}.json"),
        "result": _load(FIXTURES / "result-manifest" / f"{name}.json"),
        "runtime": _load(FIXTURES / "viewer-runtime" / f"{name}.json"),
        "mapping": _load(DOCS / "MAPPING_REGISTRY.v0.1.json"),
    }


def _verify_bundle_identity(bundle: dict[str, Any]) -> None:
    record = bundle["record"]
    scene = bundle["scene"]
    result = bundle["result"]
    runtime = bundle["runtime"]
    mapping = bundle["mapping"]
    scan_ids = {record["scanId"], scene["scanId"], result["scanId"], runtime["scanId"]}
    if len(scan_ids) != 1:
        raise AssertionError("bundle scan identities drifted")
    if not (
        record["mappingVersion"]
        == scene["mappingVersion"]
        == result["mappingVersion"]
        == runtime["mappingVersion"]
        == mapping["version"]
    ):
        raise AssertionError("bundle mapping identities drifted")
    if runtime["resultId"] != result["resultId"] or runtime["resultPath"] != result["resultPath"]:
        raise AssertionError("bundle result identities drifted")
    hashes = result["sourceHashes"]
    if hashes["scanRecordSha256"] != _sha256(record):
        raise AssertionError("bundle scan hash drifted")
    if hashes["sceneManifestSha256"] != _sha256(scene):
        raise AssertionError("bundle scene hash drifted")
    if hashes["mappingRegistrySha256"] != _sha256(mapping):
        raise AssertionError("bundle mapping hash drifted")
    for key in (
        "scanRecordSha256",
        "sceneManifestSha256",
        "mappingRegistrySha256",
        "resultBindingSha256",
    ):
        if runtime["sourceHashes"][key] != hashes[key]:
            raise AssertionError(f"runtime source binding drifted: {key}")
    if runtime["sourceHashes"]["resultManifestSha256"] != _sha256(result):
        raise AssertionError("bundle result-manifest hash drifted")


def main() -> None:
    schema_names = (
        "SCAN_SUBMISSION.schema.json",
        "SCAN_JOB.schema.json",
        "VIEWER_BUNDLE.schema.json",
        "SCAN_RECORD.schema.json",
        "SCENE_MANIFEST.schema.json",
        "RESULT_MANIFEST.schema.json",
        "VIEWER_RUNTIME.schema.json",
    )
    schemas = [_load(DOCS / name) for name in schema_names]
    for schema in schemas:
        Draft202012Validator.check_schema(schema)
    registry: Registry[dict[str, Any]] = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))

    submission_validator = _validator("SCAN_SUBMISSION.schema.json", registry)
    job_validator = _validator("SCAN_JOB.schema.json", registry)
    bundle_validator = _validator("VIEWER_BUNDLE.schema.json", registry)

    submission = {"apiVersion": "scan-api-v0.1.0", "url": "https://clean.example/"}
    _assert_valid(submission_validator, submission, "valid submission")
    _expect_invalid(submission_validator, submission, lambda item: item.update(url="ftp://x.test/"), "scheme")
    _expect_invalid(submission_validator, submission, lambda item: item.update(extra=True), "extra field")

    base = {
        "apiVersion": "scan-api-v0.1.0",
        "jobId": "j_0123456789abcdef0123456789abcdef",
        "state": "queued",
        "progress": "admission",
        "submittedAt": "2026-09-09T12:00:00Z",
        "updatedAt": "2026-09-09T12:00:00Z",
        "scanStatus": None,
        "result": None,
        "error": None,
        "pollAfterMs": 500,
    }
    queued = copy.deepcopy(base)
    running = copy.deepcopy(base)
    running.update(state="running", progress="capturing")
    ready = copy.deepcopy(base)
    ready.update(
        state="ready",
        progress="complete",
        scanStatus="partial",
        result={
            "resultId": "r_0123456789abcdef0123456789abcdef",
            "resultPath": "/r/r_0123456789abcdef0123456789abcdef",
            "bundleUrl": "/api/results/r_0123456789abcdef0123456789abcdef",
        },
        pollAfterMs=None,
    )
    rejected = copy.deepcopy(base)
    rejected.update(
        state="rejected",
        progress="rejected",
        error={"code": "invalid-target", "message": "That target is not supported.", "retryable": False},
        pollAfterMs=None,
    )
    failed = copy.deepcopy(base)
    failed.update(
        state="failed",
        progress="failed",
        error={"code": "scan-timeout", "message": "The scan reached its time limit.", "retryable": True},
        pollAfterMs=None,
    )
    for label, job in (("queued", queued), ("running", running), ("ready", ready), ("rejected", rejected), ("failed", failed)):
        _assert_valid(job_validator, job, f"valid {label} job")

    _expect_invalid(job_validator, queued, lambda item: item.update(result=ready["result"]), "early result")
    _expect_invalid(job_validator, running, lambda item: item.update(progress="complete"), "running progress")
    _expect_invalid(job_validator, ready, lambda item: item.update(scanStatus=None), "ready scan status")
    _expect_invalid(job_validator, ready, lambda item: item.update(pollAfterMs=500), "terminal polling")
    _expect_invalid(job_validator, rejected, lambda item: item["error"].update(code="worker-crashed"), "rejection code")
    _expect_invalid(job_validator, failed, lambda item: item["error"].update(code="invalid-target"), "failure code")

    for name in ("clean", "image-heavy", "third-party-heavy"):
        bundle = _bundle(name)
        _assert_valid(bundle_validator, bundle, f"{name} viewer bundle")
        _verify_bundle_identity(bundle)

    drifted = _bundle("clean")
    drifted["runtime"] = _bundle("image-heavy")["runtime"]
    try:
        _verify_bundle_identity(drifted)
    except AssertionError:
        pass
    else:
        raise AssertionError("cross-document drift was accepted")

    print(
        "Verified scan submission, five job lifecycle shapes, six lifecycle "
        "negative controls, three immutable viewer bundles, and one cross-binding control."
    )


if __name__ == "__main__":
    main()
