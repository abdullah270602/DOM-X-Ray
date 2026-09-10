"""Verify durable immutable storage, retention, and no-login deletion tokens."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.api_contract import BUNDLE_VERSION, stable_json_bytes, validate_viewer_bundle  # noqa: E402
from scanner.result_manifest import build_result_manifest  # noqa: E402
from scanner.result_store import (  # noqa: E402
    FilesystemResultStore,
    MemoryResultStore,
    ResultStoreError,
    load_or_create_store_key,
)
from scanner.viewer_runtime import build_viewer_runtime  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def fixture_bundle(name: str) -> dict[str, object]:
    value: dict[str, object] = {
        "bundleVersion": BUNDLE_VERSION,
        "record": json.loads((ROOT / "fixtures" / "scan" / f"{name}.json").read_text()),
        "scene": json.loads(
            (ROOT / "fixtures" / "scene-manifest" / f"{name}.json").read_text()
        ),
        "result": json.loads(
            (ROOT / "fixtures" / "result-manifest" / f"{name}.json").read_text()
        ),
        "runtime": json.loads(
            (ROOT / "fixtures" / "viewer-runtime" / f"{name}.json").read_text()
        ),
        "mapping": json.loads((ROOT / "docs" / "MAPPING_REGISTRY.v0.1.json").read_text()),
    }
    validate_viewer_bundle(value)
    return value


def with_result_id(bundle: dict[str, object], result_id: str) -> dict[str, object]:
    record = bundle["record"]
    scene = bundle["scene"]
    mapping = bundle["mapping"]
    assert isinstance(record, dict) and isinstance(scene, dict) and isinstance(mapping, dict)
    result = build_result_manifest(
        record,
        result_id=result_id,
        scene_manifest=scene,
        mapping_registry=mapping,
    )
    runtime = build_viewer_runtime(record, scene, result, mapping)
    value: dict[str, object] = {
        "bundleVersion": BUNDLE_VERSION,
        "record": record,
        "scene": scene,
        "result": result,
        "runtime": runtime,
        "mapping": mapping,
    }
    validate_viewer_bundle(value)
    return value


def digest_for(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def main() -> None:
    clean = fixture_bundle("clean")
    result_id = clean["result"]["resultId"]
    key_one = b"A" * 32
    key_two = b"B" * 32
    delete_token = f"dxrd_{'a' * 64}"
    delete_digest = digest_for(delete_token)
    now = [datetime(2026, 9, 10, 12, tzinfo=UTC)]

    with tempfile.TemporaryDirectory(prefix="dom-xray-result-store-") as temporary:
        data_root = Path(temporary)
        result_root = data_root / "results"
        result_root.mkdir()
        staging = result_root / ".staging-abandoned"
        staging.write_text("partial", encoding="utf-8")

        key_path = data_root / "store.key"
        created_key = load_or_create_store_key(key_path)
        require(len(created_key) == 32, "store key was not 256 bits")
        require(load_or_create_store_key(key_path) == created_key, "store key did not survive reload")

        store = FilesystemResultStore(
            result_root,
            keys=(key_one,),
            retention_seconds=3_600,
            clock=lambda: now[0],
        )
        require(not staging.exists(), "abandoned staging file survived startup cleanup")
        published = store.publish(clean, delete_digest)
        require(published.created, "first publication was not marked as created")
        require(published.payload == stable_json_bytes(clean), "stored bundle bytes drifted")
        stored_bytes = (result_root / f"{result_id}.json").read_bytes()
        require(delete_token.encode("ascii") not in stored_bytes, "plaintext token leaked")
        require(delete_digest.encode("ascii") not in stored_bytes, "public token digest leaked")
        require(not list(result_root.glob(".staging-*")), "publication left a staging file")

        repeated = store.publish(clean, digest_for(f"dxrd_{'b' * 64}"))
        require(not repeated.created, "reuse created a second publication")
        reopened = FilesystemResultStore(
            result_root,
            keys=(key_two, key_one),
            retention_seconds=3_600,
            clock=lambda: now[0],
        )
        recovered = reopened.get(result_id)
        require(recovered is not None, "stored bundle did not survive restart")
        require(recovered.payload == published.payload, "restart changed stored bytes")
        require(recovered.etag == published.etag, "restart changed the ETag")
        require(
            reopened.delete(result_id, f"dxrd_{'f' * 64}") == "forbidden",
            "wrong token deleted a result",
        )
        require(reopened.delete(result_id, "bad") == "malformed", "bad token was not rejected")
        require(reopened.delete(result_id, delete_token) == "deleted", "owner token failed")
        require(reopened.get(result_id) is None, "deleted result survived")
        require((result_root / f"{result_id}.deleted").is_file(), "deletion tombstone missing")
        (result_root / f"{result_id}.json").write_bytes(stored_bytes)
        crash_recovered = FilesystemResultStore(
            result_root,
            keys=(key_two, key_one),
            retention_seconds=3_600,
            clock=lambda: now[0],
        )
        require(
            not (result_root / f"{result_id}.json").exists(),
            "startup did not purge a live file protected by a tombstone",
        )

        try:
            crash_recovered.publish(clean, digest_for(f"dxrd_{'c' * 64}"))
        except ResultStoreError:
            pass
        else:
            raise AssertionError("retired result ID was reused after deletion")

        replacement = with_result_id(clean, "r_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        replacement_id = replacement["result"]["resultId"]
        crash_recovered.publish(replacement, digest_for(f"dxrd_{'d' * 64}"))
        result_path = result_root / f"{replacement_id}.json"
        envelope = json.loads(result_path.read_text(encoding="utf-8"))
        envelope["bundleSha256"] = "0" * 64
        result_path.write_text(json.dumps(envelope), encoding="utf-8")
        try:
            crash_recovered.get(replacement_id)
        except ResultStoreError:
            pass
        else:
            raise AssertionError("corrupt stored bundle passed validation")

    expiring = MemoryResultStore(
        keys=(key_one,),
        retention_seconds=2,
        clock=lambda: now[0],
    )
    expiry_start = now[0]
    expiring.publish(clean, delete_digest)
    now[0] = expiry_start + timedelta(seconds=3)
    require(expiring.sweep() == 1, "expired entry was not swept")
    require(expiring.get(result_id) is None, "expired entry remained readable")
    try:
        expiring.publish(clean, delete_digest)
    except ResultStoreError:
        pass
    else:
        raise AssertionError("expired result ID was reused")

    memory = MemoryResultStore(keys=(key_one,))
    with ThreadPoolExecutor(max_workers=8) as pool:
        publications = list(
            pool.map(lambda _: memory.publish(clean, delete_digest), range(16))
        )
    require(sum(item.created for item in publications) == 1, "concurrent publish was not single-create")

    for unsafe in ("../escape", "r_bad", "r_" + "a" * 31, "r_" + "A" * 32):
        try:
            memory.get(unsafe)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe result identifier reached storage")

    print(
        "Verified atomic storage, restart recovery, bounded retention, browser-minted HMAC "
        "deletion capabilities, key rotation, tombstoned non-reuse, corruption rejection, "
        "concurrent single-create behavior, and traversal-safe result IDs."
    )


if __name__ == "__main__":
    main()
