"""Verify durable immutable storage, retention, and no-login deletion tokens."""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import tempfile
import zlib
from collections.abc import Callable
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


def poster_png(pixel: bytes = b"\x00\x00\x00\xff") -> bytes:
    """Build a tiny, dependency-free valid 1080x1080 RGBA PNG fixture."""

    require(len(pixel) == 4, "PNG fixture pixel must be RGBA")

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    # Every scanline is filter 0 followed by opaque black RGBA pixels.  The
    # repeated data compresses to a few kilobytes while exercising the exact
    # dimensions and pixel format accepted by the poster boundary.
    scanlines = b"".join(
        b"\x00" + (pixel * 1080)
        for _ in range(1080)
    )
    header = struct.pack(">IIBBBBB", 1080, 1080, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(scanlines, 9))
        + chunk(b"IEND", b"")
    )


def eligible_bundle(
    result_id: str,
    poster: bytes,
) -> dict[str, object]:
    source = fixture_bundle("image-heavy")
    record = source["record"]
    scene = source["scene"]
    mapping = source["mapping"]
    assert isinstance(record, dict) and isinstance(scene, dict) and isinstance(mapping, dict)
    result = build_result_manifest(
        record,
        result_id=result_id,
        scene_manifest=scene,
        mapping_registry=mapping,
        artifact_payloads={"poster": poster},
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


def expect_store_error(action: Callable[[], object], message: str) -> None:
    try:
        action()
    except ResultStoreError:
        return
    raise AssertionError(message)


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

    # Poster artifacts cross a separate immutable byte boundary.  Keep this
    # fixture local to the verifier so the artifact checks do not depend on a
    # renderer, Pillow, or any other optional package.
    poster = poster_png()
    different_poster = poster_png(b"\x10\x20\x30\xff")
    artifact_id = "r_" + "e" * 32
    artifact_bundle = eligible_bundle(artifact_id, poster)
    artifact_result = artifact_bundle["result"]
    assert isinstance(artifact_result, dict)
    poster_target = artifact_result["exports"]["poster"]
    expected_poster_hash = hashlib.sha256(poster).hexdigest()
    require(poster_target["state"] == "ready", "eligible poster was not ready")
    require(
        poster_target["artifact"]
        == {"sha256": expected_poster_hash, "byteLength": len(poster)},
        "poster manifest did not register exact bytes",
    )
    artifact_token = f"dxrd_{'1' * 64}"
    artifact_digest = digest_for(artifact_token)

    artifact_memory = MemoryResultStore(keys=(key_one,), clock=lambda: now[0])
    artifact_publication = artifact_memory.publish(
        artifact_bundle,
        artifact_digest,
        {"poster": poster},
    )
    require(artifact_publication.created, "first poster publication was not created")
    memory_poster = artifact_memory.get_artifact(artifact_id, "poster")
    require(memory_poster is not None, "memory poster was not reachable")
    require(memory_poster.payload == poster, "memory poster bytes changed")
    require(memory_poster.sha256 == expected_poster_hash, "memory poster hash drifted")
    require(memory_poster.byte_length == len(poster), "memory poster length drifted")
    require(memory_poster.etag == f'"{expected_poster_hash}"', "memory poster ETag drifted")
    require(memory_poster.media_type == "image/png", "memory poster media type drifted")
    repeated_artifact = artifact_memory.publish(
        artifact_bundle,
        digest_for(f"dxrd_{'2' * 64}"),
        {"poster": poster},
    )
    require(not repeated_artifact.created, "identical poster republish created twice")
    require(
        repeated_artifact.payload == artifact_publication.payload
        and repeated_artifact.etag == artifact_publication.etag,
        "identical poster republish changed the result",
    )
    expect_store_error(
        lambda: artifact_memory.publish(
            artifact_bundle,
            artifact_digest,
            {"poster": different_poster},
        ),
        "different poster bytes crossed the registered-byte boundary",
    )
    missing_id = "r_" + "f" * 32
    missing_bundle = eligible_bundle(missing_id, poster)
    expect_store_error(
        lambda: artifact_memory.publish(missing_bundle, artifact_digest),
        "ready-manifest publication without poster bytes succeeded",
    )
    expect_store_error(
        lambda: artifact_memory.publish(
            eligible_bundle("r_" + "1" * 32, poster),
            artifact_digest,
            {"poster": b"not-a-poster"},
        ),
        "invalid poster bytes were accepted",
    )
    link_only = with_result_id(clean, "r_" + "2" * 32)
    expect_store_error(
        lambda: artifact_memory.publish(
            link_only,
            artifact_digest,
            {"poster": poster},
        ),
        "unregistered poster bytes were accepted",
    )
    artifact_memory._artifacts[(artifact_id, "poster")] = poster[:-1]
    expect_store_error(
        lambda: artifact_memory.get_artifact(artifact_id, "poster"),
        "truncated in-memory poster remained reachable",
    )

    concurrent_memory = MemoryResultStore(keys=(key_one,))
    concurrent_bundle = eligible_bundle("r_" + "3" * 32, poster)
    with ThreadPoolExecutor(max_workers=8) as pool:
        concurrent_publications = list(
            pool.map(
                lambda _: concurrent_memory.publish(
                    concurrent_bundle,
                    artifact_digest,
                    {"poster": poster},
                ),
                range(16),
            )
        )
    require(
        sum(item.created for item in concurrent_publications) == 1,
        "concurrent poster publish was not single-create",
    )
    try:
        artifact_memory.get_artifact(artifact_id, "video")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid artifact kind reached memory storage")
    try:
        artifact_memory.get_artifact("../escape", "poster")
    except ValueError:
        pass
    else:
        raise AssertionError("unsafe artifact result ID reached memory storage")

    with tempfile.TemporaryDirectory(prefix="dom-xray-poster-store-") as temporary:
        artifact_root = Path(temporary)
        (artifact_root / ".staging-abandoned-poster").write_bytes(b"partial")
        orphan_id = "r_" + "5" * 32
        (artifact_root / f"{orphan_id}.poster.png").write_bytes(poster)
        filesystem_artifacts = FilesystemResultStore(
            artifact_root,
            keys=(key_one,),
            retention_seconds=3_600,
            clock=lambda: now[0],
        )
        require(
            not list(artifact_root.glob(".staging-*")),
            "poster staging file survived startup cleanup",
        )
        require(
            not (artifact_root / f"{orphan_id}.poster.png").exists(),
            "orphan poster survived startup cleanup",
        )

        class FailingEnvelopeStore(FilesystemResultStore):
            def _write_atomic(self, destination: Path, value: dict[str, object]) -> None:
                if "storeVersion" in value:
                    raise ResultStoreError("injected envelope commit failure")
                super()._write_atomic(destination, value)  # type: ignore[arg-type]

        failure_root = artifact_root / "commit-failure"
        failing_store = FailingEnvelopeStore(
            failure_root,
            keys=(key_one,),
            clock=lambda: now[0],
        )
        failing_id = "r_" + "9" * 32
        failing_bundle = eligible_bundle(failing_id, poster)
        expect_store_error(
            lambda: failing_store.publish(
                failing_bundle,
                artifact_digest,
                {"poster": poster},
            ),
            "result envelope failure left a publication reachable",
        )
        require(
            not (failure_root / f"{failing_id}.json").exists()
            and not (failure_root / f"{failing_id}.poster.png").exists()
            and not list(failure_root.glob(".staging-*")),
            "failed final commit left a bundle, poster, or staging file",
        )

        filesystem_artifacts.publish(artifact_bundle, artifact_digest, {"poster": poster})
        filesystem_poster = filesystem_artifacts.get_artifact(artifact_id, "poster")
        require(filesystem_poster is not None, "filesystem poster was not reachable")
        require(filesystem_poster.payload == poster, "filesystem poster bytes changed")
        require(filesystem_poster.sha256 == expected_poster_hash, "filesystem poster hash drifted")
        require(filesystem_poster.byte_length == len(poster), "filesystem poster length drifted")
        require(filesystem_poster.etag == f'"{expected_poster_hash}"', "filesystem poster ETag drifted")
        require(filesystem_poster.media_type == "image/png", "filesystem poster media type drifted")
        restarted_artifacts = FilesystemResultStore(
            artifact_root,
            keys=(key_one,),
            retention_seconds=3_600,
            clock=lambda: now[0],
        )
        recovered_poster = restarted_artifacts.get_artifact(artifact_id, "poster")
        require(
            recovered_poster is not None and recovered_poster.payload == poster,
            "poster did not survive filesystem restart",
        )
        artifact_path = artifact_root / f"{artifact_id}.poster.png"
        artifact_path.write_bytes(poster[:-1])
        expect_store_error(
            lambda: restarted_artifacts.get(artifact_id),
            "truncated filesystem poster remained reachable through result",
        )
        expect_store_error(
            lambda: restarted_artifacts.get_artifact(artifact_id, "poster"),
            "truncated filesystem poster remained reachable through artifact API",
        )
        retired_corrupt = FilesystemResultStore(
            artifact_root,
            keys=(key_one,),
            retention_seconds=3_600,
            clock=lambda: now[0],
        )
        require(retired_corrupt.get(artifact_id) is None, "corrupt poster was revived on restart")
        require(
            not (artifact_root / f"{artifact_id}.json").exists()
            and not artifact_path.exists()
            and (artifact_root / f"{artifact_id}.deleted").is_file(),
            "startup did not retire and clean a corrupt poster publication",
        )

        unregistered_id = "r_" + "6" * 32
        unregistered_bundle = with_result_id(clean, unregistered_id)
        filesystem_artifacts.publish(unregistered_bundle, artifact_digest)
        unregistered_path = artifact_root / f"{unregistered_id}.poster.png"
        unregistered_path.write_bytes(poster)
        expect_store_error(
            lambda: filesystem_artifacts.get(unregistered_id),
            "filesystem accepted an unregistered poster",
        )
        unregistered_path.unlink()

        deleted_id = "r_" + "7" * 32
        deleted_bundle = eligible_bundle(deleted_id, poster)
        filesystem_artifacts.publish(deleted_bundle, artifact_digest, {"poster": poster})
        deleted_result_path = artifact_root / f"{deleted_id}.json"
        deleted_envelope = deleted_result_path.read_bytes()
        deleted_artifact_path = artifact_root / f"{deleted_id}.poster.png"
        require(
            filesystem_artifacts.delete(deleted_id, artifact_token) == "deleted",
            "poster owner token failed deletion",
        )
        require(filesystem_artifacts.get_artifact(deleted_id, "poster") is None, "deleted poster remained reachable")
        require(not deleted_result_path.exists() and not deleted_artifact_path.exists(), "deletion left poster files")
        require((artifact_root / f"{deleted_id}.deleted").is_file(), "poster deletion tombstone missing")
        deleted_result_path.write_bytes(deleted_envelope)
        deleted_artifact_path.write_bytes(poster)
        restarted_after_delete = FilesystemResultStore(
            artifact_root,
            keys=(key_one,),
            retention_seconds=3_600,
            clock=lambda: now[0],
        )
        require(restarted_after_delete.get(deleted_id) is None, "tombstone restored deleted poster")
        require(not deleted_result_path.exists() and not deleted_artifact_path.exists(), "tombstone restart left restored poster files")
        expect_store_error(
            lambda: restarted_after_delete.publish(deleted_bundle, artifact_digest, {"poster": poster}),
            "deleted poster result ID was reused",
        )

        expiry_id = "r_" + "8" * 32
        expiry_bundle = eligible_bundle(expiry_id, poster)
        expiry_now = [datetime(2026, 9, 10, 12, tzinfo=UTC)]
        expiring_filesystem = FilesystemResultStore(
            artifact_root,
            keys=(key_one,),
            retention_seconds=2,
            clock=lambda: expiry_now[0],
        )
        expiring_filesystem.publish(expiry_bundle, artifact_digest, {"poster": poster})
        expiry_envelope = (artifact_root / f"{expiry_id}.json").read_bytes()
        expiry_now[0] += timedelta(seconds=3)
        require(expiring_filesystem.get(expiry_id) is None, "expired poster remained reachable")
        require(
            not (artifact_root / f"{expiry_id}.json").exists()
            and not (artifact_root / f"{expiry_id}.poster.png").exists(),
            "expiry left poster files behind",
        )
        require((artifact_root / f"{expiry_id}.deleted").is_file(), "expiry tombstone missing")
        # Restore both visibility markers after expiry to model a crash or
        # stale replica; the tombstone must still win on the next startup.
        (artifact_root / f"{expiry_id}.json").write_bytes(expiry_envelope)
        (artifact_root / f"{expiry_id}.poster.png").write_bytes(poster)
        restarted_after_expiry = FilesystemResultStore(
            artifact_root,
            keys=(key_one,),
            retention_seconds=2,
            clock=lambda: expiry_now[0],
        )
        require(restarted_after_expiry.get(expiry_id) is None, "expiry tombstone restored poster")
        require(
            not (artifact_root / f"{expiry_id}.json").exists()
            and not (artifact_root / f"{expiry_id}.poster.png").exists(),
            "expiry tombstone left restored poster files",
        )

    print(
        "Verified atomic storage, restart recovery, bounded retention, browser-minted HMAC "
        "deletion capabilities, key rotation, tombstoned non-reuse, corruption rejection, "
        "concurrent single-create behavior, traversal-safe result IDs, and exact registered "
        "poster bytes across publication, restart, deletion, expiry, and tamper failures."
    )


if __name__ == "__main__":
    main()
