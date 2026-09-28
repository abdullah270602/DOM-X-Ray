"""Durable immutable viewer-bundle storage with no-login deletion capabilities.

The filesystem implementation is a single-process local proof. Production still
requires an object-store/database transaction boundary, distributed abuse
controls, retention ownership, and cache-purge evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Protocol

from scanner.api_contract import stable_json_bytes, validate_viewer_bundle
from scanner.mp4_validation import Mp4ValidationError, validate_share_video_mp4
from scanner.png_validation import PngValidationError, validate_poster_png


STORE_VERSION = "result-store-v0.1.0"
TOMBSTONE_VERSION = "result-tombstone-v0.1.0"
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
RESULT_ID_PATTERN = re.compile(r"^r_[0-9a-f]{32}$")
DELETE_TOKEN_PATTERN = re.compile(r"^dxrd_[0-9a-f]{64}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_PATTERN = re.compile(r"^[0-9a-f]{16}$")

DeleteOutcome = Literal[
    "deleted",
    "not-found",
    "forbidden",
    "malformed",
    "pending",
    "retryable",
]
ArtifactKind = Literal["poster", "video"]
ArtifactMediaType = Literal["image/png", "video/mp4"]
ARTIFACT_KINDS: tuple[ArtifactKind, ...] = ("poster", "video")
ARTIFACT_SUFFIXES: dict[ArtifactKind, str] = {
    "poster": ".poster.png",
    "video": ".video.mp4",
}


class ResultStoreError(RuntimeError):
    """Raised for storage failures, optionally marking transient failures retryable."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


@dataclass(frozen=True)
class StoredResult:
    result_id: str
    payload: bytes
    etag: str
    published_at: str
    expires_at: str | None


@dataclass(frozen=True)
class Publication(StoredResult):
    created: bool


@dataclass(frozen=True)
class StoredArtifact:
    result_id: str
    kind: ArtifactKind
    payload: bytes
    media_type: ArtifactMediaType
    sha256: str
    byte_length: int
    etag: str
    published_at: str
    expires_at: str | None


class ResultBackend(Protocol):
    """Single application-facing authority for result visibility and retirement."""

    def publish(
        self,
        bundle: dict[str, Any],
        deletion_token_digest: str,
        artifacts: Mapping[str, bytes] | None = None,
    ) -> Publication: ...

    def get(self, result_id: str) -> StoredResult | None: ...

    def get_artifact(
        self,
        result_id: str,
        kind: ArtifactKind,
    ) -> StoredArtifact | None: ...

    def delete(self, result_id: str, deletion_token: str) -> DeleteOutcome: ...

    def sweep(self) -> int: ...


# Compatibility name for existing callers. New orchestration code should use
# ResultBackend so provider storage is never mistaken for a second authority.
ResultStore = ResultBackend


class DeletionCapabilityKeyring:
    """Signs public token digests and verifies raw capabilities by stored key ID.

    Key IDs are stable prefixes of each key's SHA-256. Repeated copies of the
    same key are collapsed; a key-ID collision between different keys fails
    closed instead of silently replacing a verification key.
    """

    def __init__(self, keys: Sequence[bytes]) -> None:
        if isinstance(keys, (bytes, str)) or not isinstance(keys, Sequence):
            raise ValueError("deletion keyring requires a sequence of keys")
        if not keys:
            raise ValueError("deletion keyring requires one or more 256-bit keys")

        normalized: dict[str, bytes] = {}
        ordered_ids: list[str] = []
        for key in keys:
            if not isinstance(key, bytes) or len(key) < 32:
                raise ValueError("deletion keyring requires one or more 256-bit keys")
            key_id = hashlib.sha256(key).hexdigest()[:16]
            if KEY_ID_PATTERN.fullmatch(key_id) is None:
                raise ValueError("deletion key ID is invalid")
            existing = normalized.get(key_id)
            if existing is not None:
                if existing != key:
                    raise ValueError("deletion key ID collision")
                continue
            normalized[key_id] = key
            ordered_ids.append(key_id)

        self._keys = normalized
        self._key_ids = tuple(ordered_ids)
        self._current_key_id = self._key_ids[0]

    @property
    def current_key_id(self) -> str:
        return self._current_key_id

    @property
    def key_ids(self) -> tuple[str, ...]:
        """Return configured IDs in rotation order, with duplicates removed."""

        return self._key_ids

    def sign_digest(self, public_digest: str) -> tuple[str, str]:
        """Return the current key ID and HMAC for a validated public digest."""

        if not isinstance(public_digest, str) or SHA256_PATTERN.fullmatch(public_digest) is None:
            raise ValueError("deletion token digest must be a lowercase SHA-256 value")
        key = self._keys[self._current_key_id]
        protected_digest = hmac.new(
            key,
            public_digest.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return self._current_key_id, protected_digest

    def verify_digest(self, key_id: str, public_digest: str, expected_hmac: str) -> bool:
        """Verify a public digest only with the exact key named by stored state."""

        if (
            not isinstance(key_id, str)
            or KEY_ID_PATTERN.fullmatch(key_id) is None
            or not isinstance(public_digest, str)
            or SHA256_PATTERN.fullmatch(public_digest) is None
            or not isinstance(expected_hmac, str)
            or SHA256_PATTERN.fullmatch(expected_hmac) is None
        ):
            return False
        key = self._keys.get(key_id)
        if key is None:
            return False
        actual = hmac.new(key, public_digest.encode("ascii"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(actual, expected_hmac)

    def verify_token(self, token: str, key_id: str, expected_hmac: str) -> bool:
        """Hash a raw capability in memory and verify it against its stored key ID."""

        if not isinstance(token, str) or DELETE_TOKEN_PATTERN.fullmatch(token) is None:
            return False
        public_digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        return self.verify_digest(key_id, public_digest, expected_hmac)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ResultStoreError(f"stored {label} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ResultStoreError(f"stored {label} is invalid") from error
    if parsed.tzinfo is None:
        raise ResultStoreError(f"stored {label} has no timezone")
    return parsed.astimezone(UTC)


def _validate_result_id(result_id: str) -> None:
    if not isinstance(result_id, str) or RESULT_ID_PATTERN.fullmatch(result_id) is None:
        raise ValueError("invalid result ID")


def _validate_token(token: str) -> None:
    if not isinstance(token, str) or DELETE_TOKEN_PATTERN.fullmatch(token) is None:
        raise ValueError("invalid deletion token")


def _bundle_identity(bundle: dict[str, Any]) -> tuple[str, bytes, str]:
    validate_viewer_bundle(bundle)
    result_id = bundle["result"]["resultId"]
    _validate_result_id(result_id)
    expected_path = f"/r/{result_id}"
    if (
        bundle["result"]["resultPath"] != expected_path
        or bundle["runtime"]["resultId"] != result_id
        or bundle["runtime"]["resultPath"] != expected_path
    ):
        raise ResultStoreError("bundle route identity does not match its result ID")
    payload = stable_json_bytes(bundle)
    if len(payload) > MAX_BUNDLE_BYTES:
        raise ResultStoreError("viewer bundle exceeds the storage limit")
    digest = hashlib.sha256(payload).hexdigest()
    return result_id, payload, digest


def _validated_artifacts(
    bundle: dict[str, Any],
    artifacts: Mapping[str, bytes] | None,
) -> dict[ArtifactKind, bytes]:
    if artifacts is not None and not isinstance(artifacts, Mapping):
        raise ValueError("result artifacts must be a mapping")
    supplied = dict(artifacts or {})
    exports = bundle["result"]["exports"]
    ready = {kind for kind, target in exports.items() if target["state"] == "ready"}
    if ready - set(ARTIFACT_KINDS):
        raise ResultStoreError("result contains an unsupported ready artifact")
    if set(supplied) != ready:
        raise ResultStoreError("ready artifact bytes do not match the result manifest")
    validated: dict[ArtifactKind, bytes] = {}
    for kind in ARTIFACT_KINDS:
        if kind not in supplied:
            continue
        payload = supplied[kind]
        metadata = _artifact_metadata(kind, payload, stored=False)
        target = exports[kind]
        descriptor = target["artifact"]
        if (
            not isinstance(descriptor, dict)
            or descriptor.get("sha256") != metadata.sha256
            or descriptor.get("byteLength") != metadata.byte_length
            or target["mediaType"] != metadata.media_type
            or target["width"] != metadata.width
            or target["height"] != metadata.height
            or target["maxByteLength"] < metadata.byte_length
            or (kind == "video" and target["durationMs"] != metadata.duration_ms)
        ):
            raise ResultStoreError(
                f"{kind} bytes do not match the immutable result manifest"
            )
        validated[kind] = payload
    return validated


def _validate_artifact_kind(kind: object) -> ArtifactKind:
    if kind not in ARTIFACT_KINDS:
        raise ValueError("invalid artifact kind")
    return kind  # type: ignore[return-value]


def _artifact_metadata(kind: ArtifactKind, payload: bytes, *, stored: bool):
    try:
        if kind == "poster":
            return validate_poster_png(payload)
        return validate_share_video_mp4(payload)
    except (PngValidationError, Mp4ValidationError) as error:
        qualifier = "stored " if stored else ""
        raise ResultStoreError(f"{qualifier}{kind} artifact failed media validation") from error


def _stored_artifact(
    *,
    bundle: dict[str, Any],
    stored: StoredResult,
    kind: ArtifactKind,
    payload: bytes,
) -> StoredArtifact:
    target = bundle["result"]["exports"][kind]
    descriptor = target["artifact"]
    metadata = _artifact_metadata(kind, payload, stored=True)
    if (
        target["state"] != "ready"
        or not isinstance(descriptor, dict)
        or descriptor.get("sha256") != metadata.sha256
        or descriptor.get("byteLength") != metadata.byte_length
        or target["mediaType"] != metadata.media_type
        or target["width"] != metadata.width
        or target["height"] != metadata.height
        or (kind == "video" and target["durationMs"] != metadata.duration_ms)
    ):
        raise ResultStoreError(f"stored {kind} failed its content identity check")
    return StoredArtifact(
        result_id=stored.result_id,
        kind=kind,
        payload=payload,
        media_type=metadata.media_type,
        sha256=metadata.sha256,
        byte_length=metadata.byte_length,
        etag=f'"{metadata.sha256}"',
        published_at=stored.published_at,
        expires_at=stored.expires_at,
    )


class _StoreCore:
    def __init__(
        self,
        keys: Sequence[bytes],
        *,
        retention_seconds: float | None,
        clock: Callable[[], datetime],
    ) -> None:
        keyring = DeletionCapabilityKeyring(keys)
        if retention_seconds is not None and (
            not math.isfinite(retention_seconds) or retention_seconds <= 0
        ):
            raise ValueError("retention must be a positive finite duration")
        self._keyring = keyring
        self._retention_seconds = retention_seconds
        self._clock = clock
        self._lock = threading.RLock()

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ResultStoreError("result-store clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    def _new_envelope(
        self,
        bundle: dict[str, Any],
        deletion_token_digest: str,
        artifacts: Mapping[str, bytes] | None,
    ) -> tuple[dict[str, Any], bytes, dict[ArtifactKind, bytes]]:
        key_id, protected_digest = self._keyring.sign_digest(deletion_token_digest)
        result_id, payload, bundle_digest = _bundle_identity(bundle)
        validated_artifacts = _validated_artifacts(bundle, artifacts)
        now = self._now()
        expires_at = (
            None
            if self._retention_seconds is None
            else _timestamp(now + timedelta(seconds=self._retention_seconds))
        )
        envelope = {
            "storeVersion": STORE_VERSION,
            "resultId": result_id,
            "publishedAt": _timestamp(now),
            "expiresAt": expires_at,
            "bundleSha256": bundle_digest,
            "keyId": key_id,
            "deletionDigestHmacSha256": protected_digest,
            "bundle": bundle,
        }
        return envelope, payload, validated_artifacts

    def _decode_envelope(
        self,
        value: object,
        *,
        expected_result_id: str,
    ) -> tuple[dict[str, Any], StoredResult]:
        expected_keys = {
            "storeVersion",
            "resultId",
            "publishedAt",
            "expiresAt",
            "bundleSha256",
            "keyId",
            "deletionDigestHmacSha256",
            "bundle",
        }
        if not isinstance(value, dict) or set(value) != expected_keys:
            raise ResultStoreError("stored result envelope has an invalid shape")
        if value["storeVersion"] != STORE_VERSION or value["resultId"] != expected_result_id:
            raise ResultStoreError("stored result envelope identity drifted")
        published_at = _parse_timestamp(value["publishedAt"], "publication time")
        expires_value = value["expiresAt"]
        expires_at = None if expires_value is None else _parse_timestamp(expires_value, "expiry")
        if expires_at is not None and expires_at <= published_at:
            raise ResultStoreError("stored result expires before it was published")
        bundle_digest = value["bundleSha256"]
        key_id = value["keyId"]
        token_digest = value["deletionDigestHmacSha256"]
        if not isinstance(bundle_digest, str) or SHA256_PATTERN.fullmatch(bundle_digest) is None:
            raise ResultStoreError("stored bundle digest is invalid")
        if not isinstance(key_id, str) or KEY_ID_PATTERN.fullmatch(key_id) is None:
            raise ResultStoreError("stored deletion key identity is invalid")
        if not isinstance(token_digest, str) or SHA256_PATTERN.fullmatch(token_digest) is None:
            raise ResultStoreError("stored deletion token digest is invalid")
        bundle = value["bundle"]
        if not isinstance(bundle, dict):
            raise ResultStoreError("stored viewer bundle is not an object")
        result_id, payload, actual_digest = _bundle_identity(bundle)
        if result_id != expected_result_id or actual_digest != bundle_digest:
            raise ResultStoreError("stored viewer bundle failed its content identity check")
        stored = StoredResult(
            result_id=result_id,
            payload=payload,
            etag=f'"{actual_digest}"',
            published_at=_timestamp(published_at),
            expires_at=None if expires_at is None else _timestamp(expires_at),
        )
        return value, stored

    def _is_expired(self, stored: StoredResult) -> bool:
        return stored.expires_at is not None and _parse_timestamp(
            stored.expires_at,
            "expiry",
        ) <= self._now()

    def _token_matches(self, envelope: dict[str, Any], token: str) -> bool:
        return self._keyring.verify_token(
            token,
            envelope["keyId"],
            envelope["deletionDigestHmacSha256"],
        )


def _publication(stored: StoredResult, *, created: bool) -> Publication:
    return Publication(
        result_id=stored.result_id,
        payload=stored.payload,
        etag=stored.etag,
        published_at=stored.published_at,
        expires_at=stored.expires_at,
        created=created,
    )


class MemoryResultStore(_StoreCore):
    """Ephemeral store used by unit-level orchestration proofs."""

    def __init__(
        self,
        *,
        keys: Sequence[bytes] | None = None,
        retention_seconds: float | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        super().__init__(
            keys or (secrets.token_bytes(32),),
            retention_seconds=retention_seconds,
            clock=clock,
        )
        self._entries: dict[str, dict[str, Any]] = {}
        self._artifacts: dict[tuple[str, ArtifactKind], bytes] = {}
        self._retired: set[str] = set()

    def _remove(self, result_id: str) -> None:
        self._entries.pop(result_id, None)
        for kind in ARTIFACT_KINDS:
            self._artifacts.pop((result_id, kind), None)

    def _validate_artifact_state(
        self,
        envelope: dict[str, Any],
        stored: StoredResult,
    ) -> None:
        for kind in ARTIFACT_KINDS:
            target = envelope["bundle"]["result"]["exports"][kind]
            payload = self._artifacts.get((stored.result_id, kind))
            if target["state"] == "ready":
                if payload is None:
                    raise ResultStoreError(f"stored result is missing its {kind} artifact")
                _stored_artifact(
                    bundle=envelope["bundle"],
                    stored=stored,
                    kind=kind,
                    payload=payload,
                )
            elif payload is not None:
                raise ResultStoreError(f"stored result has an unregistered {kind} artifact")

    def publish(
        self,
        bundle: dict[str, Any],
        deletion_token_digest: str,
        artifacts: Mapping[str, bytes] | None = None,
    ) -> Publication:
        envelope, payload, validated_artifacts = self._new_envelope(
            bundle,
            deletion_token_digest,
            artifacts,
        )
        result_id = envelope["resultId"]
        with self._lock:
            if result_id in self._retired:
                raise ResultStoreError("retired result ID cannot be reused")
            existing = self.get(result_id)
            if existing is not None:
                if existing.payload != payload:
                    raise ResultStoreError("immutable result ID collision")
                for kind in ARTIFACT_KINDS:
                    existing_artifact = self.get_artifact(result_id, kind)
                    supplied_artifact = validated_artifacts.get(kind)
                    if (existing_artifact is None) != (supplied_artifact is None) or (
                        existing_artifact is not None
                        and supplied_artifact is not None
                        and existing_artifact.payload != supplied_artifact
                    ):
                        raise ResultStoreError(f"immutable {kind} artifact collision")
                return _publication(existing, created=False)
            if result_id in self._retired:
                raise ResultStoreError("expired result ID cannot be reused")
            for kind, artifact in validated_artifacts.items():
                self._artifacts[(result_id, kind)] = artifact
            self._entries[result_id] = envelope
            stored = self.get(result_id)
            if stored is None:
                raise ResultStoreError("published in-memory result disappeared")
            return _publication(stored, created=True)

    def get(self, result_id: str) -> StoredResult | None:
        _validate_result_id(result_id)
        with self._lock:
            envelope = self._entries.get(result_id)
            if envelope is None:
                return None
            _value, stored = self._decode_envelope(envelope, expected_result_id=result_id)
            if self._is_expired(stored):
                self._remove(result_id)
                self._retired.add(result_id)
                return None
            self._validate_artifact_state(envelope, stored)
            return stored

    def get_artifact(
        self,
        result_id: str,
        kind: ArtifactKind,
    ) -> StoredArtifact | None:
        _validate_result_id(result_id)
        kind = _validate_artifact_kind(kind)
        with self._lock:
            stored = self.get(result_id)
            if stored is None:
                return None
            envelope = self._entries[result_id]
            if envelope["bundle"]["result"]["exports"][kind]["state"] != "ready":
                return None
            payload = self._artifacts.get((result_id, kind))
            if payload is None:
                raise ResultStoreError(f"stored result is missing its {kind} artifact")
            return _stored_artifact(
                bundle=envelope["bundle"],
                stored=stored,
                kind=kind,
                payload=payload,
            )

    def delete(self, result_id: str, deletion_token: str) -> DeleteOutcome:
        try:
            _validate_result_id(result_id)
            _validate_token(deletion_token)
        except ValueError:
            return "malformed"
        with self._lock:
            envelope = self._entries.get(result_id)
            if envelope is None:
                return "not-found"
            value, stored = self._decode_envelope(envelope, expected_result_id=result_id)
            if self._is_expired(stored):
                self._remove(result_id)
                self._retired.add(result_id)
                return "not-found"
            if not self._token_matches(value, deletion_token):
                return "forbidden"
            self._remove(result_id)
            self._retired.add(result_id)
            return "deleted"

    def sweep(self) -> int:
        with self._lock:
            before = len(self._entries)
            for result_id in tuple(self._entries):
                self.get(result_id)
            return before - len(self._entries)


class FilesystemResultStore(_StoreCore):
    """Atomic, single-process file store for restart-stable local results."""

    def __init__(
        self,
        root: Path,
        *,
        keys: Sequence[bytes],
        retention_seconds: float | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        super().__init__(keys, retention_seconds=retention_seconds, clock=clock)
        root.mkdir(parents=True, exist_ok=True)
        if root.is_symlink() or not root.is_dir():
            raise ResultStoreError("result-store root must be a real directory")
        self._root = root.resolve(strict=True)
        self._cleanup_staging()
        self.sweep()

    def _path(self, result_id: str) -> Path:
        _validate_result_id(result_id)
        path = self._root / f"{result_id}.json"
        if path.parent != self._root:
            raise ResultStoreError("result path escaped its store root")
        return path

    def _tombstone_path(self, result_id: str) -> Path:
        _validate_result_id(result_id)
        path = self._root / f"{result_id}.deleted"
        if path.parent != self._root:
            raise ResultStoreError("tombstone path escaped its store root")
        return path

    def _artifact_path(self, result_id: str, kind: ArtifactKind) -> Path:
        _validate_result_id(result_id)
        kind = _validate_artifact_kind(kind)
        path = self._root / f"{result_id}{ARTIFACT_SUFFIXES[kind]}"
        if path.parent != self._root:
            raise ResultStoreError("artifact path escaped its store root")
        return path

    def _cleanup_staging(self) -> None:
        for path in self._root.glob(".staging-*"):
            if path.is_file() and not path.is_symlink():
                path.unlink()

    def _cleanup_orphan_artifacts(self) -> None:
        for path in self._root.iterdir():
            match = re.fullmatch(r"(r_[0-9a-f]{32})\.(poster\.png|video\.mp4)", path.name)
            if match is None:
                continue
            result_id = match.group(1)
            if self._path(result_id).is_file() and not self._is_retired(result_id):
                continue
            if path.is_symlink() or not path.is_file():
                raise ResultStoreError("stored artifact path is not a regular file")
            path.unlink()
            self._fsync_root()

    def _fsync_root(self) -> None:
        try:
            descriptor = os.open(self._root, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    def _read(self, result_id: str) -> tuple[dict[str, Any], StoredResult] | None:
        path = self._path(result_id)
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise ResultStoreError("stored result path is not a regular file")
        size = path.stat().st_size
        if size <= 0 or size > MAX_BUNDLE_BYTES + 8_192:
            raise ResultStoreError("stored result envelope exceeds its size limit")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeError, json.JSONDecodeError, OSError) as error:
            raise ResultStoreError("stored result envelope is unreadable") from error
        envelope, stored = self._decode_envelope(value, expected_result_id=result_id)
        for kind in ARTIFACT_KINDS:
            target = envelope["bundle"]["result"]["exports"][kind]
            artifact_path = self._artifact_path(result_id, kind)
            if target["state"] == "ready":
                if not artifact_path.exists():
                    raise ResultStoreError(f"stored result is missing its {kind} artifact")
                self._read_artifact(envelope["bundle"], stored, kind)
            elif artifact_path.exists():
                raise ResultStoreError(f"stored result has an unregistered {kind} artifact")
        return envelope, stored

    def _read_artifact(
        self,
        bundle: dict[str, Any],
        stored: StoredResult,
        kind: ArtifactKind,
    ) -> StoredArtifact:
        kind = _validate_artifact_kind(kind)
        path = self._artifact_path(stored.result_id, kind)
        if not path.exists():
            raise ResultStoreError(f"stored result is missing its {kind} artifact")
        if path.is_symlink() or not path.is_file():
            raise ResultStoreError("stored artifact path is not a regular file")
        size = path.stat().st_size
        if size <= 0 or size > bundle["result"]["exports"][kind]["maxByteLength"]:
            raise ResultStoreError(f"stored {kind} exceeds its size limit")
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise ResultStoreError(f"stored {kind} is unreadable") from error
        return _stored_artifact(
            bundle=bundle,
            stored=stored,
            kind=kind,
            payload=payload,
        )

    def _remove(self, result_id: str) -> None:
        removed = False
        targets = [(self._path(result_id), "result")]
        targets.extend(
            (self._artifact_path(result_id, kind), f"{kind} artifact")
            for kind in ARTIFACT_KINDS
        )
        for path, label in targets:
            if not path.exists():
                continue
            if path.is_symlink() or not path.is_file():
                raise ResultStoreError(f"stored {label} path is not a regular file")
            path.unlink()
            removed = True
        if removed:
            self._fsync_root()

    def _is_retired(self, result_id: str) -> bool:
        path = self._tombstone_path(result_id)
        if not path.exists():
            return False
        if path.is_symlink() or not path.is_file():
            raise ResultStoreError("stored tombstone path is not a regular file")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeError, json.JSONDecodeError, OSError) as error:
            raise ResultStoreError("stored tombstone is unreadable") from error
        if not isinstance(value, dict) or set(value) != {
            "tombstoneVersion",
            "resultId",
            "retiredAt",
        }:
            raise ResultStoreError("stored tombstone has an invalid shape")
        if (
            value["tombstoneVersion"] != TOMBSTONE_VERSION
            or value["resultId"] != result_id
        ):
            raise ResultStoreError("stored tombstone identity drifted")
        _parse_timestamp(value["retiredAt"], "retirement time")
        return True

    def _write_atomic(self, destination: Path, value: dict[str, Any]) -> None:
        result_id = value["resultId"]
        temporary = self._root / f".staging-{result_id}-{secrets.token_hex(8)}"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as output:
                output.write(stable_json_bytes(value))
                output.flush()
                os.fsync(output.fileno())
            if destination.exists():
                raise ResultStoreError("immutable result appeared during publication")
            os.replace(temporary, destination)
            self._fsync_root()
        finally:
            if temporary.exists():
                temporary.unlink()

    def _write_bytes_atomic(
        self,
        destination: Path,
        payload: bytes,
        *,
        result_id: str,
        kind: ArtifactKind,
    ) -> None:
        kind = _validate_artifact_kind(kind)
        temporary = self._root / f".staging-{result_id}-{kind}-{secrets.token_hex(8)}"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            if destination.exists():
                raise ResultStoreError(f"immutable {kind} appeared during publication")
            os.replace(temporary, destination)
            self._fsync_root()
        finally:
            if temporary.exists():
                temporary.unlink()

    def _retire(self, result_id: str) -> None:
        if not self._is_retired(result_id):
            self._write_atomic(
                self._tombstone_path(result_id),
                {
                    "tombstoneVersion": TOMBSTONE_VERSION,
                    "resultId": result_id,
                    "retiredAt": _timestamp(self._now()),
                },
            )
        self._remove(result_id)

    def publish(
        self,
        bundle: dict[str, Any],
        deletion_token_digest: str,
        artifacts: Mapping[str, bytes] | None = None,
    ) -> Publication:
        envelope, payload, validated_artifacts = self._new_envelope(
            bundle,
            deletion_token_digest,
            artifacts,
        )
        result_id = envelope["resultId"]
        with self._lock:
            if self._is_retired(result_id):
                raise ResultStoreError("retired result ID cannot be reused")
            existing_pair = self._read(result_id)
            if existing_pair is not None:
                _existing_envelope, existing = existing_pair
                if self._is_expired(existing):
                    self._retire(result_id)
                    raise ResultStoreError("expired result ID cannot be reused")
                else:
                    if existing.payload != payload:
                        raise ResultStoreError("immutable result ID collision")
                    for kind in ARTIFACT_KINDS:
                        existing_artifact = self.get_artifact(result_id, kind)
                        supplied_artifact = validated_artifacts.get(kind)
                        if (existing_artifact is None) != (supplied_artifact is None) or (
                            existing_artifact is not None
                            and supplied_artifact is not None
                            and existing_artifact.payload != supplied_artifact
                        ):
                            raise ResultStoreError(f"immutable {kind} artifact collision")
                    return _publication(existing, created=False)
            artifact_paths = {
                kind: self._artifact_path(result_id, kind) for kind in ARTIFACT_KINDS
            }
            for kind, artifact_path in artifact_paths.items():
                if kind not in validated_artifacts and artifact_path.exists():
                    raise ResultStoreError(
                        f"uncommitted {kind} blocks result publication"
                    )
            committed: list[Path] = []
            try:
                for kind in ARTIFACT_KINDS:
                    artifact = validated_artifacts.get(kind)
                    if artifact is None:
                        continue
                    artifact_path = artifact_paths[kind]
                    self._write_bytes_atomic(
                        artifact_path,
                        artifact,
                        result_id=result_id,
                        kind=kind,
                    )
                    committed.append(artifact_path)
                # The envelope is the sole visibility marker. It is committed
                # only after every registered artifact is durable.
                self._write_atomic(self._path(result_id), envelope)
            except Exception:
                if committed and not self._path(result_id).exists():
                    for artifact_path in committed:
                        if artifact_path.exists() and artifact_path.is_file() and not artifact_path.is_symlink():
                            artifact_path.unlink()
                    self._fsync_root()
                raise
            stored_pair = self._read(result_id)
            if stored_pair is None:
                raise ResultStoreError("published result disappeared")
            _stored_envelope, stored = stored_pair
            return _publication(stored, created=True)

    def get(self, result_id: str) -> StoredResult | None:
        _validate_result_id(result_id)
        with self._lock:
            if self._is_retired(result_id):
                self._remove(result_id)
                return None
            pair = self._read(result_id)
            if pair is None:
                return None
            _envelope, stored = pair
            if self._is_expired(stored):
                self._retire(result_id)
                return None
            return stored

    def get_artifact(
        self,
        result_id: str,
        kind: ArtifactKind,
    ) -> StoredArtifact | None:
        _validate_result_id(result_id)
        kind = _validate_artifact_kind(kind)
        with self._lock:
            if self._is_retired(result_id):
                self._remove(result_id)
                return None
            pair = self._read(result_id)
            if pair is None:
                return None
            envelope, stored = pair
            if self._is_expired(stored):
                self._retire(result_id)
                return None
            if envelope["bundle"]["result"]["exports"][kind]["state"] != "ready":
                return None
            return self._read_artifact(envelope["bundle"], stored, kind)

    def delete(self, result_id: str, deletion_token: str) -> DeleteOutcome:
        try:
            _validate_result_id(result_id)
            _validate_token(deletion_token)
        except ValueError:
            return "malformed"
        with self._lock:
            if self._is_retired(result_id):
                self._remove(result_id)
                return "not-found"
            pair = self._read(result_id)
            if pair is None:
                return "not-found"
            envelope, stored = pair
            if self._is_expired(stored):
                self._retire(result_id)
                return "not-found"
            if not self._token_matches(envelope, deletion_token):
                return "forbidden"
            self._retire(result_id)
            return "deleted"

    def sweep(self) -> int:
        removed = 0
        with self._lock:
            for path in self._root.iterdir():
                match = re.fullmatch(r"(r_[0-9a-f]{32})\.json", path.name)
                if match is None:
                    continue
                result_id = match.group(1)
                try:
                    if self._is_retired(result_id):
                        self._remove(result_id)
                        removed += 1
                        continue
                    pair = self._read(result_id)
                except ResultStoreError:
                    # A corrupt envelope/artifact pair can never become live
                    # again under this immutable ID. Retire it so both files
                    # are cleaned and an invalid artifact cannot leak disk.
                    try:
                        self._retire(result_id)
                    except ResultStoreError:
                        continue
                    removed += 1
                    continue
                if pair is not None and self._is_expired(pair[1]):
                    self._retire(result_id)
                    removed += 1
            self._cleanup_orphan_artifacts()
        return removed


def load_or_create_store_key(path: Path) -> bytes:
    """Load or atomically create the local 256-bit HMAC key."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise ResultStoreError("store-key path must not be a symlink")
    if path.exists():
        value = path.read_bytes()
        if len(value) != 32:
            raise ResultStoreError("store key has an invalid length")
        return value
    value = secrets.token_bytes(32)
    temporary = path.parent / f".staging-store-key-{secrets.token_hex(8)}"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            existing = path.read_bytes()
            if len(existing) != 32:
                raise ResultStoreError("store key has an invalid length")
            return existing
        try:
            directory = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory = None
        if directory is not None:
            try:
                os.fsync(directory)
            except OSError:
                pass
            finally:
                os.close(directory)
        return value
    finally:
        if temporary.exists():
            temporary.unlink()
