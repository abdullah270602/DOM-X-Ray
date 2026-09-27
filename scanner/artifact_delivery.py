"""Private immutable-object delivery boundary with verified retirement.

The filesystem adapter is a durable, single-process reference implementation.
Production adapters must keep object keys private, conditionally create objects,
atomically expose a live control record, and provide a cache purger whose
``confirmed`` result means every configured public route is invalidated.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

from scanner.api_contract import stable_json_bytes, validate_viewer_bundle
from scanner.mp4_validation import Mp4ValidationError, validate_share_video_mp4
from scanner.png_validation import PngValidationError, validate_poster_png


DELIVERY_VERSION = "artifact-delivery-v0.2.0"
PURGE_RECEIPT_VERSION = "artifact-purge-receipt-v0.2.0"
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
RESULT_ID_PATTERN = re.compile(r"^r_[0-9a-f]{32}$")
STAGE_ID_PATTERN = re.compile(r"^s_[0-9a-f]{64}$")
PURGE_ID_PATTERN = re.compile(r"^p_[0-9a-f]{32}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

DeliveryKind = Literal["bundle", "poster", "video"]
DeliveryState = Literal["staged", "live", "retiring", "retired"]
PurgeState = Literal["pending", "confirmed"]
DELIVERY_KINDS: tuple[DeliveryKind, ...] = ("bundle", "poster", "video")
OBJECT_SUFFIXES: dict[DeliveryKind, str] = {
    "bundle": ".bundle.json",
    "poster": ".poster.png",
    "video": ".video.mp4",
}
OBJECT_FILENAMES: dict[DeliveryKind, str] = {
    "bundle": "bundle.json",
    "poster": "poster.png",
    "video": "video.mp4",
}
MEDIA_TYPES: dict[DeliveryKind, str] = {
    "bundle": "application/json; charset=utf-8",
    "poster": "image/png",
    "video": "video/mp4",
}


class ArtifactDeliveryError(RuntimeError):
    """Raised when delivery state violates the immutable publication contract."""


class PurgePendingError(ArtifactDeliveryError):
    """Raised after origin visibility is fenced but edge purge is unconfirmed."""

    def __init__(self, result_id: str, operation_id: str, message: str) -> None:
        super().__init__(message)
        self.result_id = result_id
        self.operation_id = operation_id


@dataclass(frozen=True)
class DeliveryCachePolicy:
    value: str
    purge_required: bool

    def __post_init__(self) -> None:
        if self.value == "no-store":
            if self.purge_required:
                raise ValueError("no-store delivery cannot require cache purge")
            return
        match = re.fullmatch(
            r"public, max-age=0, s-maxage=([1-9][0-9]{0,8}), must-revalidate",
            self.value,
        )
        if match is None or not self.purge_required:
            raise ValueError("shared delivery cache policy is invalid")
        seconds = int(match.group(1))
        if seconds > 31_536_000:
            raise ValueError("shared delivery cache lifetime exceeds one year")

    @classmethod
    def no_store(cls) -> DeliveryCachePolicy:
        return cls(value="no-store", purge_required=False)

    @classmethod
    def shared(cls, *, s_maxage_seconds: int = 31_536_000) -> DeliveryCachePolicy:
        if (
            isinstance(s_maxage_seconds, bool)
            or not isinstance(s_maxage_seconds, int)
            or not 1 <= s_maxage_seconds <= 31_536_000
        ):
            raise ValueError("shared cache lifetime must be an integer from 1 to 31536000")
        return cls(
            value=(
                "public, max-age=0, "
                f"s-maxage={s_maxage_seconds}, must-revalidate"
            ),
            purge_required=True,
        )


@dataclass(frozen=True)
class DeliveryObjectRef:
    result_id: str
    kind: DeliveryKind
    key: str
    public_path: str
    media_type: str
    sha256: str
    byte_length: int
    etag: str


@dataclass(frozen=True)
class DeliveredObject(DeliveryObjectRef):
    payload: bytes
    cache_control: str


@dataclass(frozen=True)
class DeliveryBatch:
    result_id: str
    publication_sha256: str
    objects: tuple[tuple[DeliveryObjectRef, bytes], ...]
    public_paths: tuple[str, ...]


@dataclass(frozen=True)
class DeliveryStage:
    stage_id: str
    result_id: str
    publication_sha256: str
    created: bool
    already_live: bool


@dataclass(frozen=True)
class DeliveryPublication:
    result_id: str
    publication_sha256: str
    objects: tuple[DeliveryObjectRef, ...]
    public_paths: tuple[str, ...]
    cache_control: str
    activated_at: str
    created: bool


@dataclass(frozen=True)
class CachePurgeResult:
    operation_id: str
    state: PurgeState
    coverage_sha256: str
    provider_target_id: str
    provider_request_id: str | None = None
    confirmed_at: str | None = None

    def __post_init__(self) -> None:
        if PURGE_ID_PATTERN.fullmatch(self.operation_id) is None:
            raise ValueError("purge result has an invalid operation ID")
        if self.state not in {"pending", "confirmed"}:
            raise ValueError("purge result has an invalid state")
        if SHA256_PATTERN.fullmatch(self.coverage_sha256) is None:
            raise ValueError("purge result has an invalid coverage digest")
        _validate_provider_target_id(self.provider_target_id)
        if self.provider_request_id is not None and (
            not isinstance(self.provider_request_id, str)
            or not 1 <= len(self.provider_request_id) <= 256
            or any(ord(character) < 0x20 for character in self.provider_request_id)
        ):
            raise ValueError("purge result has an invalid provider request ID")
        if self.state == "confirmed":
            if self.provider_request_id is None or self.confirmed_at is None:
                raise ValueError("confirmed purge result lacks provider evidence")
            _parse_timestamp(self.confirmed_at, "provider purge confirmation time")
        elif self.confirmed_at is not None:
            raise ValueError("pending purge result cannot have a confirmation time")


@dataclass(frozen=True)
class PurgeReceipt:
    result_id: str
    operation_id: str
    provider_target_id: str | None
    provider_request_id: str | None
    confirmed_at: str
    coverage_sha256: str
    public_paths: tuple[str, ...]
    cache_control: str
    purge_required: bool


class CachePurger(Protocol):
    @property
    def provider_target_id(self) -> str: ...

    def purge(
        self,
        *,
        operation_id: str,
        result_id: str,
        public_paths: tuple[str, ...],
        objects: tuple[DeliveryObjectRef, ...],
    ) -> CachePurgeResult: ...


class ArtifactDelivery(Protocol):
    def stage(
        self,
        bundle: dict[str, Any],
        artifacts: Mapping[str, bytes] | None = None,
    ) -> DeliveryStage: ...

    def activate(self, stage: DeliveryStage) -> DeliveryPublication: ...

    def abort(self, stage: DeliveryStage) -> bool: ...

    def get(self, result_id: str, kind: DeliveryKind) -> DeliveredObject | None: ...

    def retire(self, result_id: str) -> PurgeReceipt | None: ...

    def retry_pending(self, result_id: str) -> PurgeReceipt | None: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ArtifactDeliveryError("delivery clock must return a timezone-aware datetime")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ArtifactDeliveryError(f"delivery {label} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ArtifactDeliveryError(f"delivery {label} is invalid") from error
    if parsed.tzinfo is None:
        raise ArtifactDeliveryError(f"delivery {label} has no timezone")
    return _timestamp(parsed)


def _validate_provider_target_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or any(not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ValueError("invalid delivery purge provider target ID")
    return value


def _validate_result_id(result_id: object) -> str:
    if not isinstance(result_id, str) or RESULT_ID_PATTERN.fullmatch(result_id) is None:
        raise ValueError("invalid delivery result ID")
    return result_id


def _validate_kind(kind: object) -> DeliveryKind:
    if kind not in DELIVERY_KINDS:
        raise ValueError("invalid delivery object kind")
    return kind  # type: ignore[return-value]


def _object_key(result_id: str, kind: DeliveryKind) -> str:
    return f"v1/results/{result_id}/{OBJECT_FILENAMES[kind]}"


def _public_path(result_id: str, kind: DeliveryKind) -> str:
    base = f"/api/results/{result_id}"
    if kind == "bundle":
        return base
    return f"{base}/{OBJECT_FILENAMES[kind]}"


def _object_ref(
    result_id: str,
    kind: DeliveryKind,
    payload: bytes,
) -> DeliveryObjectRef:
    digest = hashlib.sha256(payload).hexdigest()
    return DeliveryObjectRef(
        result_id=result_id,
        kind=kind,
        key=_object_key(result_id, kind),
        public_path=_public_path(result_id, kind),
        media_type=MEDIA_TYPES[kind],
        sha256=digest,
        byte_length=len(payload),
        etag=f'"{digest}"',
    )


def _ref_value(reference: DeliveryObjectRef) -> dict[str, object]:
    return {
        "kind": reference.kind,
        "key": reference.key,
        "publicPath": reference.public_path,
        "mediaType": reference.media_type,
        "sha256": reference.sha256,
        "byteLength": reference.byte_length,
        "etag": reference.etag,
    }


def purge_coverage_sha256(
    result_id: str,
    public_paths: tuple[str, ...],
    objects: tuple[DeliveryObjectRef, ...],
) -> str:
    value = {
        "deliveryVersion": DELIVERY_VERSION,
        "resultId": result_id,
        "publicPaths": list(public_paths),
        "objects": [_ref_value(reference) for reference in objects],
    }
    return hashlib.sha256(stable_json_bytes(value)).hexdigest()


def build_delivery_batch(
    bundle: dict[str, Any],
    artifacts: Mapping[str, bytes] | None = None,
) -> DeliveryBatch:
    """Validate and bind private objects to their immutable public routes."""

    validate_viewer_bundle(bundle)
    result = bundle["result"]
    result_id = _validate_result_id(result["resultId"])
    if (
        result["resultPath"] != f"/r/{result_id}"
        or bundle["runtime"]["resultId"] != result_id
        or bundle["runtime"]["resultPath"] != result["resultPath"]
    ):
        raise ArtifactDeliveryError("delivery bundle route identity drifted")
    bundle_payload = stable_json_bytes(bundle)
    if not 0 < len(bundle_payload) <= MAX_BUNDLE_BYTES:
        raise ArtifactDeliveryError("delivery bundle exceeds its byte envelope")

    if artifacts is not None and not isinstance(artifacts, Mapping):
        raise ValueError("delivery artifacts must be a mapping")
    supplied = dict(artifacts or {})
    if any(kind not in {"poster", "video"} for kind in supplied):
        raise ArtifactDeliveryError("delivery contains an unsupported artifact kind")
    if any(not isinstance(payload, bytes) for payload in supplied.values()):
        raise ValueError("delivery artifact payloads must be bytes")
    ready = {
        kind
        for kind, target in result["exports"].items()
        if target["state"] == "ready"
    }
    if set(supplied) != ready:
        raise ArtifactDeliveryError("ready delivery artifacts do not match the manifest")

    object_payloads: list[tuple[DeliveryObjectRef, bytes]] = [
        (_object_ref(result_id, "bundle", bundle_payload), bundle_payload)
    ]
    for kind in ("poster", "video"):
        if kind not in supplied:
            continue
        payload = supplied[kind]
        try:
            metadata = (
                validate_poster_png(payload)
                if kind == "poster"
                else validate_share_video_mp4(payload)
            )
        except (PngValidationError, Mp4ValidationError) as error:
            raise ArtifactDeliveryError(f"delivery {kind} failed media validation") from error
        target = result["exports"][kind]
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
            raise ArtifactDeliveryError(
                f"delivery {kind} bytes do not match the immutable manifest"
            )
        typed_kind: DeliveryKind = kind  # type: ignore[assignment]
        object_payloads.append((_object_ref(result_id, typed_kind, payload), payload))

    public_paths = (
        result["resultPath"],
        *(reference.public_path for reference, _payload in object_payloads),
    )
    publication_value = {
        "deliveryVersion": DELIVERY_VERSION,
        "resultId": result_id,
        "objects": [_ref_value(reference) for reference, _payload in object_payloads],
        "publicPaths": list(public_paths),
    }
    publication_sha256 = hashlib.sha256(stable_json_bytes(publication_value)).hexdigest()
    return DeliveryBatch(
        result_id=result_id,
        publication_sha256=publication_sha256,
        objects=tuple(object_payloads),
        public_paths=tuple(public_paths),
    )


class FilesystemArtifactDelivery:
    """Durable local lifecycle proof for a private object store plus edge purge."""

    def __init__(
        self,
        root: Path,
        *,
        cache_policy: DeliveryCachePolicy | None = None,
        purger: CachePurger | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        requested_root = root.absolute()
        if requested_root.exists() and requested_root.is_symlink():
            raise ArtifactDeliveryError("delivery root must not be a symlink")
        self._root = requested_root.resolve()
        self._cache_policy = cache_policy or DeliveryCachePolicy.no_store()
        if self._cache_policy.purge_required and purger is None:
            raise ValueError("shared delivery caching requires a verified purger")
        self._purger = purger
        self._purge_target_id = (
            _validate_provider_target_id(purger.provider_target_id)
            if self._cache_policy.purge_required and purger is not None
            else None
        )
        self._clock = clock
        self._lock = threading.RLock()
        self._directories = {
            name: self._root / name
            for name in ("objects", "stages", "live", "retiring", "retired")
        }
        self._root.mkdir(parents=True, exist_ok=True)
        for directory in self._directories.values():
            if directory.exists() and directory.is_symlink():
                raise ArtifactDeliveryError("delivery state directory must not be a symlink")
            directory.mkdir(exist_ok=True)
        self._recover()

    @property
    def cache_policy(self) -> DeliveryCachePolicy:
        return self._cache_policy

    def _now(self) -> str:
        return _timestamp(self._clock())

    def _fsync(self, directory: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _write_once(self, destination: Path, payload: bytes) -> bool:
        if destination.parent not in self._directories.values():
            raise ArtifactDeliveryError("delivery write escaped its state directories")
        temporary = destination.parent / f".staging-{secrets.token_hex(16)}"
        try:
            with temporary.open("xb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            if destination.exists():
                if destination.is_symlink() or not destination.is_file():
                    raise ArtifactDeliveryError("delivery destination is not a regular file")
                if destination.read_bytes() != payload:
                    raise ArtifactDeliveryError("immutable delivery object collision")
                return False
            os.replace(temporary, destination)
            self._fsync(destination.parent)
            return True
        finally:
            temporary.unlink(missing_ok=True)

    def _write_entry(self, destination: Path, value: dict[str, object]) -> bool:
        return self._write_once(destination, stable_json_bytes(value))

    def _read_bytes(self, path: Path, *, maximum: int) -> bytes:
        if path.is_symlink() or not path.is_file():
            raise ArtifactDeliveryError("delivery state is not a private regular file")
        size = path.stat().st_size
        if not 0 < size <= maximum:
            raise ArtifactDeliveryError("delivery state is outside its byte envelope")
        payload = path.read_bytes()
        if len(payload) != size:
            raise ArtifactDeliveryError("delivery state changed while it was read")
        return payload

    def _read_json(self, path: Path) -> dict[str, Any]:
        try:
            value = json.loads(self._read_bytes(path, maximum=128 * 1024))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ArtifactDeliveryError("delivery control record is unreadable") from error
        if not isinstance(value, dict):
            raise ArtifactDeliveryError("delivery control record is not an object")
        return value

    def _object_path(self, result_id: str, kind: DeliveryKind) -> Path:
        result_id = _validate_result_id(result_id)
        kind = _validate_kind(kind)
        path = self._directories["objects"] / f"{result_id}{OBJECT_SUFFIXES[kind]}"
        if path.parent != self._directories["objects"]:
            raise ArtifactDeliveryError("delivery object path escaped its directory")
        return path

    def _stage_path(self, stage_id: str) -> Path:
        if not isinstance(stage_id, str) or STAGE_ID_PATTERN.fullmatch(stage_id) is None:
            raise ValueError("invalid delivery stage ID")
        return self._directories["stages"] / f"{stage_id}.json"

    def _state_path(self, state: Literal["live", "retiring", "retired"], result_id: str) -> Path:
        result_id = _validate_result_id(result_id)
        return self._directories[state] / f"{result_id}.json"

    def _entry(
        self,
        batch: DeliveryBatch,
        *,
        state: DeliveryState,
        created_at: str,
        activated_at: str | None = None,
        retired_at: str | None = None,
        purge_operation_id: str | None = None,
        purge_target_id: str | None = None,
        purge_receipt: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return {
            "deliveryVersion": DELIVERY_VERSION,
            "state": state,
            "stageId": f"s_{batch.publication_sha256}",
            "resultId": batch.result_id,
            "publicationSha256": batch.publication_sha256,
            "cacheControl": self._cache_policy.value,
            "createdAt": created_at,
            "activatedAt": activated_at,
            "retiredAt": retired_at,
            "purgeOperationId": purge_operation_id,
            "purgeTargetId": purge_target_id,
            "purgeReceipt": purge_receipt,
            "objects": [_ref_value(reference) for reference, _payload in batch.objects],
            "publicPaths": list(batch.public_paths),
        }

    def _basic_entry(self, value: dict[str, Any], *, expected_state: DeliveryState) -> None:
        expected_keys = {
            "deliveryVersion",
            "state",
            "stageId",
            "resultId",
            "publicationSha256",
            "cacheControl",
            "createdAt",
            "activatedAt",
            "retiredAt",
            "purgeOperationId",
            "purgeTargetId",
            "purgeReceipt",
            "objects",
            "publicPaths",
        }
        if set(value) != expected_keys:
            raise ArtifactDeliveryError("delivery control record has an invalid shape")
        result_id = _validate_result_id(value["resultId"])
        publication = value["publicationSha256"]
        if (
            value["deliveryVersion"] != DELIVERY_VERSION
            or value["state"] != expected_state
            or not isinstance(publication, str)
            or SHA256_PATTERN.fullmatch(publication) is None
            or value["stageId"] != f"s_{publication}"
            or value["cacheControl"] != self._cache_policy.value
        ):
            raise ArtifactDeliveryError("delivery control record identity drifted")
        _parse_timestamp(value["createdAt"], "creation time")
        if expected_state == "staged":
            expected_nullable = (None, None, None, None, None)
        elif expected_state == "live":
            _parse_timestamp(value["activatedAt"], "activation time")
            expected_nullable = (value["activatedAt"], None, None, None, None)
        elif expected_state == "retiring":
            _parse_timestamp(value["activatedAt"], "activation time")
            _parse_timestamp(value["retiredAt"], "retirement time")
            operation_id = value["purgeOperationId"]
            if (
                not isinstance(operation_id, str)
                or PURGE_ID_PATTERN.fullmatch(operation_id) is None
            ):
                raise ArtifactDeliveryError("retiring delivery has an invalid purge operation")
            target_id = value["purgeTargetId"]
            if self._cache_policy.purge_required:
                try:
                    target_id = _validate_provider_target_id(target_id)
                except ValueError as error:
                    raise ArtifactDeliveryError(
                        "retiring delivery has an invalid purge target"
                    ) from error
                if target_id != self._purge_target_id:
                    raise ArtifactDeliveryError("retiring delivery purge target drifted")
            elif target_id is not None:
                raise ArtifactDeliveryError("no-store retirement has a purge target")
            expected_nullable = (
                value["activatedAt"],
                value["retiredAt"],
                operation_id,
                target_id,
                None,
            )
        else:
            _parse_timestamp(value["activatedAt"], "activation time")
            _parse_timestamp(value["retiredAt"], "retirement time")
            operation_id = value["purgeOperationId"]
            if (
                not isinstance(operation_id, str)
                or PURGE_ID_PATTERN.fullmatch(operation_id) is None
            ):
                raise ArtifactDeliveryError("retired delivery has an invalid purge operation")
            self._receipt(value, expected_result_id=result_id)
            expected_nullable = (
                value["activatedAt"],
                value["retiredAt"],
                operation_id,
                value["purgeTargetId"],
                value["purgeReceipt"],
            )
        actual_nullable = (
            value["activatedAt"],
            value["retiredAt"],
            value["purgeOperationId"],
            value["purgeTargetId"],
            value["purgeReceipt"],
        )
        if actual_nullable != expected_nullable:
            raise ArtifactDeliveryError("delivery lifecycle timestamps drifted")
        if not isinstance(value["objects"], list) or not isinstance(value["publicPaths"], list):
            raise ArtifactDeliveryError("delivery object registry is malformed")

    def _references(self, value: dict[str, Any]) -> tuple[DeliveryObjectRef, ...]:
        result_id = _validate_result_id(value.get("resultId"))
        raw_refs = value.get("objects")
        if not isinstance(raw_refs, list) or not 1 <= len(raw_refs) <= len(DELIVERY_KINDS):
            raise ArtifactDeliveryError("delivery object registry has an invalid size")
        references: list[DeliveryObjectRef] = []
        seen: set[DeliveryKind] = set()
        for index, raw in enumerate(raw_refs):
            if not isinstance(raw, dict) or set(raw) != {
                "kind",
                "key",
                "publicPath",
                "mediaType",
                "sha256",
                "byteLength",
                "etag",
            }:
                raise ArtifactDeliveryError("delivery object reference is malformed")
            kind = _validate_kind(raw["kind"])
            if kind in seen or (index == 0 and kind != "bundle"):
                raise ArtifactDeliveryError("delivery object order or uniqueness drifted")
            seen.add(kind)
            digest = raw["sha256"]
            byte_length = raw["byteLength"]
            if (
                raw["key"] != _object_key(result_id, kind)
                or raw["publicPath"] != _public_path(result_id, kind)
                or raw["mediaType"] != MEDIA_TYPES[kind]
                or not isinstance(digest, str)
                or SHA256_PATTERN.fullmatch(digest) is None
                or isinstance(byte_length, bool)
                or not isinstance(byte_length, int)
                or byte_length <= 0
                or raw["etag"] != f'"{digest}"'
            ):
                raise ArtifactDeliveryError("delivery object reference identity drifted")
            references.append(
                DeliveryObjectRef(
                    result_id=result_id,
                    kind=kind,
                    key=raw["key"],
                    public_path=raw["publicPath"],
                    media_type=raw["mediaType"],
                    sha256=digest,
                    byte_length=byte_length,
                    etag=raw["etag"],
                )
            )
        expected_paths = [
            f"/r/{result_id}",
            *(reference.public_path for reference in references),
        ]
        if value.get("publicPaths") != expected_paths:
            raise ArtifactDeliveryError("delivery public path registry drifted")
        return tuple(references)

    def _entry_batch(
        self,
        value: dict[str, Any],
        *,
        expected_state: DeliveryState,
    ) -> DeliveryBatch:
        self._basic_entry(value, expected_state=expected_state)
        result_id = value["resultId"]
        references = self._references(value)
        payload_by_kind: dict[DeliveryKind, bytes] = {}
        for reference in references:
            maximum = MAX_BUNDLE_BYTES if reference.kind == "bundle" else 8_000_000
            payload = self._read_bytes(
                self._object_path(result_id, reference.kind),
                maximum=maximum,
            )
            if (
                len(payload) != reference.byte_length
                or hashlib.sha256(payload).hexdigest() != reference.sha256
            ):
                raise ArtifactDeliveryError("delivery object failed its content identity check")
            payload_by_kind[reference.kind] = payload
        try:
            bundle = json.loads(payload_by_kind["bundle"])
        except (UnicodeError, json.JSONDecodeError, KeyError) as error:
            raise ArtifactDeliveryError("delivered bundle is unreadable") from error
        if not isinstance(bundle, dict) or stable_json_bytes(bundle) != payload_by_kind["bundle"]:
            raise ArtifactDeliveryError("delivered bundle is not canonical")
        batch = build_delivery_batch(
            bundle,
            {kind: payload for kind, payload in payload_by_kind.items() if kind != "bundle"},
        )
        if (
            batch.result_id != result_id
            or batch.publication_sha256 != value["publicationSha256"]
            or [_ref_value(reference) for reference, _payload in batch.objects] != value["objects"]
            or list(batch.public_paths) != value["publicPaths"]
        ):
            raise ArtifactDeliveryError("delivery control record failed reconstruction")
        return batch

    def _receipt(
        self,
        value: dict[str, Any],
        *,
        expected_result_id: str,
    ) -> PurgeReceipt:
        raw = value.get("purgeReceipt")
        if not isinstance(raw, dict) or set(raw) != {
            "receiptVersion",
            "operationId",
            "providerTargetId",
            "providerRequestId",
            "confirmedAt",
            "coverageSha256",
            "publicPaths",
            "purgeRequired",
        }:
            raise ArtifactDeliveryError("delivery purge receipt is malformed")
        operation_id = raw["operationId"]
        target_id = raw["providerTargetId"]
        provider_id = raw["providerRequestId"]
        paths = raw["publicPaths"]
        references = self._references(value)
        coverage = purge_coverage_sha256(
            expected_result_id,
            tuple(value["publicPaths"]),
            references,
        )
        if (
            raw["receiptVersion"] != PURGE_RECEIPT_VERSION
            or operation_id != value["purgeOperationId"]
            or not isinstance(operation_id, str)
            or PURGE_ID_PATTERN.fullmatch(operation_id) is None
            or (
                provider_id is not None
                and (
                    not isinstance(provider_id, str)
                    or not 1 <= len(provider_id) <= 256
                    or any(ord(character) < 0x20 for character in provider_id)
                )
            )
            or not isinstance(paths, list)
            or paths != value["publicPaths"]
            or raw["coverageSha256"] != coverage
            or raw["purgeRequired"] is not self._cache_policy.purge_required
            or target_id != value["purgeTargetId"]
            or (
                self._cache_policy.purge_required
                and (target_id != self._purge_target_id or provider_id is None)
            )
            or (not self._cache_policy.purge_required and target_id is not None)
        ):
            raise ArtifactDeliveryError("delivery purge receipt identity drifted")
        confirmed_at = _parse_timestamp(raw["confirmedAt"], "purge confirmation time")
        return PurgeReceipt(
            result_id=expected_result_id,
            operation_id=operation_id,
            provider_target_id=target_id,
            provider_request_id=provider_id,
            confirmed_at=confirmed_at,
            coverage_sha256=coverage,
            public_paths=tuple(paths),
            cache_control=self._cache_policy.value,
            purge_required=self._cache_policy.purge_required,
        )

    def _remove_objects(self, result_id: str) -> None:
        for kind in DELIVERY_KINDS:
            self._object_path(result_id, kind).unlink(missing_ok=True)
        self._fsync(self._directories["objects"])

    def _remove_stages_for(self, result_id: str) -> None:
        for path in self._directories["stages"].glob("s_*.json"):
            try:
                value = self._read_json(path)
            except ArtifactDeliveryError:
                continue
            if value.get("resultId") == result_id:
                path.unlink(missing_ok=True)
        self._fsync(self._directories["stages"])

    def _recover(self) -> None:
        with self._lock:
            for directory in self._directories.values():
                for path in directory.glob(".staging-*"):
                    if path.is_file() and not path.is_symlink():
                        path.unlink()
            retired_ids: set[str] = set()
            for path in self._directories["retired"].glob("r_*.json"):
                value = self._read_json(path)
                self._basic_entry(value, expected_state="retired")
                result_id = value["resultId"]
                if path.name != f"{result_id}.json":
                    raise ArtifactDeliveryError("retired delivery filename drifted")
                retired_ids.add(result_id)
                self._state_path("live", result_id).unlink(missing_ok=True)
                self._state_path("retiring", result_id).unlink(missing_ok=True)
                self._remove_stages_for(result_id)
                self._remove_objects(result_id)
            referenced: set[Path] = set()
            for state in ("staged", "live", "retiring"):
                directory = self._directories["stages" if state == "staged" else state]
                for path in directory.glob("*.json"):
                    value = self._read_json(path)
                    batch = self._entry_batch(value, expected_state=state)  # type: ignore[arg-type]
                    if batch.result_id in retired_ids:
                        raise ArtifactDeliveryError("retired delivery remained active")
                    if state == "staged" and path.name != f"s_{batch.publication_sha256}.json":
                        raise ArtifactDeliveryError("delivery stage filename drifted")
                    if state != "staged" and path.name != f"{batch.result_id}.json":
                        raise ArtifactDeliveryError("delivery state filename drifted")
                    referenced.update(
                        self._object_path(batch.result_id, reference.kind)
                        for reference, _payload in batch.objects
                    )
            for path in self._directories["objects"].iterdir():
                if path.name.startswith(".staging-"):
                    continue
                if path not in referenced:
                    if path.is_symlink() or not path.is_file():
                        raise ArtifactDeliveryError("orphan delivery object is not regular")
                    path.unlink()
            for directory in self._directories.values():
                self._fsync(directory)

    def stage(
        self,
        bundle: dict[str, Any],
        artifacts: Mapping[str, bytes] | None = None,
    ) -> DeliveryStage:
        batch = build_delivery_batch(bundle, artifacts)
        stage_id = f"s_{batch.publication_sha256}"
        stage_path = self._stage_path(stage_id)
        with self._lock:
            if self._state_path("retired", batch.result_id).exists():
                raise ArtifactDeliveryError("retired delivery result ID cannot be reused")
            if self._state_path("retiring", batch.result_id).exists():
                raise ArtifactDeliveryError("retiring delivery result cannot be restaged")
            live_path = self._state_path("live", batch.result_id)
            if live_path.exists():
                live = self._entry_batch(self._read_json(live_path), expected_state="live")
                if live.publication_sha256 != batch.publication_sha256:
                    raise ArtifactDeliveryError("immutable live delivery collision")
                return DeliveryStage(
                    stage_id=stage_id,
                    result_id=batch.result_id,
                    publication_sha256=batch.publication_sha256,
                    created=False,
                    already_live=True,
                )
            created_objects: list[Path] = []
            try:
                for reference, payload in batch.objects:
                    path = self._object_path(batch.result_id, reference.kind)
                    if self._write_once(path, payload):
                        created_objects.append(path)
                created_at = self._now()
                created = self._write_entry(
                    stage_path,
                    self._entry(batch, state="staged", created_at=created_at),
                )
            except Exception:
                if not stage_path.exists():
                    for path in created_objects:
                        path.unlink(missing_ok=True)
                    self._fsync(self._directories["objects"])
                raise
            return DeliveryStage(
                stage_id=stage_id,
                result_id=batch.result_id,
                publication_sha256=batch.publication_sha256,
                created=created,
                already_live=False,
            )

    def activate(self, stage: DeliveryStage) -> DeliveryPublication:
        if (
            not isinstance(stage, DeliveryStage)
            or STAGE_ID_PATTERN.fullmatch(stage.stage_id) is None
            or stage.stage_id != f"s_{stage.publication_sha256}"
            or _validate_result_id(stage.result_id) != stage.result_id
        ):
            raise ValueError("invalid delivery stage")
        with self._lock:
            if self._state_path("retired", stage.result_id).exists():
                raise ArtifactDeliveryError("retired delivery cannot be activated")
            if self._state_path("retiring", stage.result_id).exists():
                raise ArtifactDeliveryError("retiring delivery cannot be activated")
            live_path = self._state_path("live", stage.result_id)
            if live_path.exists():
                live_value = self._read_json(live_path)
                batch = self._entry_batch(live_value, expected_state="live")
                if batch.publication_sha256 != stage.publication_sha256:
                    raise ArtifactDeliveryError("immutable delivery activation collision")
                return self._publication(live_value, batch, created=False)
            stage_path = self._stage_path(stage.stage_id)
            if not stage_path.exists():
                raise ArtifactDeliveryError("delivery stage does not exist")
            staged_value = self._read_json(stage_path)
            batch = self._entry_batch(staged_value, expected_state="staged")
            if (
                batch.result_id != stage.result_id
                or batch.publication_sha256 != stage.publication_sha256
            ):
                raise ArtifactDeliveryError("delivery stage identity drifted")
            activated = self._now()
            live_value = self._entry(
                batch,
                state="live",
                created_at=staged_value["createdAt"],
                activated_at=activated,
            )
            self._write_entry(live_path, live_value)
            stage_path.unlink(missing_ok=True)
            self._fsync(self._directories["stages"])
            return self._publication(live_value, batch, created=True)

    def _publication(
        self,
        value: dict[str, Any],
        batch: DeliveryBatch,
        *,
        created: bool,
    ) -> DeliveryPublication:
        return DeliveryPublication(
            result_id=batch.result_id,
            publication_sha256=batch.publication_sha256,
            objects=tuple(reference for reference, _payload in batch.objects),
            public_paths=batch.public_paths,
            cache_control=self._cache_policy.value,
            activated_at=_parse_timestamp(value["activatedAt"], "activation time"),
            created=created,
        )

    def abort(self, stage: DeliveryStage) -> bool:
        if not isinstance(stage, DeliveryStage):
            raise ValueError("invalid delivery stage")
        stage_path = self._stage_path(stage.stage_id)
        with self._lock:
            if self._state_path("live", stage.result_id).exists():
                return False
            if not stage_path.exists():
                return False
            value = self._read_json(stage_path)
            batch = self._entry_batch(value, expected_state="staged")
            if (
                batch.result_id != stage.result_id
                or batch.publication_sha256 != stage.publication_sha256
            ):
                raise ArtifactDeliveryError("delivery abort stage identity drifted")
            stage_path.unlink()
            self._remove_objects(stage.result_id)
            self._fsync(self._directories["stages"])
            return True

    def get(self, result_id: str, kind: DeliveryKind) -> DeliveredObject | None:
        result_id = _validate_result_id(result_id)
        kind = _validate_kind(kind)
        with self._lock:
            if (
                self._state_path("retired", result_id).exists()
                or self._state_path("retiring", result_id).exists()
            ):
                return None
            live_path = self._state_path("live", result_id)
            if not live_path.exists():
                return None
            value = self._read_json(live_path)
            batch = self._entry_batch(value, expected_state="live")
            for reference, payload in batch.objects:
                if reference.kind == kind:
                    return DeliveredObject(
                        **reference.__dict__,
                        payload=payload,
                        cache_control=self._cache_policy.value,
                    )
            return None

    def _retiring_entry(self, result_id: str) -> dict[str, Any] | None:
        path = self._state_path("retiring", result_id)
        if not path.exists():
            return None
        value = self._read_json(path)
        self._entry_batch(value, expected_state="retiring")
        return value

    def retire(self, result_id: str) -> PurgeReceipt | None:
        result_id = _validate_result_id(result_id)
        with self._lock:
            retired_path = self._state_path("retired", result_id)
            if retired_path.exists():
                value = self._read_json(retired_path)
                self._basic_entry(value, expected_state="retired")
                return self._receipt(value, expected_result_id=result_id)
            value = self._retiring_entry(result_id)
            if value is None:
                live_path = self._state_path("live", result_id)
                if not live_path.exists():
                    return None
                live_value = self._read_json(live_path)
                batch = self._entry_batch(live_value, expected_state="live")
                value = self._entry(
                    batch,
                    state="retiring",
                    created_at=live_value["createdAt"],
                    activated_at=live_value["activatedAt"],
                    retired_at=self._now(),
                    purge_operation_id=f"p_{secrets.token_hex(16)}",
                    purge_target_id=self._purge_target_id,
                )
                self._write_entry(self._state_path("retiring", result_id), value)
                live_path.unlink()
                self._fsync(self._directories["live"])
            batch = self._entry_batch(value, expected_state="retiring")
            operation_id = value["purgeOperationId"]
            purge_target_id = value["purgeTargetId"]

        objects = tuple(reference for reference, _payload in batch.objects)
        coverage_sha256 = purge_coverage_sha256(
            result_id,
            batch.public_paths,
            objects,
        )
        if self._cache_policy.purge_required:
            assert self._purger is not None
            try:
                result = self._purger.purge(
                    operation_id=operation_id,
                    result_id=result_id,
                    public_paths=batch.public_paths,
                    objects=objects,
                )
            except Exception as error:
                raise PurgePendingError(
                    result_id,
                    operation_id,
                    "delivery origin is fenced but cache purge failed",
                ) from error
            if (
                result.operation_id != operation_id
                or result.coverage_sha256 != coverage_sha256
                or result.provider_target_id != purge_target_id
                or result.state != "confirmed"
            ):
                raise PurgePendingError(
                    result_id,
                    operation_id,
                    "delivery origin is fenced but cache purge is pending",
                )
            provider_request_id = result.provider_request_id
            assert result.confirmed_at is not None
            confirmed_at = _parse_timestamp(
                result.confirmed_at,
                "provider purge confirmation time",
            )
        else:
            purge_target_id = None
            provider_request_id = None
            confirmed_at = self._now()

        receipt_value: dict[str, object] = {
            "receiptVersion": PURGE_RECEIPT_VERSION,
            "operationId": operation_id,
            "providerTargetId": purge_target_id,
            "providerRequestId": provider_request_id,
            "confirmedAt": confirmed_at,
            "coverageSha256": coverage_sha256,
            "publicPaths": list(batch.public_paths),
            "purgeRequired": self._cache_policy.purge_required,
        }
        with self._lock:
            current = self._retiring_entry(result_id)
            if current is None:
                retired_path = self._state_path("retired", result_id)
                if retired_path.exists():
                    retired_value = self._read_json(retired_path)
                    self._basic_entry(retired_value, expected_state="retired")
                    receipt = self._receipt(
                        retired_value,
                        expected_result_id=result_id,
                    )
                    if receipt.operation_id == operation_id:
                        return receipt
                raise ArtifactDeliveryError("retiring delivery changed during purge")
            if current["purgeOperationId"] != operation_id:
                raise ArtifactDeliveryError("retiring delivery changed during purge")
            retired_value = self._entry(
                batch,
                state="retired",
                created_at=current["createdAt"],
                activated_at=current["activatedAt"],
                retired_at=current["retiredAt"],
                purge_operation_id=operation_id,
                purge_target_id=purge_target_id,
                purge_receipt=receipt_value,
            )
            self._write_entry(self._state_path("retired", result_id), retired_value)
            self._state_path("live", result_id).unlink(missing_ok=True)
            self._state_path("retiring", result_id).unlink(missing_ok=True)
            self._remove_stages_for(result_id)
            self._remove_objects(result_id)
            self._fsync(self._directories["retiring"])
            return self._receipt(retired_value, expected_result_id=result_id)

    def retry_pending(self, result_id: str) -> PurgeReceipt | None:
        return self.retire(result_id)

    def pending_result_ids(self) -> tuple[str, ...]:
        with self._lock:
            result_ids: list[str] = []
            for path in self._directories["retiring"].glob("r_*.json"):
                value = self._read_json(path)
                self._entry_batch(value, expected_state="retiring")
                result_ids.append(value["resultId"])
            return tuple(sorted(result_ids))
