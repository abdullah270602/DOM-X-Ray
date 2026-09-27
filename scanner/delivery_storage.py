"""Provider-neutral private-object primitives for result delivery."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Protocol

from scanner.artifact_delivery import DeliveryObjectRef


RESULT_ID_PATTERN = re.compile(r"^r_[0-9a-f]{32}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
OBJECT_FILENAMES = {
    "bundle": "bundle.json",
    "poster": "poster.png",
    "video": "video.mp4",
}
MEDIA_TYPES = {
    "bundle": "application/json; charset=utf-8",
    "poster": "image/png",
    "video": "video/mp4",
}
MAX_OBJECT_BYTES = {
    "bundle": 8 * 1024 * 1024,
    "poster": 5_000_000,
    "video": 8_000_000,
}


class PrivateObjectStoreError(RuntimeError):
    """Raised when a private-object operation fails within the provider boundary."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "provider-invalid",
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class ImmutableObjectCollisionError(PrivateObjectStoreError):
    """Raised when an existing provider key has a different immutable identity."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="immutable-collision")


class PrivateObjectMissingError(PrivateObjectStoreError):
    """Raised when a registered immutable object is no longer present."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="object-missing")


def _visible_ascii(value: object, label: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ValueError(f"invalid private-object {label}")
    return value


def validate_object_reference(reference: DeliveryObjectRef) -> DeliveryObjectRef:
    if not isinstance(reference, DeliveryObjectRef):
        raise ValueError("private object requires a delivery reference")
    if RESULT_ID_PATTERN.fullmatch(reference.result_id) is None:
        raise ValueError("private object has an invalid result ID")
    if reference.kind not in OBJECT_FILENAMES:
        raise ValueError("private object has an invalid kind")
    filename = OBJECT_FILENAMES[reference.kind]
    expected_path = (
        f"/api/results/{reference.result_id}"
        if reference.kind == "bundle"
        else f"/api/results/{reference.result_id}/{filename}"
    )
    if (
        reference.key != f"v1/results/{reference.result_id}/{filename}"
        or reference.public_path != expected_path
        or reference.media_type != MEDIA_TYPES[reference.kind]
        or SHA256_PATTERN.fullmatch(reference.sha256) is None
        or isinstance(reference.byte_length, bool)
        or not isinstance(reference.byte_length, int)
        or not 0 < reference.byte_length <= MAX_OBJECT_BYTES[reference.kind]
        or reference.etag != f'"{reference.sha256}"'
    ):
        raise ValueError("private object reference identity drifted")
    return reference


def validate_object_payload(reference: DeliveryObjectRef, payload: bytes) -> bytes:
    validate_object_reference(reference)
    if not isinstance(payload, bytes):
        raise ValueError("private object payload must be bytes")
    if (
        len(payload) != reference.byte_length
        or hashlib.sha256(payload).hexdigest() != reference.sha256
    ):
        raise ValueError("private object payload does not match its reference")
    return payload


@dataclass(frozen=True)
class PrivateObjectVersion:
    reference: DeliveryObjectRef
    provider_target_id: str
    provider_version_id: str
    created: bool

    def __post_init__(self) -> None:
        validate_object_reference(self.reference)
        _visible_ascii(self.provider_target_id, "provider target ID")
        _visible_ascii(self.provider_version_id, "provider version ID", maximum=1024)
        if not isinstance(self.created, bool):
            raise ValueError("private object created flag must be boolean")


class PrivateObjectStore(Protocol):
    @property
    def provider_target_id(self) -> str: ...

    def put(
        self,
        reference: DeliveryObjectRef,
        payload: bytes,
    ) -> PrivateObjectVersion: ...

    def get(self, version: PrivateObjectVersion) -> bytes: ...

    def delete(self, version: PrivateObjectVersion) -> None: ...
