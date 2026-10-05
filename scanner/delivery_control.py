"""Provider-neutral durable control records for result delivery."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Sequence

from scanner.api_contract import stable_json_bytes
from scanner.artifact_delivery import (
    DELIVERY_KINDS,
    DELIVERY_VERSION,
    DeliveryBatch,
    DeliveryCachePolicy,
    DeliveryObjectRef,
    purge_coverage_sha256,
)
from scanner.delivery_storage import (
    PrivateObjectVersion,
    validate_object_reference,
)


LEGACY_CONTROL_VERSION = "result-control-v0.1.0"
CONTROL_VERSION = "result-control-v0.2.0"
RESULT_ID_PATTERN = re.compile(r"^r_[0-9a-f]{32}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_PATTERN = re.compile(r"^[0-9a-f]{16}$")
PURGE_ID_PATTERN = re.compile(r"^p_[0-9a-f]{32}$")

ControlState = Literal["staged", "live", "retiring", "retired", "abandoned"]
PurgeState = Literal["pending", "confirmed"]
CleanupState = Literal["pending", "complete"]


class DeliveryControlError(RuntimeError):
    """Raised when a durable control record violates its lifecycle contract."""


def _visible_ascii(value: object, label: str, *, maximum: int = 1024) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ValueError(f"invalid control {label}")
    return value


def canonical_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"control {label} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"control {label} is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError(f"control {label} has no timezone")
    canonical = parsed.astimezone(UTC).isoformat(timespec="milliseconds").replace(
        "+00:00",
        "Z",
    )
    if value != canonical:
        raise ValueError(f"control {label} is not canonical")
    return canonical


def timestamp_epoch_ms(value: object, label: str) -> int:
    canonical = canonical_timestamp(value, label)
    parsed = datetime.fromisoformat(canonical.replace("Z", "+00:00"))
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    if parsed < epoch:
        raise ValueError(f"control {label} predates the Unix epoch")
    delta = parsed - epoch
    return (
        delta.days * 86_400_000
        + delta.seconds * 1_000
        + delta.microseconds // 1_000
    )


def _cache_policy(value: object) -> DeliveryCachePolicy:
    if not isinstance(value, str):
        raise ValueError("control cache policy is invalid")
    return DeliveryCachePolicy(
        value=value,
        purge_required=value != "no-store",
    )


def _reference_value(reference: DeliveryObjectRef) -> dict[str, object]:
    return {
        "kind": reference.kind,
        "key": reference.key,
        "publicPath": reference.public_path,
        "mediaType": reference.media_type,
        "sha256": reference.sha256,
        "byteLength": reference.byte_length,
        "etag": reference.etag,
    }


@dataclass(frozen=True)
class RegisteredDeliveryObject:
    reference: DeliveryObjectRef
    provider_target_id: str
    provider_version_id: str

    def __post_init__(self) -> None:
        validate_object_reference(self.reference)
        _visible_ascii(self.provider_target_id, "object provider target", maximum=256)
        _visible_ascii(self.provider_version_id, "object provider version")


def object_registry_sha256(objects: Sequence[RegisteredDeliveryObject]) -> str:
    return hashlib.sha256(
        stable_json_bytes(
            [
                {
                    **_reference_value(item.reference),
                    "providerTargetId": item.provider_target_id,
                    "providerVersionId": item.provider_version_id,
                }
                for item in objects
            ]
        )
    ).hexdigest()


def _publication_sha256(
    result_id: str,
    objects: Sequence[RegisteredDeliveryObject],
    public_paths: Sequence[str],
) -> str:
    return hashlib.sha256(
        stable_json_bytes(
            {
                "deliveryVersion": DELIVERY_VERSION,
                "resultId": result_id,
                "objects": [_reference_value(item.reference) for item in objects],
                "publicPaths": list(public_paths),
            }
        )
    ).hexdigest()


def _identity_sha256(
    *,
    result_id: str,
    publication_sha256: str,
    objects_sha256: str,
    bundle_sha256: str,
    published_at: str,
    expires_at: str | None,
    expires_at_epoch_ms: int | None,
    deletion_key_id: str,
    deletion_digest_hmac_sha256: str,
    cache_control: str,
    public_paths: Sequence[str],
    staging_expires_at: str | None = None,
    staging_expires_at_epoch_ms: int | None = None,
    control_version: str = CONTROL_VERSION,
) -> str:
    identity = {
        "controlVersion": control_version,
        "resultId": result_id,
        "publicationSha256": publication_sha256,
        "objectsSha256": objects_sha256,
        "bundleSha256": bundle_sha256,
        "publishedAt": published_at,
        "expiresAt": expires_at,
        "expiresAtEpochMs": expires_at_epoch_ms,
        "deletionKeyId": deletion_key_id,
        "deletionDigestHmacSha256": deletion_digest_hmac_sha256,
        "cacheControl": cache_control,
        "publicPaths": list(public_paths),
    }
    # Preserve the v0.1.0 identity encoding for historical records which predate
    # staging deadlines. New records bind the deadline into their identity.
    if staging_expires_at is not None:
        identity["stagingExpiresAt"] = staging_expires_at
        identity["stagingExpiresAtEpochMs"] = staging_expires_at_epoch_ms
    return hashlib.sha256(
        stable_json_bytes(identity)
    ).hexdigest()


@dataclass(frozen=True)
class RetirementPlan:
    result_id: str
    operation_id: str
    coverage_sha256: str
    purge_required: bool
    provider_target_id: str | None

    def __post_init__(self) -> None:
        if RESULT_ID_PATTERN.fullmatch(self.result_id) is None:
            raise ValueError("retirement plan has an invalid result ID")
        if PURGE_ID_PATTERN.fullmatch(self.operation_id) is None:
            raise ValueError("retirement plan has an invalid operation ID")
        if SHA256_PATTERN.fullmatch(self.coverage_sha256) is None:
            raise ValueError("retirement plan has an invalid coverage digest")
        if not isinstance(self.purge_required, bool):
            raise ValueError("retirement plan purge flag must be boolean")
        if self.purge_required:
            _visible_ascii(self.provider_target_id, "purge provider target", maximum=256)
        elif self.provider_target_id is not None:
            raise ValueError("no-purge retirement cannot bind a provider target")


@dataclass(frozen=True)
class ResultControlRecord:
    result_id: str
    state: ControlState
    revision: int
    publication_sha256: str
    objects_sha256: str
    control_identity_sha256: str
    bundle_sha256: str
    published_at: str
    expires_at: str | None
    expires_at_epoch_ms: int | None
    deletion_key_id: str
    deletion_digest_hmac_sha256: str
    cache_control: str
    objects: tuple[RegisteredDeliveryObject, ...]
    public_paths: tuple[str, ...]
    staging_expires_at: str | None = None
    staging_expires_at_epoch_ms: int | None = None
    activated_at: str | None = None
    retired_at: str | None = None
    purge_operation_id: str | None = None
    purge_coverage_sha256: str | None = None
    purge_required: bool | None = None
    purge_provider_target_id: str | None = None
    purge_state: PurgeState | None = None
    purge_provider_request_id: str | None = None
    purge_confirmed_at: str | None = None
    cleanup_state: CleanupState | None = None
    abandoned_at: str | None = None
    control_version: str = CONTROL_VERSION

    def __post_init__(self) -> None:
        if self.control_version not in {CONTROL_VERSION, LEGACY_CONTROL_VERSION}:
            raise ValueError("control record has an invalid version")
        if self.control_version == LEGACY_CONTROL_VERSION:
            if self.staging_expires_at is not None or self.staging_expires_at_epoch_ms is not None or self.state == "abandoned":
                raise ValueError("legacy control record has new lifecycle fields")
        elif self.staging_expires_at is None:
            raise ValueError("control record lacks its immutable staging deadline")
        if RESULT_ID_PATTERN.fullmatch(self.result_id) is None:
            raise ValueError("control record has an invalid result ID")
        if self.state not in {"staged", "live", "retiring", "retired", "abandoned"}:
            raise ValueError("control record has an invalid state")
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 0
        ):
            raise ValueError("control record has an invalid revision")
        for value, label in (
            (self.publication_sha256, "publication digest"),
            (self.objects_sha256, "object-registry digest"),
            (self.control_identity_sha256, "identity digest"),
            (self.bundle_sha256, "bundle digest"),
            (self.deletion_digest_hmac_sha256, "deletion HMAC"),
        ):
            if SHA256_PATTERN.fullmatch(value) is None:
                raise ValueError(f"control record has an invalid {label}")
        if KEY_ID_PATTERN.fullmatch(self.deletion_key_id) is None:
            raise ValueError("control record has an invalid deletion key ID")
        canonical_timestamp(self.published_at, "publication time")
        parsed_publication = datetime.fromisoformat(
            self.published_at.replace("Z", "+00:00")
        )
        if (self.expires_at is None) != (self.expires_at_epoch_ms is None):
            raise ValueError("control expiry fields are incomplete")
        if self.expires_at is not None:
            canonical_timestamp(self.expires_at, "expiry time")
            parsed_expiry = datetime.fromisoformat(
                self.expires_at.replace("Z", "+00:00")
            )
            if (
                isinstance(self.expires_at_epoch_ms, bool)
                or not isinstance(self.expires_at_epoch_ms, int)
                or self.expires_at_epoch_ms
                != timestamp_epoch_ms(self.expires_at, "expiry time")
                or parsed_expiry <= parsed_publication
            ):
                raise ValueError("control expiry epoch is invalid")
        if (self.staging_expires_at is None) != (self.staging_expires_at_epoch_ms is None):
            raise ValueError("control staging expiry fields are incomplete")
        parsed_staging_expiry = None
        if self.staging_expires_at is not None:
            canonical_timestamp(self.staging_expires_at, "staging expiry time")
            parsed_staging_expiry = datetime.fromisoformat(
                self.staging_expires_at.replace("Z", "+00:00")
            )
            if (
                isinstance(self.staging_expires_at_epoch_ms, bool)
                or not isinstance(self.staging_expires_at_epoch_ms, int)
                or self.staging_expires_at_epoch_ms
                != timestamp_epoch_ms(self.staging_expires_at, "staging expiry time")
                or parsed_staging_expiry <= parsed_publication
                or (self.expires_at is not None and parsed_staging_expiry > parsed_expiry)
            ):
                raise ValueError("control staging expiry is invalid")
        policy = _cache_policy(self.cache_control)
        if not isinstance(self.objects, tuple) or not 1 <= len(self.objects) <= 3:
            raise ValueError("control object registry is invalid")
        if any(not isinstance(item, RegisteredDeliveryObject) for item in self.objects):
            raise ValueError("control object registry entry is invalid")
        kinds = tuple(item.reference.kind for item in self.objects)
        expected_kinds = tuple(kind for kind in DELIVERY_KINDS if kind in kinds)
        if kinds != expected_kinds or kinds[0] != "bundle" or len(set(kinds)) != len(kinds):
            raise ValueError("control object registry order is invalid")
        for item in self.objects:
            if item.reference.result_id != self.result_id:
                raise ValueError("control object belongs to a different result")
        if len({item.provider_target_id for item in self.objects}) != 1:
            raise ValueError("control objects span provider targets")
        expected_paths = (
            f"/r/{self.result_id}",
            *(item.reference.public_path for item in self.objects),
        )
        if self.public_paths != expected_paths or len(set(self.public_paths)) != len(
            self.public_paths
        ):
            raise ValueError("control public paths drifted")
        if self.bundle_sha256 != self.objects[0].reference.sha256:
            raise ValueError("control bundle digest drifted")
        if self.publication_sha256 != _publication_sha256(
            self.result_id,
            self.objects,
            self.public_paths,
        ):
            raise ValueError("control publication digest drifted")
        if self.objects_sha256 != object_registry_sha256(self.objects):
            raise ValueError("control object-registry digest drifted")
        if self.control_identity_sha256 != _identity_sha256(
            result_id=self.result_id,
            publication_sha256=self.publication_sha256,
            objects_sha256=self.objects_sha256,
            bundle_sha256=self.bundle_sha256,
            published_at=self.published_at,
            expires_at=self.expires_at,
            expires_at_epoch_ms=self.expires_at_epoch_ms,
            deletion_key_id=self.deletion_key_id,
            deletion_digest_hmac_sha256=self.deletion_digest_hmac_sha256,
            cache_control=self.cache_control,
            public_paths=self.public_paths,
            staging_expires_at=self.staging_expires_at,
            staging_expires_at_epoch_ms=self.staging_expires_at_epoch_ms,
            control_version=self.control_version,
        ):
            raise ValueError("control identity digest drifted")

        retirement_values = (
            self.retired_at,
            self.purge_operation_id,
            self.purge_coverage_sha256,
            self.purge_required,
            self.purge_provider_target_id,
            self.purge_state,
            self.purge_provider_request_id,
            self.purge_confirmed_at,
            self.cleanup_state,
        )
        if self.state == "staged":
            if self.revision != 0 or self.activated_at is not None or self.abandoned_at is not None or any(
                value is not None for value in retirement_values
            ):
                raise ValueError("staged control record has lifecycle evidence")
            return
        if self.state == "abandoned":
            if (
                self.revision < 1
                or self.activated_at is not None
                or self.retired_at is not None
                or self.purge_operation_id is not None
                or self.purge_coverage_sha256 is not None
                or self.purge_required is not None
                or self.purge_provider_target_id is not None
                or self.purge_state is not None
                or self.purge_provider_request_id is not None
                or self.purge_confirmed_at is not None
                or self.cleanup_state not in {"pending", "complete"}
                or self.staging_expires_at is None
                or self.abandoned_at is None
            ):
                raise ValueError("abandoned control record has invalid lifecycle evidence")
            canonical_timestamp(self.abandoned_at, "abandonment time")
            if datetime.fromisoformat(self.abandoned_at.replace("Z", "+00:00")) < parsed_staging_expiry:
                raise ValueError("control abandonment precedes staging expiry")
            return
        if self.abandoned_at is not None:
            raise ValueError("non-abandoned control record has abandonment time")
        if self.activated_at is None:
            raise ValueError("active control record lacks activation time")
        canonical_timestamp(self.activated_at, "activation time")
        parsed_activation = datetime.fromisoformat(
            self.activated_at.replace("Z", "+00:00")
        )
        if parsed_activation < parsed_publication:
            raise ValueError("control activation precedes publication")
        if parsed_staging_expiry is not None and parsed_activation >= parsed_staging_expiry:
            raise ValueError("control activation does not precede staging expiry")
        if self.expires_at is not None:
            parsed_expiry = datetime.fromisoformat(
                self.expires_at.replace("Z", "+00:00")
            )
            if parsed_activation >= parsed_expiry:
                raise ValueError("control activation does not precede expiry")
        if self.state == "live":
            if self.revision < 1 or any(value is not None for value in retirement_values):
                raise ValueError("live control record has invalid lifecycle evidence")
            return
        if self.revision < 2 or self.retired_at is None:
            raise ValueError("retiring control record lacks retirement evidence")
        canonical_timestamp(self.retired_at, "retirement time")
        parsed_retirement = datetime.fromisoformat(
            self.retired_at.replace("Z", "+00:00")
        )
        if parsed_retirement < parsed_activation:
            raise ValueError("control retirement precedes activation")
        if (
            self.purge_operation_id is None
            or PURGE_ID_PATTERN.fullmatch(self.purge_operation_id) is None
            or self.purge_coverage_sha256 is None
            or SHA256_PATTERN.fullmatch(self.purge_coverage_sha256) is None
            or not isinstance(self.purge_required, bool)
            or self.purge_required != policy.purge_required
            or self.purge_state not in {"pending", "confirmed"}
            or self.cleanup_state not in {"pending", "complete"}
        ):
            raise ValueError("control retirement binding is invalid")
        expected_coverage = purge_coverage_sha256(
            self.result_id,
            self.public_paths,
            tuple(item.reference for item in self.objects),
        )
        if self.purge_coverage_sha256 != expected_coverage:
            raise ValueError("control purge coverage drifted")
        if self.purge_required:
            _visible_ascii(
                self.purge_provider_target_id,
                "purge provider target",
                maximum=256,
            )
            if self.purge_state == "confirmed":
                _visible_ascii(
                    self.purge_provider_request_id,
                    "purge provider request",
                    maximum=256,
                )
                if self.purge_confirmed_at is None:
                    raise ValueError("confirmed purge lacks confirmation time")
                canonical_timestamp(self.purge_confirmed_at, "purge confirmation time")
                if datetime.fromisoformat(
                    self.purge_confirmed_at.replace("Z", "+00:00")
                ) < parsed_retirement:
                    raise ValueError("purge confirmation precedes retirement")
            elif self.purge_confirmed_at is not None:
                raise ValueError("pending purge has a confirmation time")
            elif self.purge_provider_request_id is not None:
                _visible_ascii(
                    self.purge_provider_request_id,
                    "purge provider request",
                    maximum=256,
                )
        elif (
            self.purge_provider_target_id is not None
            or self.purge_provider_request_id is not None
            or self.purge_state != "confirmed"
            or self.purge_confirmed_at is None
        ):
            raise ValueError("no-purge retirement has provider evidence")
        else:
            canonical_timestamp(self.purge_confirmed_at, "purge confirmation time")
            if datetime.fromisoformat(
                self.purge_confirmed_at.replace("Z", "+00:00")
            ) < parsed_retirement:
                raise ValueError("purge confirmation precedes retirement")
        if self.state == "retiring" and self.cleanup_state != "pending":
            raise ValueError("retiring control record has invalid cleanup state")
        if self.state == "retired":
            if self.revision < 3 or self.purge_state != "confirmed":
                raise ValueError("retired control record lacks confirmed purge evidence")

def build_staged_control(
    batch: DeliveryBatch,
    versions: Sequence[PrivateObjectVersion],
    *,
    published_at: str,
    expires_at: str | None,
    staging_expires_at: str,
    deletion_key_id: str,
    deletion_digest_hmac_sha256: str,
    cache_policy: DeliveryCachePolicy,
) -> ResultControlRecord:
    if not isinstance(batch, DeliveryBatch):
        raise ValueError("staged control requires a delivery batch")
    if not isinstance(cache_policy, DeliveryCachePolicy):
        raise ValueError("staged control requires a cache policy")
    if len(versions) != len(batch.objects):
        raise ValueError("staged control has an incomplete object registry")
    registered: list[RegisteredDeliveryObject] = []
    for (reference, _payload), version in zip(batch.objects, versions, strict=True):
        if not isinstance(version, PrivateObjectVersion) or version.reference != reference:
            raise ValueError("staged control object version drifted")
        registered.append(
            RegisteredDeliveryObject(
                reference=reference,
                provider_target_id=version.provider_target_id,
                provider_version_id=version.provider_version_id,
            )
        )
    canonical_timestamp(published_at, "publication time")
    expires_at_epoch_ms: int | None = None
    if expires_at is not None:
        expires_at_epoch_ms = timestamp_epoch_ms(expires_at, "expiry time")
    staging_expires_at_epoch_ms = timestamp_epoch_ms(staging_expires_at, "staging expiry time")
    objects = tuple(registered)
    objects_digest = object_registry_sha256(objects)
    bundle_sha256 = objects[0].reference.sha256
    identity_digest = _identity_sha256(
        result_id=batch.result_id,
        publication_sha256=batch.publication_sha256,
        objects_sha256=objects_digest,
        bundle_sha256=bundle_sha256,
        published_at=published_at,
        expires_at=expires_at,
        expires_at_epoch_ms=expires_at_epoch_ms,
        deletion_key_id=deletion_key_id,
        deletion_digest_hmac_sha256=deletion_digest_hmac_sha256,
        cache_control=cache_policy.value,
        public_paths=batch.public_paths,
        staging_expires_at=staging_expires_at,
        staging_expires_at_epoch_ms=staging_expires_at_epoch_ms,
    )
    return ResultControlRecord(
        result_id=batch.result_id,
        state="staged",
        revision=0,
        publication_sha256=batch.publication_sha256,
        objects_sha256=objects_digest,
        control_identity_sha256=identity_digest,
        bundle_sha256=bundle_sha256,
        published_at=published_at,
        expires_at=expires_at,
        expires_at_epoch_ms=expires_at_epoch_ms,
        staging_expires_at=staging_expires_at,
        staging_expires_at_epoch_ms=staging_expires_at_epoch_ms,
        deletion_key_id=deletion_key_id,
        deletion_digest_hmac_sha256=deletion_digest_hmac_sha256,
        cache_control=cache_policy.value,
        objects=objects,
        public_paths=batch.public_paths,
    )


def build_retirement_plan(
    record: ResultControlRecord,
    *,
    operation_id: str,
    provider_target_id: str | None,
) -> RetirementPlan:
    if record.state != "live":
        raise ValueError("retirement plan requires a live control record")
    policy = _cache_policy(record.cache_control)
    return RetirementPlan(
        result_id=record.result_id,
        operation_id=operation_id,
        coverage_sha256=purge_coverage_sha256(
            record.result_id,
            record.public_paths,
            tuple(item.reference for item in record.objects),
        ),
        purge_required=policy.purge_required,
        provider_target_id=provider_target_id,
    )


def retirement_plan_from_record(record: ResultControlRecord) -> RetirementPlan:
    if record.state not in {"retiring", "retired"}:
        raise ValueError("control record has no retirement plan")
    assert record.purge_operation_id is not None
    assert record.purge_coverage_sha256 is not None
    assert record.purge_required is not None
    return RetirementPlan(
        result_id=record.result_id,
        operation_id=record.purge_operation_id,
        coverage_sha256=record.purge_coverage_sha256,
        purge_required=record.purge_required,
        provider_target_id=record.purge_provider_target_id,
    )


__all__ = [
    "CONTROL_VERSION",
    "CleanupState",
    "ControlState",
    "DeliveryControlError",
    "PurgeState",
    "RegisteredDeliveryObject",
    "ResultControlRecord",
    "RetirementPlan",
    "build_retirement_plan",
    "build_staged_control",
    "canonical_timestamp",
    "object_registry_sha256",
    "retirement_plan_from_record",
    "timestamp_epoch_ms",
]
