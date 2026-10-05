"""Conditional DynamoDB control state for version-bound result delivery."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from scanner.api_contract import stable_json_bytes
from scanner.artifact_delivery import DeliveryObjectRef
from scanner.delivery_control import (
    CONTROL_VERSION,
    LEGACY_CONTROL_VERSION,
    RegisteredDeliveryObject,
    ResultControlRecord,
    RetirementPlan,
    build_retirement_plan,
    canonical_timestamp,
    retirement_plan_from_record,
    timestamp_epoch_ms,
)


TABLE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")
RESULT_ID_PATTERN = re.compile(r"^r_[0-9a-f]{32}$")
MAX_ENCODED_ITEM_BYTES = 350_000
DEFAULT_EXPIRY_INDEX = "GSI1"
EXPIRY_PARTITION = "LIVE_EXPIRY"
STAGED_EXPIRY_PARTITION = "STAGED_EXPIRY"
WORK_PARTITION = "DELIVERY_WORK"
TTL_DELETION_QUARANTINE_SECONDS = 60 * 60

TRANSIENT_CODES = {
    "InternalServerError",
    "LimitExceededException",
    "ProvisionedThroughputExceededException",
    "ReplicatedWriteConflictException",
    "RequestLimitExceeded",
    "ServiceUnavailable",
    "ThrottlingException",
    "TransactionConflictException",
}
DENIED_CODES = {
    "AccessDeniedException",
    "IncompleteSignatureException",
    "InvalidSignatureException",
    "MissingAuthenticationTokenException",
    "UnrecognizedClientException",
}
TRANSIENT_EXCEPTION_NAMES = {
    "ConnectTimeoutError",
    "ConnectionClosedError",
    "EndpointConnectionError",
    "ReadTimeoutError",
}


class DynamoDBClient(Protocol):
    def describe_table(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def describe_time_to_live(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def put_item(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def update_item(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def get_item(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def query(self, **kwargs: Any) -> Mapping[str, Any]: ...


class ControlStoreError(RuntimeError):
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


class ControlCollisionError(ControlStoreError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="immutable-collision")


class ControlMissingError(ControlStoreError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="control-missing")


class ControlConflictError(ControlStoreError):
    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message, code="conditional-conflict", retryable=retryable)


class ControlNotExpiredError(ControlStoreError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="not-expired")


def _error_identity(error: Exception) -> tuple[str | None, int | None]:
    response = getattr(error, "response", None)
    if not isinstance(response, Mapping):
        return None, None
    raw_error = response.get("Error")
    metadata = response.get("ResponseMetadata")
    code = raw_error.get("Code") if isinstance(raw_error, Mapping) else None
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    return (
        code if isinstance(code, str) else None,
        status if isinstance(status, int) and not isinstance(status, bool) else None,
    )


def _is_conditional(error: Exception) -> bool:
    code, _status = _error_identity(error)
    return code == "ConditionalCheckFailedException"


def _provider_failure(message: str, error: Exception) -> ControlStoreError:
    code, status = _error_identity(error)
    if code in DENIED_CODES or status in {401, 403}:
        return ControlStoreError(message, code="provider-denied")
    if (
        code in TRANSIENT_CODES
        or status in {408, 429}
        or status is not None
        and 500 <= status <= 599
        or type(error).__name__ in TRANSIENT_EXCEPTION_NAMES
        or isinstance(error, (ConnectionError, TimeoutError))
    ):
        return ControlStoreError(
            message,
            code="provider-transient",
            retryable=True,
        )
    return ControlStoreError(message)


def _validate_name(value: object, label: str) -> str:
    if not isinstance(value, str) or TABLE_NAME_PATTERN.fullmatch(value) is None:
        raise ValueError(f"invalid DynamoDB {label}")
    return value


def _validate_result_id(result_id: object) -> str:
    if not isinstance(result_id, str) or RESULT_ID_PATTERN.fullmatch(result_id) is None:
        raise ValueError("invalid control result ID")
    return result_id


def _validate_epoch(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"invalid DynamoDB {label}")
    return value


def _visible_ascii(value: object, label: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ValueError(f"invalid control {label}")
    return value


def _s(value: str) -> dict[str, str]:
    return {"S": value}


def _n(value: int) -> dict[str, str]:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("DynamoDB number must be an integer")
    return {"N": str(value)}


def _b(value: bool) -> dict[str, bool]:
    if not isinstance(value, bool):
        raise ValueError("DynamoDB boolean must be boolean")
    return {"BOOL": value}


def _av_string(value: object, label: str) -> str:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"S"}
        or not isinstance(value.get("S"), str)
    ):
        raise ControlStoreError(f"DynamoDB {label} is not a string")
    return value["S"]


def _av_int(value: object, label: str) -> int:
    if not isinstance(value, Mapping) or set(value) != {"N"}:
        raise ControlStoreError(f"DynamoDB {label} is not a number")
    raw = value.get("N")
    if not isinstance(raw, str) or re.fullmatch(r"0|[1-9][0-9]*", raw) is None:
        raise ControlStoreError(f"DynamoDB {label} is not a canonical integer")
    return int(raw)


def _av_bool(value: object, label: str) -> bool:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"BOOL"}
        or not isinstance(value.get("BOOL"), bool)
    ):
        raise ControlStoreError(f"DynamoDB {label} is not a boolean")
    return value["BOOL"]


def _av_list(value: object, label: str) -> list[object]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"L"}
        or not isinstance(value.get("L"), list)
    ):
        raise ControlStoreError(f"DynamoDB {label} is not a list")
    return value["L"]


def _av_map(value: object, label: str) -> Mapping[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"M"}
        or not isinstance(value.get("M"), Mapping)
    ):
        raise ControlStoreError(f"DynamoDB {label} is not a map")
    return value["M"]


def _key(result_id: str) -> dict[str, dict[str, str]]:
    result_id = _validate_result_id(result_id)
    return {"PK": _s(f"RESULT#{result_id}"), "SK": _s("CONTROL")}


def _encode_object(item: RegisteredDeliveryObject) -> dict[str, object]:
    reference = item.reference
    return {
        "M": {
            "kind": _s(reference.kind),
            "key": _s(reference.key),
            "publicPath": _s(reference.public_path),
            "mediaType": _s(reference.media_type),
            "sha256": _s(reference.sha256),
            "byteLength": _n(reference.byte_length),
            "etag": _s(reference.etag),
            "providerTargetId": _s(item.provider_target_id),
            "providerVersionId": _s(item.provider_version_id),
        }
    }


def _decode_registered_object(
    value: object,
    result_id: str,
) -> RegisteredDeliveryObject:
    item = _av_map(value, "object registry entry")
    required = {
        "kind",
        "key",
        "publicPath",
        "mediaType",
        "sha256",
        "byteLength",
        "etag",
        "providerTargetId",
        "providerVersionId",
    }
    if set(item) != required:
        raise ControlStoreError("DynamoDB object registry entry has an invalid shape")
    reference = DeliveryObjectRef(
        result_id=result_id,
        kind=_av_string(item["kind"], "object kind"),  # type: ignore[arg-type]
        key=_av_string(item["key"], "object key"),
        public_path=_av_string(item["publicPath"], "object public path"),
        media_type=_av_string(item["mediaType"], "object media type"),
        sha256=_av_string(item["sha256"], "object digest"),
        byte_length=_av_int(item["byteLength"], "object byte length"),
        etag=_av_string(item["etag"], "object ETag"),
    )
    return RegisteredDeliveryObject(
        reference=reference,
        provider_target_id=_av_string(item["providerTargetId"], "object provider target"),
        provider_version_id=_av_string(item["providerVersionId"], "object provider version"),
    )


REQUIRED_ITEM_FIELDS = {
    "PK",
    "SK",
    "controlVersion",
    "resultId",
    "state",
    "revision",
    "publicationSha256",
    "objectsSha256",
    "controlIdentitySha256",
    "bundleSha256",
    "publishedAt",
    "deletionKeyId",
    "deletionDigestHmacSha256",
    "cacheControl",
    "objects",
    "publicPaths",
}
OPTIONAL_ITEM_FIELDS = {
    "expiresAt",
    "expiresAtEpochMs",
    "stagingExpiresAt",
    "stagingExpiresAtEpochMs",
    "activatedAt",
    "abandonedAt",
    "retiredAt",
    "purgeOperationId",
    "purgeCoverageSha256",
    "purgeRequired",
    "purgeProviderTargetId",
    "purgeState",
    "purgeProviderRequestId",
    "purgeConfirmedAt",
    "cleanupState",
    "GSI1PK",
    "GSI1SK",
}


def encode_control_item(record: ResultControlRecord) -> dict[str, object]:
    if not isinstance(record, ResultControlRecord):
        raise ValueError("DynamoDB control write requires a control record")
    item: dict[str, object] = {
        **_key(record.result_id),
        "controlVersion": _s(record.control_version),
        "resultId": _s(record.result_id),
        "state": _s(record.state),
        "revision": _n(record.revision),
        "publicationSha256": _s(record.publication_sha256),
        "objectsSha256": _s(record.objects_sha256),
        "controlIdentitySha256": _s(record.control_identity_sha256),
        "bundleSha256": _s(record.bundle_sha256),
        "publishedAt": _s(record.published_at),
        "deletionKeyId": _s(record.deletion_key_id),
        "deletionDigestHmacSha256": _s(record.deletion_digest_hmac_sha256),
        "cacheControl": _s(record.cache_control),
        "objects": {"L": [_encode_object(value) for value in record.objects]},
        "publicPaths": {"L": [_s(value) for value in record.public_paths]},
    }
    optional_strings = {
        "expiresAt": record.expires_at,
        "activatedAt": record.activated_at,
        "retiredAt": record.retired_at,
        "purgeOperationId": record.purge_operation_id,
        "purgeCoverageSha256": record.purge_coverage_sha256,
        "purgeProviderTargetId": record.purge_provider_target_id,
        "purgeState": record.purge_state,
        "purgeProviderRequestId": record.purge_provider_request_id,
        "purgeConfirmedAt": record.purge_confirmed_at,
        "cleanupState": record.cleanup_state,
        "abandonedAt": record.abandoned_at,
    }
    item.update({name: _s(value) for name, value in optional_strings.items() if value is not None})
    if record.expires_at_epoch_ms is not None:
        item["expiresAtEpochMs"] = _n(record.expires_at_epoch_ms)
    if record.staging_expires_at is not None:
        item["stagingExpiresAt"] = _s(record.staging_expires_at)
    if record.staging_expires_at_epoch_ms is not None:
        item["stagingExpiresAtEpochMs"] = _n(record.staging_expires_at_epoch_ms)
    if record.purge_required is not None:
        item["purgeRequired"] = _b(record.purge_required)
    if record.state == "staged" and record.control_version != LEGACY_CONTROL_VERSION:
        if record.staging_expires_at_epoch_ms is None:
            raise ControlStoreError("DynamoDB staged item lacks its immutable deadline")
        item["GSI1PK"] = _s(STAGED_EXPIRY_PARTITION)
        item["GSI1SK"] = _n(record.staging_expires_at_epoch_ms)
    elif record.state == "live" and record.expires_at_epoch_ms is not None:
        item["GSI1PK"] = _s(EXPIRY_PARTITION)
        item["GSI1SK"] = _n(record.expires_at_epoch_ms)
    elif record.state == "retiring" or (
        record.state == "retired" and record.cleanup_state == "pending"
    ) or (record.state == "abandoned" and record.cleanup_state == "pending"):
        work_time = record.retired_at if record.state != "abandoned" else record.abandoned_at
        if work_time is None:
            raise ControlStoreError("DynamoDB lifecycle work lacks its work timestamp")
        item["GSI1PK"] = _s(WORK_PARTITION)
        item["GSI1SK"] = _n(timestamp_epoch_ms(work_time, "lifecycle work time"))
    if len(stable_json_bytes(item)) > MAX_ENCODED_ITEM_BYTES:
        raise ControlStoreError("DynamoDB control item exceeds its encoded size budget")
    return item


def _decode_control_item(value: object) -> ResultControlRecord:
    if not isinstance(value, Mapping):
        raise ControlStoreError("DynamoDB control item is not a map")
    if not REQUIRED_ITEM_FIELDS <= set(value) or set(value) - (
        REQUIRED_ITEM_FIELDS | OPTIONAL_ITEM_FIELDS
    ):
        raise ControlStoreError("DynamoDB control item has an invalid shape")
    control_version = _av_string(value["controlVersion"], "control version")
    if control_version not in {CONTROL_VERSION, LEGACY_CONTROL_VERSION}:
        raise ControlStoreError("DynamoDB control version drifted")
    result_id = _av_string(value["resultId"], "result ID")
    _validate_result_id(result_id)
    if (
        _av_string(value["PK"], "partition key") != f"RESULT#{result_id}"
        or _av_string(value["SK"], "sort key") != "CONTROL"
    ):
        raise ControlStoreError("DynamoDB control key drifted")
    objects = tuple(
        _decode_registered_object(item, result_id)
        for item in _av_list(value["objects"], "object registry")
    )
    public_paths = tuple(
        _av_string(item, "public path")
        for item in _av_list(value["publicPaths"], "public paths")
    )

    def optional_string(name: str) -> str | None:
        return None if name not in value else _av_string(value[name], name)

    record = ResultControlRecord(
        control_version=control_version,
        result_id=result_id,
        state=_av_string(value["state"], "state"),  # type: ignore[arg-type]
        revision=_av_int(value["revision"], "revision"),
        publication_sha256=_av_string(value["publicationSha256"], "publication digest"),
        objects_sha256=_av_string(value["objectsSha256"], "object-registry digest"),
        control_identity_sha256=_av_string(
            value["controlIdentitySha256"],
            "control identity digest",
        ),
        bundle_sha256=_av_string(value["bundleSha256"], "bundle digest"),
        published_at=_av_string(value["publishedAt"], "publication time"),
        expires_at=optional_string("expiresAt"),
        expires_at_epoch_ms=(
            None
            if "expiresAtEpochMs" not in value
            else _av_int(value["expiresAtEpochMs"], "expiry epoch milliseconds")
        ),
        staging_expires_at=optional_string("stagingExpiresAt"),
        staging_expires_at_epoch_ms=(
            None
            if "stagingExpiresAtEpochMs" not in value
            else _av_int(value["stagingExpiresAtEpochMs"], "staging expiry epoch milliseconds")
        ),
        deletion_key_id=_av_string(value["deletionKeyId"], "deletion key ID"),
        deletion_digest_hmac_sha256=_av_string(
            value["deletionDigestHmacSha256"],
            "deletion HMAC",
        ),
        cache_control=_av_string(value["cacheControl"], "cache policy"),
        objects=objects,
        public_paths=public_paths,
        activated_at=optional_string("activatedAt"),
        abandoned_at=optional_string("abandonedAt"),
        retired_at=optional_string("retiredAt"),
        purge_operation_id=optional_string("purgeOperationId"),
        purge_coverage_sha256=optional_string("purgeCoverageSha256"),
        purge_required=(
            None
            if "purgeRequired" not in value
            else _av_bool(value["purgeRequired"], "purge-required flag")
        ),
        purge_provider_target_id=optional_string("purgeProviderTargetId"),
        purge_state=optional_string("purgeState"),  # type: ignore[arg-type]
        purge_provider_request_id=optional_string("purgeProviderRequestId"),
        purge_confirmed_at=optional_string("purgeConfirmedAt"),
        cleanup_state=optional_string("cleanupState"),  # type: ignore[arg-type]
    )
    has_expiry_index = "GSI1PK" in value or "GSI1SK" in value
    if record.state == "staged" and record.control_version != LEGACY_CONTROL_VERSION:
        if (
            not has_expiry_index
            or set(value) & {"GSI1PK", "GSI1SK"} != {"GSI1PK", "GSI1SK"}
            or _av_string(value["GSI1PK"], "staging expiry partition") != STAGED_EXPIRY_PARTITION
            or record.staging_expires_at_epoch_ms is None
            or _av_int(value["GSI1SK"], "staging expiry sort key")
            != record.staging_expires_at_epoch_ms
        ):
            raise ControlStoreError("DynamoDB staged expiry index drifted")
    elif record.state == "live" and record.expires_at_epoch_ms is not None:
        if (
            set(value) & {"GSI1PK", "GSI1SK"} != {"GSI1PK", "GSI1SK"}
            or _av_string(value["GSI1PK"], "expiry partition") != EXPIRY_PARTITION
            or _av_int(value["GSI1SK"], "expiry sort key")
            != record.expires_at_epoch_ms
        ):
            raise ControlStoreError("DynamoDB live expiry index drifted")
    elif record.state == "retiring" or (
        record.state == "retired" and record.cleanup_state == "pending"
    ) or (record.state == "abandoned" and record.cleanup_state == "pending"):
        work_time = record.retired_at if record.state != "abandoned" else record.abandoned_at
        if (
            not has_expiry_index
            or set(value) & {"GSI1PK", "GSI1SK"} != {"GSI1PK", "GSI1SK"}
            or _av_string(value["GSI1PK"], "work partition") != WORK_PARTITION
            or work_time is None
            or _av_int(value["GSI1SK"], "work sort key")
            != timestamp_epoch_ms(work_time, "lifecycle work time")
        ):
            raise ControlStoreError("DynamoDB pending-work index drifted")
    elif has_expiry_index:
        raise ControlStoreError("DynamoDB inactive item retained lifecycle index fields")
    return record


def decode_control_item(value: object) -> ResultControlRecord:
    try:
        if len(stable_json_bytes(value)) > MAX_ENCODED_ITEM_BYTES:
            raise ControlStoreError(
                "DynamoDB control item exceeds its encoded size budget"
            )
        return _decode_control_item(value)
    except ControlStoreError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise ControlStoreError(
            "DynamoDB control item failed semantic validation"
        ) from error


def _retirement_binding_matches(
    record: ResultControlRecord,
    expected: ResultControlRecord | RetirementPlan,
    *,
    allow_operation_drift: bool = False,
) -> bool:
    if record.state not in {"retiring", "retired"}:
        return False
    if isinstance(expected, ResultControlRecord):
        expected_plan = retirement_plan_from_record(expected)
        expected_identity = expected.control_identity_sha256
    else:
        expected_plan = expected
        expected_identity = None
    return (
        (expected_identity is None or record.control_identity_sha256 == expected_identity)
        and record.result_id == expected_plan.result_id
        and (
            allow_operation_drift
            or record.purge_operation_id == expected_plan.operation_id
        )
        and record.purge_coverage_sha256 == expected_plan.coverage_sha256
        and record.purge_required == expected_plan.purge_required
        and record.purge_provider_target_id == expected_plan.provider_target_id
    )


def _same_control_identity(
    existing: ResultControlRecord,
    proposed: ResultControlRecord,
) -> bool:
    return (
        existing.result_id == proposed.result_id
        and existing.publication_sha256 == proposed.publication_sha256
        and existing.objects_sha256 == proposed.objects_sha256
        and existing.bundle_sha256 == proposed.bundle_sha256
        and existing.public_paths == proposed.public_paths
        and existing.cache_control == proposed.cache_control
        and existing.control_identity_sha256 == proposed.control_identity_sha256
    )


def _validated_expiry_cursor(
    value: object,
    *,
    provider_response: bool,
    maximum_epoch_ms: int,
) -> dict[str, object]:
    try:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"PK", "SK", "GSI1PK", "GSI1SK"}
            or len(stable_json_bytes(value)) > 4096
        ):
            raise ValueError("cursor shape is invalid")
        partition = _av_string(value["PK"], "cursor partition key")
        if not partition.startswith("RESULT#"):
            raise ValueError("cursor partition prefix drifted")
        _validate_result_id(partition.removeprefix("RESULT#"))
        if (
            _av_string(value["SK"], "cursor sort key") != "CONTROL"
            or _av_string(value["GSI1PK"], "cursor expiry partition")
            != EXPIRY_PARTITION
        ):
            raise ValueError("cursor identity drifted")
        if _av_int(value["GSI1SK"], "cursor expiry sort key") > maximum_epoch_ms:
            raise ValueError("cursor exceeds the query boundary")
        return dict(value)
    except (ControlStoreError, KeyError, TypeError, ValueError) as error:
        if provider_response:
            raise ControlStoreError(
                "DynamoDB expiry query cursor is malformed"
            ) from error
        raise ValueError("expiry query cursor is invalid") from error


def _validated_staged_cursor(
    value: object,
    *,
    provider_response: bool,
    maximum_epoch_ms: int,
) -> dict[str, object]:
    try:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"PK", "SK", "GSI1PK", "GSI1SK"}
            or len(stable_json_bytes(value)) > 4096
        ):
            raise ValueError("cursor shape is invalid")
        partition = _av_string(value["PK"], "cursor partition key")
        if not partition.startswith("RESULT#"):
            raise ValueError("cursor partition prefix drifted")
        _validate_result_id(partition.removeprefix("RESULT#"))
        if (
            _av_string(value["SK"], "cursor sort key") != "CONTROL"
            or _av_string(value["GSI1PK"], "cursor staged partition") != STAGED_EXPIRY_PARTITION
            or _av_int(value["GSI1SK"], "cursor staged sort key") > maximum_epoch_ms
        ):
            raise ValueError("cursor identity or boundary drifted")
        return dict(value)
    except (ControlStoreError, KeyError, TypeError, ValueError) as error:
        if provider_response:
            raise ControlStoreError("DynamoDB staged query cursor is malformed") from error
        raise ValueError("staged query cursor is invalid") from error


def _validated_work_cursor(
    value: object,
    *,
    provider_response: bool,
    maximum_epoch_ms: int,
) -> dict[str, object]:
    try:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"PK", "SK", "GSI1PK", "GSI1SK"}
            or len(stable_json_bytes(value)) > 4096
        ):
            raise ValueError("cursor shape is invalid")
        partition = _av_string(value["PK"], "cursor partition key")
        if not partition.startswith("RESULT#"):
            raise ValueError("cursor partition prefix drifted")
        _validate_result_id(partition.removeprefix("RESULT#"))
        if (
            _av_string(value["SK"], "cursor sort key") != "CONTROL"
            or _av_string(value["GSI1PK"], "cursor work partition") != WORK_PARTITION
            or _av_int(value["GSI1SK"], "cursor work sort key") > maximum_epoch_ms
        ):
            raise ValueError("cursor identity or boundary drifted")
        return dict(value)
    except (ControlStoreError, KeyError, TypeError, ValueError) as error:
        if provider_response:
            raise ControlStoreError(
                "DynamoDB pending-work query cursor is malformed"
            ) from error
        raise ValueError("pending-work query cursor is invalid") from error


class DynamoDBControlStore:
    """Strict single-item lifecycle transitions for one authoritative result record."""

    def __init__(
        self,
        client: DynamoDBClient,
        table_name: str,
        *,
        expiry_index_name: str = DEFAULT_EXPIRY_INDEX,
        ttl_disabled_at_epoch: int,
        checked_at_epoch: int | None = None,
    ) -> None:
        self._client = client
        self._table = _validate_name(table_name, "table name")
        self._expiry_index = _validate_name(expiry_index_name, "expiry index name")
        self._ttl_disabled_at_epoch = _validate_epoch(
            ttl_disabled_at_epoch,
            "TTL-disabled timestamp",
        )
        if self._ttl_disabled_at_epoch == 0:
            raise ValueError("invalid DynamoDB TTL-disabled timestamp")
        self._checked_at_epoch = _validate_epoch(
            int(time.time()) if checked_at_epoch is None else checked_at_epoch,
            "configuration-check timestamp",
        )
        self.verify_table_configuration()

    @property
    def table_name(self) -> str:
        return self._table

    @staticmethod
    def _key_schema(value: object, label: str) -> dict[str, str]:
        if not isinstance(value, list) or len(value) != 2:
            raise ControlStoreError(f"DynamoDB {label} key schema is malformed")
        result: dict[str, str] = {}
        for entry in value:
            if (
                not isinstance(entry, Mapping)
                or set(entry) != {"AttributeName", "KeyType"}
                or not isinstance(entry.get("AttributeName"), str)
                or entry.get("KeyType") not in {"HASH", "RANGE"}
                or entry["KeyType"] in result
            ):
                raise ControlStoreError(f"DynamoDB {label} key schema is malformed")
            result[entry["KeyType"]] = entry["AttributeName"]
        if set(result) != {"HASH", "RANGE"}:
            raise ControlStoreError(f"DynamoDB {label} key schema is malformed")
        return result

    @staticmethod
    def _attribute_types(value: object) -> dict[str, str]:
        if not isinstance(value, list):
            raise ControlStoreError("DynamoDB attribute definitions are malformed")
        result: dict[str, str] = {}
        for entry in value:
            if (
                not isinstance(entry, Mapping)
                or set(entry) != {"AttributeName", "AttributeType"}
                or not isinstance(entry.get("AttributeName"), str)
                or entry.get("AttributeType") not in {"S", "N", "B"}
                or entry["AttributeName"] in result
            ):
                raise ControlStoreError("DynamoDB attribute definitions are malformed")
            result[entry["AttributeName"]] = entry["AttributeType"]
        return result

    def verify_table_configuration(self) -> None:
        try:
            table_response = self._client.describe_table(TableName=self._table)
            ttl_response = self._client.describe_time_to_live(TableName=self._table)
        except Exception as error:
            raise _provider_failure(
                "DynamoDB control table configuration could not be verified",
                error,
            ) from error
        if not isinstance(table_response, Mapping) or not isinstance(
            ttl_response,
            Mapping,
        ):
            raise ControlStoreError(
                "DynamoDB control table configuration response is malformed"
            )
        table = table_response.get("Table")
        ttl = ttl_response.get("TimeToLiveDescription")
        if not isinstance(table, Mapping) or not isinstance(ttl, Mapping):
            raise ControlStoreError(
                "DynamoDB control table configuration response is malformed"
            )
        if table.get("TableName") != self._table or table.get("TableStatus") != "ACTIVE":
            raise ControlStoreError("DynamoDB control table is not active")
        attribute_types = self._attribute_types(table.get("AttributeDefinitions"))
        if self._key_schema(table.get("KeySchema"), "table") != {
            "HASH": "PK",
            "RANGE": "SK",
        } or any(attribute_types.get(name) != kind for name, kind in {
            "PK": "S",
            "SK": "S",
        }.items()):
            raise ControlStoreError("DynamoDB control table key schema drifted")
        indexes = table.get("GlobalSecondaryIndexes")
        if not isinstance(indexes, list):
            raise ControlStoreError("DynamoDB expiry index metadata is malformed")
        matching_indexes = [
            index
            for index in indexes
            if isinstance(index, Mapping)
            and index.get("IndexName") == self._expiry_index
        ]
        if len(matching_indexes) != 1:
            raise ControlStoreError("DynamoDB expiry index is missing or duplicated")
        index = matching_indexes[0]
        projection = index.get("Projection")
        if (
            index.get("IndexStatus") != "ACTIVE"
            or self._key_schema(index.get("KeySchema"), "expiry index")
            != {"HASH": "GSI1PK", "RANGE": "GSI1SK"}
            or attribute_types.get("GSI1PK") != "S"
            or attribute_types.get("GSI1SK") != "N"
            or not isinstance(projection, Mapping)
            or projection.get("ProjectionType") not in {"ALL", "INCLUDE", "KEYS_ONLY"}
        ):
            raise ControlStoreError("DynamoDB expiry index configuration drifted")
        if (
            ttl.get("TimeToLiveStatus") != "DISABLED"
            or "AttributeName" in ttl
        ):
            raise ControlStoreError(
                "DynamoDB TTL must be cleanly disabled to preserve result tombstones"
            )
        if (
            self._checked_at_epoch - self._ttl_disabled_at_epoch
            < TTL_DELETION_QUARANTINE_SECONDS
        ):
            raise ControlStoreError(
                "DynamoDB TTL deletion quarantine has not elapsed"
            )

    def _read(self, result_id: str) -> ResultControlRecord | None:
        try:
            response = self._client.get_item(
                TableName=self._table,
                Key=_key(result_id),
                ConsistentRead=True,
                ReturnConsumedCapacity="TOTAL",
            )
        except Exception as error:
            raise _provider_failure("DynamoDB control item could not be read", error) from error
        if not isinstance(response, Mapping):
            raise ControlStoreError("DynamoDB get response is malformed")
        item = response.get("Item")
        return None if item is None else decode_control_item(item)

    def get_control(self, result_id: str) -> ResultControlRecord | None:
        return self._read(_validate_result_id(result_id))

    def get_live(
        self,
        result_id: str,
        *,
        now_epoch_ms: int,
    ) -> ResultControlRecord | None:
        now_epoch_ms = _validate_epoch(now_epoch_ms, "visibility timestamp")
        record = self._read(_validate_result_id(result_id))
        if record is None or record.state != "live":
            return None
        if (
            record.expires_at_epoch_ms is not None
            and record.expires_at_epoch_ms <= now_epoch_ms
        ):
            return None
        return record

    def _updated(self, response: object, operation: str) -> ResultControlRecord:
        if not isinstance(response, Mapping) or not isinstance(
            response.get("Attributes"),
            Mapping,
        ):
            raise ControlStoreError(f"DynamoDB {operation} response is malformed")
        return decode_control_item(response["Attributes"])

    def create_staged(self, record: ResultControlRecord) -> ResultControlRecord:
        if not isinstance(record, ResultControlRecord) or record.state != "staged":
            raise ValueError("DynamoDB staged creation requires a staged control record")
        try:
            response = self._client.put_item(
                TableName=self._table,
                Item=encode_control_item(record),
                ConditionExpression="attribute_not_exists(#pk)",
                ExpressionAttributeNames={"#pk": "PK"},
                ReturnValuesOnConditionCheckFailure="ALL_OLD",
                ReturnConsumedCapacity="TOTAL",
            )
        except Exception as error:
            if not _is_conditional(error):
                raise _provider_failure("DynamoDB staged creation failed", error) from error
            existing = self._read(record.result_id)
            if existing is None:
                raise ControlConflictError("conditional staged row disappeared") from error
            if (
                existing.state in {"staged", "live"}
                and _same_control_identity(existing, record)
            ):
                return existing
            raise ControlCollisionError("result control identity cannot be reused") from error
        if not isinstance(response, Mapping):
            raise ControlStoreError("DynamoDB put response is malformed")
        return record

    def activate(
        self,
        staged: ResultControlRecord,
        *,
        activated_at: str,
        now_epoch_ms: int,
    ) -> ResultControlRecord:
        if not isinstance(staged, ResultControlRecord) or staged.state != "staged":
            raise ValueError("DynamoDB activation requires a staged control record")
        canonical_timestamp(activated_at, "activation time")
        now_epoch_ms = _validate_epoch(now_epoch_ms, "activation timestamp")
        if timestamp_epoch_ms(activated_at, "activation time") != now_epoch_ms:
            raise ValueError("DynamoDB activation timestamps disagree")
        if activated_at < staged.published_at:
            raise ValueError("DynamoDB activation precedes publication")
        if (
            staged.expires_at_epoch_ms is not None
            and now_epoch_ms >= staged.expires_at_epoch_ms
        ):
            raise ValueError("DynamoDB activation does not precede expiry")
        names = {
            "#state": "state",
            "#activated": "activatedAt",
            "#revision": "revision",
            "#identity": "controlIdentitySha256",
        }
        values: dict[str, object] = {
            ":staged": _s("staged"),
            ":live": _s("live"),
            ":activated": _s(activated_at),
            ":zero": _n(0),
            ":one": _n(1),
            ":identity": _s(staged.control_identity_sha256),
        }
        updates = [
            "#state = :live",
            "#activated = :activated",
            "#revision = #revision + :one",
        ]
        condition = "#state = :staged AND #revision = :zero AND #identity = :identity"
        if staged.staging_expires_at_epoch_ms is None:
            raise ValueError("DynamoDB activation lacks the staging deadline")
        names.update({"#stagingExpires": "stagingExpiresAtEpochMs", "#gsiPk": "GSI1PK", "#gsiSk": "GSI1SK"})
        values.update({":stagingNow": _n(now_epoch_ms)})
        condition += " AND #stagingExpires > :stagingNow"
        if staged.expires_at_epoch_ms is not None:
            names.update(
                {
                    "#expires": "expiresAtEpochMs",
                }
            )
            values.update(
                {
                    ":expiryPk": _s(EXPIRY_PARTITION),
                    ":expiryEpoch": _n(staged.expires_at_epoch_ms),
                    ":now": _n(now_epoch_ms),
                }
            )
            updates.extend(["#gsiPk = :expiryPk", "#gsiSk = :expiryEpoch"])
            condition += " AND #expires > :now"
        try:
            response = self._client.update_item(
                TableName=self._table,
                Key=_key(staged.result_id),
                UpdateExpression=(
                    "SET " + ", ".join(updates)
                    if staged.expires_at_epoch_ms is not None
                    else "SET " + ", ".join(updates) + " REMOVE #gsiPk, #gsiSk"
                ),
                ConditionExpression=condition,
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
                ReturnValues="ALL_NEW",
                ReturnValuesOnConditionCheckFailure="ALL_OLD",
                ReturnConsumedCapacity="TOTAL",
            )
        except Exception as error:
            if not _is_conditional(error):
                raise _provider_failure("DynamoDB activation failed", error) from error
            existing = self._read(staged.result_id)
            if existing is None:
                raise ControlMissingError("staged control item disappeared") from error
            if (
                existing.state == "live"
                and existing.control_identity_sha256 == staged.control_identity_sha256
                and existing.activated_at == activated_at
            ):
                return existing
            raise ControlCollisionError("control activation identity drifted") from error
        activated = self._updated(response, "activation")
        if (
            activated.state != "live"
            or activated.control_identity_sha256 != staged.control_identity_sha256
            or activated.activated_at != activated_at
        ):
            raise ControlStoreError("DynamoDB activation returned the wrong control item")
        return activated

    def begin_retirement(
        self,
        live: ResultControlRecord,
        plan: RetirementPlan,
        *,
        retired_at: str,
        require_expired: bool = False,
        now_epoch_ms: int | None = None,
    ) -> ResultControlRecord:
        if not isinstance(live, ResultControlRecord) or live.state != "live":
            raise ValueError("DynamoDB retirement requires a live control record")
        if not isinstance(plan, RetirementPlan) or plan.result_id != live.result_id:
            raise ValueError("DynamoDB retirement plan does not match the result")
        if plan != build_retirement_plan(
            live,
            operation_id=plan.operation_id,
            provider_target_id=plan.provider_target_id,
        ):
            raise ValueError("DynamoDB retirement plan coverage drifted")
        canonical_timestamp(retired_at, "retirement time")
        if live.activated_at is None or retired_at < live.activated_at:
            raise ValueError("DynamoDB retirement precedes activation")
        if not isinstance(require_expired, bool):
            raise ValueError("expiry retirement flag must be boolean")
        if require_expired:
            if (
                isinstance(now_epoch_ms, bool)
                or not isinstance(now_epoch_ms, int)
                or now_epoch_ms < 0
                or live.expires_at_epoch_ms is None
            ):
                raise ValueError("expiry retirement requires a valid expiry boundary")
            if live.expires_at_epoch_ms > now_epoch_ms:
                raise ControlNotExpiredError("result retention has not elapsed")
        names = {
            "#state": "state",
            "#revision": "revision",
            "#identity": "controlIdentitySha256",
            "#retiredAt": "retiredAt",
            "#operation": "purgeOperationId",
            "#coverage": "purgeCoverageSha256",
            "#required": "purgeRequired",
            "#purgeState": "purgeState",
            "#cleanup": "cleanupState",
            "#gsiPk": "GSI1PK",
            "#gsiSk": "GSI1SK",
        }
        values: dict[str, object] = {
            ":live": _s("live"),
            ":retiring": _s("retiring"),
            ":revision": _n(live.revision),
            ":one": _n(1),
            ":identity": _s(live.control_identity_sha256),
            ":retiredAt": _s(retired_at),
            ":operation": _s(plan.operation_id),
            ":coverage": _s(plan.coverage_sha256),
            ":required": _b(plan.purge_required),
            ":purgeState": _s("pending" if plan.purge_required else "confirmed"),
            ":cleanup": _s("pending"),
            ":workPk": _s(WORK_PARTITION),
            ":workEpoch": _n(timestamp_epoch_ms(retired_at, "retirement time")),
        }
        updates = [
            "#state = :retiring",
            "#retiredAt = :retiredAt",
            "#operation = :operation",
            "#coverage = :coverage",
            "#required = :required",
            "#purgeState = :purgeState",
            "#cleanup = :cleanup",
            "#revision = #revision + :one",
        ]
        if plan.provider_target_id is not None:
            names["#target"] = "purgeProviderTargetId"
            values[":target"] = _s(plan.provider_target_id)
            updates.append("#target = :target")
        if not plan.purge_required:
            names["#confirmedAt"] = "purgeConfirmedAt"
            values[":confirmedAt"] = _s(retired_at)
            updates.append("#confirmedAt = :confirmedAt")
        condition = (
            "#state = :live AND #revision = :revision AND #identity = :identity"
        )
        if require_expired:
            names["#expires"] = "expiresAtEpochMs"
            values[":now"] = _n(now_epoch_ms)  # type: ignore[arg-type]
            condition += " AND attribute_exists(#expires) AND #expires <= :now"
        try:
            response = self._client.update_item(
                TableName=self._table,
                Key=_key(live.result_id),
                UpdateExpression=(
                    "SET " + ", ".join(
                        (*updates, "#gsiPk = :workPk", "#gsiSk = :workEpoch")
                    )
                ),
                ConditionExpression=condition,
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
                ReturnValues="ALL_NEW",
                ReturnValuesOnConditionCheckFailure="ALL_OLD",
                ReturnConsumedCapacity="TOTAL",
            )
        except Exception as error:
            if not _is_conditional(error):
                raise _provider_failure("DynamoDB retirement fence failed", error) from error
            existing = self._read(live.result_id)
            if existing is None:
                raise ControlMissingError("live control item disappeared") from error
            if _retirement_binding_matches(
                existing,
                plan,
                allow_operation_drift=True,
            ) and existing.control_identity_sha256 == live.control_identity_sha256:
                return existing
            if (
                require_expired
                and existing.state == "live"
                and existing.expires_at_epoch_ms is not None
                and existing.expires_at_epoch_ms > now_epoch_ms  # type: ignore[operator]
            ):
                raise ControlNotExpiredError("result retention has not elapsed") from error
            raise ControlConflictError("control retirement did not converge") from error
        retiring = self._updated(response, "retirement")
        if (
            not _retirement_binding_matches(retiring, plan)
            or retiring.control_identity_sha256 != live.control_identity_sha256
        ):
            raise ControlStoreError("DynamoDB retirement returned the wrong binding")
        return retiring

    def record_pending_purge(
        self,
        retiring: ResultControlRecord,
        *,
        provider_request_id: str,
    ) -> ResultControlRecord:
        if (
            not isinstance(retiring, ResultControlRecord)
            or retiring.state != "retiring"
            or retiring.purge_required is not True
            or retiring.purge_state not in {"pending", "confirmed"}
        ):
            raise ValueError("pending purge requires a retiring shared-cache record")
        provider_request_id = _visible_ascii(
            provider_request_id,
            "purge provider request",
        )
        if retiring.purge_state == "confirmed":
            existing = self._read(retiring.result_id)
            if (
                existing is not None
                and existing.purge_state == "confirmed"
                and existing.purge_provider_request_id == provider_request_id
                and _retirement_binding_matches(existing, retiring)
            ):
                return existing
            raise ControlCollisionError("confirmed purge request identity drifted")
        names = {
            "#state": "state",
            "#identity": "controlIdentitySha256",
            "#operation": "purgeOperationId",
            "#coverage": "purgeCoverageSha256",
            "#target": "purgeProviderTargetId",
            "#purgeState": "purgeState",
            "#request": "purgeProviderRequestId",
            "#revision": "revision",
        }
        values = {
            ":retiring": _s("retiring"),
            ":identity": _s(retiring.control_identity_sha256),
            ":operation": _s(retiring.purge_operation_id),  # type: ignore[arg-type]
            ":coverage": _s(retiring.purge_coverage_sha256),  # type: ignore[arg-type]
            ":target": _s(retiring.purge_provider_target_id),  # type: ignore[arg-type]
            ":pending": _s("pending"),
            ":request": _s(provider_request_id),
            ":one": _n(1),
        }
        try:
            response = self._client.update_item(
                TableName=self._table,
                Key=_key(retiring.result_id),
                UpdateExpression=(
                    "SET #request = :request, #revision = #revision + :one"
                ),
                ConditionExpression=(
                    "#state = :retiring AND #identity = :identity "
                    "AND #operation = :operation AND #coverage = :coverage "
                    "AND #target = :target AND #purgeState = :pending "
                    "AND attribute_not_exists(#request)"
                ),
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
                ReturnValues="ALL_NEW",
                ReturnValuesOnConditionCheckFailure="ALL_OLD",
                ReturnConsumedCapacity="TOTAL",
            )
        except Exception as error:
            if not _is_conditional(error):
                raise _provider_failure("DynamoDB pending purge write failed", error) from error
            existing = self._read(retiring.result_id)
            if (
                existing is not None
                and _retirement_binding_matches(existing, retiring)
                and existing.purge_provider_request_id == provider_request_id
                and existing.purge_state in {"pending", "confirmed"}
            ):
                return existing
            raise ControlConflictError("pending purge evidence did not converge") from error
        updated = self._updated(response, "pending purge")
        if (
            not _retirement_binding_matches(updated, retiring)
            or updated.state != "retiring"
            or updated.purge_state != "pending"
            or updated.purge_provider_request_id != provider_request_id
        ):
            raise ControlStoreError(
                "DynamoDB pending purge returned the wrong evidence"
            )
        return updated

    def record_confirmed_purge(
        self,
        retiring: ResultControlRecord,
        *,
        provider_request_id: str,
        confirmed_at: str,
    ) -> ResultControlRecord:
        if (
            not isinstance(retiring, ResultControlRecord)
            or retiring.state != "retiring"
            or retiring.purge_required is not True
        ):
            raise ValueError("purge confirmation requires a retiring shared-cache record")
        provider_request_id = _visible_ascii(
            provider_request_id,
            "purge provider request",
        )
        canonical_timestamp(confirmed_at, "purge confirmation time")
        if retiring.retired_at is None or confirmed_at < retiring.retired_at:
            raise ValueError("DynamoDB purge confirmation precedes retirement")
        if retiring.purge_state == "confirmed":
            existing = self._read(retiring.result_id)
            if (
                existing is not None
                and existing.purge_state == "confirmed"
                and existing.purge_provider_request_id == provider_request_id
                and _retirement_binding_matches(existing, retiring)
            ):
                return existing
            raise ControlCollisionError("confirmed purge request identity drifted")
        names = {
            "#state": "state",
            "#identity": "controlIdentitySha256",
            "#operation": "purgeOperationId",
            "#coverage": "purgeCoverageSha256",
            "#target": "purgeProviderTargetId",
            "#purgeState": "purgeState",
            "#request": "purgeProviderRequestId",
            "#confirmedAt": "purgeConfirmedAt",
            "#revision": "revision",
        }
        values = {
            ":retiring": _s("retiring"),
            ":identity": _s(retiring.control_identity_sha256),
            ":operation": _s(retiring.purge_operation_id),  # type: ignore[arg-type]
            ":coverage": _s(retiring.purge_coverage_sha256),  # type: ignore[arg-type]
            ":target": _s(retiring.purge_provider_target_id),  # type: ignore[arg-type]
            ":pending": _s("pending"),
            ":confirmed": _s("confirmed"),
            ":request": _s(provider_request_id),
            ":confirmedAt": _s(confirmed_at),
            ":one": _n(1),
        }
        try:
            response = self._client.update_item(
                TableName=self._table,
                Key=_key(retiring.result_id),
                UpdateExpression=(
                    "SET #purgeState = :confirmed, #request = :request, "
                    "#confirmedAt = :confirmedAt, #revision = #revision + :one"
                ),
                ConditionExpression=(
                    "#state = :retiring AND #identity = :identity "
                    "AND #operation = :operation AND #coverage = :coverage "
                    "AND #target = :target AND #purgeState = :pending "
                    "AND (attribute_not_exists(#request) OR #request = :request)"
                ),
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
                ReturnValues="ALL_NEW",
                ReturnValuesOnConditionCheckFailure="ALL_OLD",
                ReturnConsumedCapacity="TOTAL",
            )
        except Exception as error:
            if not _is_conditional(error):
                raise _provider_failure("DynamoDB purge confirmation failed", error) from error
            existing = self._read(retiring.result_id)
            if (
                existing is not None
                and _retirement_binding_matches(existing, retiring)
                and existing.purge_state == "confirmed"
                and existing.purge_provider_request_id == provider_request_id
            ):
                return existing
            raise ControlConflictError("purge confirmation did not converge") from error
        updated = self._updated(response, "purge confirmation")
        if (
            not _retirement_binding_matches(updated, retiring)
            or updated.state != "retiring"
            or updated.purge_state != "confirmed"
            or updated.purge_provider_request_id != provider_request_id
            or updated.purge_confirmed_at != confirmed_at
        ):
            raise ControlStoreError(
                "DynamoDB purge confirmation returned the wrong evidence"
            )
        return updated

    def finalize_retirement(
        self,
        retiring: ResultControlRecord,
    ) -> ResultControlRecord:
        if (
            not isinstance(retiring, ResultControlRecord)
            or retiring.state != "retiring"
            or retiring.purge_state != "confirmed"
            or retiring.cleanup_state != "pending"
        ):
            raise ValueError("retirement finalization requires confirmed purge evidence")
        names = {
            "#state": "state",
            "#identity": "controlIdentitySha256",
            "#operation": "purgeOperationId",
            "#coverage": "purgeCoverageSha256",
            "#purgeState": "purgeState",
            "#revision": "revision",
        }
        values = {
            ":retiring": _s("retiring"),
            ":retired": _s("retired"),
            ":identity": _s(retiring.control_identity_sha256),
            ":operation": _s(retiring.purge_operation_id),  # type: ignore[arg-type]
            ":coverage": _s(retiring.purge_coverage_sha256),  # type: ignore[arg-type]
            ":confirmed": _s("confirmed"),
            ":revision": _n(retiring.revision),
            ":one": _n(1),
        }
        try:
            response = self._client.update_item(
                TableName=self._table,
                Key=_key(retiring.result_id),
                UpdateExpression=(
                    "SET #state = :retired, #revision = #revision + :one"
                ),
                ConditionExpression=(
                    "#state = :retiring AND #identity = :identity "
                    "AND #operation = :operation AND #coverage = :coverage "
                    "AND #purgeState = :confirmed AND #revision = :revision"
                ),
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
                ReturnValues="ALL_NEW",
                ReturnValuesOnConditionCheckFailure="ALL_OLD",
                ReturnConsumedCapacity="TOTAL",
            )
        except Exception as error:
            if not _is_conditional(error):
                raise _provider_failure("DynamoDB retirement finalization failed", error) from error
            existing = self._read(retiring.result_id)
            if (
                existing is not None
                and existing.state == "retired"
                and _retirement_binding_matches(existing, retiring)
            ):
                return existing
            raise ControlConflictError("retirement finalization did not converge") from error
        updated = self._updated(response, "retirement finalization")
        if (
            updated.state != "retired"
            or updated.cleanup_state != "pending"
            or not _retirement_binding_matches(updated, retiring)
        ):
            raise ControlStoreError(
                "DynamoDB retirement finalization returned the wrong evidence"
            )
        return updated

    def mark_cleanup_complete(
        self,
        retired: ResultControlRecord,
    ) -> ResultControlRecord:
        if not isinstance(retired, ResultControlRecord) or retired.state not in {"retired", "abandoned"}:
            raise ValueError("cleanup completion requires a retired or abandoned control record")
        abandoned = retired.state == "abandoned"
        if retired.cleanup_state == "complete":
            existing = self._read(retired.result_id)
            if (
                existing is not None
                and existing.state == retired.state
                and existing.cleanup_state == "complete"
                and (existing.control_identity_sha256 == retired.control_identity_sha256 if abandoned else _retirement_binding_matches(existing, retired))
            ):
                return existing
            raise ControlConflictError("cleanup completion evidence did not converge")
        if retired.cleanup_state != "pending" or (not abandoned and retired.purge_state != "confirmed"):
            raise ValueError("cleanup completion requires confirmed retirement")
        names = {
            "#state": "state",
            "#identity": "controlIdentitySha256",
            "#cleanup": "cleanupState",
            "#revision": "revision",
            "#gsiPk": "GSI1PK",
            "#gsiSk": "GSI1SK",
        }
        values = {
            ":retired": _s(retired.state),
            ":identity": _s(retired.control_identity_sha256),
            ":pending": _s("pending"),
            ":complete": _s("complete"),
            ":revision": _n(retired.revision),
            ":one": _n(1),
        }
        if not abandoned:
            names["#purgeState"] = "purgeState"
            values[":confirmed"] = _s("confirmed")
        try:
            response = self._client.update_item(
                TableName=self._table,
                Key=_key(retired.result_id),
                UpdateExpression=(
                    "SET #cleanup = :complete, #revision = #revision + :one "
                    "REMOVE #gsiPk, #gsiSk"
                ),
                ConditionExpression=(
                    "#state = :retired AND #identity = :identity "
                    "AND #cleanup = :pending AND #revision = :revision"
                    if abandoned else
                    "#state = :retired AND #identity = :identity "
                    "AND #cleanup = :pending AND #purgeState = :confirmed "
                    "AND #revision = :revision"
                ),
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
                ReturnValues="ALL_NEW",
                ReturnValuesOnConditionCheckFailure="ALL_OLD",
                ReturnConsumedCapacity="TOTAL",
            )
        except Exception as error:
            if not _is_conditional(error):
                raise _provider_failure("DynamoDB cleanup completion failed", error) from error
            existing = self._read(retired.result_id)
            if (
                existing is not None
                and existing.state == retired.state
                and existing.cleanup_state == "complete"
                and (existing.control_identity_sha256 == retired.control_identity_sha256 if abandoned else _retirement_binding_matches(existing, retired))
            ):
                return existing
            raise ControlConflictError("cleanup completion did not converge") from error
        updated = self._updated(response, "cleanup completion")
        if (
            updated.state != retired.state
            or updated.cleanup_state != "complete"
            or (updated.control_identity_sha256 != retired.control_identity_sha256 if abandoned else not _retirement_binding_matches(updated, retired))
        ):
            raise ControlStoreError(
                "DynamoDB cleanup completion returned the wrong evidence"
            )
        return updated

    def abandon_staged(
        self,
        staged: ResultControlRecord,
        *,
        abandoned_at: str,
        now_epoch_ms: int,
    ) -> ResultControlRecord:
        if not isinstance(staged, ResultControlRecord) or staged.state != "staged":
            raise ValueError("DynamoDB abandonment requires a staged control record")
        canonical_timestamp(abandoned_at, "abandonment time")
        now_epoch_ms = _validate_epoch(now_epoch_ms, "abandonment timestamp")
        if timestamp_epoch_ms(abandoned_at, "abandonment time") != now_epoch_ms:
            raise ValueError("DynamoDB abandonment timestamps disagree")
        deadline = staged.staging_expires_at_epoch_ms
        if deadline is None or deadline > now_epoch_ms:
            raise ControlNotExpiredError("staging deadline has not elapsed")
        names = {
            "#state": "state", "#identity": "controlIdentitySha256",
            "#revision": "revision", "#deadline": "stagingExpiresAtEpochMs",
            "#abandonedAt": "abandonedAt", "#cleanup": "cleanupState",
            "#gsiPk": "GSI1PK", "#gsiSk": "GSI1SK",
        }
        values = {
            ":staged": _s("staged"), ":abandoned": _s("abandoned"),
            ":identity": _s(staged.control_identity_sha256), ":zero": _n(0),
            ":one": _n(1), ":deadline": _n(deadline), ":now": _n(now_epoch_ms),
            ":abandonedAt": _s(abandoned_at), ":pending": _s("pending"),
            ":workPk": _s(WORK_PARTITION), ":workSk": _n(now_epoch_ms),
        }
        try:
            response = self._client.update_item(
                TableName=self._table, Key=_key(staged.result_id),
                UpdateExpression=("SET #state = :abandoned, #abandonedAt = :abandonedAt, "
                                 "#cleanup = :pending, #revision = #revision + :one, "
                                 "#gsiPk = :workPk, #gsiSk = :workSk"),
                ConditionExpression=("#state = :staged AND #revision = :zero "
                                     "AND #identity = :identity AND #deadline = :deadline "
                                     "AND #deadline <= :now"),
                ExpressionAttributeNames=names, ExpressionAttributeValues=values,
                ReturnValues="ALL_NEW", ReturnValuesOnConditionCheckFailure="ALL_OLD",
                ReturnConsumedCapacity="TOTAL",
            )
        except Exception as error:
            if not _is_conditional(error):
                raise _provider_failure("DynamoDB staged abandonment failed", error) from error
            existing = self._read(staged.result_id)
            if existing is None:
                raise ControlMissingError("staged control item disappeared") from error
            if (existing.state == "abandoned" and existing.control_identity_sha256 == staged.control_identity_sha256
                    and existing.abandoned_at == abandoned_at):
                return existing
            if existing.state == "staged" and existing.control_identity_sha256 == staged.control_identity_sha256:
                if existing.staging_expires_at_epoch_ms is not None and existing.staging_expires_at_epoch_ms > now_epoch_ms:
                    raise ControlNotExpiredError("staging deadline has not elapsed") from error
            raise ControlConflictError("staged abandonment did not converge") from error
        updated = self._updated(response, "staged abandonment")
        if (updated.state != "abandoned" or updated.control_identity_sha256 != staged.control_identity_sha256
                or updated.abandoned_at != abandoned_at or updated.cleanup_state != "pending"):
            raise ControlStoreError("DynamoDB abandonment returned the wrong evidence")
        return updated

    def list_expired_staged(
        self,
        now_epoch_ms: int,
        *,
        limit: int = 100,
        next_token: Mapping[str, Any] | None = None,
    ) -> tuple[tuple[ResultControlRecord, ...], Mapping[str, Any] | None]:
        now_epoch_ms = _validate_epoch(now_epoch_ms, "staged query boundary")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("staged query limit must be from 1 to 100")
        args: dict[str, object] = {
            "TableName": self._table, "IndexName": self._expiry_index,
            "KeyConditionExpression": "#gpk = :stagedPk AND #gsk <= :now",
            "ProjectionExpression": "#pk, #sk",
            "ExpressionAttributeNames": {"#gpk": "GSI1PK", "#gsk": "GSI1SK", "#pk": "PK", "#sk": "SK"},
            "ExpressionAttributeValues": {":stagedPk": _s(STAGED_EXPIRY_PARTITION), ":now": _n(now_epoch_ms)},
            "Limit": limit, "ReturnConsumedCapacity": "TOTAL",
        }
        if next_token is not None:
            args["ExclusiveStartKey"] = _validated_staged_cursor(next_token, provider_response=False, maximum_epoch_ms=now_epoch_ms)
        try:
            response = self._client.query(**args)
        except Exception as error:
            raise _provider_failure("DynamoDB staged query failed", error) from error
        if not isinstance(response, Mapping) or not isinstance(response.get("Items", []), list):
            raise ControlStoreError("DynamoDB staged query response is malformed")
        items = response.get("Items", [])
        if len(items) > limit:
            raise ControlStoreError("DynamoDB staged query exceeded its requested limit")
        ids: list[str] = []
        for item in items:
            if not isinstance(item, Mapping) or set(item) != {"PK", "SK"}:
                raise ControlStoreError("DynamoDB staged candidate is malformed")
            partition = _av_string(item["PK"], "staged candidate partition key")
            if not partition.startswith("RESULT#") or _av_string(item["SK"], "staged candidate sort key") != "CONTROL":
                raise ControlStoreError("DynamoDB staged candidate key drifted")
            ids.append(_validate_result_id(partition.removeprefix("RESULT#")))
        if len(set(ids)) != len(ids):
            raise ControlStoreError("DynamoDB staged query repeated a result")
        records = []
        for result_id in ids:
            record = self._read(result_id)
            if (record is not None and record.state == "staged"
                    and record.staging_expires_at_epoch_ms is not None
                    and record.staging_expires_at_epoch_ms <= now_epoch_ms):
                records.append(record)
        cursor = response.get("LastEvaluatedKey")
        token = None if cursor is None else _validated_staged_cursor(cursor, provider_response=True, maximum_epoch_ms=now_epoch_ms)
        return tuple(records), token

    def list_expired(
        self,
        now_epoch_ms: int,
        *,
        limit: int = 100,
        next_token: Mapping[str, Any] | None = None,
    ) -> tuple[tuple[ResultControlRecord, ...], Mapping[str, Any] | None]:
        if (
            isinstance(now_epoch_ms, bool)
            or not isinstance(now_epoch_ms, int)
            or now_epoch_ms < 0
        ):
            raise ValueError("expiry query boundary must be a non-negative integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("expiry query limit must be from 1 to 100")
        arguments: dict[str, object] = {
            "TableName": self._table,
            "IndexName": self._expiry_index,
            "KeyConditionExpression": "#gpk = :expiryPk AND #gsk <= :now",
            "ProjectionExpression": "#pk, #sk",
            "ExpressionAttributeNames": {
                "#gpk": "GSI1PK",
                "#gsk": "GSI1SK",
                "#pk": "PK",
                "#sk": "SK",
            },
            "ExpressionAttributeValues": {
                ":expiryPk": _s(EXPIRY_PARTITION),
                ":now": _n(now_epoch_ms),
            },
            "Limit": limit,
            "ReturnConsumedCapacity": "TOTAL",
        }
        if next_token is not None:
            arguments["ExclusiveStartKey"] = _validated_expiry_cursor(
                next_token,
                provider_response=False,
                maximum_epoch_ms=now_epoch_ms,
            )
        try:
            response = self._client.query(**arguments)
        except Exception as error:
            raise _provider_failure("DynamoDB expiry query failed", error) from error
        if not isinstance(response, Mapping) or not isinstance(response.get("Items", []), list):
            raise ControlStoreError("DynamoDB expiry query response is malformed")
        if len(response.get("Items", [])) > limit:
            raise ControlStoreError("DynamoDB expiry query exceeded its requested limit")
        result_ids: list[str] = []
        for item in response.get("Items", []):
            if not isinstance(item, Mapping) or set(item) != {"PK", "SK"}:
                raise ControlStoreError("DynamoDB expiry candidate is malformed")
            partition = _av_string(item["PK"], "expiry candidate partition key")
            if (
                not partition.startswith("RESULT#")
                or _av_string(item["SK"], "expiry candidate sort key") != "CONTROL"
            ):
                raise ControlStoreError("DynamoDB expiry candidate key drifted")
            result_ids.append(_validate_result_id(partition.removeprefix("RESULT#")))
        if len(set(result_ids)) != len(result_ids):
            raise ControlStoreError("DynamoDB expiry query repeated a result")
        records: list[ResultControlRecord] = []
        for result_id in result_ids:
            record = self._read(result_id)
            if (
                record is not None
                and record.state == "live"
                and record.expires_at_epoch_ms is not None
                and record.expires_at_epoch_ms <= now_epoch_ms
            ):
                records.append(record)
        cursor = response.get("LastEvaluatedKey")
        validated_cursor = (
            None
            if cursor is None
            else _validated_expiry_cursor(
                cursor,
                provider_response=True,
                maximum_epoch_ms=now_epoch_ms,
            )
        )
        return tuple(records), validated_cursor

    def list_pending_work(
        self,
        now_epoch_ms: int,
        *,
        limit: int = 100,
        next_token: Mapping[str, Any] | None = None,
    ) -> tuple[tuple[ResultControlRecord, ...], Mapping[str, Any] | None]:
        """Discover retiring and not-yet-cleaned tombstones using the shared GSI."""
        if (
            isinstance(now_epoch_ms, bool)
            or not isinstance(now_epoch_ms, int)
            or now_epoch_ms < 0
        ):
            raise ValueError("pending-work query boundary must be a non-negative integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("pending-work query limit must be from 1 to 100")
        arguments: dict[str, object] = {
            "TableName": self._table,
            "IndexName": self._expiry_index,
            "KeyConditionExpression": "#gpk = :workPk AND #gsk <= :now",
            "ProjectionExpression": "#pk, #sk",
            "ExpressionAttributeNames": {
                "#gpk": "GSI1PK",
                "#gsk": "GSI1SK",
                "#pk": "PK",
                "#sk": "SK",
            },
            "ExpressionAttributeValues": {
                ":workPk": _s(WORK_PARTITION),
                ":now": _n(now_epoch_ms),
            },
            "Limit": limit,
            "ReturnConsumedCapacity": "TOTAL",
        }
        if next_token is not None:
            arguments["ExclusiveStartKey"] = _validated_work_cursor(
                next_token,
                provider_response=False,
                maximum_epoch_ms=now_epoch_ms,
            )
        try:
            response = self._client.query(**arguments)
        except Exception as error:
            raise _provider_failure("DynamoDB pending-work query failed", error) from error
        if not isinstance(response, Mapping) or not isinstance(response.get("Items", []), list):
            raise ControlStoreError("DynamoDB pending-work query response is malformed")
        if len(response.get("Items", [])) > limit:
            raise ControlStoreError("DynamoDB pending-work query exceeded its requested limit")
        result_ids: list[str] = []
        for item in response.get("Items", []):
            if not isinstance(item, Mapping) or set(item) != {"PK", "SK"}:
                raise ControlStoreError("DynamoDB pending-work candidate is malformed")
            partition = _av_string(item["PK"], "pending-work candidate partition key")
            if (
                not partition.startswith("RESULT#")
                or _av_string(item["SK"], "pending-work candidate sort key") != "CONTROL"
            ):
                raise ControlStoreError("DynamoDB pending-work candidate key drifted")
            result_ids.append(_validate_result_id(partition.removeprefix("RESULT#")))
        if len(set(result_ids)) != len(result_ids):
            raise ControlStoreError("DynamoDB pending-work query repeated a result")
        records: list[ResultControlRecord] = []
        for result_id in result_ids:
            record = self._read(result_id)
            if (
                record is not None
                and (record.state == "retiring" or (
                    record.state == "retired" and record.cleanup_state == "pending"
                ) or (record.state == "abandoned" and record.cleanup_state == "pending"))
                and (record.abandoned_at is not None if record.state == "abandoned" else record.retired_at is not None)
                and timestamp_epoch_ms(
                    record.abandoned_at if record.state == "abandoned" else record.retired_at,
                    "lifecycle work time",
                ) <= now_epoch_ms
            ):
                records.append(record)
        cursor = response.get("LastEvaluatedKey")
        validated_cursor = (
            None
            if cursor is None
            else _validated_work_cursor(
                cursor,
                provider_response=True,
                maximum_epoch_ms=now_epoch_ms,
            )
        )
        return tuple(records), validated_cursor


def dynamodb_control_store_from_environment(
    *,
    environ: Mapping[str, str] | None = None,
    client_factory: Callable[[str], DynamoDBClient] | None = None,
) -> DynamoDBControlStore:
    values = os.environ if environ is None else environ
    table = values.get("DOM_XRAY_DYNAMODB_TABLE", "")
    index = values.get("DOM_XRAY_DYNAMODB_EXPIRY_INDEX", DEFAULT_EXPIRY_INDEX)
    ttl_disabled_at = values.get("DOM_XRAY_DYNAMODB_TTL_DISABLED_AT_EPOCH", "")
    if not table:
        raise ValueError("DOM_XRAY_DYNAMODB_TABLE is required")
    if re.fullmatch(r"0|[1-9][0-9]*", ttl_disabled_at) is None:
        raise ValueError(
            "DOM_XRAY_DYNAMODB_TTL_DISABLED_AT_EPOCH is required"
        )
    if client_factory is None:
        try:
            import boto3  # type: ignore[import-not-found]
        except ModuleNotFoundError as error:
            raise ControlStoreError(
                "Boto3 is required for the DynamoDB deployment adapter"
            ) from error
        client_factory = boto3.client
    return DynamoDBControlStore(
        client_factory("dynamodb"),
        table,
        expiry_index_name=index,
        ttl_disabled_at_epoch=int(ttl_disabled_at),
    )


__all__ = [
    "ControlCollisionError",
    "ControlConflictError",
    "ControlMissingError",
    "ControlNotExpiredError",
    "ControlStoreError",
    "DynamoDBControlStore",
    "decode_control_item",
    "dynamodb_control_store_from_environment",
    "encode_control_item",
]
