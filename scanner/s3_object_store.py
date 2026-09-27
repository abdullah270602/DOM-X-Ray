"""Version-bound immutable S3 object storage for DOM X-Ray delivery."""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import time
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from scanner.artifact_delivery import DELIVERY_VERSION, DeliveryObjectRef
from scanner.delivery_storage import (
    ImmutableObjectCollisionError,
    PrivateObjectMissingError,
    PrivateObjectStoreError,
    PrivateObjectVersion,
    validate_object_payload,
    validate_object_reference,
)


BUCKET_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
ACCOUNT_ID_PATTERN = re.compile(r"^[0-9]{12}$")
MAX_CONDITIONAL_CONFLICT_RETRIES = 3
TRANSIENT_CODES = {
    "409",
    "ConditionalRequestConflict",
    "InternalError",
    "RequestTimeout",
    "RequestTimeoutException",
    "ServiceUnavailable",
    "SlowDown",
    "Throttling",
    "ThrottlingException",
}
DENIED_CODES = {
    "AccessDenied",
    "AllAccessDisabled",
    "AuthorizationHeaderMalformed",
    "ExpiredToken",
    "InvalidAccessKeyId",
    "InvalidToken",
    "KMSAccessDeniedException",
    "SignatureDoesNotMatch",
}
TRANSIENT_EXCEPTION_NAMES = {
    "ConnectTimeoutError",
    "ConnectionClosedError",
    "EndpointConnectionError",
    "ReadTimeoutError",
}


class S3Client(Protocol):
    def get_bucket_versioning(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def get_public_access_block(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def get_bucket_ownership_controls(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def put_object(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def head_object(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def get_object(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def delete_object(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def list_object_versions(self, **kwargs: Any) -> Mapping[str, Any]: ...


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


def _is_missing(error: Exception) -> bool:
    code, _status = _error_identity(error)
    return code in {"404", "NoSuchKey", "NoSuchVersion", "NotFound"}


def _is_precondition(error: Exception) -> bool:
    code, status = _error_identity(error)
    return status == 412 or code in {"412", "PreconditionFailed"}


def _is_conflict(error: Exception) -> bool:
    code, status = _error_identity(error)
    return status == 409 or code in {"409", "ConditionalRequestConflict"}


def _provider_failure(message: str, error: Exception) -> PrivateObjectStoreError:
    code, status = _error_identity(error)
    if code in DENIED_CODES or status in {401, 403}:
        return PrivateObjectStoreError(message, code="provider-denied")
    if (
        code in TRANSIENT_CODES
        or status in {408, 429}
        or status is not None
        and 500 <= status <= 599
        or type(error).__name__ in TRANSIENT_EXCEPTION_NAMES
        or isinstance(error, (ConnectionError, TimeoutError))
    ):
        return PrivateObjectStoreError(
            message,
            code="provider-transient",
            retryable=True,
        )
    return PrivateObjectStoreError(message)


def _default_conflict_backoff(attempt: int) -> None:
    time.sleep(min(0.025 * (2**attempt), 0.1))


def _validate_bucket_name(bucket: object) -> str:
    if not isinstance(bucket, str) or BUCKET_PATTERN.fullmatch(bucket) is None:
        raise ValueError("invalid S3 bucket name")
    if ".." in bucket:
        raise ValueError("invalid S3 bucket name")
    try:
        ipaddress.ip_address(bucket)
    except ValueError:
        return bucket
    raise ValueError("S3 bucket name must not be an IP address")


def _version_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1024
        or any(not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise PrivateObjectStoreError("S3 response omitted a valid object version ID")
    return value


def _checksum(reference: DeliveryObjectRef) -> str:
    return base64.b64encode(bytes.fromhex(reference.sha256)).decode("ascii")


def _metadata(reference: DeliveryObjectRef) -> dict[str, str]:
    return {
        "dom-xray-delivery-version": DELIVERY_VERSION,
        "dom-xray-byte-length": str(reference.byte_length),
        "dom-xray-sha256": reference.sha256,
        "dom-xray-result-id": reference.result_id,
        "dom-xray-kind": reference.kind,
    }


class S3PrivateObjectStore:
    """Private, version-bound S3 storage with permanent exact-version deletion."""

    def __init__(
        self,
        client: S3Client,
        bucket: str,
        expected_bucket_owner: str,
        *,
        conflict_backoff: Callable[[int], None] = _default_conflict_backoff,
    ) -> None:
        self._client = client
        self._bucket = _validate_bucket_name(bucket)
        if (
            not isinstance(expected_bucket_owner, str)
            or ACCOUNT_ID_PATTERN.fullmatch(expected_bucket_owner) is None
        ):
            raise ValueError("expected S3 bucket owner must be a 12-digit account ID")
        self._expected_owner = expected_bucket_owner
        if not callable(conflict_backoff):
            raise ValueError("S3 conflict backoff must be callable")
        self._conflict_backoff = conflict_backoff
        self.verify_bucket_configuration()

    @property
    def provider_target_id(self) -> str:
        return f"aws:s3:{self._expected_owner}:{self._bucket}"

    def _bucket_args(self) -> dict[str, str]:
        return {
            "Bucket": self._bucket,
            "ExpectedBucketOwner": self._expected_owner,
        }

    def verify_bucket_configuration(self) -> None:
        try:
            versioning = self._client.get_bucket_versioning(**self._bucket_args())
            access = self._client.get_public_access_block(**self._bucket_args())
            ownership = self._client.get_bucket_ownership_controls(**self._bucket_args())
        except Exception as error:
            raise _provider_failure(
                "S3 bucket configuration could not be verified",
                error,
            ) from error
        if not all(isinstance(value, Mapping) for value in (versioning, access, ownership)):
            raise PrivateObjectStoreError("S3 bucket configuration response is malformed")
        if versioning.get("Status") != "Enabled":
            raise PrivateObjectStoreError("S3 delivery bucket must have versioning enabled")
        block = access.get("PublicAccessBlockConfiguration")
        required = {
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        }
        if (
            not isinstance(block, Mapping)
            or any(block.get(field) is not True for field in required)
        ):
            raise PrivateObjectStoreError("S3 delivery bucket must block all public access")
        controls = ownership.get("OwnershipControls")
        rules = controls.get("Rules") if isinstance(controls, Mapping) else None
        if (
            not isinstance(rules, list)
            or len(rules) != 1
            or not isinstance(rules[0], Mapping)
            or rules[0].get("ObjectOwnership") != "BucketOwnerEnforced"
        ):
            raise PrivateObjectStoreError(
                "S3 delivery bucket must enforce bucket-owner object ownership"
            )

    def _validate_headers(
        self,
        response: Mapping[str, Any],
        reference: DeliveryObjectRef,
        *,
        expected_version_id: str | None = None,
    ) -> str:
        metadata = response.get("Metadata")
        content_length = response.get("ContentLength")
        actual_version = _version_id(response.get("VersionId"))
        if (
            not isinstance(metadata, Mapping)
            or dict(metadata) != _metadata(reference)
            or isinstance(content_length, bool)
            or content_length != reference.byte_length
            or response.get("ContentType") != reference.media_type
            or response.get("CacheControl") != "no-store"
            or response.get("ChecksumSHA256") != _checksum(reference)
            or (
                expected_version_id is not None
                and actual_version != expected_version_id
            )
        ):
            raise ImmutableObjectCollisionError("S3 object identity does not match its registry")
        return actual_version

    def _head(
        self,
        reference: DeliveryObjectRef,
        *,
        version_id: str | None = None,
    ) -> str:
        arguments: dict[str, object] = {
            **self._bucket_args(),
            "Key": reference.key,
            "ChecksumMode": "ENABLED",
        }
        if version_id is not None:
            arguments["VersionId"] = version_id
        try:
            response = self._client.head_object(**arguments)
        except Exception as error:
            if _is_missing(error):
                raise PrivateObjectMissingError("registered S3 object is missing") from error
            raise _provider_failure("S3 object identity could not be read", error) from error
        if not isinstance(response, Mapping):
            raise PrivateObjectStoreError("S3 object identity response is malformed")
        return self._validate_headers(
            response,
            reference,
            expected_version_id=version_id,
        )

    def _validate_version(self, version: PrivateObjectVersion) -> DeliveryObjectRef:
        if not isinstance(version, PrivateObjectVersion):
            raise ValueError("S3 object operation requires a private object version")
        if version.provider_target_id != self.provider_target_id:
            raise ValueError("S3 object belongs to a different provider target")
        validate_object_reference(version.reference)
        return version.reference

    def put(
        self,
        reference: DeliveryObjectRef,
        payload: bytes,
    ) -> PrivateObjectVersion:
        validate_object_payload(reference, payload)
        arguments: dict[str, object] = {
            **self._bucket_args(),
            "Key": reference.key,
            "Body": payload,
            "ContentType": reference.media_type,
            "CacheControl": "no-store",
            "ChecksumSHA256": _checksum(reference),
            "Metadata": _metadata(reference),
            "IfNoneMatch": "*",
        }
        response: Mapping[str, Any] | None = None
        for attempt in range(MAX_CONDITIONAL_CONFLICT_RETRIES + 1):
            try:
                response = self._client.put_object(**arguments)
                break
            except Exception as error:
                if _is_precondition(error):
                    version_id = self._head(reference)
                    existing = PrivateObjectVersion(
                        reference=reference,
                        provider_target_id=self.provider_target_id,
                        provider_version_id=version_id,
                        created=False,
                    )
                    self.get(existing)
                    return existing
                if _is_conflict(error) and attempt < MAX_CONDITIONAL_CONFLICT_RETRIES:
                    self._conflict_backoff(attempt)
                    continue
                raise _provider_failure("conditional S3 object creation failed", error) from error
        if response is None:
            raise PrivateObjectStoreError("conditional S3 object creation did not complete")
        if not isinstance(response, Mapping):
            raise PrivateObjectStoreError("S3 object creation response is malformed")
        version_id = _version_id(response.get("VersionId"))
        created = PrivateObjectVersion(
            reference=reference,
            provider_target_id=self.provider_target_id,
            provider_version_id=version_id,
            created=True,
        )
        if self.get(created) != payload:
            raise PrivateObjectStoreError("S3 readback changed the uploaded object")
        return created

    def get(self, version: PrivateObjectVersion) -> bytes:
        reference = self._validate_version(version)
        try:
            response = self._client.get_object(
                **self._bucket_args(),
                Key=reference.key,
                VersionId=version.provider_version_id,
                ChecksumMode="ENABLED",
            )
        except Exception as error:
            if _is_missing(error):
                raise PrivateObjectMissingError("registered S3 object version is missing") from error
            raise _provider_failure("S3 object could not be read", error) from error
        if not isinstance(response, Mapping):
            raise PrivateObjectStoreError("S3 object response is malformed")
        self._validate_headers(
            response,
            reference,
            expected_version_id=version.provider_version_id,
        )
        body = response.get("Body")
        reader = getattr(body, "read", None)
        closer = getattr(body, "close", None)
        if not callable(reader):
            raise PrivateObjectStoreError("S3 object response has no readable body")
        read_error: Exception | None = None
        try:
            payload = reader(reference.byte_length + 1)
        except Exception as error:
            read_error = error
            payload = None
        close_error: Exception | None = None
        if callable(closer):
            try:
                closer()
            except Exception as error:
                close_error = error
        if read_error is not None:
            raise PrivateObjectStoreError(
                "S3 object body could not be read",
                code="provider-transient",
                retryable=True,
            ) from read_error
        if close_error is not None:
            raise PrivateObjectStoreError(
                "S3 object body could not be closed",
                code="provider-transient",
                retryable=True,
            ) from close_error
        if not isinstance(payload, bytes):
            raise PrivateObjectStoreError("S3 object body did not return bytes")
        try:
            return validate_object_payload(reference, payload)
        except ValueError as error:
            raise ImmutableObjectCollisionError("S3 object bytes failed identity validation") from error

    def _assert_no_versions(self, reference: DeliveryObjectRef) -> None:
        try:
            response = self._client.list_object_versions(
                **self._bucket_args(),
                Prefix=reference.key,
                MaxKeys=1000,
            )
        except Exception as error:
            raise _provider_failure("S3 object versions could not be verified", error) from error
        if not isinstance(response, Mapping):
            raise PrivateObjectStoreError("S3 object version listing is malformed")
        if response.get("IsTruncated") is not False:
            raise PrivateObjectStoreError("S3 object has an unbounded version history")
        residual: list[object] = []
        for field in ("Versions", "DeleteMarkers"):
            values = response.get(field, [])
            if not isinstance(values, list):
                raise PrivateObjectStoreError("S3 version listing is malformed")
            for value in values:
                if not isinstance(value, Mapping):
                    raise PrivateObjectStoreError("S3 version listing is malformed")
                key = value.get("Key")
                if not isinstance(key, str):
                    raise PrivateObjectStoreError("S3 version listing is malformed")
                try:
                    _version_id(value.get("VersionId"))
                except PrivateObjectStoreError as error:
                    raise PrivateObjectStoreError("S3 version listing is malformed") from error
                if key == reference.key:
                    residual.append(value)
        if residual:
            raise PrivateObjectStoreError("S3 object deletion left a residual version")

    def delete(self, version: PrivateObjectVersion) -> None:
        reference = self._validate_version(version)
        try:
            response = self._client.delete_object(
                **self._bucket_args(),
                Key=reference.key,
                VersionId=version.provider_version_id,
            )
        except Exception as error:
            if not _is_missing(error):
                raise _provider_failure("S3 object version could not be deleted", error) from error
            response = {}
        if not isinstance(response, Mapping):
            raise PrivateObjectStoreError("S3 object deletion response is malformed")
        returned_version = response.get("VersionId")
        if returned_version is not None and returned_version != version.provider_version_id:
            raise PrivateObjectStoreError("S3 deleted a different object version")
        try:
            self._head(reference, version_id=version.provider_version_id)
        except PrivateObjectMissingError:
            pass
        else:
            raise PrivateObjectStoreError("S3 object version remained after deletion")
        self._assert_no_versions(reference)


def s3_object_store_from_environment(
    *,
    environ: Mapping[str, str] | None = None,
    client_factory: Callable[[str], S3Client] | None = None,
) -> S3PrivateObjectStore:
    values = os.environ if environ is None else environ
    bucket = values.get("DOM_XRAY_S3_BUCKET", "")
    owner = values.get("DOM_XRAY_AWS_ACCOUNT_ID", "")
    if not bucket or not owner:
        raise ValueError("DOM_XRAY_S3_BUCKET and DOM_XRAY_AWS_ACCOUNT_ID are required")
    if client_factory is None:
        try:
            import boto3  # type: ignore[import-not-found]
        except ModuleNotFoundError as error:
            raise PrivateObjectStoreError(
                "Boto3 is required for the S3 deployment adapter"
            ) from error
        client_factory = boto3.client
    return S3PrivateObjectStore(client_factory("s3"), bucket, owner)
