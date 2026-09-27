"""CloudFront cache-purge adapter for the artifact-delivery lifecycle.

The adapter is deliberately non-blocking: one call submits or reuses an
idempotent invalidation and observes its current status.  ``InProgress`` maps
to a pending result so the durable delivery lifecycle can retry later;
``Completed`` is the only status that becomes a confirmed purge receipt.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol

from scanner.artifact_delivery import (
    ArtifactDeliveryError,
    CachePurgeResult,
    DeliveryObjectRef,
    purge_coverage_sha256,
)


DISTRIBUTION_ID_PATTERN = re.compile(r"^[A-Za-z0-9]{1,128}$")
OPERATION_ID_PATTERN = re.compile(r"^p_[0-9a-f]{32}$")
RESULT_ID_PATTERN = re.compile(r"^r_[0-9a-f]{32}$")
OBJECT_FILENAMES = {
    "bundle": "bundle.json",
    "poster": "poster.png",
    "video": "video.mp4",
}


class CloudFrontPurgeError(ArtifactDeliveryError):
    """Raised when CloudFront does not return the expected invalidation identity."""


class CloudFrontClient(Protocol):
    """Narrow subset of the Boto3 CloudFront client used by this adapter."""

    def create_invalidation(
        self,
        *,
        DistributionId: str,
        InvalidationBatch: dict[str, object],
    ) -> Mapping[str, Any]: ...

    def get_invalidation(
        self,
        *,
        DistributionId: str,
        Id: str,
    ) -> Mapping[str, Any]: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CloudFrontPurgeError("CloudFront purge clock must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _validated_coverage(
    result_id: str,
    public_paths: tuple[str, ...],
    objects: tuple[DeliveryObjectRef, ...],
) -> str:
    if RESULT_ID_PATTERN.fullmatch(result_id) is None:
        raise ValueError("invalid CloudFront purge result ID")
    if not objects:
        raise ValueError("CloudFront purge has no delivery objects")
    kinds = tuple(reference.kind for reference in objects)
    expected_kinds = tuple(kind for kind in ("bundle", "poster", "video") if kind in kinds)
    if kinds != expected_kinds or kinds[0] != "bundle" or len(set(kinds)) != len(kinds):
        raise ValueError("CloudFront purge object order is invalid")
    expected_public_paths = [f"/r/{result_id}"]
    for reference in objects:
        filename = OBJECT_FILENAMES[reference.kind]
        expected_path = (
            f"/api/results/{result_id}"
            if reference.kind == "bundle"
            else f"/api/results/{result_id}/{filename}"
        )
        if (
            reference.result_id != result_id
            or reference.key != f"v1/results/{result_id}/{filename}"
            or reference.public_path != expected_path
        ):
            raise ValueError("CloudFront purge object identity drifted")
        expected_public_paths.append(expected_path)
    if public_paths != tuple(expected_public_paths):
        raise ValueError("CloudFront purge paths do not match the delivery objects")
    return purge_coverage_sha256(result_id, public_paths, objects)


def _invalidation_paths(public_paths: tuple[str, ...]) -> tuple[str, ...]:
    # A trailing CloudFront wildcard also matches the bare canonical path and
    # every query-string variant.  The application rejects meaningful route
    # suffixes, so this is intentionally broader than one cache-key variant.
    return tuple(f"{path}*" for path in public_paths)


def _read_invalidation(
    response: Mapping[str, Any],
    *,
    operation_id: str,
    expected_paths: tuple[str, ...],
    expected_id: str | None = None,
) -> tuple[str, str]:
    invalidation = response.get("Invalidation")
    if not isinstance(invalidation, Mapping):
        raise CloudFrontPurgeError("CloudFront response omitted its invalidation")
    invalidation_id = invalidation.get("Id")
    status = invalidation.get("Status")
    batch = invalidation.get("InvalidationBatch")
    if (
        not isinstance(invalidation_id, str)
        or not 1 <= len(invalidation_id) <= 256
        or any(ord(character) < 0x21 for character in invalidation_id)
        or (expected_id is not None and invalidation_id != expected_id)
        or status not in {"InProgress", "Completed"}
        or not isinstance(batch, Mapping)
    ):
        raise CloudFrontPurgeError("CloudFront invalidation identity is malformed")
    paths = batch.get("Paths")
    if not isinstance(paths, Mapping):
        raise CloudFrontPurgeError("CloudFront invalidation paths are missing")
    items = paths.get("Items")
    quantity = paths.get("Quantity")
    if (
        batch.get("CallerReference") != operation_id
        or isinstance(quantity, bool)
        or not isinstance(quantity, int)
        or quantity != len(expected_paths)
        or not isinstance(items, list)
        or tuple(items) != expected_paths
    ):
        raise CloudFrontPurgeError("CloudFront invalidation coverage drifted")
    return invalidation_id, status


class CloudFrontCachePurger:
    """Map one DOM X-Ray purge operation to one CloudFront invalidation."""

    def __init__(
        self,
        client: CloudFrontClient,
        distribution_id: str,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if (
            not isinstance(distribution_id, str)
            or DISTRIBUTION_ID_PATTERN.fullmatch(distribution_id) is None
        ):
            raise ValueError("invalid CloudFront distribution ID")
        self._client = client
        self._distribution_id = distribution_id
        self._clock = clock

    @property
    def distribution_id(self) -> str:
        return self._distribution_id

    @property
    def provider_target_id(self) -> str:
        return f"aws:cloudfront:{self._distribution_id}"

    def purge(
        self,
        *,
        operation_id: str,
        result_id: str,
        public_paths: tuple[str, ...],
        objects: tuple[DeliveryObjectRef, ...],
    ) -> CachePurgeResult:
        if OPERATION_ID_PATTERN.fullmatch(operation_id) is None:
            raise ValueError("invalid CloudFront purge operation ID")
        coverage = _validated_coverage(result_id, public_paths, objects)
        invalidation_paths = _invalidation_paths(public_paths)
        batch: dict[str, object] = {
            "Paths": {
                "Quantity": len(invalidation_paths),
                "Items": list(invalidation_paths),
            },
            "CallerReference": operation_id,
        }
        created = self._client.create_invalidation(
            DistributionId=self._distribution_id,
            InvalidationBatch=batch,
        )
        invalidation_id, status = _read_invalidation(
            created,
            operation_id=operation_id,
            expected_paths=invalidation_paths,
        )
        if status == "InProgress":
            observed = self._client.get_invalidation(
                DistributionId=self._distribution_id,
                Id=invalidation_id,
            )
            observed_id, status = _read_invalidation(
                observed,
                operation_id=operation_id,
                expected_paths=invalidation_paths,
                expected_id=invalidation_id,
            )
            if observed_id != invalidation_id:
                raise CloudFrontPurgeError("CloudFront changed invalidation identity")
        if status == "Completed":
            return CachePurgeResult(
                operation_id=operation_id,
                state="confirmed",
                coverage_sha256=coverage,
                provider_target_id=self.provider_target_id,
                provider_request_id=invalidation_id,
                confirmed_at=_timestamp(self._clock()),
            )
        return CachePurgeResult(
            operation_id=operation_id,
            state="pending",
            coverage_sha256=coverage,
            provider_target_id=self.provider_target_id,
            provider_request_id=invalidation_id,
        )


def cloudfront_purger_from_environment(
    *,
    environ: Mapping[str, str] | None = None,
    client_factory: Callable[[str], CloudFrontClient] | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> CloudFrontCachePurger:
    """Build the adapter from the runtime role and one distribution setting."""

    values = os.environ if environ is None else environ
    distribution_id = values.get("DOM_XRAY_CLOUDFRONT_DISTRIBUTION_ID", "")
    if not distribution_id:
        raise ValueError("DOM_XRAY_CLOUDFRONT_DISTRIBUTION_ID is required")
    if client_factory is None:
        try:
            import boto3  # type: ignore[import-not-found]
        except ModuleNotFoundError as error:
            raise CloudFrontPurgeError(
                "Boto3 is required for the CloudFront deployment adapter"
            ) from error
        client_factory = boto3.client
    return CloudFrontCachePurger(
        client_factory("cloudfront"),
        distribution_id,
        clock=clock,
    )
