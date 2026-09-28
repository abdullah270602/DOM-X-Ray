"""One application-facing result backend over private objects and control state.

The control store is the sole visibility authority. Private objects remain
unservable until a validated, version-bound control record becomes live.
"""

from __future__ import annotations

import json
import math
import secrets
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, Sequence

from scanner.artifact_delivery import (
    ArtifactDeliveryError,
    CachePurger,
    DeliveryCachePolicy,
    DeliveryObjectRef,
    build_delivery_batch,
)
from scanner.delivery_control import (
    ResultControlRecord,
    build_retirement_plan,
    build_staged_control,
    canonical_timestamp,
)
from scanner.delivery_storage import (
    PrivateObjectStore,
    PrivateObjectVersion,
    validate_object_payload,
)
from scanner.result_store import (
    ARTIFACT_KINDS,
    DELETE_TOKEN_PATTERN,
    RESULT_ID_PATTERN,
    SHA256_PATTERN,
    ArtifactKind,
    DeleteOutcome,
    Publication,
    ResultStoreError,
    StoredArtifact,
    StoredResult,
    _bundle_identity,
    _publication,
    _stored_artifact,
    _validate_artifact_kind,
    _validate_result_id,
)


class DeletionKeyring(Protocol):
    """Minimal bridge to the keyring shared with other result backends.

    ``sign_digest`` returns the active key ID and its HMAC of the public
    SHA-256 token digest. ``verify_digest`` is used when resuming an existing
    staged publication, and ``verify_token`` authenticates raw delete tokens.
    """

    def sign_digest(self, public_digest: str) -> tuple[str, str]: ...

    def verify_digest(
        self,
        key_id: str,
        public_digest: str,
        protected_digest: str,
    ) -> bool: ...

    def verify_token(
        self,
        token: str,
        key_id: str,
        protected_digest: str,
    ) -> bool: ...


class ControlStore(Protocol):
    """Lifecycle subset implemented by DynamoDBControlStore and test fakes."""

    def get_control(self, result_id: str) -> ResultControlRecord | None: ...

    def get_live(
        self,
        result_id: str,
        *,
        now_epoch_ms: int,
    ) -> ResultControlRecord | None: ...

    def create_staged(self, record: ResultControlRecord) -> ResultControlRecord: ...

    def activate(
        self,
        staged: ResultControlRecord,
        *,
        activated_at: str,
        now_epoch_ms: int,
    ) -> ResultControlRecord: ...

    def begin_retirement(
        self,
        live: ResultControlRecord,
        plan: Any,
        *,
        retired_at: str,
        require_expired: bool = False,
        now_epoch_ms: int | None = None,
    ) -> ResultControlRecord: ...

    def record_pending_purge(
        self,
        retiring: ResultControlRecord,
        *,
        provider_request_id: str,
    ) -> ResultControlRecord: ...

    def record_confirmed_purge(
        self,
        retiring: ResultControlRecord,
        *,
        provider_request_id: str,
        confirmed_at: str,
    ) -> ResultControlRecord: ...

    def finalize_retirement(self, retiring: ResultControlRecord) -> ResultControlRecord: ...

    def mark_cleanup_complete(self, retired: ResultControlRecord) -> ResultControlRecord: ...

    def list_expired(
        self,
        now_epoch_ms: int,
        *,
        limit: int = 100,
        next_token: Mapping[str, Any] | None = None,
    ) -> tuple[tuple[ResultControlRecord, ...], Mapping[str, Any] | None]: ...

    def list_pending_work(
        self,
        now_epoch_ms: int,
        *,
        limit: int = 100,
        next_token: Mapping[str, Any] | None = None,
    ) -> tuple[tuple[ResultControlRecord, ...], Mapping[str, Any] | None]: ...


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ResultStoreError("result backend clock must return a timezone-aware datetime")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _is_retryable(error: Exception) -> bool:
    return bool(getattr(error, "retryable", False)) or isinstance(
        error,
        (ConnectionError, TimeoutError),
    )


def _backend_error(message: str, error: Exception) -> ResultStoreError:
    return ResultStoreError(message, retryable=_is_retryable(error))


class _RetirementPending(ResultStoreError):
    """Raised only after visibility is durably fenced or already expired."""

    def __init__(self, message: str) -> None:
        super().__init__(message, retryable=True)


def _version(record_object: Any) -> PrivateObjectVersion:
    return PrivateObjectVersion(
        reference=record_object.reference,
        provider_target_id=record_object.provider_target_id,
        provider_version_id=record_object.provider_version_id,
        created=False,
    )


class CompositeResultBackend:
    """ResultBackend composed from private object and durable control providers."""

    def __init__(
        self,
        object_store: PrivateObjectStore,
        control_store: ControlStore,
        keyring: DeletionKeyring,
        *,
        retention_seconds: float | None = None,
        cache_policy: DeliveryCachePolicy | None = None,
        purger: CachePurger | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if retention_seconds is not None and (
            isinstance(retention_seconds, bool)
            or not isinstance(retention_seconds, (int, float))
            or not math.isfinite(retention_seconds)
            or retention_seconds <= 0
        ):
            raise ValueError("retention must be a positive finite duration")
        policy = cache_policy or DeliveryCachePolicy.no_store()
        if not isinstance(policy, DeliveryCachePolicy):
            raise ValueError("result backend requires a delivery cache policy")
        if policy.purge_required:
            if purger is None:
                raise ValueError("shared-cache delivery requires a cache purger")
        elif purger is not None:
            raise ValueError("a cache purger requires a purge-enabled cache policy")
        self._objects = object_store
        self._controls = control_store
        self._keyring = keyring
        self._retention_seconds = retention_seconds
        self._cache_policy = policy
        self._purger = purger
        self._clock = clock

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ResultStoreError("result backend clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    def _record_versions_match_batch(self, record: ResultControlRecord, batch: Any) -> bool:
        if record.publication_sha256 != batch.publication_sha256:
            return False
        if record.cache_control != self._cache_policy.value:
            return False
        if len(record.objects) != len(batch.objects):
            return False
        return all(
            registered.reference == reference
            and registered.provider_target_id == self._objects.provider_target_id
            for registered, (reference, _payload) in zip(record.objects, batch.objects, strict=True)
        )

    def _discard_unregistered_versions(
        self,
        versions: Sequence[PrivateObjectVersion],
        record: ResultControlRecord,
    ) -> None:
        registered = {
            (
                item.reference.key,
                item.provider_target_id,
                item.provider_version_id,
            )
            for item in record.objects
        }
        for version in versions:
            identity = (
                version.reference.key,
                version.provider_target_id,
                version.provider_version_id,
            )
            if version.created and identity not in registered:
                try:
                    self._objects.delete(version)
                except Exception:
                    # These versions are not named by authoritative control
                    # state. A failed removal is an unreachable private orphan.
                    pass

    def _read_objects(
        self,
        record: ResultControlRecord,
    ) -> tuple[dict[str, Any], StoredResult, dict[ArtifactKind, StoredArtifact]]:
        by_kind: dict[str, bytes] = {}
        for registered in record.objects:
            version = _version(registered)
            if version.provider_target_id != self._objects.provider_target_id:
                raise ResultStoreError("registered object provider target drifted")
            try:
                payload = self._objects.get(version)
                validate_object_payload(version.reference, payload)
            except Exception as error:
                raise _backend_error(
                    "registered immutable result object failed validation",
                    error,
                ) from error
            by_kind[version.reference.kind] = payload

        try:
            bundle = json.loads(by_kind["bundle"])
            result_id, payload, digest = _bundle_identity(bundle)
            if (
                result_id != record.result_id
                or digest != record.bundle_sha256
                or payload != by_kind["bundle"]
            ):
                raise ResultStoreError("stored viewer bundle failed its control identity check")
            batch = build_delivery_batch(
                bundle,
                {kind: value for kind, value in by_kind.items() if kind != "bundle"},
            )
        except ResultStoreError:
            raise
        except Exception as error:
            raise ResultStoreError("stored viewer bundle or artifact manifest is invalid") from error
        if not self._record_versions_match_batch(record, batch):
            raise ResultStoreError("stored delivery does not match its control registry")
        published_at = canonical_timestamp(record.published_at, "publication time")
        stored = StoredResult(
            result_id=result_id,
            payload=payload,
            etag=f'"{digest}"',
            published_at=published_at,
            expires_at=record.expires_at,
        )
        artifacts: dict[ArtifactKind, StoredArtifact] = {}
        for kind in ARTIFACT_KINDS:
            if kind not in by_kind:
                continue
            artifacts[kind] = _stored_artifact(
                bundle=bundle,
                stored=stored,
                kind=kind,
                payload=by_kind[kind],
            )
        return bundle, stored, artifacts

    def _live(self, result_id: str) -> ResultControlRecord | None:
        _validate_result_id(result_id)
        try:
            now = self._now()
            return self._controls.get_live(
                result_id,
                now_epoch_ms=int(now.timestamp() * 1000),
            )
        except Exception as error:
            if isinstance(error, ResultStoreError):
                raise
            raise _backend_error("result control lookup failed", error) from error

    def _activate_staged(
        self,
        staged: ResultControlRecord,
        *,
        token_digest: str,
    ) -> ResultControlRecord:
        if not self._keyring.verify_digest(
            staged.deletion_key_id,
            token_digest,
            staged.deletion_digest_hmac_sha256,
        ):
            raise ResultStoreError("staged result deletion capability does not match retry")
        for registered in staged.objects:
            version = _version(registered)
            try:
                payload = self._objects.get(version)
                validate_object_payload(version.reference, payload)
            except Exception as error:
                raise ResultStoreError("staged result object failed readback validation") from error
        now = self._now()
        activated_at = _timestamp(now)
        try:
            activated = self._controls.activate(
                staged,
                activated_at=activated_at,
                now_epoch_ms=int(now.timestamp() * 1000),
            )
        except Exception as error:
            # A concurrent publisher can commit the same durable stage with a
            # different activation timestamp. Resolve an uncertain/losing CAS
            # only through a strong authoritative reread.
            try:
                existing = self._controls.get_control(staged.result_id)
            except Exception as read_error:
                raise _backend_error(
                    "staged result activation could not be resolved",
                    read_error if _is_retryable(read_error) else error,
                ) from error
            if (
                existing is None
                or existing.state != "live"
                or existing.control_identity_sha256 != staged.control_identity_sha256
            ):
                raise _backend_error("staged result activation did not converge", error) from error
            activated = existing
        if activated.state != "live" or activated.control_identity_sha256 != staged.control_identity_sha256:
            raise ResultStoreError("control store returned an unexpected activation")
        visibility_now_ms = int(self._now().timestamp() * 1000)
        if (
            activated.expires_at_epoch_ms is not None
            and activated.expires_at_epoch_ms <= visibility_now_ms
        ):
            raise ResultStoreError("result expired before activation converged")
        return activated

    def publish(
        self,
        bundle: dict[str, Any],
        deletion_token_digest: str,
        artifacts: Mapping[str, bytes] | None = None,
    ) -> Publication:
        if not isinstance(deletion_token_digest, str) or SHA256_PATTERN.fullmatch(deletion_token_digest) is None:
            raise ValueError("deletion token digest must be a lowercase SHA-256 value")
        try:
            batch = build_delivery_batch(bundle, artifacts)
        except (ArtifactDeliveryError, ValueError) as error:
            raise ResultStoreError("result publication failed validation") from error

        try:
            existing = self._controls.get_control(batch.result_id)
        except Exception as error:
            raise _backend_error("result control lookup failed during publication", error) from error
        if existing is not None:
            if not self._record_versions_match_batch(existing, batch):
                raise ResultStoreError("immutable result ID collision")
            if not self._keyring.verify_digest(
                existing.deletion_key_id,
                deletion_token_digest,
                existing.deletion_digest_hmac_sha256,
            ):
                raise ResultStoreError("immutable result deletion capability collision")
            created = existing.state == "staged"
            if existing.state == "live":
                record = self._controls.get_live(
                    batch.result_id,
                    now_epoch_ms=int(self._now().timestamp() * 1000),
                )
                if record is None:
                    raise ResultStoreError("existing result is no longer live")
            elif existing.state == "staged":
                record = self._activate_staged(existing, token_digest=deletion_token_digest)
            else:
                raise ResultStoreError("retired result ID cannot be reused")
            _bundle, stored, _artifacts = self._read_objects(record)
            return _publication(stored, created=created)

        now = self._now()
        published_at = _timestamp(now)
        expires_at = (
            None
            if self._retention_seconds is None
            else _timestamp(now + timedelta(seconds=self._retention_seconds))
        )
        key_id, protected_digest = self._keyring.sign_digest(deletion_token_digest)
        versions: list[PrivateObjectVersion] = []
        try:
            for reference, payload in batch.objects:
                version = self._objects.put(reference, payload)
                if (
                    version.reference != reference
                    or version.provider_target_id != self._objects.provider_target_id
                ):
                    raise ResultStoreError("object store returned a mismatched object version")
                versions.append(version)
                readback = self._objects.get(version)
                validate_object_payload(reference, readback)
                if readback != payload:
                    raise ResultStoreError("object store readback differed from publication bytes")

            staged = build_staged_control(
                batch,
                versions,
                published_at=published_at,
                expires_at=expires_at,
                deletion_key_id=key_id,
                deletion_digest_hmac_sha256=protected_digest,
                cache_policy=self._cache_policy,
            )
            try:
                staged = self._controls.create_staged(staged)
            except Exception:
                persisted = self._controls.get_control(batch.result_id)
                if persisted is None:
                    raise
                staged = persisted
            if not self._record_versions_match_batch(staged, batch):
                raise ResultStoreError("persisted staged control conflicts with publication")
            self._discard_unregistered_versions(versions, staged)
            if not self._keyring.verify_digest(
                staged.deletion_key_id,
                deletion_token_digest,
                staged.deletion_digest_hmac_sha256,
            ):
                raise ResultStoreError("persisted staged control has a different deletion capability")
            record = (
                staged
                if staged.state == "live"
                else self._activate_staged(staged, token_digest=deletion_token_digest)
            )
            if record.state != "live":
                raise ResultStoreError("control store did not make the result live")
            _bundle, stored, _artifact_values = self._read_objects(record)
            return _publication(stored, created=record.activated_at == _timestamp(now))
        except Exception as error:
            # Once control state exists, its exact provider versions belong to
            # that lifecycle and must remain available for a safe retry.
            try:
                persisted = self._controls.get_control(batch.result_id)
            except Exception:
                persisted = object()  # Unknown persistence outcome: retain objects.
            if persisted is None:
                for version in versions:
                    if version.created:
                        try:
                            self._objects.delete(version)
                        except Exception:
                            pass
            elif isinstance(persisted, ResultControlRecord):
                self._discard_unregistered_versions(versions, persisted)
            if isinstance(error, ResultStoreError):
                raise
            raise _backend_error("result publication did not complete", error) from error

    def get(self, result_id: str) -> StoredResult | None:
        record = self._live(result_id)
        if record is None:
            return None
        _bundle, stored, _artifacts = self._read_objects(record)
        return stored

    def get_artifact(self, result_id: str, kind: ArtifactKind) -> StoredArtifact | None:
        _validate_result_id(result_id)
        kind = _validate_artifact_kind(kind)
        record = self._live(result_id)
        if record is None:
            return None
        _bundle, _stored, artifacts = self._read_objects(record)
        return artifacts.get(kind)

    def _cleanup_retired(self, retired: ResultControlRecord) -> bool:
        if retired.cleanup_state == "complete":
            return True
        try:
            for registered in retired.objects:
                self._objects.delete(_version(registered))
            completed = self._controls.mark_cleanup_complete(retired)
        except Exception as error:
            raise _RetirementPending(
                "result is retired but exact object cleanup is pending"
            ) from error
        if completed.cleanup_state != "complete":
            raise _RetirementPending("control store did not confirm object cleanup")
        return True

    def _retire(self, record: ResultControlRecord, *, require_expired: bool = False) -> bool:
        if record.state == "retired":
            return self._cleanup_retired(record)
        if record.state == "live":
            now = self._now()
            operation_id = f"p_{secrets.token_hex(16)}"
            target = self._purger.provider_target_id if self._purger is not None else None
            plan = build_retirement_plan(
                record,
                operation_id=operation_id,
                provider_target_id=target,
            )
            try:
                record = self._controls.begin_retirement(
                    record,
                    plan,
                    retired_at=_timestamp(now),
                    require_expired=require_expired,
                    now_epoch_ms=int(now.timestamp() * 1000) if require_expired else None,
                )
            except Exception as error:
                try:
                    existing = self._controls.get_control(record.result_id)
                except Exception as read_error:
                    raise _backend_error(
                        "result retirement fence could not be resolved",
                        read_error if _is_retryable(read_error) else error,
                    ) from error
                if (
                    existing is None
                    or existing.state not in {"retiring", "retired"}
                    or existing.control_identity_sha256
                    != record.control_identity_sha256
                ):
                    raise _backend_error("result retirement fence failed", error) from error
                record = existing
        if record.state == "retired":
            return self._cleanup_retired(record)
        if record.state != "retiring":
            return False

        if record.purge_required and record.purge_state != "confirmed":
            if self._purger is None:
                raise _RetirementPending(
                    "retiring shared-cache result has no configured purger"
                )
            if self._purger.provider_target_id != record.purge_provider_target_id:
                raise _RetirementPending(
                    "retiring result belongs to another purge target"
                )
            references = tuple(item.reference for item in record.objects)
            try:
                purge = self._purger.purge(
                    operation_id=record.purge_operation_id,
                    result_id=record.result_id,
                    public_paths=record.public_paths,
                    objects=references,
                )
            except Exception as error:
                raise _RetirementPending(
                    "result is fenced while cache purge remains pending"
                ) from error
            if (
                purge.operation_id != record.purge_operation_id
                or purge.coverage_sha256 != record.purge_coverage_sha256
                or purge.provider_target_id != record.purge_provider_target_id
            ):
                raise _RetirementPending(
                    "cache purger returned evidence for another delivery"
                )
            if purge.state == "pending":
                if purge.provider_request_id is not None:
                    try:
                        self._controls.record_pending_purge(
                            record,
                            provider_request_id=purge.provider_request_id,
                        )
                    except Exception as error:
                        raise _RetirementPending(
                            "result is fenced while pending purge evidence is unresolved"
                        ) from error
                raise _RetirementPending(
                    "result is fenced while cache purge remains pending"
                )
            if purge.provider_request_id is None or purge.confirmed_at is None:
                raise _RetirementPending(
                    "confirmed cache purge omitted provider evidence"
                )
            try:
                record = self._controls.record_confirmed_purge(
                    record,
                    provider_request_id=purge.provider_request_id,
                    confirmed_at=purge.confirmed_at,
                )
            except Exception as error:
                raise _RetirementPending(
                    "confirmed cache purge evidence is not yet durable"
                ) from error

        if record.purge_state != "confirmed":
            raise _RetirementPending("retirement lacks confirmed purge evidence")
        try:
            retired = self._controls.finalize_retirement(record)
        except Exception as error:
            raise _RetirementPending(
                "confirmed result retirement is not yet durable"
            ) from error
        return self._cleanup_retired(retired)

    def delete(self, result_id: str, deletion_token: str) -> DeleteOutcome:
        if not isinstance(result_id, str) or RESULT_ID_PATTERN.fullmatch(result_id) is None:
            return "malformed"
        if not isinstance(deletion_token, str) or DELETE_TOKEN_PATTERN.fullmatch(deletion_token) is None:
            return "malformed"
        try:
            record = self._controls.get_control(result_id)
        except Exception as error:
            failure = _backend_error("result control lookup failed during deletion", error)
            if failure.retryable:
                return "retryable"
            raise failure from error
        if record is None or record.state == "staged":
            return "not-found"

        now_ms = int(self._now().timestamp() * 1000)
        expired = (
            record.expires_at_epoch_ms is not None
            and record.expires_at_epoch_ms <= now_ms
        )
        if expired:
            try:
                self._retire(record, require_expired=record.state == "live")
            except ResultStoreError:
                pass
            return "not-found"

        if record.state == "retired" and record.cleanup_state == "complete":
            return "not-found"
        matches = self._keyring.verify_token(
            deletion_token,
            record.deletion_key_id,
            record.deletion_digest_hmac_sha256,
        )
        if not matches:
            return "forbidden" if record.state == "live" else "not-found"
        try:
            return "deleted" if self._retire(record) else "not-found"
        except _RetirementPending:
            return "pending"
        except ResultStoreError as error:
            if error.retryable:
                return "retryable"
            raise
        except Exception as error:
            failure = _backend_error("result retirement did not complete", error)
            return "retryable" if failure.retryable else "pending"

    def sweep(self) -> int:
        now = self._now()
        now_ms = int(now.timestamp() * 1000)
        cursor: Mapping[str, Any] | None = None
        completed: set[str] = set()
        while True:
            try:
                records, cursor = self._controls.list_expired(
                    now_ms,
                    next_token=cursor,
                )
            except Exception as error:
                raise _backend_error("expired-result discovery failed", error) from error
            for record in records:
                if record.state != "live":
                    continue
                try:
                    if self._retire(record, require_expired=True):
                        completed.add(record.result_id)
                except ResultStoreError:
                    continue
            if cursor is None:
                break

        cursor = None
        while True:
            try:
                records, cursor = self._controls.list_pending_work(
                    now_ms,
                    next_token=cursor,
                )
            except Exception as error:
                raise _backend_error("pending-result discovery failed", error) from error
            for record in records:
                try:
                    if self._retire(record):
                        completed.add(record.result_id)
                except ResultStoreError:
                    # The result is already origin-fenced. Its durable work
                    # index keeps the exact operation available to a later run.
                    continue
            if cursor is None:
                break
        return len(completed)


__all__ = ["CompositeResultBackend", "ControlStore", "DeletionKeyring"]
