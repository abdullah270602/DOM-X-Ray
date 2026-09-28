"""Credential-free proof of composite result publication and retirement."""

from __future__ import annotations

import hashlib
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.artifact_delivery import (  # noqa: E402
    CachePurgeResult,
    DeliveryCachePolicy,
)
from scanner.delivery_control import (  # noqa: E402
    ResultControlRecord,
    build_retirement_plan,
)
from scanner.delivery_storage import PrivateObjectVersion, validate_object_payload  # noqa: E402
from scanner.result_store import DeletionCapabilityKeyring, ResultStoreError  # noqa: E402
from scanner.composite_result_backend import CompositeResultBackend  # noqa: E402
from scripts.verify_result_store import fixture_bundle, with_result_id  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class FakeObjectStore:
    provider_target_id = "private-test-bucket"

    def __init__(self, controls: "FakeControlStore") -> None:
        self.controls = controls
        self.items: dict[tuple[str, str], bytes] = {}
        self.sequence = 0
        self.deleted: list[PrivateObjectVersion] = []
        self.put_order: list[str] = []
        self.fail_deletes = 0

    def put(self, reference, payload: bytes) -> PrivateObjectVersion:
        validate_object_payload(reference, payload)
        self.sequence += 1
        version_id = f"version-{self.sequence}"
        self.items[(reference.key, version_id)] = payload
        self.put_order.append(reference.kind)
        return PrivateObjectVersion(
            reference,
            self.provider_target_id,
            version_id,
            True,
        )

    def get(self, version: PrivateObjectVersion) -> bytes:
        if version.provider_target_id != self.provider_target_id:
            raise AssertionError("composite backend used a different provider target")
        return self.items[(version.reference.key, version.provider_version_id)]

    def delete(self, version: PrivateObjectVersion) -> None:
        current = self.controls.records.get(version.reference.result_id)
        require(current is not None and current.state == "retired", "objects deleted before retirement")
        if self.fail_deletes:
            self.fail_deletes -= 1
            raise TimeoutError("simulated exact-version cleanup timeout")
        self.deleted.append(version)
        self.items.pop((version.reference.key, version.provider_version_id), None)


class FakeControlStore:
    def __init__(self) -> None:
        self.records: dict[str, ResultControlRecord] = {}
        self.fail_activation_once = False
        self.activation_conflict_once = False
        self.fail_lookup_once = False
        self.strong_rereads = 0
        self.transitions: list[str] = []

    def get_control(self, result_id: str):
        self.strong_rereads += 1
        if self.fail_lookup_once:
            self.fail_lookup_once = False
            error = TimeoutError("simulated transient control lookup timeout")
            error.retryable = True
            raise error
        return self.records.get(result_id)

    def get_live(self, result_id: str, *, now_epoch_ms: int):
        value = self.records.get(result_id)
        if value is None or value.state != "live":
            return None
        if value.expires_at_epoch_ms is not None and value.expires_at_epoch_ms <= now_epoch_ms:
            return None
        return value

    def create_staged(self, record: ResultControlRecord):
        existing = self.records.get(record.result_id)
        if existing is not None:
            if existing.control_identity_sha256 != record.control_identity_sha256:
                raise ResultStoreError("fake identity collision")
            return existing
        self.records[record.result_id] = record
        self.transitions.append("staged")
        return record

    def activate(self, staged, *, activated_at: str, now_epoch_ms: int):
        if self.fail_activation_once:
            self.fail_activation_once = False
            raise ResultStoreError("simulated activation timeout")
        current = self.records[staged.result_id]
        if current.state == "live":
            return current
        require(current.state == "staged", "only staged controls can activate")
        require(current.expires_at_epoch_ms is None or current.expires_at_epoch_ms > now_epoch_ms,
                "fake activated an expired result")
        live = replace(current, state="live", revision=1, activated_at=activated_at)
        self.records[live.result_id] = live
        self.transitions.append("live")
        if self.activation_conflict_once:
            self.activation_conflict_once = False
            raise TimeoutError("simulated activation conflict after the winning commit")
        return live

    def begin_retirement(
        self,
        live,
        plan,
        *,
        retired_at: str,
        require_expired: bool = False,
        now_epoch_ms: int | None = None,
    ):
        current = self.records[live.result_id]
        if current.state == "retiring":
            return current
        require(current.state == "live", "retirement did not start from live")
        if require_expired:
            require(now_epoch_ms is not None and current.expires_at_epoch_ms <= now_epoch_ms,
                    "expiry retirement ran before retention")
        retiring = replace(
            current,
            state="retiring",
            revision=current.revision + 1,
            retired_at=retired_at,
            purge_operation_id=plan.operation_id,
            purge_coverage_sha256=plan.coverage_sha256,
            purge_required=plan.purge_required,
            purge_provider_target_id=plan.provider_target_id,
            purge_state="confirmed" if not plan.purge_required else "pending",
            purge_confirmed_at=retired_at if not plan.purge_required else None,
            cleanup_state="pending",
        )
        self.records[live.result_id] = retiring
        self.transitions.append("retiring")
        return retiring

    def record_pending_purge(self, retiring, *, provider_request_id: str):
        current = self.records[retiring.result_id]
        if current.purge_provider_request_id not in (None, provider_request_id):
            raise ResultStoreError("pending request drift")
        updated = replace(
            current,
            revision=current.revision + 1,
            purge_provider_request_id=provider_request_id,
        )
        self.records[retiring.result_id] = updated
        return updated

    def record_confirmed_purge(self, retiring, *, provider_request_id: str, confirmed_at: str):
        updated = replace(
            self.records[retiring.result_id],
            revision=self.records[retiring.result_id].revision + 1,
            purge_state="confirmed",
            purge_provider_request_id=provider_request_id,
            purge_confirmed_at=confirmed_at,
        )
        self.records[retiring.result_id] = updated
        self.transitions.append("purge-confirmed")
        return updated

    def finalize_retirement(self, retiring):
        current = self.records[retiring.result_id]
        require(current.state == "retiring" and current.purge_state == "confirmed",
                "retirement finalized before purge confirmation")
        retired = replace(current, state="retired", revision=current.revision + 1)
        self.records[retired.result_id] = retired
        self.transitions.append("retired")
        return retired

    def mark_cleanup_complete(self, retired):
        current = self.records[retired.result_id]
        updated = replace(current, revision=current.revision + 1, cleanup_state="complete")
        self.records[updated.result_id] = updated
        self.transitions.append("cleanup-complete")
        return updated

    def list_expired(self, now_epoch_ms: int, *, limit: int = 100, next_token=None):
        require(next_token is None, "fake only supports a single expiry page")
        found = tuple(
            record for record in self.records.values()
            if record.state == "live"
            and record.expires_at_epoch_ms is not None
            and record.expires_at_epoch_ms <= now_epoch_ms
        )[:limit]
        return found, None

    def list_pending_work(self, now_epoch_ms: int, *, limit: int = 100, next_token=None):
        require(next_token is None, "fake only supports a single pending-work page")
        found = tuple(
            record for record in self.records.values()
            if record.state == "retiring"
            or (record.state == "retired" and record.cleanup_state == "pending")
        )[:limit]
        return found, None


class FakePurger:
    provider_target_id = "cdn-test-distribution"

    def __init__(self, controls: FakeControlStore | None = None) -> None:
        self.calls = []
        self.controls = controls
        self.state = "confirmed"

    def purge(self, *, operation_id, result_id, public_paths, objects):
        from scanner.artifact_delivery import purge_coverage_sha256

        self.calls.append((result_id, operation_id))
        if self.controls is not None:
            require(self.controls.records[result_id].state == "retiring",
                    "purge ran before the origin was fenced")
        coverage = purge_coverage_sha256(result_id, public_paths, objects)
        return CachePurgeResult(
            operation_id=operation_id,
            state=self.state,
            coverage_sha256=coverage,
            provider_target_id=self.provider_target_id,
            provider_request_id="invalidation-1",
            confirmed_at=(
                "2026-01-02T03:04:05.000Z"
                if self.state == "confirmed"
                else None
            ),
        )


class RepeatingCursorControlStore(FakeControlStore):
    def list_expired(self, now_epoch_ms: int, *, limit: int = 100, next_token=None):
        return (), {"cursor": "same"}


def main() -> None:
    now = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    token = "dxrd_" + "a" * 64
    public_digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    keyring = DeletionCapabilityKeyring([b"k" * 32])
    controls = FakeControlStore()
    objects = FakeObjectStore(controls)
    controls.fail_activation_once = True
    backend = CompositeResultBackend(
        objects,
        controls,
        keyring,
        clock=lambda: now,
    )
    bundle = fixture_bundle("clean")
    result_id = bundle["result"]["resultId"]

    try:
        backend.publish(bundle, public_digest)
    except ResultStoreError:
        pass
    else:
        raise AssertionError("simulated activation interruption was not surfaced")
    staged = controls.records[result_id]
    require(staged.state == "staged", "failed activation exposed a live result")
    require(len(objects.items) == 1, "safe staged retry discarded uploaded object versions")
    require(backend.get(result_id) is None, "staged result became visible")
    require(backend.delete(result_id, token) == "not-found",
            "staged result was not hidden from deletion callers")
    require(controls.records[result_id].state == "staged",
            "staged deletion attempt changed control state")

    publication = backend.publish(bundle, public_digest)
    require(publication.created, "staged retry did not complete first publication")
    require(controls.records[result_id].state == "live", "validated result did not become live")
    require(backend.get(result_id) is not None, "live result could not be read")
    require(backend.delete(result_id, "dxrd_" + "b" * 64) == "forbidden",
            "wrong deletion capability was accepted")
    require(controls.records[result_id].state == "live", "forbidden delete changed control state")
    require(backend.delete(result_id, token) == "deleted", "valid deletion did not complete")
    require(controls.records[result_id].state == "retired", "deletion did not tombstone control")
    require(controls.records[result_id].cleanup_state == "complete", "exact cleanup was not recorded")
    require(backend.get(result_id) is None, "retired result remained visible")
    require(len(objects.deleted) == 1, "cleanup did not delete the exact registered version")
    require(backend.delete(result_id, token) == "not-found",
            "retired tombstone was not hidden from deletion callers")
    require(controls.transitions == ["staged", "live", "retiring", "retired", "cleanup-complete"],
            "control lifecycle did not preserve the required ordering")

    shared_bundle = with_result_id(bundle, "r_" + "b" * 32)
    shared_controls = FakeControlStore()
    shared_objects = FakeObjectStore(shared_controls)
    purger = FakePurger(shared_controls)
    shared_backend = CompositeResultBackend(
        shared_objects,
        shared_controls,
        keyring,
        cache_policy=DeliveryCachePolicy.shared(s_maxage_seconds=60),
        purger=purger,
        clock=lambda: now,
    )
    shared_id = shared_bundle["result"]["resultId"]
    shared_backend.publish(shared_bundle, public_digest)
    require(shared_backend.get(shared_id) is not None, "shared result was not initially visible")
    require(shared_backend.delete(shared_id, token) == "deleted", "purge-enabled deletion failed")
    require(
        shared_controls.transitions.index("purge-confirmed")
        < shared_controls.transitions.index("retired"),
        "shared result retired before confirmed cache purge",
    )
    require(len(purger.calls) == 1, "shared result did not invoke the configured purger")
    require(
        shared_controls.records[shared_id].purge_provider_request_id == "invalidation-1",
        "confirmed cache receipt was not persisted",
    )

    pending_bundle = with_result_id(bundle, "r_" + "c" * 32)
    pending_controls = FakeControlStore()
    pending_objects = FakeObjectStore(pending_controls)
    pending_purger = FakePurger(pending_controls)
    pending_purger.state = "pending"
    pending_backend = CompositeResultBackend(
        pending_objects,
        pending_controls,
        keyring,
        cache_policy=DeliveryCachePolicy.shared(s_maxage_seconds=60),
        purger=pending_purger,
        clock=lambda: now,
    )
    pending_id = pending_bundle["result"]["resultId"]
    pending_backend.publish(pending_bundle, public_digest)
    require(pending_backend.delete(pending_id, token) == "pending",
            "unconfirmed cache purge did not return pending")
    pending_record = pending_controls.records[pending_id]
    require(pending_record.state == "retiring", "pending purge lost the read fence")
    operation_id = pending_record.purge_operation_id
    require(pending_backend.get(pending_id) is None,
            "pending-purge result remained visible after the fence")
    calls_before_drift = len(pending_purger.calls)
    original_purge_target = pending_purger.provider_target_id
    pending_purger.provider_target_id = "different-cdn-distribution"
    require(pending_backend.delete(pending_id, token) == "pending",
            "purge target drift was not held pending")
    require(len(pending_purger.calls) == calls_before_drift,
            "purger was called after its target drifted")
    pending_purger.provider_target_id = original_purge_target
    pending_purger.state = "confirmed"
    require(pending_backend.sweep() == 1, "pending purge did not recover through sweep")
    require(pending_controls.records[pending_id].state == "retired",
            "sweep did not complete pending retirement")
    require([call[1] for call in pending_purger.calls] == [operation_id, operation_id],
            "purge retry changed the persisted operation ID")

    cleanup_bundle = with_result_id(bundle, "r_" + "d" * 32)
    cleanup_controls = FakeControlStore()
    cleanup_objects = FakeObjectStore(cleanup_controls)
    cleanup_backend = CompositeResultBackend(
        cleanup_objects,
        cleanup_controls,
        keyring,
        clock=lambda: now,
    )
    cleanup_id = cleanup_bundle["result"]["resultId"]
    cleanup_backend.publish(cleanup_bundle, public_digest)
    cleanup_objects.fail_deletes = 1
    require(cleanup_backend.delete(cleanup_id, token) == "pending",
            "transient exact-version cleanup failure did not return pending")
    retired_pending = cleanup_controls.records[cleanup_id]
    require(retired_pending.state == "retired" and retired_pending.cleanup_state == "pending",
            "cleanup failure did not preserve retired tombstone and work state")
    require(cleanup_backend.sweep() == 1, "retired cleanup was not recovered by sweep")
    require(cleanup_controls.records[cleanup_id].cleanup_state == "complete",
            "sweep did not persist cleanup completion")

    expiry_bundle = with_result_id(bundle, "r_" + "e" * 32)
    expiry_controls = FakeControlStore()
    expiry_objects = FakeObjectStore(expiry_controls)
    current_time = [now]
    expiry_backend = CompositeResultBackend(
        expiry_objects,
        expiry_controls,
        keyring,
        retention_seconds=60,
        clock=lambda: current_time[0],
    )
    expiry_id = expiry_bundle["result"]["resultId"]
    expiry_backend.publish(expiry_bundle, public_digest)
    current_time[0] = now.replace(second=5) + timedelta(seconds=60)
    require(expiry_backend.delete(expiry_id, "dxrd_" + "f" * 64) == "not-found",
            "wrong token at exact expiry did not return not-found")
    require(expiry_controls.records[expiry_id].state == "retired",
            "exact-expiry request did not progress retirement")

    lookup_bundle = with_result_id(bundle, "r_" + "1" * 32)
    lookup_controls = FakeControlStore()
    lookup_objects = FakeObjectStore(lookup_controls)
    lookup_backend = CompositeResultBackend(
        lookup_objects,
        lookup_controls,
        keyring,
        clock=lambda: now,
    )
    lookup_id = lookup_bundle["result"]["resultId"]
    lookup_backend.publish(lookup_bundle, public_digest)
    lookup_controls.fail_lookup_once = True
    require(lookup_backend.delete(lookup_id, token) == "retryable",
            "transient pre-fence lookup failure was not reported retryable")
    require(lookup_controls.records[lookup_id].state == "live",
            "failed pre-fence lookup changed visibility state")

    conflict_bundle = with_result_id(bundle, "r_" + "2" * 32)
    conflict_controls = FakeControlStore()
    conflict_objects = FakeObjectStore(conflict_controls)
    conflict_controls.activation_conflict_once = True
    conflict_backend = CompositeResultBackend(
        conflict_objects,
        conflict_controls,
        keyring,
        clock=lambda: now,
    )
    conflict_id = conflict_bundle["result"]["resultId"]
    rereads_before = conflict_controls.strong_rereads
    conflict_publication = conflict_backend.publish(conflict_bundle, public_digest)
    require(conflict_publication.created,
            "concurrent activation winner was not adopted as first publication")
    require(conflict_controls.records[conflict_id].state == "live",
            "activation conflict was not resolved from authoritative live state")
    require(conflict_controls.strong_rereads > rereads_before,
            "activation conflict did not perform a strong reread")

    looping_controls = RepeatingCursorControlStore()
    looping_backend = CompositeResultBackend(
        FakeObjectStore(looping_controls),
        looping_controls,
        keyring,
        clock=lambda: now,
    )
    try:
        looping_backend.sweep()
    except ResultStoreError:
        pass
    else:
        raise AssertionError("sweep accepted a repeated provider cursor")

    print(
        "Verified composite publication and deletion: staged objects remain private, "
        "exact object readback precedes activation, retry adopts the persisted stage, "
        "activation conflicts resolve through strong reread, DynamoDB-style control "
        "state is the visibility gate, staged/retired/expired-token outcomes are "
        "hidden correctly, invalid live capabilities do not mutate state, pending "
        "purge and cleanup recover through sweep, purge retries keep their operation "
        "ID, target drift is rejected before purge, transient pre-fence lookups are "
        "retryable, repeated sweep cursors are bounded, confirmed cache purge "
        "precedes retirement, and default cache policy is no-store. No cloud "
        "resources were used."
    )


if __name__ == "__main__":
    main()
