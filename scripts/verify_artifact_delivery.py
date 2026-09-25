"""Verify immutable delivery staging, visibility fencing, and cache purge proof."""

from __future__ import annotations

import json
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.artifact_delivery import (  # noqa: E402
    ArtifactDeliveryError,
    CachePurgeResult,
    DeliveryCachePolicy,
    FilesystemArtifactDelivery,
    PurgePendingError,
    build_delivery_batch,
    purge_coverage_sha256,
)
from scripts.verify_result_store import eligible_bundle, poster_png, video_mp4  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_delivery_error(action, message: str) -> None:
    try:
        action()
    except (ArtifactDeliveryError, ValueError):
        return
    raise AssertionError(message)


class ScriptedPurger:
    def __init__(self, states: list[str]) -> None:
        self.states = states
        self.calls: list[dict[str, object]] = []
        self.delivery: FilesystemArtifactDelivery | None = None

    def purge(
        self,
        *,
        operation_id: str,
        result_id: str,
        public_paths: tuple[str, ...],
        objects,
    ) -> CachePurgeResult:
        require(self.delivery is not None, "purger has no delivery reference")
        require(
            self.delivery.get(result_id, "bundle") is None,
            "origin remained visible while purge was requested",
        )
        require(objects and objects[0].kind == "bundle", "purger received no bundle identity")
        state = self.states.pop(0)
        self.calls.append(
            {
                "operationId": operation_id,
                "resultId": result_id,
                "publicPaths": public_paths,
                "objectEtags": tuple(item.etag for item in objects),
                "state": state,
            }
        )
        return CachePurgeResult(
            operation_id=operation_id,
            state=state,  # type: ignore[arg-type]
            coverage_sha256=purge_coverage_sha256(
                result_id,
                public_paths,
                tuple(objects),
            ),
            provider_request_id=f"provider-{len(self.calls)}",
            confirmed_at=(
                "2026-09-25T12:31:00.000Z" if state == "confirmed" else None
            ),
        )


class WrongCoveragePurger:
    def purge(
        self,
        *,
        operation_id: str,
        result_id: str,
        public_paths: tuple[str, ...],
        objects,
    ) -> CachePurgeResult:
        del result_id, public_paths, objects
        return CachePurgeResult(
            operation_id=operation_id,
            state="confirmed",
            coverage_sha256="0" * 64,
            provider_request_id="provider-wrong-coverage",
            confirmed_at="2026-09-25T12:31:00.000Z",
        )


class ConcurrentPurger:
    def __init__(self) -> None:
        self.barrier = Barrier(2)
        self.operation_ids: list[str] = []

    def purge(
        self,
        *,
        operation_id: str,
        result_id: str,
        public_paths: tuple[str, ...],
        objects,
    ) -> CachePurgeResult:
        self.operation_ids.append(operation_id)
        self.barrier.wait(timeout=5)
        return CachePurgeResult(
            operation_id=operation_id,
            state="confirmed",
            coverage_sha256=purge_coverage_sha256(
                result_id,
                public_paths,
                tuple(objects),
            ),
            provider_request_id=f"provider-concurrent-{len(self.operation_ids)}",
            confirmed_at="2026-09-25T12:31:00.000Z",
        )


def main() -> None:
    fixed_now = datetime(2026, 9, 25, 12, 30, tzinfo=UTC)
    poster = poster_png()
    video = video_mp4()
    result_id = "r_" + "a" * 32
    bundle = eligible_bundle(result_id, poster, video)
    batch = build_delivery_batch(bundle, {"poster": poster, "video": video})

    require(batch.result_id == result_id, "delivery batch result identity drifted")
    require(
        tuple(reference.kind for reference, _payload in batch.objects)
        == ("bundle", "poster", "video"),
        "delivery objects are incomplete or unordered",
    )
    require(
        tuple(reference.key for reference, _payload in batch.objects)
        == (
            f"v1/results/{result_id}/bundle.json",
            f"v1/results/{result_id}/poster.png",
            f"v1/results/{result_id}/video.mp4",
        ),
        "private delivery keys drifted",
    )
    require(
        batch.public_paths
        == (
            f"/r/{result_id}",
            f"/api/results/{result_id}",
            f"/api/results/{result_id}/poster.png",
            f"/api/results/{result_id}/video.mp4",
        ),
        "delivery purge paths are incomplete",
    )
    expect_delivery_error(
        lambda: build_delivery_batch(bundle, {"poster": poster}),
        "delivery accepted a missing ready video",
    )
    expect_delivery_error(
        lambda: build_delivery_batch(bundle, {"poster": poster, "video": b"not-an-mp4"}),
        "delivery accepted invalid video bytes",
    )
    expect_delivery_error(
        lambda: DeliveryCachePolicy(
            value="public, max-age=31536000, immutable",
            purge_required=True,
        ),
        "delivery accepted an owner-undeletable browser cache policy",
    )

    with tempfile.TemporaryDirectory(prefix="dom-xray-delivery-") as temporary:
        root = Path(temporary)
        delivery = FilesystemArtifactDelivery(root, clock=lambda: fixed_now)
        stage = delivery.stage(bundle, {"poster": poster, "video": video})
        require(stage.created and not stage.already_live, "first delivery stage was not created")
        require(delivery.get(result_id, "bundle") is None, "staged bundle became public")
        require(delivery.get(result_id, "poster") is None, "staged poster became public")
        require(delivery.get(result_id, "video") is None, "staged video became public")

        publication = delivery.activate(stage)
        require(publication.created, "first delivery activation was not created")
        require(publication.cache_control == "no-store", "local delivery became cacheable")
        for kind, expected_payload in (
            ("bundle", batch.objects[0][1]),
            ("poster", poster),
            ("video", video),
        ):
            delivered = delivery.get(result_id, kind)  # type: ignore[arg-type]
            require(delivered is not None, f"live {kind} was unavailable")
            require(delivered.payload == expected_payload, f"live {kind} bytes changed")
            require(delivered.byte_length == len(expected_payload), f"live {kind} length drifted")
            require(delivered.cache_control == "no-store", f"live {kind} cache policy drifted")

        restarted = FilesystemArtifactDelivery(root, clock=lambda: fixed_now)
        require(
            restarted.get(result_id, "video") is not None,
            "live delivery did not survive restart",
        )
        repeated_stage = restarted.stage(bundle, {"poster": poster, "video": video})
        require(
            not repeated_stage.created and repeated_stage.already_live,
            "identical delivery restage was not idempotent",
        )
        repeated_publication = restarted.activate(repeated_stage)
        require(not repeated_publication.created, "identical delivery reactivated")

        different_poster = poster_png(b"\x10\x20\x30\xff")
        collision = eligible_bundle(result_id, different_poster, video)
        expect_delivery_error(
            lambda: restarted.stage(
                collision,
                {"poster": different_poster, "video": video},
            ),
            "different bytes reused a live delivery result ID",
        )

        live_marker = (root / "live" / f"{result_id}.json").read_bytes()
        object_snapshots = {
            path.name: path.read_bytes() for path in (root / "objects").iterdir()
        }
        receipt = restarted.retire(result_id)
        require(receipt is not None, "no-store retirement returned no receipt")
        require(receipt.cache_control == "no-store", "retirement cache policy drifted")
        require(
            not receipt.purge_required and receipt.provider_request_id is None,
            "no-store retirement falsely claimed a provider purge",
        )
        require(restarted.get(result_id, "bundle") is None, "retired bundle remained public")
        require(not list((root / "objects").iterdir()), "retirement left private objects")
        require(
            restarted.retire(result_id) == receipt,
            "retirement was not idempotent",
        )
        expect_delivery_error(
            lambda: restarted.stage(bundle, {"poster": poster, "video": video}),
            "retired delivery result ID was reused",
        )

        # Model a stale replica restoring both the live marker and private
        # objects after retirement.  The durable tombstone must win on restart.
        (root / "live" / f"{result_id}.json").write_bytes(live_marker)
        for name, payload in object_snapshots.items():
            (root / "objects" / name).write_bytes(payload)
        recovered = FilesystemArtifactDelivery(root, clock=lambda: fixed_now)
        require(recovered.get(result_id, "bundle") is None, "stale live marker beat tombstone")
        require(not list((root / "objects").iterdir()), "tombstone left stale private objects")

    with tempfile.TemporaryDirectory(prefix="dom-xray-delivery-abort-") as temporary:
        abort_id = "r_" + "b" * 32
        abort_bundle = eligible_bundle(abort_id, poster, video)
        delivery = FilesystemArtifactDelivery(Path(temporary), clock=lambda: fixed_now)
        stage = delivery.stage(abort_bundle, {"poster": poster, "video": video})
        require(delivery.abort(stage), "staged delivery could not be aborted")
        require(not delivery.abort(stage), "delivery abort was not idempotent")
        require(not list((Path(temporary) / "objects").iterdir()), "abort left private objects")
        require(delivery.get(abort_id, "bundle") is None, "aborted bundle became public")

    with tempfile.TemporaryDirectory(prefix="dom-xray-delivery-order-") as temporary:
        class FailingActivationDelivery(FilesystemArtifactDelivery):
            def _write_entry(self, destination: Path, value: dict[str, object]) -> bool:
                if destination.parent.name == "live":
                    raise ArtifactDeliveryError("injected live-marker failure")
                return super()._write_entry(destination, value)

        order_id = "r_" + "c" * 32
        order_bundle = eligible_bundle(order_id, poster, video)
        delivery = FailingActivationDelivery(Path(temporary), clock=lambda: fixed_now)
        stage = delivery.stage(order_bundle, {"poster": poster, "video": video})
        expect_delivery_error(
            lambda: delivery.activate(stage),
            "failed visibility commit exposed staged objects",
        )
        require(delivery.get(order_id, "bundle") is None, "failed activation exposed a bundle")
        require(delivery.abort(stage), "failed activation could not be rolled back")

    with tempfile.TemporaryDirectory(prefix="dom-xray-delivery-concurrent-") as temporary:
        concurrent_id = "r_" + "d" * 32
        concurrent_bundle = eligible_bundle(concurrent_id, poster, video)
        delivery = FilesystemArtifactDelivery(Path(temporary), clock=lambda: fixed_now)
        with ThreadPoolExecutor(max_workers=8) as pool:
            stages = list(
                pool.map(
                    lambda _index: delivery.stage(
                        concurrent_bundle,
                        {"poster": poster, "video": video},
                    ),
                    range(16),
                )
            )
        require(
            sum(stage.created for stage in stages) == 1,
            "concurrent stage was not single-create",
        )
        with ThreadPoolExecutor(max_workers=8) as pool:
            publications = list(pool.map(delivery.activate, stages))
        require(
            sum(publication.created for publication in publications) == 1,
            "concurrent activation was not single-create",
        )

    shared_policy = DeliveryCachePolicy.shared()
    with tempfile.TemporaryDirectory(prefix="dom-xray-delivery-concurrent-purge-") as temporary:
        concurrent_retire_id = "r_" + "3" * 32
        concurrent_retire_bundle = eligible_bundle(concurrent_retire_id, poster, video)
        purger = ConcurrentPurger()
        delivery = FilesystemArtifactDelivery(
            Path(temporary),
            cache_policy=shared_policy,
            purger=purger,
            clock=lambda: fixed_now,
        )
        delivery.activate(
            delivery.stage(
                concurrent_retire_bundle,
                {"poster": poster, "video": video},
            )
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            receipts = list(
                pool.map(
                    lambda _index: delivery.retire(concurrent_retire_id),
                    range(2),
                )
            )
        require(
            receipts[0] is not None and receipts[0] == receipts[1],
            "concurrent retirement did not converge on one durable receipt",
        )
        require(
            len(purger.operation_ids) == 2
            and len(set(purger.operation_ids)) == 1,
            "concurrent retirement changed purge operation identity",
        )

    with tempfile.TemporaryDirectory(prefix="dom-xray-delivery-wrong-purge-") as temporary:
        wrong_id = "r_" + "2" * 32
        wrong_bundle = eligible_bundle(wrong_id, poster, video)
        delivery = FilesystemArtifactDelivery(
            Path(temporary),
            cache_policy=shared_policy,
            purger=WrongCoveragePurger(),
            clock=lambda: fixed_now,
        )
        delivery.activate(delivery.stage(wrong_bundle, {"poster": poster, "video": video}))
        expect_delivery_error(
            lambda: delivery.retire(wrong_id),
            "wrong purge coverage was accepted as retirement proof",
        )
        require(delivery.get(wrong_id, "bundle") is None, "bad purge reopened the origin")
        require(
            delivery.pending_result_ids() == (wrong_id,),
            "bad purge coverage was not left durably pending",
        )

    with tempfile.TemporaryDirectory(prefix="dom-xray-delivery-shared-") as temporary:
        expect_delivery_error(
            lambda: FilesystemArtifactDelivery(
                Path(temporary) / "missing-purger",
                cache_policy=shared_policy,
                clock=lambda: fixed_now,
            ),
            "shared cache was enabled without a purger",
        )
        shared_id = "r_" + "e" * 32
        shared_bundle = eligible_bundle(shared_id, poster, video)
        purger = ScriptedPurger(["pending", "confirmed"])
        shared_root = Path(temporary) / "delivery"
        delivery = FilesystemArtifactDelivery(
            shared_root,
            cache_policy=shared_policy,
            purger=purger,
            clock=lambda: fixed_now,
        )
        purger.delivery = delivery
        stage = delivery.stage(shared_bundle, {"poster": poster, "video": video})
        publication = delivery.activate(stage)
        stale_live_marker = (shared_root / "live" / f"{shared_id}.json").read_bytes()
        require(
            publication.cache_control
            == "public, max-age=0, s-maxage=31536000, must-revalidate",
            "shared cache policy drifted",
        )
        try:
            delivery.retire(shared_id)
        except PurgePendingError as pending:
            first_operation = pending.operation_id
        else:
            raise AssertionError("pending edge purge was reported as retired")
        require(delivery.get(shared_id, "bundle") is None, "retiring origin remained public")
        require(delivery.pending_result_ids() == (shared_id,), "pending purge was not durable")
        # A crash can leave or restore the former live marker after the retiring
        # fence commits.  Retiring must win before and after restart.
        (shared_root / "live" / f"{shared_id}.json").write_bytes(stale_live_marker)
        require(delivery.get(shared_id, "bundle") is None, "stale live marker bypassed retiring")

        restarted = FilesystemArtifactDelivery(
            shared_root,
            cache_policy=shared_policy,
            purger=purger,
            clock=lambda: fixed_now,
        )
        purger.delivery = restarted
        receipt = restarted.retry_pending(shared_id)
        require(receipt is not None, "confirmed retry produced no purge receipt")
        require(receipt.operation_id == first_operation, "purge retry changed operation identity")
        require(receipt.provider_request_id == "provider-2", "purge receipt lost provider evidence")
        require(receipt.purge_required, "shared-cache receipt omitted its purge requirement")
        require(
            len(receipt.coverage_sha256) == 64,
            "shared-cache receipt omitted exact route/object coverage",
        )
        require(receipt.public_paths == build_delivery_batch(
            shared_bundle,
            {"poster": poster, "video": video},
        ).public_paths, "purge receipt omitted a public path")
        require(restarted.pending_result_ids() == (), "confirmed purge stayed pending")
        require(restarted.get(shared_id, "video") is None, "purged video remained public")
        require(len(purger.calls) == 2, "purge retry count drifted")
        require(
            purger.calls[0]["operationId"] == purger.calls[1]["operationId"],
            "purge retries were not idempotent",
        )

    with tempfile.TemporaryDirectory(prefix="dom-xray-delivery-purge-crash-") as temporary:
        class FailingRetiredMarkerDelivery(FilesystemArtifactDelivery):
            fail_retired_marker = True

            def _write_entry(self, destination: Path, value: dict[str, object]) -> bool:
                if destination.parent.name == "retired" and self.fail_retired_marker:
                    self.fail_retired_marker = False
                    raise ArtifactDeliveryError("injected retired-marker failure")
                return super()._write_entry(destination, value)

        crash_id = "r_" + "1" * 32
        crash_bundle = eligible_bundle(crash_id, poster, video)
        crash_root = Path(temporary)
        purger = ScriptedPurger(["confirmed", "confirmed"])
        delivery = FailingRetiredMarkerDelivery(
            crash_root,
            cache_policy=shared_policy,
            purger=purger,
            clock=lambda: fixed_now,
        )
        purger.delivery = delivery
        delivery.activate(delivery.stage(crash_bundle, {"poster": poster, "video": video}))
        expect_delivery_error(
            lambda: delivery.retire(crash_id),
            "purge confirmation plus retired-marker failure was reported complete",
        )
        require(delivery.pending_result_ids() == (crash_id,), "failed receipt was not retryable")
        first_operation = purger.calls[0]["operationId"]
        restarted = FilesystemArtifactDelivery(
            crash_root,
            cache_policy=shared_policy,
            purger=purger,
            clock=lambda: fixed_now,
        )
        purger.delivery = restarted
        receipt = restarted.retry_pending(crash_id)
        require(receipt is not None, "confirmed purge retry did not retire")
        require(
            receipt.operation_id == first_operation
            and purger.calls[1]["operationId"] == first_operation,
            "post-confirmation crash changed purge idempotency identity",
        )

    with tempfile.TemporaryDirectory(prefix="dom-xray-delivery-tamper-") as temporary:
        tamper_id = "r_" + "f" * 32
        tamper_bundle = eligible_bundle(tamper_id, poster, video)
        root = Path(temporary)
        delivery = FilesystemArtifactDelivery(root, clock=lambda: fixed_now)
        delivery.activate(delivery.stage(tamper_bundle, {"poster": poster, "video": video}))
        (root / "objects" / f"{tamper_id}.poster.png").write_bytes(poster[:-1])
        expect_delivery_error(
            lambda: delivery.get(tamper_id, "poster"),
            "tampered delivery object remained reachable",
        )
        expect_delivery_error(
            lambda: FilesystemArtifactDelivery(root, clock=lambda: fixed_now),
            "tampered delivery survived restart validation",
        )

    for unsafe in ("../escape", "r_bad", "r_" + "A" * 32):
        with tempfile.TemporaryDirectory(prefix="dom-xray-delivery-id-") as temporary:
            delivery = FilesystemArtifactDelivery(Path(temporary), clock=lambda: fixed_now)
            expect_delivery_error(
                lambda value=unsafe: delivery.get(value, "bundle"),
                "unsafe result ID reached delivery storage",
            )

    with tempfile.TemporaryDirectory(prefix="dom-xray-delivery-symlink-") as temporary:
        base = Path(temporary)
        target = base / "target"
        target.mkdir()
        link = base / "linked-root"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            pass
        else:
            expect_delivery_error(
                lambda: FilesystemArtifactDelivery(link, clock=lambda: fixed_now),
                "symlinked delivery root was accepted",
            )

    print(
        "Verified the local delivery state-machine proof: private immutable keys, "
        "object-before-live publication, restart "
        "identity, conditional-create collisions, abort cleanup, concurrent idempotency, "
        "live-to-retiring origin fencing, concurrent and durable purge retries and "
        "receipts, tombstoned non-reuse, exact and mismatched scripted-purge coverage, "
        "cache-policy gating, and fail-closed "
        "tamper handling; no CDN or multi-writer provider was exercised."
    )


if __name__ == "__main__":
    main()
