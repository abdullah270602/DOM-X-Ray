"""Verify the CloudFront adapter request, retry, and completion boundary."""

from __future__ import annotations

import copy
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.artifact_delivery import (  # noqa: E402
    DeliveryCachePolicy,
    FilesystemArtifactDelivery,
    PurgePendingError,
    build_delivery_batch,
    purge_coverage_sha256,
)
from scanner.cloudfront_purger import (  # noqa: E402
    CloudFrontCachePurger,
    CloudFrontPurgeError,
    cloudfront_purger_from_environment,
)
from scripts.verify_result_store import eligible_bundle, poster_png, video_mp4  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(action, message: str) -> None:
    try:
        action()
    except (CloudFrontPurgeError, ValueError):
        return
    raise AssertionError(message)


class FakeCloudFrontClient:
    def __init__(self, observed_statuses: list[str]) -> None:
        self._statuses = list(observed_statuses)
        self._records: dict[str, dict[str, object]] = {}
        self.create_calls: list[dict[str, object]] = []
        self.get_calls: list[dict[str, str]] = []

    def _response(self, record: dict[str, object]) -> dict[str, object]:
        return {"Invalidation": copy.deepcopy(record)}

    def create_invalidation(
        self,
        *,
        DistributionId: str,
        InvalidationBatch: dict[str, object],
    ) -> dict[str, object]:
        call = {
            "DistributionId": DistributionId,
            "InvalidationBatch": copy.deepcopy(InvalidationBatch),
        }
        self.create_calls.append(call)
        caller = InvalidationBatch["CallerReference"]
        require(isinstance(caller, str), "fake received a non-string caller reference")
        existing = self._records.get(caller)
        if existing is None:
            existing = {
                "Id": f"INV{len(self._records) + 1:08d}",
                "Status": "InProgress",
                "InvalidationBatch": copy.deepcopy(InvalidationBatch),
            }
            self._records[caller] = existing
        elif existing["InvalidationBatch"] != InvalidationBatch:
            raise RuntimeError("CallerReference reused with different coverage")
        return self._response(existing)

    def get_invalidation(
        self,
        *,
        DistributionId: str,
        Id: str,
    ) -> dict[str, object]:
        self.get_calls.append({"DistributionId": DistributionId, "Id": Id})
        record = next(
            (candidate for candidate in self._records.values() if candidate["Id"] == Id),
            None,
        )
        if record is None:
            raise RuntimeError("unknown fake invalidation")
        if self._statuses:
            record["Status"] = self._statuses.pop(0)
        return self._response(record)

    @property
    def invalidation_count(self) -> int:
        return len(self._records)


class WrongIdentityClient(FakeCloudFrontClient):
    def create_invalidation(
        self,
        *,
        DistributionId: str,
        InvalidationBatch: dict[str, object],
    ) -> dict[str, object]:
        response = super().create_invalidation(
            DistributionId=DistributionId,
            InvalidationBatch=InvalidationBatch,
        )
        invalidation = response["Invalidation"]  # type: ignore[assignment]
        batch = invalidation["InvalidationBatch"]  # type: ignore[index]
        batch["CallerReference"] = "wrong"  # type: ignore[index]
        return response


class WrongQuantityClient(FakeCloudFrontClient):
    def create_invalidation(
        self,
        *,
        DistributionId: str,
        InvalidationBatch: dict[str, object],
    ) -> dict[str, object]:
        response = super().create_invalidation(
            DistributionId=DistributionId,
            InvalidationBatch=InvalidationBatch,
        )
        paths = response["Invalidation"]["InvalidationBatch"]["Paths"]  # type: ignore[index]
        paths["Quantity"] = float(paths["Quantity"])  # type: ignore[index]
        return response


def main() -> None:
    fixed_now = datetime(2026, 9, 25, 14, 0, tzinfo=UTC)
    result_id = "r_" + "5" * 32
    poster = poster_png()
    video = video_mp4()
    bundle = eligible_bundle(result_id, poster, video)
    batch = build_delivery_batch(bundle, {"poster": poster, "video": video})
    objects = tuple(reference for reference, _payload in batch.objects)
    operation_id = "p_" + "6" * 32
    expected_paths = tuple(f"{path}*" for path in batch.public_paths)

    client = FakeCloudFrontClient(["InProgress", "Completed"])
    purger = CloudFrontCachePurger(
        client,
        "E123DOMXRAY",
        clock=lambda: fixed_now,
    )
    pending = purger.purge(
        operation_id=operation_id,
        result_id=result_id,
        public_paths=batch.public_paths,
        objects=objects,
    )
    require(pending.state == "pending", "in-progress invalidation was confirmed")
    require(
        pending.provider_target_id == "aws:cloudfront:E123DOMXRAY",
        "pending purge lost its distribution identity",
    )
    require(pending.provider_request_id == "INV00000001", "provider ID drifted")
    require(
        pending.coverage_sha256
        == purge_coverage_sha256(result_id, batch.public_paths, objects),
        "pending purge lost route/object coverage",
    )
    submitted = client.create_calls[0]
    require(submitted["DistributionId"] == "E123DOMXRAY", "distribution ID drifted")
    submitted_batch = submitted["InvalidationBatch"]
    require(isinstance(submitted_batch, dict), "invalidation batch was not an object")
    require(
        submitted_batch["CallerReference"] == operation_id,
        "operation ID was not the idempotency key",
    )
    require(
        submitted_batch["Paths"]
        == {"Quantity": len(expected_paths), "Items": list(expected_paths)},
        "canonical/query-variant invalidation coverage drifted",
    )

    confirmed = purger.purge(
        operation_id=operation_id,
        result_id=result_id,
        public_paths=batch.public_paths,
        objects=objects,
    )
    require(confirmed.state == "confirmed", "completed invalidation stayed pending")
    require(confirmed.provider_request_id == pending.provider_request_id, "retry changed ID")
    require(
        confirmed.confirmed_at == "2026-09-25T14:00:00.000Z",
        "completion observation time drifted",
    )
    require(client.invalidation_count == 1, "retry created a second invalidation")
    require(len(client.create_calls) == 2 and len(client.get_calls) == 2, "retry calls drifted")

    expect_error(
        lambda: purger.purge(
            operation_id=operation_id,
            result_id=result_id,
            public_paths=batch.public_paths[:-1],
            objects=objects,
        ),
        "purger accepted incomplete canonical coverage",
    )
    wrong_client = WrongIdentityClient([])
    wrong_purger = CloudFrontCachePurger(wrong_client, "E123DOMXRAY")
    expect_error(
        lambda: wrong_purger.purge(
            operation_id=operation_id,
            result_id=result_id,
            public_paths=batch.public_paths,
            objects=objects,
        ),
        "purger accepted a mismatched provider response",
    )
    wrong_quantity_purger = CloudFrontCachePurger(
        WrongQuantityClient([]),
        "E123DOMXRAY",
    )
    expect_error(
        lambda: wrong_quantity_purger.purge(
            operation_id=operation_id,
            result_id=result_id,
            public_paths=batch.public_paths,
            objects=objects,
        ),
        "purger accepted a non-integer provider path quantity",
    )
    require(
        cloudfront_purger_from_environment(
            environ={"DOM_XRAY_CLOUDFRONT_DISTRIBUTION_ID": "E123DOMXRAY"},
            client_factory=(
                lambda service: client if service == "cloudfront" else None
            ),  # type: ignore[arg-type]
            clock=lambda: fixed_now,
        ).distribution_id
        == "E123DOMXRAY",
        "environment factory did not build the configured adapter",
    )
    expect_error(
        lambda: cloudfront_purger_from_environment(
            environ={},
            client_factory=lambda _service: client,
        ),
        "environment factory accepted a missing distribution ID",
    )

    with tempfile.TemporaryDirectory(prefix="dom-xray-cloudfront-delivery-") as temporary:
        integrated_client = FakeCloudFrontClient(["InProgress", "Completed"])
        integrated_purger = CloudFrontCachePurger(
            integrated_client,
            "E123DOMXRAY",
            clock=lambda: fixed_now,
        )
        delivery = FilesystemArtifactDelivery(
            Path(temporary),
            cache_policy=DeliveryCachePolicy.shared(),
            purger=integrated_purger,
            clock=lambda: fixed_now,
        )
        delivery.activate(delivery.stage(bundle, {"poster": poster, "video": video}))
        try:
            delivery.retire(result_id)
        except PurgePendingError as pending_error:
            durable_operation = pending_error.operation_id
        else:
            raise AssertionError("in-progress CloudFront purge retired the result")
        require(delivery.get(result_id, "bundle") is None, "pending purge exposed origin")
        receipt = delivery.retry_pending(result_id)
        require(receipt is not None, "completed CloudFront retry returned no receipt")
        require(receipt.operation_id == durable_operation, "durable retry changed operation ID")
        require(
            receipt.provider_target_id == "aws:cloudfront:E123DOMXRAY"
            and receipt.provider_request_id == "INV00000001"
            and receipt.purge_required,
            "CloudFront evidence was not persisted in the retirement receipt",
        )
        require(integrated_client.invalidation_count == 1, "delivery retry duplicated purge")

    print(
        "Verified the credential-free CloudFront adapter contract: canonical and query-variant "
        "coverage, operation-ID idempotency, pending-to-Completed polling, provider identity "
        "validation, environment wiring, and durable delivery retry integration; no AWS resource "
        "or real edge cache was exercised."
    )


if __name__ == "__main__":
    main()
