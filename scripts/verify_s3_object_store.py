"""Verify conditional, version-bound private S3 object storage semantics."""

from __future__ import annotations

import copy
import io
import sys
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.artifact_delivery import DELIVERY_VERSION, build_delivery_batch  # noqa: E402
from scanner.delivery_storage import (  # noqa: E402
    ImmutableObjectCollisionError,
    PrivateObjectMissingError,
    PrivateObjectStoreError,
)
from scanner.s3_object_store import (  # noqa: E402
    S3PrivateObjectStore,
    s3_object_store_from_environment,
)
from scripts.verify_result_store import eligible_bundle, poster_png, video_mp4  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(action, message: str) -> None:
    try:
        action()
    except (PrivateObjectStoreError, ValueError):
        return
    raise AssertionError(message)


def capture_store_error(action, message: str) -> PrivateObjectStoreError:
    try:
        action()
    except PrivateObjectStoreError as error:
        return error
    raise AssertionError(message)


class FakeS3Error(RuntimeError):
    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.response = {
            "Error": {"Code": code},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


class ExplodingBody:
    def __init__(self) -> None:
        self.closed = False

    def read(self, _maximum: int) -> bytes:
        raise TimeoutError("simulated stream timeout")

    def close(self) -> None:
        self.closed = True


class FakeS3Client:
    def __init__(
        self,
        *,
        versioning: str = "Enabled",
        public_block: bool = True,
        ownership: str = "BucketOwnerEnforced",
    ) -> None:
        self.versioning = versioning
        self.public_block = public_block
        self.ownership = ownership
        self.objects: dict[str, list[dict[str, object]]] = {}
        self.versioning_calls: list[dict[str, object]] = []
        self.public_access_calls: list[dict[str, object]] = []
        self.ownership_calls: list[dict[str, object]] = []
        self.put_calls: list[dict[str, object]] = []
        self.head_calls: list[dict[str, object]] = []
        self.get_calls: list[dict[str, object]] = []
        self.delete_calls: list[dict[str, object]] = []
        self.list_calls: list[dict[str, object]] = []
        self.conflicts_remaining = 0
        self.omit_version = False
        self.malformed_version_listing = False
        self.truncated_version_listing = False
        self.residual_version = False
        self.residual_delete_marker = False
        self.delete_response_version: str | None = None
        self.get_error: FakeS3Error | None = None
        self.explode_body = False
        self.last_body: ExplodingBody | None = None

    def get_bucket_versioning(self, **kwargs):
        self.versioning_calls.append(copy.deepcopy(kwargs))
        return {"Status": self.versioning}

    def get_public_access_block(self, **kwargs):
        self.public_access_calls.append(copy.deepcopy(kwargs))
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": self.public_block,
                "IgnorePublicAcls": self.public_block,
                "BlockPublicPolicy": self.public_block,
                "RestrictPublicBuckets": self.public_block,
                "FutureAwsField": True,
            }
        }

    def get_bucket_ownership_controls(self, **kwargs):
        self.ownership_calls.append(copy.deepcopy(kwargs))
        return {"OwnershipControls": {"Rules": [{"ObjectOwnership": self.ownership}]}}

    def put_object(self, **kwargs):
        self.put_calls.append(copy.deepcopy(kwargs))
        require(kwargs.get("IfNoneMatch") == "*", "fake received a non-conditional write")
        require("ExpectedBucketOwner" in kwargs, "fake received an unguarded bucket write")
        require("ChecksumSHA256" in kwargs, "fake received a write without a checksum")
        require("ACL" not in kwargs, "fake received an ACL-bearing write")
        if self.conflicts_remaining:
            self.conflicts_remaining -= 1
            raise FakeS3Error("ConditionalRequestConflict", 409)
        key = kwargs["Key"]
        if self.objects.get(key):
            raise FakeS3Error("PreconditionFailed", 412)
        version_id = f"version-{len(self.put_calls):04d}"
        record = {
            "Key": key,
            "VersionId": version_id,
            "BodyBytes": kwargs["Body"],
            "ContentLength": len(kwargs["Body"]),
            "ContentType": kwargs["ContentType"],
            "CacheControl": kwargs["CacheControl"],
            "ChecksumSHA256": kwargs["ChecksumSHA256"],
            "Metadata": copy.deepcopy(kwargs["Metadata"]),
        }
        self.objects.setdefault(key, []).append(record)
        return {} if self.omit_version else {"VersionId": version_id}

    def _find(self, key: str, version_id: str | None) -> dict[str, object]:
        values = self.objects.get(key, [])
        if version_id is None:
            if not values:
                raise FakeS3Error("NoSuchKey", 404)
            return values[-1]
        for value in values:
            if value["VersionId"] == version_id:
                return value
        raise FakeS3Error("NoSuchVersion", 404)

    @staticmethod
    def _headers(record: dict[str, object]) -> dict[str, object]:
        return {
            field: copy.deepcopy(record[field])
            for field in (
                "VersionId",
                "ContentLength",
                "ContentType",
                "CacheControl",
                "ChecksumSHA256",
                "Metadata",
            )
        }

    def head_object(self, **kwargs):
        self.head_calls.append(copy.deepcopy(kwargs))
        return self._headers(self._find(kwargs["Key"], kwargs.get("VersionId")))

    def get_object(self, **kwargs):
        self.get_calls.append(copy.deepcopy(kwargs))
        if self.get_error is not None:
            raise self.get_error
        record = self._find(kwargs["Key"], kwargs.get("VersionId"))
        if self.explode_body:
            self.last_body = ExplodingBody()
            return {**self._headers(record), "Body": self.last_body}
        return {**self._headers(record), "Body": io.BytesIO(record["BodyBytes"])}

    def delete_object(self, **kwargs):
        self.delete_calls.append(copy.deepcopy(kwargs))
        key = kwargs["Key"]
        version_id = kwargs["VersionId"]
        values = self.objects.get(key, [])
        self.objects[key] = [value for value in values if value["VersionId"] != version_id]
        if not self.objects[key]:
            self.objects.pop(key, None)
        return {"VersionId": self.delete_response_version or version_id}

    def list_object_versions(self, **kwargs):
        self.list_calls.append(copy.deepcopy(kwargs))
        if self.truncated_version_listing:
            return {"IsTruncated": True, "Versions": [], "DeleteMarkers": []}
        if self.malformed_version_listing:
            return {"IsTruncated": False, "Versions": ["invalid"], "DeleteMarkers": []}
        prefix = kwargs["Prefix"]
        versions = [
            {"Key": key, "VersionId": value["VersionId"]}
            for key, values in self.objects.items()
            if key.startswith(prefix)
            for value in values
        ]
        if self.residual_version:
            versions.append({"Key": prefix, "VersionId": "unregistered-version"})
        delete_markers = (
            [{"Key": prefix, "VersionId": "residual-delete-marker"}]
            if self.residual_delete_marker
            else []
        )
        return {
            "IsTruncated": False,
            "Versions": versions,
            "DeleteMarkers": delete_markers,
        }


def main() -> None:
    owner = "123456789012"
    bucket = "dom-xray-private-results"
    poster = poster_png()
    video = video_mp4()
    result_id = "r_" + "7" * 32
    bundle = eligible_bundle(result_id, poster, video)
    batch = build_delivery_batch(bundle, {"poster": poster, "video": video})

    client = FakeS3Client()
    store = S3PrivateObjectStore(client, bucket, owner)
    versions = []
    for reference, payload in batch.objects:
        created = store.put(reference, payload)
        require(created.created, f"first {reference.kind} write was not created")
        require(created.provider_version_id.startswith("version-"), "version ID was lost")
        require(store.get(created) == payload, f"{reference.kind} readback changed")
        repeated = store.put(reference, payload)
        require(not repeated.created, f"identical {reference.kind} retry was recreated")
        require(
            repeated.provider_version_id == created.provider_version_id,
            f"identical {reference.kind} retry changed version identity",
        )
        versions.append(created)

    first_put = client.put_calls[0]
    require(
        all(
            calls == [{"Bucket": bucket, "ExpectedBucketOwner": owner}]
            for calls in (
                client.versioning_calls,
                client.public_access_calls,
                client.ownership_calls,
            )
        ),
        "bucket preflight was not owner-guarded",
    )
    require(first_put["IfNoneMatch"] == "*", "S3 write was not conditional")
    require(first_put["ExpectedBucketOwner"] == owner, "bucket owner guard was omitted")
    require(first_put["CacheControl"] == "no-store", "private object became cacheable")
    require("ACL" not in first_put, "S3 write attempted to grant an ACL")
    require(
        first_put["Metadata"]["dom-xray-sha256"] == batch.objects[0][0].sha256,
        "application SHA metadata drifted",
    )
    require(
        first_put["Metadata"]["dom-xray-delivery-version"] == DELIVERY_VERSION,
        "delivery version metadata drifted",
    )
    require(
        first_put["Metadata"]["dom-xray-byte-length"]
        == str(batch.objects[0][0].byte_length),
        "byte-length metadata drifted",
    )
    require(
        all(call.get("ChecksumMode") == "ENABLED" for call in client.get_calls),
        "version-bound reads omitted checksum verification",
    )
    require(
        all(call.get("ChecksumMode") == "ENABLED" for call in client.head_calls),
        "identity reads omitted checksum verification",
    )
    require(
        all("VersionId" in call for call in client.get_calls),
        "registered reads were not bound to exact versions",
    )

    poster_reference = next(item for item, _body in batch.objects if item.kind == "poster")
    bounds_client = FakeS3Client()
    bounds_store = S3PrivateObjectStore(bounds_client, bucket, owner)
    expect_error(
        lambda: bounds_store.put(
            replace(poster_reference, byte_length=5_000_001),
            b"x",
        ),
        "S3 store accepted a poster above the manifest limit",
    )
    require(not bounds_client.put_calls, "invalid poster reached S3")

    conflict_client = FakeS3Client()
    conflict_client.conflicts_remaining = 1
    conflict_backoffs: list[int] = []
    conflict_store = S3PrivateObjectStore(
        conflict_client,
        bucket,
        owner,
        conflict_backoff=conflict_backoffs.append,
    )
    reference, payload = batch.objects[0]
    conflicted = conflict_store.put(reference, payload)
    require(conflicted.created, "retryable 409 did not complete")
    require(len(conflict_client.put_calls) == 2, "conditional conflict was not retried once")
    require(conflict_backoffs == [0], "conditional conflict backoff drifted")

    exhausted_client = FakeS3Client()
    exhausted_client.conflicts_remaining = 10
    exhausted_backoffs: list[int] = []
    exhausted_store = S3PrivateObjectStore(
        exhausted_client,
        bucket,
        owner,
        conflict_backoff=exhausted_backoffs.append,
    )
    exhausted = capture_store_error(
        lambda: exhausted_store.put(reference, payload),
        "exhausted conditional conflicts were accepted",
    )
    require(
        exhausted.code == "provider-transient" and exhausted.retryable,
        "exhausted conditional conflict lost retry semantics",
    )
    require(exhausted_backoffs == [0, 1, 2], "conditional retries were not bounded")

    collision_client = FakeS3Client()
    collision_store = S3PrivateObjectStore(collision_client, bucket, owner)
    collision_store.put(reference, payload)
    collision_client.objects[reference.key][0]["Metadata"] = {
        "dom-xray-sha256": "0" * 64,
        "dom-xray-result-id": reference.result_id,
        "dom-xray-kind": reference.kind,
    }
    try:
        collision_store.put(reference, payload)
    except ImmutableObjectCollisionError:
        pass
    else:
        raise AssertionError("existing mismatched S3 identity was accepted")

    stream_client = FakeS3Client()
    stream_store = S3PrivateObjectStore(stream_client, bucket, owner)
    stream_version = stream_store.put(reference, payload)
    stream_client.explode_body = True
    stream_error = capture_store_error(
        lambda: stream_store.get(stream_version),
        "stream read failure escaped the store error boundary",
    )
    require(
        stream_error.code == "provider-transient" and stream_error.retryable,
        "stream read failure lost retry semantics",
    )
    require(
        stream_client.last_body is not None and stream_client.last_body.closed,
        "failed stream was not closed",
    )
    stream_client.explode_body = False
    missing = capture_store_error(
        lambda: stream_store.get(
            replace(stream_version, provider_version_id="missing-version")
        ),
        "missing exact version was accepted",
    )
    require(
        isinstance(missing, PrivateObjectMissingError)
        and missing.code == "object-missing",
        "missing exact version was not classified safely",
    )
    stream_client.get_error = FakeS3Error("NoSuchBucket", 404)
    missing_bucket = capture_store_error(
        lambda: stream_store.get(stream_version),
        "missing bucket was treated as a successful read",
    )
    require(
        not isinstance(missing_bucket, PrivateObjectMissingError)
        and missing_bucket.code == "provider-invalid",
        "missing bucket was misclassified as a missing object",
    )

    corrupt_client = FakeS3Client()
    corrupt_store = S3PrivateObjectStore(corrupt_client, bucket, owner)
    corrupt_version = corrupt_store.put(reference, payload)
    altered = bytearray(payload)
    altered[-1] ^= 1
    corrupt_client.objects[reference.key][0]["BodyBytes"] = bytes(altered)
    corrupted = capture_store_error(
        lambda: corrupt_store.get(corrupt_version),
        "altered S3 body was accepted",
    )
    require(
        isinstance(corrupted, ImmutableObjectCollisionError),
        "altered S3 body lost immutable-collision classification",
    )

    for version in versions:
        expect_error(
            lambda item=replace(version, provider_target_id="aws:s3:other:bucket"): store.get(item),
            "S3 read accepted a different provider target",
        )
        store.delete(version)
        store.delete(version)
    require(not client.objects, "exact-version deletion left private bytes")
    require(
        all(
            call.get("ExpectedBucketOwner") == owner
            and isinstance(call.get("VersionId"), str)
            for call in client.delete_calls
        ),
        "permanent deletion was not owner-guarded and version-bound",
    )
    require(
        all(
            call.get("Prefix") in {item.key for item, _body in batch.objects}
            and call.get("MaxKeys") == 1000
            and call.get("ExpectedBucketOwner") == owner
            for call in client.list_calls
        ),
        "S3 version-listing request was not key-bounded and owner-guarded",
    )

    mismatch_delete_client = FakeS3Client()
    mismatch_delete_store = S3PrivateObjectStore(mismatch_delete_client, bucket, owner)
    mismatch_delete_version = mismatch_delete_store.put(reference, payload)
    mismatch_delete_client.delete_response_version = "different-version"
    expect_error(
        lambda: mismatch_delete_store.delete(mismatch_delete_version),
        "S3 delete response for a different version was accepted",
    )

    for listing_flag, message in (
        ("malformed_version_listing", "malformed S3 version listing was accepted"),
        ("truncated_version_listing", "truncated S3 version listing was accepted"),
        ("residual_version", "residual S3 version was accepted"),
        ("residual_delete_marker", "residual S3 delete marker was accepted"),
    ):
        deletion_client = FakeS3Client()
        deletion_store = S3PrivateObjectStore(deletion_client, bucket, owner)
        deletion_version = deletion_store.put(reference, payload)
        setattr(deletion_client, listing_flag, True)
        expect_error(
            lambda: deletion_store.delete(deletion_version),
            f"{message} as deletion proof",
        )

    for bad_client, message in (
        (FakeS3Client(versioning="Suspended"), "non-versioned bucket was accepted"),
        (FakeS3Client(public_block=False), "publicly exposable bucket was accepted"),
        (FakeS3Client(ownership="ObjectWriter"), "ACL-owned bucket was accepted"),
    ):
        expect_error(
            lambda candidate=bad_client: S3PrivateObjectStore(candidate, bucket, owner),
            message,
        )

    versionless_client = FakeS3Client()
    versionless_client.omit_version = True
    versionless_store = S3PrivateObjectStore(versionless_client, bucket, owner)
    expect_error(
        lambda: versionless_store.put(reference, payload),
        "version-bound store accepted a write without a version ID",
    )

    built = s3_object_store_from_environment(
        environ={
            "DOM_XRAY_S3_BUCKET": bucket,
            "DOM_XRAY_AWS_ACCOUNT_ID": owner,
        },
        client_factory=lambda service: client if service == "s3" else None,  # type: ignore[arg-type]
    )
    require(built.provider_target_id == store.provider_target_id, "environment wiring drifted")
    expect_error(
        lambda: s3_object_store_from_environment(
            environ={},
            client_factory=lambda _service: client,
        ),
        "environment factory accepted missing S3 settings",
    )

    print(
        "Verified the credential-free S3 private-object contract: bucket privacy/versioning "
        "preflight, If-None-Match creation, SHA/checksum metadata, strong readback, 409 retry, "
        "idempotent collision checks, target/version binding, and permanent exact-version "
        "deletion; no AWS resource or credential was exercised."
    )


if __name__ == "__main__":
    main()
