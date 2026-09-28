"""Credential-free proof of explicit filesystem/composite runtime selection."""

from __future__ import annotations

import base64
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.composite_result_backend import CompositeResultBackend  # noqa: E402
from scanner.local_scan_api import build_result_backend  # noqa: E402
from scanner.result_store import FilesystemResultStore  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class FakeS3:
    def get_bucket_versioning(self, **_kwargs):
        return {"Status": "Enabled"}

    def get_public_access_block(self, **_kwargs):
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

    def get_bucket_ownership_controls(self, **_kwargs):
        return {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}}


class FakeDynamoDB:
    def describe_table(self, **kwargs):
        table = kwargs["TableName"]
        return {
            "Table": {
                "TableName": table,
                "TableStatus": "ACTIVE",
                "AttributeDefinitions": [
                    {"AttributeName": "PK", "AttributeType": "S"},
                    {"AttributeName": "SK", "AttributeType": "S"},
                    {"AttributeName": "GSI1PK", "AttributeType": "S"},
                    {"AttributeName": "GSI1SK", "AttributeType": "N"},
                ],
                "KeySchema": [
                    {"AttributeName": "PK", "KeyType": "HASH"},
                    {"AttributeName": "SK", "KeyType": "RANGE"},
                ],
                "GlobalSecondaryIndexes": [
                    {
                        "IndexName": "GSI1",
                        "IndexStatus": "ACTIVE",
                        "KeySchema": [
                            {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                            {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                    }
                ],
            }
        }

    def describe_time_to_live(self, **_kwargs):
        return {"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}}


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="dom-xray-runtime-") as temporary:
        data_dir = Path(temporary)
        called: list[str] = []

        def forbidden_factory(service: str):
            called.append(service)
            raise AssertionError("filesystem mode requested an AWS client")

        before_aws_modules = {
            name
            for name in ("boto3", "scanner.s3_object_store", "scanner.dynamodb_control_store")
            if name in sys.modules
        }
        local = build_result_backend(
            "filesystem",
            data_dir,
            aws_client_factory=forbidden_factory,
        )
        after_aws_modules = {
            name
            for name in ("boto3", "scanner.s3_object_store", "scanner.dynamodb_control_store")
            if name in sys.modules
        }
        require(isinstance(local, FilesystemResultStore), "filesystem selection returned another backend")
        require(not called, "filesystem selection called an AWS client factory")
        require(before_aws_modules == after_aws_modules, "filesystem selection imported AWS runtime modules")
        require((data_dir / "store.key").is_file(), "filesystem selection did not create its persistent key")
        require(local._retention_seconds == 24 * 60 * 60, "filesystem default retention is not 24 hours")

        secret_keys = (b"a" * 32, b"b" * 32)
        encoded_keys = ",".join(
            base64.urlsafe_b64encode(key).decode("ascii").rstrip("=") for key in secret_keys
        )
        env = {
            "DOM_XRAY_S3_BUCKET": "dom-xray-private-results",
            "DOM_XRAY_AWS_ACCOUNT_ID": "123456789012",
            "DOM_XRAY_DYNAMODB_TABLE": "DomXrayResults",
            "DOM_XRAY_DYNAMODB_TTL_DISABLED_AT_EPOCH": str(int(time.time()) - 7200),
            "DOM_XRAY_CLOUDFRONT_DISTRIBUTION_ID": "EIGNOREDWHILENOSTORE",
            "DOM_XRAY_DELETION_KEYS_B64": encoded_keys,
            "DOM_XRAY_RETENTION_HOURS": "72",
        }
        services: list[str] = []

        def client_factory(service: str):
            services.append(service)
            return FakeS3() if service == "s3" else FakeDynamoDB()

        try:
            composite = build_result_backend(
                "composite",
                data_dir,
                environ=env,
                aws_client_factory=client_factory,
            )
        except RuntimeError as error:
            require(encoded_keys not in str(error), "startup error exposed deletion key material")
            raise
        else:
            pass
        require(isinstance(composite, CompositeResultBackend), "composite selection returned another backend")
        require(composite._retention_seconds == 72 * 60 * 60, "environment retention was not applied")
        require(composite._cache_policy.value == "no-store", "composite mode enabled shared caching")
        require(composite._purger is None, "no-store composite mode unexpectedly configured a purger")
        require(services == ["s3", "dynamodb"], "composite mode did not use injected AWS clients")

        # Invalid credentials/configuration fail closed and never reveal the key.
        try:
            build_result_backend(
                "composite",
                data_dir,
                retention_hours=1,
                environ={**env, "DOM_XRAY_S3_BUCKET": "invalid-secret-bearing-value"},
                aws_client_factory=lambda _service: object(),
            )
        except RuntimeError as error:
            require(encoded_keys not in str(error), "failure output exposed deletion key material")
        else:
            raise AssertionError("invalid composite provider setup unexpectedly succeeded")

        invalid_encodings = (
            encoded_keys + "=",  # padded, not canonical
            " ".join(encoded_keys.split(",")),
            encoded_keys + ",",
            base64.urlsafe_b64encode(b"short").decode("ascii").rstrip("="),
            ",".join(
                base64.urlsafe_b64encode(bytes([index]) * 32)
                .decode("ascii")
                .rstrip("=")
                for index in range(5)
            ),
        )
        for invalid in invalid_encodings:
            try:
                build_result_backend(
                    "composite",
                    data_dir,
                    retention_hours=1,
                    environ={**env, "DOM_XRAY_DELETION_KEYS_B64": invalid},
                    aws_client_factory=forbidden_factory,
                )
            except ValueError as error:
                require(invalid not in str(error), "key parser echoed secret input")
            else:
                raise AssertionError("noncanonical deletion keys were accepted")

        for invalid_hours in (None, 0, -1, float("inf"), float("nan")):
            invalid_env = dict(env)
            if invalid_hours is None:
                invalid_env.pop("DOM_XRAY_RETENTION_HOURS")
            else:
                invalid_env["DOM_XRAY_RETENTION_HOURS"] = str(invalid_hours)
            try:
                build_result_backend(
                    "composite",
                    data_dir,
                    environ=invalid_env,
                    aws_client_factory=forbidden_factory,
                )
            except ValueError:
                continue
            raise AssertionError("composite mode accepted missing or invalid retention")

    print(
        "Verified filesystem default/key/24-hour retention without AWS imports or client calls, "
        "and explicit composite configuration with injected AWS clients, no-store policy, "
        "strict secret-safe deletion-key parsing, and fail-closed retention/provider errors."
    )


if __name__ == "__main__":
    main()
