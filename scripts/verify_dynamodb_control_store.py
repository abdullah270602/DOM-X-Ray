"""Verify conditional DynamoDB result-control lifecycle semantics."""

from __future__ import annotations

import copy
import sys
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.artifact_delivery import (  # noqa: E402
    DeliveryCachePolicy,
    build_delivery_batch,
)
from scanner.delivery_control import (  # noqa: E402
    ResultControlRecord,
    build_retirement_plan,
    build_staged_control,
    timestamp_epoch_ms,
)
from scanner.delivery_storage import PrivateObjectVersion  # noqa: E402
from scanner.dynamodb_control_store import (  # noqa: E402
    ControlCollisionError,
    ControlConflictError,
    ControlNotExpiredError,
    ControlStoreError,
    DynamoDBControlStore,
    decode_control_item,
    dynamodb_control_store_from_environment,
    encode_control_item,
)
from scripts.verify_result_store import eligible_bundle, poster_png, video_mp4  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def capture_error(action, message: str) -> ControlStoreError:
    try:
        action()
    except ControlStoreError as error:
        return error
    raise AssertionError(message)


def capture_value_error(action, message: str) -> ValueError:
    try:
        action()
    except ValueError as error:
        return error
    raise AssertionError(message)


class FakeDynamoError(RuntimeError):
    def __init__(self, code: str, status: int, *, item=None) -> None:
        super().__init__(code)
        self.response = {
            "Error": {"Code": code},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }
        if item is not None:
            self.response["Item"] = copy.deepcopy(item)


class FakeDynamoClient:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, object]] = {}
        self.describe_table_calls: list[dict[str, object]] = []
        self.describe_ttl_calls: list[dict[str, object]] = []
        self.put_calls: list[dict[str, object]] = []
        self.update_calls: list[dict[str, object]] = []
        self.get_calls: list[dict[str, object]] = []
        self.query_calls: list[dict[str, object]] = []
        self.query_error: Exception | None = None
        self.query_response: dict[str, object] | None = None
        self.describe_error: Exception | None = None
        self.table_response: dict[str, object] | None = None
        self.ttl_response: dict[str, object] | None = None

    def describe_table(self, **kwargs):
        self.describe_table_calls.append(copy.deepcopy(kwargs))
        if self.describe_error is not None:
            raise self.describe_error
        if self.table_response is not None:
            return copy.deepcopy(self.table_response)
        indexes = []
        for name in ("GSI1", "ExpiryIndex"):
            indexes.append(
                {
                    "IndexName": name,
                    "IndexStatus": "ACTIVE",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "KEYS_ONLY"},
                }
            )
        return {
            "Table": {
                "TableName": kwargs["TableName"],
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
                "GlobalSecondaryIndexes": indexes,
            }
        }

    def describe_time_to_live(self, **kwargs):
        self.describe_ttl_calls.append(copy.deepcopy(kwargs))
        if self.describe_error is not None:
            raise self.describe_error
        if self.ttl_response is not None:
            return copy.deepcopy(self.ttl_response)
        return {"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}}

    @staticmethod
    def _string(value: object) -> str:
        assert isinstance(value, dict) and set(value) == {"S"}
        result = value["S"]
        assert isinstance(result, str)
        return result

    @staticmethod
    def _number(value: object) -> int:
        assert isinstance(value, dict) and set(value) == {"N"}
        result = value["N"]
        assert isinstance(result, str)
        return int(result)

    @classmethod
    def _key_tuple(cls, key: object) -> tuple[str, str]:
        assert isinstance(key, dict) and set(key) == {"PK", "SK"}
        return cls._string(key["PK"]), cls._string(key["SK"])

    @staticmethod
    def _conditional(item: dict[str, object] | None = None):
        raise FakeDynamoError(
            "ConditionalCheckFailedException",
            400,
            item=item,
        )

    def put_item(self, **kwargs):
        self.put_calls.append(copy.deepcopy(kwargs))
        require(
            kwargs.get("ConditionExpression") == "attribute_not_exists(#pk)",
            "fake received an unconditional control put",
        )
        require(
            kwargs.get("ReturnValuesOnConditionCheckFailure") == "ALL_OLD",
            "control put omitted failed-condition evidence",
        )
        item = copy.deepcopy(kwargs["Item"])
        key = self._key_tuple({"PK": item["PK"], "SK": item["SK"]})
        if key in self.items:
            self._conditional(self.items[key])
        self.items[key] = item
        return {"ConsumedCapacity": {"CapacityUnits": 1.0}}

    def get_item(self, **kwargs):
        self.get_calls.append(copy.deepcopy(kwargs))
        require(kwargs.get("ConsistentRead") is True, "control read was not consistent")
        item = self.items.get(self._key_tuple(kwargs["Key"]))
        return {} if item is None else {"Item": copy.deepcopy(item)}

    @staticmethod
    def _matches(item: dict[str, object], name: str, value: object) -> bool:
        return item.get(name) == value

    def update_item(self, **kwargs):
        self.update_calls.append(copy.deepcopy(kwargs))
        key = self._key_tuple(kwargs["Key"])
        item = self.items.get(key)
        if item is None:
            self._conditional()
        assert item is not None
        names = kwargs["ExpressionAttributeNames"]
        values = kwargs["ExpressionAttributeValues"]
        expression = kwargs["UpdateExpression"]

        def actual(alias: str) -> str:
            return names[alias]

        def equals(alias: str, token: str) -> bool:
            return self._matches(item, actual(alias), values[token])

        def set_value(alias: str, token: str) -> None:
            item[actual(alias)] = copy.deepcopy(values[token])

        def increment_revision() -> None:
            revision_name = actual("#revision")
            item[revision_name] = {
                "N": str(self._number(item[revision_name]) + self._number(values[":one"]))
            }

        if expression.startswith("SET #state = :live"):
            condition = (
                equals("#state", ":staged")
                and equals("#revision", ":zero")
                and equals("#identity", ":identity")
            )
            if "#expires" in names:
                condition = condition and self._number(
                    item[actual("#expires")]
                ) > self._number(values[":now"])
            if not condition:
                self._conditional(item)
            set_value("#state", ":live")
            set_value("#activated", ":activated")
            increment_revision()
            if "#gsiPk" in names:
                set_value("#gsiPk", ":expiryPk")
                set_value("#gsiSk", ":expiryEpoch")
        elif expression.startswith("SET #state = :retiring"):
            condition = (
                equals("#state", ":live")
                and equals("#revision", ":revision")
                and equals("#identity", ":identity")
            )
            if "#expires" in names:
                condition = condition and self._number(item[actual("#expires")]) <= self._number(
                    values[":now"]
                )
            if not condition:
                self._conditional(item)
            for alias, token in (
                ("#state", ":retiring"),
                ("#retiredAt", ":retiredAt"),
                ("#operation", ":operation"),
                ("#coverage", ":coverage"),
                ("#required", ":required"),
                ("#purgeState", ":purgeState"),
                ("#cleanup", ":cleanup"),
            ):
                set_value(alias, token)
            if "#target" in names:
                set_value("#target", ":target")
            if "#confirmedAt" in names:
                set_value("#confirmedAt", ":confirmedAt")
            increment_revision()
            item.pop(actual("#gsiPk"), None)
            item.pop(actual("#gsiSk"), None)
        elif expression.startswith("SET #request = :request"):
            condition = (
                equals("#state", ":retiring")
                and equals("#identity", ":identity")
                and equals("#operation", ":operation")
                and equals("#coverage", ":coverage")
                and equals("#target", ":target")
                and equals("#purgeState", ":pending")
                and actual("#request") not in item
            )
            if not condition:
                self._conditional(item)
            set_value("#request", ":request")
            increment_revision()
        elif expression.startswith("SET #purgeState = :confirmed"):
            request_name = actual("#request")
            condition = (
                equals("#state", ":retiring")
                and equals("#identity", ":identity")
                and equals("#operation", ":operation")
                and equals("#coverage", ":coverage")
                and equals("#target", ":target")
                and equals("#purgeState", ":pending")
                and (request_name not in item or item[request_name] == values[":request"])
            )
            if not condition:
                self._conditional(item)
            set_value("#purgeState", ":confirmed")
            set_value("#request", ":request")
            set_value("#confirmedAt", ":confirmedAt")
            increment_revision()
        elif expression.startswith("SET #state = :retired"):
            if not (
                equals("#state", ":retiring")
                and equals("#identity", ":identity")
                and equals("#operation", ":operation")
                and equals("#coverage", ":coverage")
                and equals("#purgeState", ":confirmed")
                and equals("#revision", ":revision")
            ):
                self._conditional(item)
            set_value("#state", ":retired")
            increment_revision()
        elif expression.startswith("SET #cleanup = :complete"):
            if not (
                equals("#state", ":retired")
                and equals("#identity", ":identity")
                and equals("#cleanup", ":pending")
                and equals("#purgeState", ":confirmed")
                and equals("#revision", ":revision")
            ):
                self._conditional(item)
            set_value("#cleanup", ":complete")
            increment_revision()
        else:
            raise AssertionError(f"unexpected update expression: {expression}")
        self.items[key] = item
        return {"Attributes": copy.deepcopy(item)}

    def query(self, **kwargs):
        self.query_calls.append(copy.deepcopy(kwargs))
        if self.query_error is not None:
            raise self.query_error
        require("ConsistentRead" not in kwargs, "GSI query requested strong consistency")
        require(
            kwargs.get("KeyConditionExpression") == "#gpk = :expiryPk AND #gsk <= :now",
            "expiry query condition drifted",
        )
        if self.query_response is not None:
            return copy.deepcopy(self.query_response)
        now_epoch_ms = self._number(kwargs["ExpressionAttributeValues"][":now"])
        candidates = sorted(
            (
                item
                for item in self.items.values()
                if "GSI1PK" in item
                and self._string(item["GSI1PK"]) == "LIVE_EXPIRY"
                and self._number(item["GSI1SK"]) <= now_epoch_ms
            ),
            key=lambda item: (self._number(item["GSI1SK"]), self._string(item["PK"])),
        )
        cursor = kwargs.get("ExclusiveStartKey")
        if cursor is not None:
            cursor_key = (
                self._number(cursor["GSI1SK"]),
                self._string(cursor["PK"]),
            )
            candidates = [
                item
                for item in candidates
                if (self._number(item["GSI1SK"]), self._string(item["PK"])) > cursor_key
            ]
        limit = kwargs["Limit"]
        page = candidates[:limit]
        response = {
            "Items": [
                {"PK": copy.deepcopy(item["PK"]), "SK": copy.deepcopy(item["SK"])}
                for item in page
            ]
        }
        if len(candidates) > limit and page:
            last = page[-1]
            response["LastEvaluatedKey"] = {
                "PK": copy.deepcopy(last["PK"]),
                "SK": copy.deepcopy(last["SK"]),
                "GSI1PK": copy.deepcopy(last["GSI1PK"]),
                "GSI1SK": copy.deepcopy(last["GSI1SK"]),
            }
        return response


def control_store(
    client: FakeDynamoClient,
    table: str,
    *,
    ttl_disabled_at_epoch: int = 1_000_000,
    checked_at_epoch: int = 1_003_600,
) -> DynamoDBControlStore:
    return DynamoDBControlStore(
        client,
        table,
        ttl_disabled_at_epoch=ttl_disabled_at_epoch,
        checked_at_epoch=checked_at_epoch,
    )


def staged_record(
    result_id: str,
    *,
    cache_policy: DeliveryCachePolicy,
    expires_at: str | None,
    deletion_hmac: str = "b" * 64,
    version_suffix: str = "one",
) -> ResultControlRecord:
    poster = poster_png()
    video = video_mp4()
    bundle = eligible_bundle(result_id, poster, video)
    batch = build_delivery_batch(bundle, {"poster": poster, "video": video})
    versions = tuple(
        PrivateObjectVersion(
            reference=reference,
            provider_target_id="aws:s3:123456789012:dom-xray-private-results",
            provider_version_id=f"version-{reference.kind}-{version_suffix}",
            created=True,
        )
        for reference, _payload in batch.objects
    )
    return build_staged_control(
        batch,
        versions,
        published_at="2026-09-27T12:00:00.000Z",
        expires_at=expires_at,
        deletion_key_id="a" * 16,
        deletion_digest_hmac_sha256=deletion_hmac,
        cache_policy=cache_policy,
    )


def main() -> None:
    table = "dom-xray-result-control"
    client = FakeDynamoClient()
    store = control_store(client, table)
    require(
        client.describe_table_calls == [{"TableName": table}]
        and client.describe_ttl_calls == [{"TableName": table}],
        "control store skipped its table/TTL preflight",
    )
    wrong_schema_client = FakeDynamoClient()
    wrong_schema = wrong_schema_client.describe_table(TableName=table)
    wrong_schema["Table"]["AttributeDefinitions"][0]["AttributeType"] = "N"  # type: ignore[index]
    wrong_schema_client.table_response = wrong_schema
    wrong_schema_error = capture_error(
        lambda: control_store(wrong_schema_client, table),
        "control store accepted a numeric partition key",
    )
    require(
        wrong_schema_error.code == "provider-invalid" and not wrong_schema_error.retryable,
        "schema drift lost permanent provider classification",
    )
    ttl_client = FakeDynamoClient()
    ttl_client.ttl_response = {
        "TimeToLiveDescription": {
            "TimeToLiveStatus": "ENABLED",
            "AttributeName": "expiresAtEpochMs",
        }
    }
    ttl_error = capture_error(
        lambda: control_store(ttl_client, table),
        "control store accepted TTL that could delete tombstones",
    )
    require(
        ttl_error.code == "provider-invalid" and not ttl_error.retryable,
        "TTL drift lost permanent provider classification",
    )
    preflight_throttle_client = FakeDynamoClient()
    preflight_throttle_client.describe_error = FakeDynamoError(
        "ThrottlingException",
        400,
    )
    preflight_throttle = capture_error(
        lambda: control_store(preflight_throttle_client, table),
        "DynamoDB preflight throttling escaped the adapter boundary",
    )
    require(
        preflight_throttle.code == "provider-transient"
        and preflight_throttle.retryable,
        "DynamoDB preflight throttling lost retry semantics",
    )
    drain_client = FakeDynamoClient()
    drain_error = capture_error(
        lambda: control_store(drain_client, table, checked_at_epoch=1_003_599),
        "control store accepted DynamoDB's post-disable TTL deletion window",
    )
    require(
        drain_error.code == "provider-invalid" and not drain_error.retryable,
        "TTL quarantine failure lost permanent provider classification",
    )
    staged = staged_record(
        "r_" + "1" * 32,
        cache_policy=DeliveryCachePolicy.no_store(),
        expires_at="2026-09-27T12:00:10.500Z",
    )
    encoded = encode_control_item(staged)
    require(decode_control_item(encoded) == staged, "control codec changed the staged record")
    require("bundle" not in encoded and len(str(encoded)) < 350_000, "control item stored payload bytes")
    malformed_state = copy.deepcopy(encoded)
    malformed_state["state"] = {"S": "invented"}
    require(
        capture_error(
            lambda: decode_control_item(malformed_state),
            "semantic item corruption escaped the control-store boundary",
        ).code
        == "provider-invalid",
        "semantic item corruption lost provider-invalid classification",
    )
    oversized = copy.deepcopy(encoded)
    oversized["unexpected"] = {"S": "x" * 350_000}
    require(
        "size budget"
        in str(
            capture_error(
                lambda: decode_control_item(oversized),
                "oversized provider item bypassed the decode budget",
            )
        ),
        "oversized provider item was not rejected at the size boundary",
    )

    created = store.create_staged(staged)
    require(created == staged, "staged control creation changed the record")
    require(store.create_staged(staged) == staged, "identical staged retry did not converge")
    require(
        client.put_calls[0]["ReturnValuesOnConditionCheckFailure"] == "ALL_OLD",
        "staged write omitted conditional failure evidence",
    )
    competing_owner = staged_record(
        staged.result_id,
        cache_policy=DeliveryCachePolicy.no_store(),
        expires_at=staged.expires_at,
        deletion_hmac="c" * 64,
    )
    require(
        isinstance(
            capture_error(
                lambda: store.create_staged(competing_owner),
                "different deletion capability was accepted as an idempotent retry",
            ),
            ControlCollisionError,
        ),
        "deletion-capability drift lost immutable-collision classification",
    )
    require(
        store.get_control(staged.result_id) == staged,
        "rejected capability drift changed the first writer's control identity",
    )
    competing_expiry = staged_record(
        staged.result_id,
        cache_policy=DeliveryCachePolicy.no_store(),
        expires_at="2026-09-27T12:00:20.500Z",
    )
    require(
        isinstance(
            capture_error(
                lambda: store.create_staged(competing_expiry),
                "different retention was accepted as an idempotent retry",
            ),
            ControlCollisionError,
        ),
        "retention drift lost immutable-collision classification",
    )
    changed_version = staged_record(
        staged.result_id,
        cache_policy=DeliveryCachePolicy.no_store(),
        expires_at=staged.expires_at,
        version_suffix="different",
    )
    require(
        isinstance(
            capture_error(
                lambda: store.create_staged(changed_version),
                "different S3 version registry reused one result ID",
            ),
            ControlCollisionError,
        ),
        "different S3 registry lost immutable-collision classification",
    )

    live = store.activate(
        staged,
        activated_at="2026-09-27T12:00:01.000Z",
        now_epoch_ms=timestamp_epoch_ms(
            "2026-09-27T12:00:01.000Z",
            "activation time",
        ),
    )
    require(live.state == "live" and live.revision == 1, "activation did not become live")
    require(
        store.get_live(
            live.result_id,
            now_epoch_ms=live.expires_at_epoch_ms - 1,  # type: ignore[operator]
        )
        == live,
        "visibility read hid a result before its exact expiry",
    )
    require(
        store.get_live(
            live.result_id,
            now_epoch_ms=live.expires_at_epoch_ms,  # type: ignore[arg-type]
        )
        is None,
        "visibility read exposed a result at its exact expiry",
    )
    require(
        store.activate(
            staged,
            activated_at="2026-09-27T12:00:01.000Z",
            now_epoch_ms=timestamp_epoch_ms(
                "2026-09-27T12:00:01.000Z",
                "activation time",
            ),
        )
        == live,
        "activation retry did not converge",
    )
    require(
        isinstance(
            capture_error(
                lambda: store.activate(
                    staged,
                    activated_at="2026-09-27T12:00:02.000Z",
                    now_epoch_ms=timestamp_epoch_ms(
                        "2026-09-27T12:00:02.000Z",
                        "activation time",
                    ),
                ),
                "activation retry changed the persisted activation time",
            ),
            ControlCollisionError,
        ),
        "activation-time drift lost immutable-collision classification",
    )
    capture_value_error(
        lambda: control_store(FakeDynamoClient(), table).activate(
            staged_record(
                "r_" + "9" * 32,
                cache_policy=DeliveryCachePolicy.no_store(),
                expires_at="2026-09-27T12:00:00.500Z",
            ),
            activated_at="2026-09-27T12:00:00.500Z",
            now_epoch_ms=timestamp_epoch_ms(
                "2026-09-27T12:00:00.500Z",
                "activation time",
            ),
        ),
        "control activation accepted an elapsed expiry",
    )
    require(
        store.list_expired(live.expires_at_epoch_ms - 1)[0] == (),  # type: ignore[operator]
        "expiry index returned a result before its boundary",
    )
    expired, cursor = store.list_expired(live.expires_at_epoch_ms)  # type: ignore[arg-type]
    require(expired == (live,) and cursor is None, "expiry query lost the live candidate")
    require(
        all(call.get("ConsistentRead") is True for call in client.get_calls),
        "control lifecycle used an eventual base-table read",
    )
    require(
        isinstance(
            capture_error(
                lambda: store.begin_retirement(
                    live,
                    build_retirement_plan(
                        live,
                        operation_id="p_" + "1" * 32,
                        provider_target_id=None,
                    ),
                    retired_at="2026-09-27T12:00:02.000Z",
                    require_expired=True,
                    now_epoch_ms=live.expires_at_epoch_ms - 1,  # type: ignore[operator]
                ),
                "retention retired a live result early",
            ),
            ControlNotExpiredError,
        ),
        "early expiry lost not-expired classification",
    )
    no_purge_plan = build_retirement_plan(
        live,
        operation_id="p_" + "1" * 32,
        provider_target_id=None,
    )
    capture_value_error(
        lambda: store.begin_retirement(
            live,
            no_purge_plan,
            retired_at="2026-09-27T12:00:00.500Z",
        ),
        "control retirement accepted a timestamp before activation",
    )
    retiring_no_purge = store.begin_retirement(
        live,
        no_purge_plan,
        retired_at="2026-09-27T12:00:11.000Z",
        require_expired=True,
        now_epoch_ms=live.expires_at_epoch_ms,  # type: ignore[arg-type]
    )
    require(
        retiring_no_purge.state == "retiring"
        and retiring_no_purge.purge_required is False
        and retiring_no_purge.purge_state == "confirmed",
        "no-store retirement invented a provider purge",
    )
    retired_no_purge = store.finalize_retirement(retiring_no_purge)
    cleaned_no_purge = store.mark_cleanup_complete(retired_no_purge)
    require(
        cleaned_no_purge.state == "retired"
        and cleaned_no_purge.cleanup_state == "complete",
        "no-store tombstone did not retain cleanup proof",
    )
    require(
        store.mark_cleanup_complete(retired_no_purge) == cleaned_no_purge,
        "cleanup retry did not converge",
    )
    require(
        isinstance(
            capture_error(
                lambda: store.create_staged(staged),
                "retired result ID was reused",
            ),
            ControlCollisionError,
        ),
        "retired result lost tombstone precedence",
    )

    shared_staged = staged_record(
        "r_" + "2" * 32,
        cache_policy=DeliveryCachePolicy.shared(s_maxage_seconds=3600),
        expires_at=None,
    )
    store.create_staged(shared_staged)
    shared_live = store.activate(
        shared_staged,
        activated_at="2026-09-27T12:00:01.000Z",
        now_epoch_ms=timestamp_epoch_ms(
            "2026-09-27T12:00:01.000Z",
            "activation time",
        ),
    )
    first_plan = build_retirement_plan(
        shared_live,
        operation_id="p_" + "2" * 32,
        provider_target_id="aws:cloudfront:E1234567890",
    )
    shared_retiring = store.begin_retirement(
        shared_live,
        first_plan,
        retired_at="2026-09-27T12:00:02.000Z",
    )
    require(
        shared_retiring.state == "retiring" and shared_retiring.purge_state == "pending",
        "shared retirement became visible or confirmed too early",
    )
    competing_plan = build_retirement_plan(
        shared_live,
        operation_id="p_" + "3" * 32,
        provider_target_id=first_plan.provider_target_id,
    )
    converged = store.begin_retirement(
        shared_live,
        competing_plan,
        retired_at="2026-09-27T12:00:03.000Z",
    )
    require(
        converged.purge_operation_id == first_plan.operation_id,
        "concurrent retirement did not reuse the winning operation ID",
    )
    alternate_staged = staged_record(
        shared_live.result_id,
        cache_policy=DeliveryCachePolicy.shared(s_maxage_seconds=3600),
        expires_at=None,
        deletion_hmac="c" * 64,
    )
    alternate_live = replace(
        alternate_staged,
        state="live",
        revision=1,
        activated_at=shared_live.activated_at,
    )
    alternate_plan = build_retirement_plan(
        alternate_live,
        operation_id="p_" + "4" * 32,
        provider_target_id=first_plan.provider_target_id,
    )
    require(
        isinstance(
            capture_error(
                lambda: store.begin_retirement(
                    alternate_live,
                    alternate_plan,
                    retired_at="2026-09-27T12:00:03.000Z",
                ),
                "concurrent retirement crossed control identities",
            ),
            ControlConflictError,
        ),
        "control-identity drift lost conflict classification",
    )
    pending = store.record_pending_purge(
        shared_retiring,
        provider_request_id="invalidation-001",
    )
    require(pending.purge_provider_request_id == "invalidation-001", "pending purge ID was lost")
    require(
        store.record_pending_purge(
            shared_retiring,
            provider_request_id="invalidation-001",
        )
        == pending,
        "pending purge retry did not converge",
    )
    drifted_target = replace(
        shared_retiring,
        purge_provider_target_id="aws:cloudfront:E9999999999",
    )
    require(
        isinstance(
            capture_error(
                lambda: store.record_pending_purge(
                    drifted_target,
                    provider_request_id="invalidation-001",
                ),
                "purge target drift was accepted",
            ),
            ControlConflictError,
        ),
        "purge target drift lost conflict classification",
    )
    forged_confirmed = replace(
        pending,
        purge_state="confirmed",
        purge_confirmed_at="2026-09-27T12:00:04.000Z",
    )
    require(
        isinstance(
            capture_error(
                lambda: store.record_confirmed_purge(
                    forged_confirmed,
                    provider_request_id="invalidation-001",
                    confirmed_at="2026-09-27T12:00:04.000Z",
                ),
                "caller-supplied purge confirmation bypassed persistence",
            ),
            ControlCollisionError,
        ),
        "unpersisted purge confirmation did not fail closed",
    )
    capture_value_error(
        lambda: store.record_confirmed_purge(
            pending,
            provider_request_id="invalidation-001",
            confirmed_at="2026-09-27T12:00:01.500Z",
        ),
        "purge confirmation accepted a timestamp before retirement",
    )
    confirmed = store.record_confirmed_purge(
        pending,
        provider_request_id="invalidation-001",
        confirmed_at="2026-09-27T12:00:04.000Z",
    )
    require(confirmed.purge_state == "confirmed", "provider completion was not recorded")
    require(
        store.record_pending_purge(
            shared_retiring,
            provider_request_id="invalidation-001",
        )
        == confirmed,
        "stale pending retry overwrote confirmed evidence",
    )
    shared_retired = store.finalize_retirement(confirmed)
    require(
        store.finalize_retirement(confirmed) == shared_retired,
        "retirement finalization retry did not converge",
    )
    forged_cleanup = replace(shared_retired, cleanup_state="complete")
    require(
        isinstance(
            capture_error(
                lambda: store.mark_cleanup_complete(forged_cleanup),
                "caller-supplied cleanup receipt bypassed persistence",
            ),
            ControlConflictError,
        ),
        "unpersisted cleanup receipt did not fail closed",
    )
    shared_clean = store.mark_cleanup_complete(shared_retired)
    require(shared_clean.cleanup_state == "complete", "shared cleanup was not recorded")

    page_client = FakeDynamoClient()
    page_store = control_store(page_client, table)
    page_lives = []
    for digit, expiry in (("3", "2026-09-27T12:00:05.000Z"), ("4", "2026-09-27T12:00:06.000Z")):
        candidate = staged_record(
            "r_" + digit * 32,
            cache_policy=DeliveryCachePolicy.no_store(),
            expires_at=expiry,
        )
        page_store.create_staged(candidate)
        page_lives.append(
            page_store.activate(
                candidate,
                activated_at="2026-09-27T12:00:01.000Z",
                now_epoch_ms=timestamp_epoch_ms(
                    "2026-09-27T12:00:01.000Z",
                    "activation time",
                ),
            )
        )
    first_page, next_token = page_store.list_expired(
        page_lives[-1].expires_at_epoch_ms,  # type: ignore[arg-type]
        limit=1,
    )
    require(len(first_page) == 1 and next_token is not None, "expiry cursor was not emitted")
    second_page, final_token = page_store.list_expired(
        page_lives[-1].expires_at_epoch_ms,  # type: ignore[arg-type]
        limit=1,
        next_token=next_token,
    )
    require(
        len(second_page) == 1
        and second_page[0].result_id != first_page[0].result_id
        and final_token is None,
        "expiry cursor repeated or skipped a result",
    )
    capture_value_error(
        lambda: page_store.list_expired(
            page_lives[-1].expires_at_epoch_ms,  # type: ignore[arg-type]
            next_token={"PK": {"S": "wrong"}},
        ),
        "expiry query accepted a malformed input cursor",
    )
    future_cursor = copy.deepcopy(next_token)
    assert future_cursor is not None
    future_cursor["GSI1SK"] = {
        "N": str(page_lives[-1].expires_at_epoch_ms + 1)  # type: ignore[operator]
    }
    capture_value_error(
        lambda: page_store.list_expired(
            page_lives[-1].expires_at_epoch_ms,  # type: ignore[arg-type]
            next_token=future_cursor,
        ),
        "expiry query accepted a cursor beyond its time boundary",
    )
    malformed_page_client = FakeDynamoClient()
    malformed_page_client.query_response = {
        "Items": [],
        "LastEvaluatedKey": {"PK": {"S": "wrong"}},
    }
    malformed_page_store = control_store(malformed_page_client, table)
    capture_error(
        lambda: malformed_page_store.list_expired(1),
        "expiry query accepted a malformed provider cursor",
    )
    future_page_client = FakeDynamoClient()
    future_page_client.query_response = {
        "Items": [],
        "LastEvaluatedKey": copy.deepcopy(future_cursor),
    }
    future_page_store = control_store(future_page_client, table)
    capture_error(
        lambda: future_page_store.list_expired(
            page_lives[-1].expires_at_epoch_ms,  # type: ignore[arg-type]
        ),
        "expiry query accepted a provider cursor beyond its time boundary",
    )
    oversized_page_client = FakeDynamoClient()
    candidate_key = {
        "PK": {"S": "RESULT#r_" + "8" * 32},
        "SK": {"S": "CONTROL"},
    }
    oversized_page_client.query_response = {
        "Items": [copy.deepcopy(candidate_key), copy.deepcopy(candidate_key)],
    }
    oversized_page_store = control_store(oversized_page_client, table)
    capture_error(
        lambda: oversized_page_store.list_expired(1, limit=1),
        "expiry query accepted more provider candidates than requested",
    )

    transient_client = FakeDynamoClient()
    transient_store = control_store(transient_client, table)
    transient_client.query_error = FakeDynamoError("ThrottlingException", 400)
    transient = capture_error(
        lambda: transient_store.list_expired(1),
        "DynamoDB throttling escaped the adapter boundary",
    )
    require(
        transient.code == "provider-transient" and transient.retryable,
        "DynamoDB throttling lost retry semantics",
    )

    built = dynamodb_control_store_from_environment(
        environ={
            "DOM_XRAY_DYNAMODB_TABLE": table,
            "DOM_XRAY_DYNAMODB_EXPIRY_INDEX": "ExpiryIndex",
            "DOM_XRAY_DYNAMODB_TTL_DISABLED_AT_EPOCH": "1000000",
        },
        client_factory=lambda service: client if service == "dynamodb" else None,  # type: ignore[arg-type]
    )
    require(built.table_name == table, "DynamoDB environment wiring drifted")
    try:
        dynamodb_control_store_from_environment(
            environ={},
            client_factory=lambda _service: client,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("DynamoDB factory accepted a missing table")

    require(
        all(call.get("ConsistentRead") is None for call in client.query_calls),
        "GSI expiry query requested unsupported strong consistency",
    )
    print(
        "Verified the credential-free DynamoDB control contract: table/GSI/TTL and quarantine "
        "preflight, bounded AttributeValue codec, full-identity insert-only staging, exact-"
        "millisecond activation/visibility/expiry fences, strong reads, bounded candidate "
        "cursors, winning operation-ID convergence, persisted purge evidence, permanent "
        "tombstones, and cleanup receipts; no AWS resource or credential was exercised."
    )


if __name__ == "__main__":
    main()
