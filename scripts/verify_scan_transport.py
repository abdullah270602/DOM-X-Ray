"""Verify the deployment-neutral public-scan transport seam."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.destination_policy import (  # noqa: E402
    MAX_DNS_ANSWERS,
    DestinationPolicy,
    DestinationPolicyError,
)
from scanner.scan_transport import (  # noqa: E402
    PublicScanGrant,
    RecordValidator,
    WorkerLaunch,
    authorize_connection,
    run_public_scan_transport,
)
from scripts.validate_fixtures import validate_semantics  # noqa: E402


PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"
WORKER = ROOT / "fixtures" / "worker" / "scan_transport_worker_fixture.py"
RECORD = ROOT / "fixtures" / "scan" / "clean.json"
SCHEMA = json.loads(
    (ROOT / "docs" / "SCAN_RECORD.schema.json").read_text(encoding="utf-8")
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class SequenceResolver:
    def __init__(self, answers: list[object]) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, int]] = []

    def __call__(self, hostname: str, port: int) -> list[str]:
        self.calls.append((hostname, port))
        if not self.answers:
            raise RuntimeError("resolver sequence exhausted")
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return list(answer)  # type: ignore[arg-type]


class LaunchLedger:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.grants: list[PublicScanGrant] = []

    def __call__(self, grant: PublicScanGrant, result_path: Path) -> WorkerLaunch:
        self.grants.append(grant)
        environment = None
        if self.mode == "rewrite-requested-url":
            environment = os.environ.copy()
            environment["DOM_X_RAY_FIXTURE_REQUESTED_URL"] = grant.target_url
        return WorkerLaunch(
            command=(
                sys.executable,
                str(WORKER),
                self.mode,
                str(RECORD),
                str(result_path),
            ),
            cwd=ROOT,
            environment=environment,
        )


def validators() -> tuple[RecordValidator, RecordValidator]:
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())

    def schema_validator(record: dict[str, Any]) -> None:
        errors = sorted(validator.iter_errors(record), key=lambda error: list(error.path))
        if errors:
            raise ValueError("scan record failed schema")

    def semantic_validator(record: dict[str, Any]) -> None:
        validate_semantics(record, "scan transport record", validator)

    return schema_validator, semantic_validator


def run_case(
    mode: str,
    *,
    policy: DestinationPolicy | None = None,
    target_url: str = "https://public.example/path",
    deadline_seconds: float = 2,
):
    launch = LaunchLedger(mode)
    schema_validator, semantic_validator = validators()
    result = run_public_scan_transport(
        target_url,
        policy=policy or DestinationPolicy(lambda _host, _port: [PUBLIC_V4]),
        launch_worker=launch,
        schema_validator=schema_validator,
        semantic_validator=semantic_validator,
        deadline_seconds=deadline_seconds,
    )
    return result, launch


def verify_valid_grants_and_admission() -> None:
    resolver = SequenceResolver([[PUBLIC_V6, PUBLIC_V4], [PUBLIC_V4], [PUBLIC_V6]])
    policy = DestinationPolicy(resolver)
    cases = (
        ("https://public.example/path", "initial"),
        ("https://redirect.example/next?state=opaque", "redirect"),
        ("http://assets.example/image.png?token=secret", "subresource"),
    )
    destinations = []
    for target_url, purpose in cases:
        result = authorize_connection(
            target_url,
            purpose=purpose,  # type: ignore[arg-type]
            policy=policy,
            connector=lambda destination: destination,
        )
        destinations.append(result)
    require(
        resolver.calls
        == [
            ("public.example", 443),
            ("redirect.example", 443),
            ("assets.example", 80),
        ],
        "destinations were not independently resolved exactly once",
    )
    require(
        [destination.addresses for destination in destinations]
        == [(PUBLIC_V4, PUBLIC_V6), (PUBLIC_V4,), (PUBLIC_V6,)],
        "connector did not receive the validated address grants",
    )
    rendered = " ".join(repr(destination) for destination in destinations)
    require(
        PUBLIC_V4 not in rendered
        and PUBLIC_V6 not in rendered,
        "connector grant repr leaked a resolver answer",
    )

    admitted, launch = run_case(
        "valid",
        policy=DestinationPolicy(lambda _host, _port: [PUBLIC_V4]),
        target_url="https://clean.example/",
    )
    require(admitted.admitted and admitted.record is not None, "matching scan was not admitted")
    require(admitted.record["scanId"] == "fixture-clean", "admitted record drifted")
    require(len(launch.grants) == 1, "initial scan launched without exactly one grant")

    mismatch, mismatch_launch = run_case("valid")
    require(
        mismatch.outcome == "invalid-record"
        and not mismatch.admitted
        and mismatch.record is None,
        "valid record for a different target was admitted",
    )
    require(len(mismatch_launch.grants) == 1, "mismatch did not exercise worker admission")

    expanded_ipv6 = "https://[2606:4700:4700:0:0:0:0:1111]/x"
    ipv6_result, ipv6_launch = run_case(
        "rewrite-requested-url",
        target_url=expanded_ipv6,
    )
    require(
        ipv6_result.admitted
        and ipv6_result.record is not None
        and ipv6_result.record["requestedUrl"] == expanded_ipv6,
        "valid expanded IPv6 target was rejected after address normalization",
    )
    require(
        ipv6_launch.grants[0].destination.hostname == "2606:4700:4700::1111",
        "expanded IPv6 literal did not produce a canonical connector grant",
    )


def verify_rejections_prevent_launch() -> None:
    rejected_urls = (
        " https://example.com/",
        "https://example.com/\n",
        "https:\\example.com/",
        "ftp://example.com/",
        "https://user:secret@example.com/",
        "https://example.com/?token=secret",
        "https://example.com/#secret",
        "https://example.com/?",
        "https://example.com/#",
        "https://example.com./",
        "https://example.com:8080/",
        "https://example.com:0/",
        "http://example.com:000/",
        "https://exa%6dple.com/",
        "https://bücher.example/",
        "https://bad_host.example/",
        "https://[example.com]/",
        "https://localhost/",
        "https://service.localhost/",
        "https://printer.local/",
        "https://metadata.google.internal/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://[::127.0.0.1]/",
        "http://2130706433/",
        "http://127.1/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
        "https:///missing-host",
    )
    launch = LaunchLedger("valid")
    schema_validator, semantic_validator = validators()
    policy = DestinationPolicy(lambda _host, _port: [PUBLIC_V4])
    for url in rejected_urls:
        try:
            run_public_scan_transport(
                url,
                policy=policy,
                launch_worker=launch,
                schema_validator=schema_validator,
                semantic_validator=semantic_validator,
                deadline_seconds=2,
            )
        except DestinationPolicyError as error:
            require(str(error) == error.reason, "policy rejection leaked target content")
            continue
        raise AssertionError(f"rejected target reached transport: {url!r}")
    require(not launch.grants, "a malformed or private target reached worker launch")

    dns_cases = (
        [],
        RuntimeError("resolver-secret-canary-39170846"),
        ["not-an-address"],
        [PUBLIC_V4, "127.0.0.1"],
        [PUBLIC_V4, "fc00::1"],
        ["fe80::1%3"],
        [PUBLIC_V4] * (MAX_DNS_ANSWERS + 1),
    )
    for answers in dns_cases:
        resolver = SequenceResolver([answers])
        dns_launch = LaunchLedger("valid")
        try:
            run_public_scan_transport(
                "https://public.example/",
                policy=DestinationPolicy(resolver),
                launch_worker=dns_launch,
                schema_validator=schema_validator,
                semantic_validator=semantic_validator,
                deadline_seconds=2,
            )
        except DestinationPolicyError as error:
            formatted = "".join(traceback.format_exception(error))
            require("resolver-secret-canary-39170846" not in formatted, "resolver details leaked")
        else:
            raise AssertionError(f"DNS failure reached transport: {answers!r}")
        require(not dns_launch.grants, "a rejected DNS answer reached worker launch")


def verify_rebinding_prevents_second_launch() -> None:
    resolver = SequenceResolver([[PUBLIC_V4], ["127.0.0.1"]])
    policy = DestinationPolicy(resolver)
    connector_calls = []
    first = authorize_connection(
        "https://public.example/path",
        purpose="initial",
        policy=policy,
        connector=lambda destination: connector_calls.append(destination),
    )
    require(first is None and len(connector_calls) == 1, "public grant did not reach connector")
    try:
        authorize_connection(
            "https://public.example/path",
            purpose="initial",
            policy=policy,
            connector=lambda destination: connector_calls.append(destination),
        )
    except DestinationPolicyError as error:
        require(error.reason == "forbidden-address", "rebind rejection category drifted")
    else:
        raise AssertionError("public-to-private rebound target was launched")
    require(len(connector_calls) == 1, "rebound private answer reached connector")


def verify_worker_and_record_rejections() -> None:
    expected = {
        "invalid-nonce": "worker-invalid-result",
        "oversized-result": "worker-invalid-result",
        "nonregular-result": "worker-invalid-result",
        "crash": "worker-crashed",
        "timeout": "worker-timeout",
        "malformed-envelope": "invalid-envelope",
        "schema-invalid": "invalid-record",
        "semantic-invalid": "invalid-record",
    }
    with tempfile.TemporaryDirectory(prefix="dom-xray-scan-transport-tests-") as temporary:
        temporary_root = Path(temporary)
        for mode, outcome in expected.items():
            launch = LaunchLedger(mode)
            schema_validator, semantic_validator = validators()
            result = run_public_scan_transport(
                "https://public.example/path",
                policy=DestinationPolicy(lambda _host, _port: [PUBLIC_V4]),
                launch_worker=launch,
                schema_validator=schema_validator,
                semantic_validator=semantic_validator,
                deadline_seconds=1 if mode == "timeout" else 2,
                temporary_root=temporary_root,
            )
            require(result.outcome == outcome, f"{mode} produced {result.outcome}, not {outcome}")
            require(not result.admitted and result.record is None, f"{mode} published a record")
        require(not list(temporary_root.iterdir()), "private worker artifacts survived admission")

    class ExplodingLaunch:
        def __call__(self, grant: PublicScanGrant, _result_path: Path) -> WorkerLaunch:
            raise RuntimeError(f"launch-secret:{grant.target_url}")

    schema_validator, semantic_validator = validators()
    launch_failure = run_public_scan_transport(
        "https://clean.example/",
        policy=DestinationPolicy(lambda _host, _port: [PUBLIC_V4]),
        launch_worker=ExplodingLaunch(),
        schema_validator=schema_validator,
        semantic_validator=semantic_validator,
        deadline_seconds=2,
    )
    require(
        launch_failure.outcome == "launch-failed"
        and launch_failure.worker is None
        and launch_failure.record is None,
        "launcher exception escaped its content-free outcome",
    )

    supervisor_failure = run_public_scan_transport(
        "https://clean.example/",
        policy=DestinationPolicy(lambda _host, _port: [PUBLIC_V4]),
        launch_worker=lambda _grant, _path: WorkerLaunch(command=()),
        schema_validator=schema_validator,
        semantic_validator=semantic_validator,
        deadline_seconds=2,
    )
    require(
        supervisor_failure.outcome == "supervisor-failed"
        and supervisor_failure.worker is None
        and supervisor_failure.record is None,
        "supervisor setup exception escaped its content-free outcome",
    )


def main() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    verify_valid_grants_and_admission()
    verify_rejections_prevent_launch()
    verify_rebinding_prevents_second_launch()
    verify_worker_and_record_rejections()
    print(
        "Validated public-scan transport: independent initial/redirect/subresource "
        "address grants, zero launch on 29 target and 7 DNS rejections, rebinding "
        "denial, supervised artifact eligibility, strict envelope admission, and "
        "schema-plus-semantic target-bound record validation."
    )


if __name__ == "__main__":
    main()
