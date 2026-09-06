"""Verify real browser-probe records through the supervised worker boundary."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fixtures.browser.fixture_server import FIXTURES, run_fixture_server
from scanner.worker_supervisor import MAX_WORKER_SECONDS, run_worker_command
from scripts.validate_fixtures import validate_semantics
from scripts.verify_browser_fixtures import deterministic_fingerprint


WORKER = ROOT / "fixtures" / "worker" / "capture_worker_fixture.py"
EXPECTED_CHROMIUM_VERSION = "140.0.7339.16"
SCHEMA = json.loads(
    (ROOT / "docs" / "SCAN_RECORD.schema.json").read_text(encoding="utf-8")
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def write_config(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def fixture_config(server_port: int, fixture_name: str) -> dict[str, object]:
    fixture = FIXTURES[fixture_name]
    return {
        "url": f"http://{fixture.host}:{server_port}{fixture.route}",
        "fixtureUpstreamPort": server_port,
        "usePolicyProxy": fixture.use_policy_proxy,
        "trustedLoopback": fixture.trusted_loopback,
        "cacheDisabled": fixture.cache_disabled,
        "hardStopSeconds": fixture.hard_stop_seconds,
        "maxRequests": fixture.max_requests,
        "maxResponseBytes": fixture.max_response_bytes,
        "maxTotalReceivedBytes": fixture.max_total_received_bytes,
        "maxAuxiliaryEvents": fixture.max_auxiliary_events,
    }


def capture_fixture(
    root: Path,
    server_port: int,
    fixture_name: str,
    ordinal: int,
    validator: Draft202012Validator,
) -> dict:
    config_path = root / f"{fixture_name}-{ordinal}.config.json"
    result_path = root / f"{fixture_name}-{ordinal}.result.json"
    fixture = FIXTURES[fixture_name]
    write_config(config_path, fixture_config(server_port, fixture_name))
    run = run_worker_command(
        [sys.executable, str(WORKER), str(config_path), str(result_path)],
        result_path=result_path,
        deadline_seconds=MAX_WORKER_SECONDS,
        cwd=ROOT,
    )
    require(run.outcome == "completed", f"{fixture_name} worker outcome: {run.outcome}")
    require(run.artifact_eligible, f"{fixture_name} transport was not eligible")
    require(
        run.duration_ms <= MAX_WORKER_SECONDS * 1000,
        f"{fixture_name} escaped the worker wall-time ceiling",
    )
    envelope = json.loads(result_path.read_text(encoding="utf-8"))
    record = envelope["result"]["record"]
    require(
        record["capture"]["browser"]
        == f"Chromium {EXPECTED_CHROMIUM_VERSION}",
        f"{fixture_name} did not use the pinned Chromium proof build",
    )
    validate_semantics(
        record,
        f"supervised browser fixture {fixture_name}",
        validator,
        allow_trusted_loopback=fixture.trusted_loopback,
    )
    require(record["status"] == fixture.expected_status, f"{fixture_name} status drifted")
    require(
        record["failureCode"] == fixture.expected_failure_code,
        f"{fixture_name} failure code drifted",
    )
    require(
        tuple(record["capture"]["limitsReached"]) == fixture.expected_limits,
        f"{fixture_name} capture limits drifted",
    )
    require(
        record["capture"]["requestCount"] == fixture.expected_request_count,
        f"{fixture_name} request count drifted",
    )
    return record


def verify_invalid_config(root: Path, server_port: int) -> None:
    invalid_configs: dict[str, dict[str, object]] = {}
    string_boolean = fixture_config(server_port, "clean")
    string_boolean["usePolicyProxy"] = "false"
    invalid_configs["string-boolean"] = string_boolean
    fractional_limit = fixture_config(server_port, "clean")
    fractional_limit["maxRequests"] = 12.5
    invalid_configs["fractional-limit"] = fractional_limit
    inactive_string_port = fixture_config(server_port, "service-worker")
    inactive_string_port["fixtureUpstreamPort"] = str(server_port)
    invalid_configs["inactive-string-port"] = inactive_string_port

    for label, config in invalid_configs.items():
        config_path = root / f"invalid-{label}.config.json"
        result_path = root / f"invalid-{label}.result.json"
        write_config(config_path, config)
        run = run_worker_command(
            [sys.executable, str(WORKER), str(config_path), str(result_path)],
            result_path=result_path,
            deadline_seconds=2,
            cwd=ROOT,
        )
        require(run.outcome == "crashed", f"{label} worker config was not rejected")
        require(not run.artifact_eligible, f"{label} worker config became eligible")
        require(not result_path.exists(), f"{label} worker config published a result")


def verify_real_capture_timeout(root: Path, server_port: int) -> None:
    config_path = root / "post-capture-timeout.config.json"
    result_path = root / "post-capture-timeout.result.json"
    marker_path = root / "post-capture-timeout.marker"
    config = fixture_config(server_port, "clean")
    config.update(
        {
            "postCaptureDelaySeconds": 60,
            "postCaptureMarkerPath": str(marker_path),
        }
    )
    write_config(config_path, config)
    run = run_worker_command(
        [sys.executable, str(WORKER), str(config_path), str(result_path)],
        result_path=result_path,
        deadline_seconds=8,
        cwd=ROOT,
    )
    require(run.outcome == "timeout", "real post-capture hang escaped its deadline")
    require(not run.artifact_eligible, "timed-out capture worker became eligible")
    require(marker_path.exists(), "real probe did not reach its post-capture phase")
    require(not result_path.exists(), "timed-out capture worker published a result")
    require(
        run.duration_ms <= 8_200,
        f"real capture timeout exceeded its outer ceiling: {run.duration_ms}",
    )


def main() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    with (
        tempfile.TemporaryDirectory(prefix="dom-xray-capture-worker-") as temporary,
        run_fixture_server() as server,
    ):
        root = Path(temporary)
        clean = capture_fixture(root, server.server_port, "clean", 1, validator)
        server.clear_ledger()
        clean_repeat = capture_fixture(root, server.server_port, "clean", 2, validator)
        require(
            deterministic_fingerprint(clean)
            == deterministic_fingerprint(clean_repeat),
            "supervised clean-capture evidence changed on repeat",
        )
        server.clear_ledger()
        capture_fixture(root, server.server_port, "response-byte-limit", 1, validator)
        server.clear_ledger()
        capture_fixture(root, server.server_port, "service-worker", 1, validator)
        server.clear_ledger()
        unsettled = capture_fixture(
            root,
            server.server_port,
            "never-settling",
            1,
            validator,
        )
        require(
            [item["code"] for item in unsettled["limitations"]]
            == ["settle-timeout"],
            "page-level settle timeout was not preserved as partial evidence",
        )
        require(unsettled["nodes"], "page-level settle timeout lost useful geometry")
        server.clear_ledger()
        verify_invalid_config(root, server.server_port)
        verify_real_capture_timeout(root, server.server_port)

    print(
        "Validated complete, resource-limited, service-worker, and page-timeout scan "
        "records through the supervised capture-worker transport; strict config parsing, "
        "deterministic clean evidence, and a real post-capture worker timeout also hold."
    )


if __name__ == "__main__":
    main()
