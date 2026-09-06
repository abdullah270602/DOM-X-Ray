"""Verify the disposable worker deadline and descendant cleanup boundary."""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.worker_supervisor import (
    MAX_WORKER_RESULT_BYTES,
    MAX_WORKER_SECONDS,
    MIN_WORKER_SECONDS,
    run_worker_command,
)


FIXTURE = ROOT / "fixtures" / "worker" / "worker_fixture.py"
EXPECTED_CHROMIUM_VERSION = "140.0.7339.16"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def process_instance_is_alive(pid: int, created_at: float) -> bool:
    try:
        process = psutil.Process(pid)
        return (
            abs(process.create_time() - created_at) < 0.001
            and process.is_running()
            and process.status() != psutil.STATUS_ZOMBIE
        )
    except psutil.NoSuchProcess:
        return False
    except psutil.AccessDenied:
        return True


def assert_process_tree_stopped(descendants: list[dict[str, object]]) -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if all(
            not process_instance_is_alive(
                int(item["pid"]),
                float(item["createdAt"]),
            )
            for item in descendants
        ):
            return
        time.sleep(0.05)
    survivors = [
        item
        for item in descendants
        if process_instance_is_alive(int(item["pid"]), float(item["createdAt"]))
    ]
    raise AssertionError(f"worker descendants survived termination: {survivors}")


def run_timeout_fixture(root: Path) -> tuple[str, int | None, bool]:
    root.mkdir(parents=True)
    result_path = root / "result.json"
    state_path = root / "state.json"
    capture_path = root / "capture.marker"
    run = run_worker_command(
        [
            sys.executable,
            str(FIXTURE),
            "browser-post-capture-hang",
            str(result_path),
            str(state_path),
            str(capture_path),
        ],
        result_path=result_path,
        deadline_seconds=4,
        cwd=ROOT,
    )
    require(run.outcome == "timeout", "post-capture hang did not reach worker timeout")
    require(not run.artifact_eligible, "a timed-out worker made its artifact eligible")
    require(
        2_300 <= run.duration_ms <= 4_200,
        f"worker timeout duration escaped its bounded termination window: {run.duration_ms}",
    )
    require(capture_path.exists(), "fixture did not reach the post-capture phase")
    require(state_path.exists(), "fixture did not publish its process-tree evidence")
    require(not result_path.exists(), "a post-deadline result artifact was committed")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    descendants = state["descendants"]
    require(
        state["browserVersion"] == EXPECTED_CHROMIUM_VERSION,
        "deadline fixture did not launch the pinned Chromium build",
    )
    require(
        any(
            "headless_shell" in str(item["name"]).lower()
            or "chrom" in str(item["name"]).lower()
            for item in descendants
        ),
        "deadline fixture did not observe a Chromium descendant",
    )
    assert_process_tree_stopped(descendants)
    return run.outcome, run.returncode, run.artifact_eligible


def main() -> None:
    for invalid_deadline in (
        0,
        -1,
        True,
        MIN_WORKER_SECONDS - 0.001,
        MAX_WORKER_SECONDS + 0.001,
    ):
        try:
            run_worker_command(
                [sys.executable, "-c", "pass"],
                result_path=Path("unused-invalid-result.json"),
                deadline_seconds=invalid_deadline,
            )
        except ValueError:
            continue
        raise AssertionError(f"worker deadline accepted invalid value {invalid_deadline!r}")
    for invalid_command in ([], "python"):
        try:
            run_worker_command(  # type: ignore[arg-type]
                invalid_command,
                result_path=Path("unused-invalid-command-result.json"),
            )
        except ValueError:
            continue
        raise AssertionError(f"worker supervisor accepted invalid command {invalid_command!r}")

    with tempfile.TemporaryDirectory(prefix="dom-xray-worker-") as temporary:
        root = Path(temporary)
        result_path = root / "complete.json"
        completed = run_worker_command(
            [
                sys.executable,
                str(FIXTURE),
                "complete",
                str(result_path),
                str(root / "unused-state.json"),
                str(root / "unused-capture.marker"),
            ],
            result_path=result_path,
            deadline_seconds=2,
            cwd=ROOT,
        )
        require(completed.outcome == "completed", "normal worker did not complete")
        require(completed.artifact_eligible, "normal worker artifact was not eligible")
        require(
            json.loads(result_path.read_text(encoding="utf-8"))["result"]["status"]
            == "complete",
            "normal worker did not atomically persist its result",
        )

        missing_result_path = root / "missing-result.json"
        missing = run_worker_command(
            [
                sys.executable,
                str(FIXTURE),
                "exit-without-result",
                str(missing_result_path),
                str(root / "unused-missing-state.json"),
                str(root / "unused-missing-capture.marker"),
            ],
            result_path=missing_result_path,
            deadline_seconds=2,
            cwd=ROOT,
        )
        require(
            missing.outcome == "invalid-result"
            and not missing.artifact_eligible,
            "zero exit without a result artifact was accepted",
        )

        for mode in ("invalid-nonce", "oversized-result"):
            invalid_path = root / f"{mode}.json"
            invalid = run_worker_command(
                [
                    sys.executable,
                    str(FIXTURE),
                    mode,
                    str(invalid_path),
                    str(root / f"unused-{mode}-state.json"),
                    str(root / f"unused-{mode}-capture.marker"),
                ],
                result_path=invalid_path,
                deadline_seconds=2,
                cwd=ROOT,
            )
            require(
                invalid.outcome == "invalid-result"
                and not invalid.artifact_eligible,
                f"{mode} artifact was accepted",
            )
        require(
            (root / "oversized-result.json").stat().st_size
            > MAX_WORKER_RESULT_BYTES,
            "oversized-result fixture did not cross the artifact boundary",
        )

        stale_path = root / "stale.json"
        stale_path.write_text("stale", encoding="utf-8")
        try:
            run_worker_command(
                [sys.executable, "-c", "pass"],
                result_path=stale_path,
                deadline_seconds=1,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("supervisor accepted a stale result destination")

        first = run_timeout_fixture(root / "first-timeout")
        second = run_timeout_fixture(root / "second-timeout")
        require(first == second == ("timeout", None, False), "timeout outcome drifted")

    print(
        "Validated a 15-second-ceiling worker supervisor, bounded nonce-scoped transport "
        "eligibility, repeatable post-capture timeout, and Chromium descendant cleanup."
    )


if __name__ == "__main__":
    main()
