"""Disposable child used to prove the worker-supervisor boundary."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

RESULT_NONCE_ENV = "DOM_X_RAY_WORKER_RESULT_NONCE"
OVERSIZED_RESULT_BYTES = 4_000_100


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: worker_fixture.py MODE RESULT STATE CAPTURE")
    mode, result_value, state_value, capture_value = sys.argv[1:]
    result_path = Path(result_value)
    state_path = Path(state_value)
    capture_path = Path(capture_value)
    nonce = os.environ.get(RESULT_NONCE_ENV, "")

    if mode == "complete":
        _atomic_json(
            result_path,
            {
                "supervisorNonce": nonce,
                "result": {"status": "complete", "workerPid": os.getpid()},
            },
        )
        return
    if mode == "exit-without-result":
        return
    if mode == "invalid-nonce":
        _atomic_json(
            result_path,
            {"supervisorNonce": "wrong", "result": {"status": "complete"}},
        )
        return
    if mode == "oversized-result":
        result_path.write_text("x" * OVERSIZED_RESULT_BYTES, encoding="utf-8")
        return
    if mode != "browser-post-capture-hang":
        raise SystemExit(f"unknown fixture mode: {mode}")

    import psutil
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content("<!doctype html><title>bounded worker</title><main>captured</main>")
        capture_path.write_text("capture-complete", encoding="utf-8")
        descendants = []
        for process in psutil.Process(os.getpid()).children(recursive=True):
            descendants.append(
                {
                    "pid": process.pid,
                    "name": process.name(),
                    "createdAt": process.create_time(),
                }
            )
        _atomic_json(
            state_path,
            {
                "workerPid": os.getpid(),
                "browserVersion": browser.version,
                "descendants": descendants,
            },
        )
        time.sleep(60)
        _atomic_json(
            result_path,
            {
                "supervisorNonce": nonce,
                "result": {"status": "late-result-must-not-survive"},
            },
        )


if __name__ == "__main__":
    main()
