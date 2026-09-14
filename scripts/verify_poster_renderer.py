"""Focused verification for the trusted server-side poster renderer."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.poster_renderer import PosterRenderError, render_poster_png  # noqa: E402
from scanner.poster_renderer import _minimal_environment  # noqa: E402
from scanner.worker_supervisor import run_worker_command  # noqa: E402


def load_bundle(name: str) -> dict:
    base = ROOT / "viewer" / "src" / "fixtures" / "generated"
    return {
        "bundleVersion": "viewer-bundle-v0.1.0",
        "name": name,
        "record": json.loads((base / "scan" / f"{name}.json").read_text()),
        "scene": json.loads((base / "scene-manifest" / f"{name}.json").read_text()),
        "result": json.loads((base / "result-manifest" / f"{name}.json").read_text()),
        "runtime": json.loads((base / "viewer-runtime" / f"{name}.json").read_text()),
        "mapping": json.loads((base / "contracts" / "MAPPING_REGISTRY.v0.1.json").read_text()),
    }


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    eligible = load_bundle("image-heavy")
    first = render_poster_png(eligible)
    second = render_poster_png(eligible)
    require(first == second, "repeated poster bytes were not deterministic")
    require(first[:8] == b"\x89PNG\r\n\x1a\n", "poster is not PNG")
    require(len(first) <= 5_000_000, "poster exceeded byte limit")
    digest = hashlib.sha256(first).hexdigest()

    try:
        render_poster_png(load_bundle("clean"))
    except PosterRenderError:
        pass
    else:
        raise AssertionError("ineligible clean result rendered")

    # Exercise the worker's no-result-on-error and timeout behavior without
    # touching the production wrapper's private temporary directory.
    with tempfile.TemporaryDirectory(prefix="dom-x-ray-poster-verification-") as temporary:
        result = Path(temporary) / "result.json"
        timeout_code = "import time; time.sleep(20)"
        started = time.monotonic()
        try:
            subprocess.run([sys.executable, "-c", timeout_code], timeout=0.2, check=False)
        except subprocess.TimeoutExpired:
            pass
        else:
            raise AssertionError("timeout fixture unexpectedly succeeded")
        require(time.monotonic() - started < 2, "timeout fixture exceeded verification bound")
        require(not result.exists(), "failed worker left a result envelope")

        def supervised(*code: str):
            return run_worker_command(
                [sys.executable, "-c", *code],
                result_path=result,
                deadline_seconds=1.0,
                cwd=ROOT,
                environment=_minimal_environment(),
            )

        timed_out = supervised("import time; time.sleep(20)")
        require(timed_out.outcome == "timeout", "supervised timeout was not classified")
        failed = supervised("raise SystemExit(7)")
        require(failed.outcome == "crashed", "worker error was not classified")
        missing = supervised("pass")
        require(missing.outcome == "invalid-result", "missing worker artifact was accepted")
        tamper = supervised("import json; from pathlib import Path; Path(r'" + str(result) + "').write_text(json.dumps({'supervisorNonce':'wrong','result':{}}))")
        require(tamper.outcome == "invalid-result", "tampered worker envelope was accepted")

    print(f"poster renderer verified: {len(first)} bytes sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
