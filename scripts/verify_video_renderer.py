"""Focused verification for the controlled five-second video renderer."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.mp4_validation import Mp4ValidationError, validate_share_video_mp4  # noqa: E402
from scanner.video_renderer import VideoRenderError, render_video_mp4  # noqa: E402


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


def load_seeded_gallery() -> dict:
    """Capture the actual video input after real seeded transport/poster work."""
    from scanner.local_scan_api import FixtureScanExecutor

    captured = []
    def defer_video(bundle):
        captured.append(bundle)
        raise VideoRenderError("test-only deferred video render")
    FixtureScanExecutor(video_renderer=defer_video).execute(
        "https://gallery.example/", lambda _: None)
    require(len(captured) == 1, "seeded gallery did not supply one video input")
    return captured[0]


def measure_attempts(bundle, attempts, *, render=render_video_mp4, clock=time.monotonic):
    """Bound retained video memory; keep evidence for failed attempts too."""
    require(type(attempts) is int and 2 <= attempts <= 20, "invalid attempt count")
    rows = []
    first = None
    aborted = False
    for index in range(attempts):
        started = clock()
        row = {"attempt": index + 1, "outcome": "render-error"}
        try:
            rendered = render(bundle)
        except VideoRenderError:
            pass  # Never serialize exception text or target data into evidence.
        except Exception:
            # Do not launch another worker after an unexpected operational fault:
            # containment/cleanup may be unproven. Preserve only redacted evidence.
            row["outcome"] = "unexpected-error"
            aborted = True
        else:
            try:
                metadata = validate_share_video_mp4(rendered)
                require(metadata.media_type == "video/mp4" and metadata.codec == "avc1", "video type drifted")
                require((metadata.width, metadata.height) == (1080, 1080), "video dimensions drifted")
                require(metadata.duration_ms == 5_000, "video duration drifted")
                require(metadata.frame_rate == 30 and metadata.frame_count == 150, "video cadence drifted")
                require(metadata.byte_length == len(rendered) <= 8_000_000, "video byte limit drifted")
                require(b"https://" not in rendered, "video container leaked a target URL")
            except (Mp4ValidationError, AssertionError):
                row["outcome"] = "invalid-artifact"
            except Exception:
                row["outcome"] = "unexpected-error"
                aborted = True
            else:
                row.update(outcome="ok", bytes=len(rendered), sha256=hashlib.sha256(rendered).hexdigest())
                if first is None:
                    first = rendered
        elapsed = clock() - started
        require(math.isfinite(elapsed) and elapsed >= 0, "benchmark clock invalid")
        row["seconds"] = elapsed
        rows.append(row)
        if aborted:
            break
    successes = [row for row in rows if row["outcome"] == "ok"]
    durations = [row["seconds"] for row in successes]
    return first, {
        "attempts": rows,
        "successes": len(successes),
        "total": attempts,
        "attempted": len(rows),
        "aborted": aborted,
        "successP50Seconds": statistics.median(durations) if durations else None,
        "successMaxSeconds": max(durations) if durations else None,
        "allAttemptMaxSeconds": max(row["seconds"] for row in rows),
        "successfulBytesDeterministic": bool(successes) and len({row["sha256"] for row in successes}) == 1,
    }


def check_export_gate(report):
    require(not report["aborted"] and report["attempted"] == report["total"],
            "video benchmark aborted on an unexpected operational failure")
    require(report["successes"] >= math.ceil(report["total"] * 0.95),
            f"video generation succeeded {report['successes']}/{report['total']}")
    require(report["successfulBytesDeterministic"], "repeated video bytes were not deterministic")
    require(report["successMaxSeconds"] < 10, "video export exceeded the ten-second product bound")


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--attempts", type=int, default=2)
    parser.add_argument("--seeded-gallery", action="store_true")
    return parser.parse_args()


def main() -> int:
    options = arguments()
    require(2 <= options.attempts <= 20, "video attempt count must be between 2 and 20")
    eligible = load_seeded_gallery() if options.seeded_gallery else load_bundle("image-heavy")
    first, report = measure_attempts(eligible, options.attempts)
    report["input"] = "seeded-gallery-after-poster" if options.seeded_gallery else "generated-image-heavy"
    # Print failures and durations before assertions, so a rejected gate is observable.
    print(json.dumps(report, sort_keys=True, allow_nan=False), flush=True)
    check_export_gate(report)

    try:
        render_video_mp4(load_bundle("clean"))
    except VideoRenderError:
        pass
    else:
        raise AssertionError("ineligible clean result rendered a video")

    if options.output is not None:
        output = options.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(first)
        print(f"preview written: {output}")
    digest = hashlib.sha256(first).hexdigest()
    print(
        f"video renderer verified: {len(first)} bytes sha256={digest} "
        f"success={report['successes']}/{options.attempts} "
        f"p50={report['successP50Seconds']:.3f}s max={report['successMaxSeconds']:.3f}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
