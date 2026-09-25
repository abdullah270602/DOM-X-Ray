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

from scanner.mp4_validation import validate_share_video_mp4  # noqa: E402
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


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--attempts", type=int, default=2)
    return parser.parse_args()


def main() -> int:
    options = arguments()
    require(2 <= options.attempts <= 20, "video attempt count must be between 2 and 20")
    eligible = load_bundle("image-heavy")
    renders: list[bytes] = []
    durations: list[float] = []
    failures: list[str] = []
    for _index in range(options.attempts):
        started = time.monotonic()
        try:
            rendered = render_video_mp4(eligible)
        except VideoRenderError as error:
            failures.append(str(error))
            continue
        elapsed = time.monotonic() - started
        metadata = validate_share_video_mp4(rendered)
        require(metadata.media_type == "video/mp4" and metadata.codec == "avc1", "video type drifted")
        require((metadata.width, metadata.height) == (1080, 1080), "video dimensions drifted")
        require(metadata.duration_ms == 5_000, "video duration drifted")
        require(metadata.frame_rate == 30 and metadata.frame_count == 150, "video cadence drifted")
        require(metadata.byte_length <= 8_000_000, "video exceeded its byte limit")
        require(b"https://" not in rendered, "video container leaked a target URL")
        renders.append(rendered)
        durations.append(elapsed)

    required_successes = math.ceil(options.attempts * 0.95)
    require(
        len(renders) >= required_successes,
        f"video generation succeeded {len(renders)}/{options.attempts}; failures={failures}",
    )
    first = renders[0]
    require(all(rendered == first for rendered in renders), "repeated video bytes were not deterministic")
    require(max(durations) < 10, "video export exceeded the ten-second product bound")

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
        f"success={len(renders)}/{options.attempts} "
        f"p50={statistics.median(durations):.3f}s max={max(durations):.3f}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
