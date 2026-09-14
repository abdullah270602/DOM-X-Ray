"""Focused verification for the controlled five-second video renderer."""

from __future__ import annotations

import argparse
import hashlib
import json
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
    return parser.parse_args()


def main() -> int:
    options = arguments()
    eligible = load_bundle("image-heavy")
    started = time.monotonic()
    first = render_video_mp4(eligible)
    first_seconds = time.monotonic() - started
    second = render_video_mp4(eligible)
    total_seconds = time.monotonic() - started
    require(first == second, "repeated video bytes were not deterministic")
    metadata = validate_share_video_mp4(first)
    require(metadata.media_type == "video/mp4" and metadata.codec == "avc1", "video type drifted")
    require((metadata.width, metadata.height) == (1080, 1080), "video dimensions drifted")
    require(metadata.duration_ms == 5_000, "video duration drifted")
    require(metadata.frame_rate == 30 and metadata.frame_count == 150, "video cadence drifted")
    require(metadata.byte_length <= 8_000_000, "video exceeded its byte limit")
    require(first_seconds < 15, "video renderer exceeded its worker deadline outside supervision")
    require(b"https://" not in first, "video container leaked a target URL")

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
        f"first={first_seconds:.3f}s two-renders={total_seconds:.3f}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
