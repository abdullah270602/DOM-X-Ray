"""Contained Chromium + FFmpeg worker for the trusted share-video seam."""

from __future__ import annotations

import argparse
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path

from .mp4_validation import validate_share_video_mp4
from .svg_rasterizer import rasterize_svg_screenshots


RESULT_NONCE_ENV = "DOM_X_RAY_WORKER_RESULT_NONCE"
RENDER_ROOT_ENV = "DOM_X_RAY_VIDEO_RENDER_ROOT"
RENDER_VERSION = "video-renderer-v0.1.0"
STORYBOARD_VERSION = "video-storyboard-v0.1.0"
VIDEO_SIZE = 1080
VIDEO_DURATION_MS = 5_000
VIDEO_FRAME_RATE = 30
VIDEO_FRAME_COUNT = 150
MAX_VIDEO_BYTES = 8_000_000
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_SVG_BYTES = 2_000_000
MAX_PNG_BYTES = 5_000_000
STAGE_IDS = ("page", "structure", "weight", "origins", "hero")
STAGE_LABELS = (
    "01 / PAGE SURFACE",
    "02 / DOM STRUCTURE",
    "03 / TRANSFER WEIGHT",
    "04 / EXTERNAL ORIGINS",
    "05 / HERO EVIDENCE",
)


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--ffmpeg", required=True)
    parser.add_argument("--storyboard", required=True)
    parser.add_argument("--video", required=True)
    parser.add_argument("--result", required=True)
    return parser.parse_args()


def _render_root() -> Path:
    value = os.environ.get(RENDER_ROOT_ENV, "")
    root = Path(value)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("video render root is invalid")
    return root.resolve(strict=True)


def _private_path(argument: str, label: str, *, root: Path, must_exist: bool) -> Path:
    path = Path(argument)
    if not path.is_absolute() or path.parent.resolve(strict=True) != root:
        raise ValueError(f"{label} path escaped the video render root")
    if must_exist:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{label} input is not a regular file")
    elif path.exists():
        raise ValueError(f"{label} output already exists")
    return path.resolve(strict=False)


def _trusted_executable(argument: str, label: str) -> Path:
    path = Path(argument)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} runtime path is invalid")
    return path.resolve(strict=True)


def _write_atomic(path: Path, payload: bytes) -> None:
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as temporary:
        temporary_path = Path(temporary.name)
        temporary.write(payload)
        temporary.flush()
        os.fsync(temporary.fileno())
    try:
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _validate_stage_png(payload: bytes) -> None:
    if not 0 < len(payload) <= MAX_PNG_BYTES or payload[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("video stage PNG is outside its byte envelope")
    if len(payload) < 33 or payload[12:16] != b"IHDR":
        raise ValueError("video stage PNG header is malformed")
    width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(
        ">IIBBBBB", payload[16:29]
    )
    if (
        (width, height) != (VIDEO_SIZE, VIDEO_SIZE)
        or bit_depth != 8
        or color_type not in {2, 6}
        or compression != 0
        or filtering != 0
        or interlace != 0
    ):
        raise ValueError("video stage PNG pixel format is unsupported")


def _storyboard(path: Path, root: Path) -> tuple[str, ...]:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 16_384:
        raise ValueError("video storyboard metadata is outside its byte envelope")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {
        "version",
        "width",
        "height",
        "durationMs",
        "frameRate",
        "frameCount",
        "maxByteLength",
        "frames",
    }:
        raise ValueError("video storyboard metadata has an invalid shape")
    if (
        value["version"] != STORYBOARD_VERSION
        or value["width"] != VIDEO_SIZE
        or value["height"] != VIDEO_SIZE
        or value["durationMs"] != VIDEO_DURATION_MS
        or value["frameRate"] != VIDEO_FRAME_RATE
        or value["frameCount"] != VIDEO_FRAME_COUNT
        or value["maxByteLength"] != MAX_VIDEO_BYTES
        or not isinstance(value["frames"], list)
        or len(value["frames"]) != len(STAGE_IDS)
    ):
        raise ValueError("video storyboard metadata drifted from its contract")
    svgs: list[str] = []
    for index, (expected_id, expected_label) in enumerate(zip(STAGE_IDS, STAGE_LABELS)):
        frame = value["frames"][index]
        filename = f"stage-{index}.svg"
        if not isinstance(frame, dict) or frame != {
            "id": expected_id,
            "label": expected_label,
            "filename": filename,
            "byteLength": frame.get("byteLength"),
        }:
            raise ValueError("video storyboard frame metadata is invalid")
        frame_path = root / filename
        if frame_path.parent != root or frame_path.is_symlink() or not frame_path.is_file():
            raise ValueError("video storyboard SVG is not a private regular file")
        byte_length = frame_path.stat().st_size
        if (
            isinstance(frame["byteLength"], bool)
            or not isinstance(frame["byteLength"], int)
            or frame["byteLength"] != byte_length
            or not 0 < byte_length <= MAX_SVG_BYTES
        ):
            raise ValueError("video storyboard SVG is outside its byte envelope")
        svgs.append(frame_path.read_text(encoding="utf-8"))
    return tuple(svgs)


def _encode(ffmpeg: Path, png_paths: tuple[Path, ...], video_path: Path) -> None:
    command = [str(ffmpeg), "-hide_banner", "-loglevel", "error", "-nostdin"]
    for path in png_paths:
        command.extend(["-stream_loop", "-1", "-r", str(VIDEO_FRAME_RATE), "-i", str(path)])
    filters = []
    for index in range(len(png_paths)):
        x_expression = "10+4*sin(n/21)" if index % 2 == 0 else "10-4*sin(n/23)"
        y_expression = "10-4*cos(n/25)" if index % 2 == 0 else "10+4*cos(n/27)"
        filters.append(
            f"[{index}:v]scale=1100:1100:flags=bicubic,"
            f"crop=1080:1080:x='{x_expression}':y='{y_expression}',"
            "setsar=1,setpts=PTS-STARTPTS,fps=30"
            f"[stage{index}]"
        )
    filters.extend(
        [
            "[stage0][stage1]xfade=transition=fade:duration=0.25:offset=0.80[x1]",
            "[x1][stage2]xfade=transition=fade:duration=0.25:offset=1.70[x2]",
            "[x2][stage3]xfade=transition=fade:duration=0.25:offset=2.60[x3]",
            "[x3][stage4]xfade=transition=fade:duration=0.25:offset=3.50,"
            "trim=duration=5,setpts=PTS-STARTPTS[outv]",
        ]
    )
    command.extend(
        [
            "-filter_complex_threads",
            "1",
            "-filter_complex",
            ";".join(filters),
            "-map",
            "[outv]",
            "-frames:v",
            str(VIDEO_FRAME_COUNT),
            "-r",
            str(VIDEO_FRAME_RATE),
            "-fps_mode",
            "cfr",
            "-an",
            "-sn",
            "-dn",
            "-c:v",
            "libx264",
            "-preset",
            "veryfast",
            "-crf",
            "18",
            "-pix_fmt",
            "yuv420p",
            "-profile:v",
            "high",
            "-level:v",
            "4.0",
            "-x264-params",
            "threads=1:bframes=0:scenecut=0:keyint=30:min-keyint=30:force-cfr=1",
            "-color_primaries",
            "bt709",
            "-color_trc",
            "bt709",
            "-colorspace",
            "bt709",
            "-color_range",
            "tv",
            "-movflags",
            "+faststart",
            "-video_track_timescale",
            "30000",
            "-map_metadata",
            "-1",
            "-f",
            "mp4",
            "-n",
            str(video_path),
        ]
    )
    options: dict[str, object] = {
        "cwd": video_path.parent,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "shell": False,
        "timeout": 10.0,
        "check": False,
    }
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW
    encoded = subprocess.run(command, **options)  # type: ignore[arg-type]
    if encoded.returncode != 0 or video_path.is_symlink() or not video_path.is_file():
        raise RuntimeError("controlled H.264 encoding failed")


def main() -> int:
    arguments = _args()
    root = _render_root()
    bundle_path = _private_path(arguments.bundle, "bundle", root=root, must_exist=True)
    storyboard_path = _private_path(arguments.storyboard, "storyboard", root=root, must_exist=False)
    video_path = _private_path(arguments.video, "video", root=root, must_exist=False)
    result_path = _private_path(arguments.result, "result", root=root, must_exist=False)
    node_path = _trusted_executable(arguments.node, "Node")
    ffmpeg_path = _trusted_executable(arguments.ffmpeg, "FFmpeg")
    if bundle_path.stat().st_size <= 0 or bundle_path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("video bundle is outside the input byte envelope")
    nonce = os.environ.get(RESULT_NONCE_ENV)
    if not nonce or len(nonce) > 128:
        raise ValueError("missing worker result nonce")
    helper = Path(__file__).resolve().parents[1] / "viewer" / "scripts" / "render-video-storyboard.mjs"
    generated = subprocess.run(
        [
            str(node_path),
            "--no-warnings",
            "--experimental-strip-types",
            str(helper),
            str(bundle_path),
            str(root),
            str(storyboard_path),
        ],
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
        timeout=4.0,
        check=False,
    )
    if generated.returncode != 0:
        raise RuntimeError("video storyboard generation failed")
    svgs = _storyboard(storyboard_path, root)
    pngs = rasterize_svg_screenshots(svgs, size=VIDEO_SIZE)
    png_paths: list[Path] = []
    for index, png in enumerate(pngs):
        _validate_stage_png(png)
        png_path = root / f"stage-{index}.png"
        if png_path.exists():
            raise ValueError("video raster output already exists")
        _write_atomic(png_path, png)
        png_paths.append(png_path)
    _encode(ffmpeg_path, tuple(png_paths), video_path)
    payload = video_path.read_bytes()
    metadata = validate_share_video_mp4(payload)
    envelope = {
        "supervisorNonce": nonce,
        "result": {
            "status": "ok",
            "version": RENDER_VERSION,
            "width": metadata.width,
            "height": metadata.height,
            "durationMs": metadata.duration_ms,
            "frameRate": metadata.frame_rate,
            "frameCount": metadata.frame_count,
            "byteLength": metadata.byte_length,
            "artifactPath": str(video_path),
        },
    }
    _write_atomic(result_path, (json.dumps(envelope, separators=(",", ":")) + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit(1)
