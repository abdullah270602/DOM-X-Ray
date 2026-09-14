"""Trusted controlled renderer for the exact DOM X-Ray share video."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

from .api_contract import ApiContractError, stable_json_bytes, validate_viewer_bundle
from .mp4_validation import Mp4ValidationError, validate_share_video_mp4
from .worker_supervisor import run_worker_command


ROOT = Path(__file__).resolve().parents[1]
WORKER_DEADLINE_SECONDS = 15.0
VIDEO_SIZE = 1080
VIDEO_DURATION_MS = 5_000
VIDEO_FRAME_RATE = 30
VIDEO_FRAME_COUNT = 150
MAX_VIDEO_BYTES = 8_000_000
MAX_RENDER_BUNDLE_BYTES = 8 * 1024 * 1024
RENDER_VERSION = "video-renderer-v0.1.0"
RENDER_ROOT_ENV = "DOM_X_RAY_VIDEO_RENDER_ROOT"


class VideoRenderError(RuntimeError):
    """Raised whenever the trusted video boundary cannot prove success."""


def _minimal_environment() -> dict[str, str]:
    names = {
        "PATH",
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "windir",
        "TEMP",
        "TMP",
        "LOCALAPPDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
    }
    return {name: value for name, value in os.environ.items() if name in names}


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def _eligible(bundle: Mapping[str, Any]) -> None:
    result = bundle.get("result")
    if not isinstance(result, Mapping):
        raise VideoRenderError("viewer bundle has no result manifest")
    hero = result.get("hero")
    exports = result.get("exports")
    video = exports.get("video") if isinstance(exports, Mapping) else None
    if (
        result.get("shareState") != "artifact-eligible"
        or not isinstance(hero, Mapping)
        or hero.get("shareEligible") is not True
        or not isinstance(video, Mapping)
        or video.get("eligible") is not True
        or video.get("mediaType") != "video/mp4"
        or video.get("width") != VIDEO_SIZE
        or video.get("height") != VIDEO_SIZE
        or video.get("durationMs") != VIDEO_DURATION_MS
        or video.get("maxByteLength") != MAX_VIDEO_BYTES
    ):
        raise VideoRenderError("viewer bundle is not eligible for a video artifact")


def _trusted_ffmpeg_path() -> Path:
    try:
        import imageio_ffmpeg

        candidate = Path(imageio_ffmpeg.get_ffmpeg_exe())
    except Exception as error:
        raise VideoRenderError("trusted FFmpeg runtime is unavailable") from error
    if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_file():
        raise VideoRenderError("trusted FFmpeg runtime path is invalid")
    return candidate.resolve(strict=True)


def render_video_mp4(bundle: Mapping[str, Any]) -> bytes:
    """Return same-runtime deterministic H.264 MP4 bytes for an eligible bundle."""

    normalized = dict(bundle)
    normalized.pop("name", None)
    try:
        validate_viewer_bundle(normalized)
    except ApiContractError as error:
        raise VideoRenderError("viewer bundle failed trusted validation") from error
    _eligible(normalized)
    environment = _minimal_environment()
    node_executable = shutil.which("node", path=environment.get("PATH"))
    if node_executable is None:
        raise VideoRenderError("trusted Node runtime is unavailable")
    node_path = Path(node_executable).resolve(strict=True)
    ffmpeg_path = _trusted_ffmpeg_path()
    serialized_bundle = stable_json_bytes(normalized)
    if not 0 < len(serialized_bundle) <= MAX_RENDER_BUNDLE_BYTES:
        raise VideoRenderError("viewer bundle exceeds the video renderer input limit")

    with tempfile.TemporaryDirectory(prefix="dom-x-ray-video-") as temporary:
        directory = Path(temporary).resolve()
        environment[RENDER_ROOT_ENV] = str(directory)
        bundle_path = directory / "bundle.json"
        storyboard_path = directory / "storyboard.json"
        video_path = directory / "video.mp4"
        result_path = directory / "worker-result.json"
        bundle_path.write_bytes(serialized_bundle)
        run = run_worker_command(
            [
                sys.executable,
                "-m",
                "scanner.video_renderer_worker",
                "--bundle",
                str(bundle_path),
                "--node",
                str(node_path),
                "--ffmpeg",
                str(ffmpeg_path),
                "--storyboard",
                str(storyboard_path),
                "--video",
                str(video_path),
                "--result",
                str(result_path),
            ],
            result_path=result_path,
            deadline_seconds=WORKER_DEADLINE_SECONDS,
            cwd=ROOT,
            environment=environment,
        )
        if not run.artifact_eligible:
            raise VideoRenderError(f"video worker did not complete ({run.outcome})")
        if not _inside(result_path, directory) or not _inside(video_path, directory):
            raise VideoRenderError("video artifact path escaped its private directory")
        try:
            envelope = json.loads(result_path.read_text(encoding="utf-8"))
            result = envelope["result"]
            artifact_path = Path(result["artifactPath"]).resolve()
            payload = video_path.read_bytes()
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise VideoRenderError("video worker result was malformed") from error
        if (
            envelope.get("supervisorNonce") is None
            or result.get("status") != "ok"
            or result.get("version") != RENDER_VERSION
            or result.get("width") != VIDEO_SIZE
            or result.get("height") != VIDEO_SIZE
            or result.get("durationMs") != VIDEO_DURATION_MS
            or result.get("frameRate") != VIDEO_FRAME_RATE
            or result.get("frameCount") != VIDEO_FRAME_COUNT
            or result.get("byteLength") != len(payload)
            or artifact_path != video_path.resolve()
            or len(payload) == 0
            or len(payload) > MAX_VIDEO_BYTES
        ):
            raise VideoRenderError("video worker result failed validation")
        try:
            validate_share_video_mp4(payload)
        except Mp4ValidationError as error:
            raise VideoRenderError("video MP4 failed validation") from error
        return payload


__all__ = ["VideoRenderError", "render_video_mp4"]
