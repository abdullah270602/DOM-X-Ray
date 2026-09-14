"""Trusted server-side poster PNG renderer.

This wrapper accepts an already assembled viewer bundle, derives SVG through
the pure viewer poster implementation, and rasterizes it in disposable
Chromium.  It never accepts or captures client pixels.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

from .api_contract import ApiContractError, stable_json_bytes, validate_viewer_bundle
from .png_validation import PngValidationError, validate_poster_png
from .worker_supervisor import run_worker_command


ROOT = Path(__file__).resolve().parents[1]
WORKER_DEADLINE_SECONDS = 10.0
POSTER_SIZE = 1080
MAX_PNG_BYTES = 5_000_000
MAX_RENDER_BUNDLE_BYTES = 8 * 1024 * 1024
RENDER_VERSION = "poster-renderer-v0.1.0"
RENDER_ROOT_ENV = "DOM_X_RAY_POSTER_RENDER_ROOT"


class PosterRenderError(RuntimeError):
    """Raised whenever the trusted poster boundary cannot prove success."""


def _minimal_environment() -> dict[str, str]:
    # Keep only process/runtime lookup essentials; target-page and user data
    # are deliberately not inherited by either renderer process.
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
        raise PosterRenderError("viewer bundle has no result manifest")
    hero = result.get("hero")
    exports = result.get("exports")
    poster = exports.get("poster") if isinstance(exports, Mapping) else None
    if (
        result.get("shareState") != "artifact-eligible"
        or not isinstance(hero, Mapping)
        or hero.get("shareEligible") is not True
        or not isinstance(poster, Mapping)
        or poster.get("eligible") is not True
        or poster.get("mediaType") != "image/png"
        or poster.get("width") != POSTER_SIZE
        or poster.get("height") != POSTER_SIZE
    ):
        raise PosterRenderError("viewer bundle is not eligible for a poster artifact")


def _validate_png(payload: bytes) -> None:
    try:
        validate_poster_png(
            payload,
            width=POSTER_SIZE,
            height=POSTER_SIZE,
            max_byte_length=MAX_PNG_BYTES,
        )
    except PngValidationError as error:
        raise PosterRenderError("poster PNG failed validation") from error


def render_poster_png(bundle: Mapping[str, Any]) -> bytes:
    """Return deterministic PNG bytes for an eligible provisional bundle."""

    normalized = dict(bundle)
    normalized.pop("name", None)
    try:
        validate_viewer_bundle(normalized)
    except ApiContractError as error:
        raise PosterRenderError("viewer bundle failed trusted validation") from error
    _eligible(normalized)
    environment = _minimal_environment()
    node_executable = shutil.which("node", path=environment.get("PATH"))
    if node_executable is None:
        raise PosterRenderError("trusted Node runtime is unavailable")
    node_path = Path(node_executable).resolve(strict=True)
    serialized_bundle = stable_json_bytes(normalized)
    if not 0 < len(serialized_bundle) <= MAX_RENDER_BUNDLE_BYTES:
        raise PosterRenderError("viewer bundle exceeds the poster renderer input limit")
    with tempfile.TemporaryDirectory(prefix="dom-x-ray-poster-") as temporary:
        directory = Path(temporary).resolve()
        environment[RENDER_ROOT_ENV] = str(directory)
        bundle_path = directory / "bundle.json"
        svg_path = directory / "poster.svg"
        png_path = directory / "poster.png"
        result_path = directory / "worker-result.json"
        bundle_path.write_bytes(serialized_bundle)
        run = run_worker_command(
            [
                sys.executable,
                "-m",
                "scanner.poster_renderer_worker",
                "--bundle",
                str(bundle_path),
                "--node",
                str(node_path),
                "--svg",
                str(svg_path),
                "--png",
                str(png_path),
                "--result",
                str(result_path),
            ],
            result_path=result_path,
            deadline_seconds=WORKER_DEADLINE_SECONDS,
            cwd=ROOT,
            environment=environment,
        )
        if not run.artifact_eligible:
            raise PosterRenderError(f"poster worker did not complete ({run.outcome})")
        if not _inside(result_path, directory) or not _inside(png_path, directory):
            raise PosterRenderError("poster artifact path escaped its private directory")
        try:
            envelope = json.loads(result_path.read_text(encoding="utf-8"))
            result = envelope["result"]
            artifact_path = Path(result["artifactPath"]).resolve()
            payload = png_path.read_bytes()
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise PosterRenderError("poster worker result was malformed") from error
        if (
            envelope.get("supervisorNonce") is None
            or result.get("status") != "ok"
            or result.get("version") != RENDER_VERSION
            or result.get("width") != POSTER_SIZE
            or result.get("height") != POSTER_SIZE
            or result.get("byteLength") != len(payload)
            or artifact_path != png_path.resolve()
            or len(payload) == 0
            or len(payload) > MAX_PNG_BYTES
        ):
            raise PosterRenderError("poster worker result failed validation")
        _validate_png(payload)
        return payload


__all__ = ["PosterRenderError", "render_poster_png"]
