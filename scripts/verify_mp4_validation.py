"""Adversarial verification for the strict controlled MP4 boundary."""

from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import imageio_ffmpeg  # noqa: E402

import scanner.mp4_validation as mp4  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def valid_fixture() -> bytes:
    with tempfile.TemporaryDirectory(prefix="dom-x-ray-mp4-validation-") as temporary:
        output = Path(temporary) / "valid.mp4"
        command = [
            imageio_ffmpeg.get_ffmpeg_exe(),
            "-hide_banner",
            "-loglevel",
            "error",
            "-nostdin",
            "-f",
            "lavfi",
            "-i",
            "color=c=#e9e1d2:s=1080x1080:r=30:d=5",
            "-frames:v",
            "150",
            "-r",
            "30",
            "-fps_mode",
            "cfr",
            "-an",
            "-c:v",
            "libx264",
            "-preset",
            "medium",
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
            "-movflags",
            "+faststart",
            "-video_track_timescale",
            "30000",
            "-map_metadata",
            "-1",
            "-f",
            "mp4",
            "-n",
            str(output),
        ]
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        require(completed.returncode == 0 and output.is_file(), "valid MP4 fixture did not encode")
        return output.read_bytes()


def mutate(payload: bytes, offset: int, replacement: bytes) -> bytes:
    require(0 <= offset <= len(payload) - len(replacement), "mutation escaped fixture")
    result = bytearray(payload)
    result[offset : offset + len(replacement)] = replacement
    return bytes(result)


def expect_rejection(payload: bytes, code: str, label: str) -> None:
    try:
        mp4.validate_share_video_mp4(payload)
    except mp4.Mp4ValidationError as error:
        require(error.code == code, f"{label}: expected {code}, got {error.code}")
        require(str(error) == error.message, f"{label}: error string is not stable")
        require("http" not in str(error).lower(), f"{label}: error echoed content")
        return
    raise AssertionError(f"{label}: malformed MP4 was accepted")


def structure(payload: bytes):
    top = mp4._boxes(payload, 0, len(payload))
    moov = mp4._one(top, b"moov")
    movie = mp4._children(payload, moov)
    trak = next(box for box in movie if box.kind == b"trak")
    track = mp4._children(payload, trak)
    mdia = mp4._one(track, b"mdia")
    media = mp4._children(payload, mdia)
    minf = mp4._one(media, b"minf")
    stbl = mp4._one(mp4._children(payload, minf), b"stbl")
    samples = mp4._children(payload, stbl)
    stsd = mp4._one(samples, b"stsd")
    entry = mp4._boxes(payload, stsd.content_start + 8, stsd.end)[0]
    avcc = mp4._one(mp4._boxes(payload, entry.content_start + 78, entry.end), b"avcC")
    return top, movie, track, media, samples, entry, avcc


def main() -> None:
    valid = valid_fixture()
    metadata = mp4.validate_share_video_mp4(valid)
    require(metadata.byte_length == len(valid), "valid MP4 length mismatch")
    require(metadata.duration_ms == 5_000, "valid MP4 duration mismatch")
    require(metadata.frame_count == 150 and metadata.frame_rate == 30, "valid MP4 cadence mismatch")
    require((metadata.width, metadata.height) == (1080, 1080), "valid MP4 dimensions mismatch")
    require(metadata.codec == "avc1" and metadata.media_type == "video/mp4", "valid MP4 type mismatch")

    top, movie, track, media, samples, entry, avcc = structure(valid)
    mvhd = mp4._one(movie, b"mvhd")
    tkhd = mp4._one(track, b"tkhd")
    hdlr = mp4._one(media, b"hdlr")
    stts = mp4._one(samples, b"stts")
    stsz = mp4._one(samples, b"stsz")
    mdat = mp4._one(top, b"mdat")

    expect_rejection(b"", "mp4-size", "empty payload")
    expect_rejection(mutate(valid, 4, b"nope"), "mp4-signature", "missing ftyp")
    expect_rejection(valid + b"x", "mp4-trailing-bytes", "trailing byte")
    expect_rejection(mutate(valid, top[0].content_start, b"zzzz"), "mp4-signature", "wrong major brand")
    free = next(box for box in top if box.kind == b"free")
    expect_rejection(mutate(valid, free.start + 4, b"uuid"), "mp4-topology", "unsupported top-level box")
    expect_rejection(
        mutate(valid, mvhd.content_start + 16, struct.pack(">I", 4_999)),
        "mp4-duration",
        "wrong movie duration",
    )
    expect_rejection(
        mutate(valid, tkhd.content_start + 40, struct.pack(">I", 0)),
        "mp4-rotation",
        "track transform",
    )
    expect_rejection(
        mutate(valid, tkhd.content_start + 76, struct.pack(">I", 1079 << 16)),
        "mp4-dimensions",
        "wrong track width",
    )
    expect_rejection(
        mutate(valid, hdlr.content_start + 8, b"soun"),
        "mp4-streams",
        "audio handler",
    )
    expect_rejection(mutate(valid, entry.start + 4, b"hvc1"), "mp4-codec", "wrong codec")
    expect_rejection(
        mutate(valid, avcc.content_start + 1, b"\x4d"),
        "mp4-codec",
        "wrong AVC profile",
    )
    timing_delta_offset = stts.content_start + 12
    expect_rejection(
        mutate(valid, timing_delta_offset, struct.pack(">I", 1_001)),
        "mp4-frame-rate",
        "wrong media cadence",
    )
    expect_rejection(
        mutate(valid, stsz.content_start + 8, struct.pack(">I", 149)),
        "mp4-samples",
        "wrong sample table count",
    )
    expect_rejection(
        mutate(valid, mdat.content_start, struct.pack(">I", 0x7FFFFFFF)),
        "mp4-codec",
        "escaped AVC NAL",
    )
    oversized = valid + b"x" * (mp4.MAX_MP4_BYTES + 1 - len(valid))
    expect_rejection(oversized, "mp4-size", "oversized payload")

    print(f"MP4 validation verification passed ({len(valid)}-byte valid fixture).")


if __name__ == "__main__":
    main()
