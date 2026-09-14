"""Dependency-free adversarial verification for scanner.png_validation."""

from __future__ import annotations

import hashlib
import struct
import sys
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.png_validation import (  # noqa: E402
    MAX_CHUNK_COUNT,
    MAX_ENCODED_LENGTH,
    PNG_HEIGHT,
    PNG_SIGNATURE,
    PNG_WIDTH,
    PngValidationError,
    validate_png,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def chunk(kind: bytes, data: bytes) -> bytes:
    require(len(kind) == 4, "test chunk type must be four bytes")
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def split_chunks(payload: bytes) -> list[tuple[bytes, bytes]]:
    offset = len(PNG_SIGNATURE)
    result: list[tuple[bytes, bytes]] = []
    while offset < len(payload):
        length = struct.unpack_from(">I", payload, offset)[0]
        kind = payload[offset + 4 : offset + 8]
        start = offset + 8
        result.append((kind, payload[start : start + length]))
        offset += 12 + length
    return result


def assemble(chunks: list[tuple[bytes, bytes]]) -> bytes:
    return PNG_SIGNATURE + b"".join(chunk(kind, data) for kind, data in chunks)


def make_valid_png() -> bytes:
    # A valid full-size image is generated using only the standard library.
    row = b"\x00" + (b"\x12\x34\x56\xff" * PNG_WIDTH)
    raw = row * PNG_HEIGHT
    ihdr = struct.pack(">IIBBBBB", PNG_WIDTH, PNG_HEIGHT, 8, 6, 0, 0, 0)
    return assemble([(b"IHDR", ihdr), (b"IDAT", zlib.compress(raw, 9)), (b"IEND", b"")])


def expect_rejection(payload: bytes, code: str, label: str) -> None:
    try:
        validate_png(payload)
    except PngValidationError as error:
        require(error.code == code, f"{label}: expected {code}, got {error.code}")
        require(str(error) == error.message, f"{label}: error string is not stable")
        require("\x89PNG" not in str(error), f"{label}: error echoed payload bytes")
        return
    raise AssertionError(f"{label}: malformed PNG was accepted")


def verify_valid(valid: bytes) -> None:
    metadata = validate_png(valid)
    require(metadata.sha256 == hashlib.sha256(valid).hexdigest(), "valid PNG digest mismatch")
    require(metadata.byte_length == len(valid), "valid PNG byte length mismatch")
    require((metadata.width, metadata.height) == (1080, 1080), "valid PNG dimensions mismatch")
    require(metadata.media_type == "image/png", "valid PNG media type mismatch")
    try:
        metadata.width = 1  # type: ignore[misc]
    except AttributeError:
        pass
    else:
        raise AssertionError("PNG metadata dataclass is mutable")


def verify_signature(valid: bytes) -> None:
    expect_rejection(b"", "png-size", "empty payload")
    expect_rejection(b"not a PNG", "png-signature", "short signature")
    expect_rejection(b"X" + valid[1:], "png-signature", "wrong signature")


def verify_crc(valid: bytes) -> None:
    corrupted = bytearray(valid)
    # The final byte of the IHDR CRC is inside the fixed first chunk.
    corrupted[8 + 4 + 4 + 13 + 3] ^= 0x01
    expect_rejection(bytes(corrupted), "png-crc", "CRC corruption")


def verify_dimensions_and_format(valid: bytes) -> None:
    chunks = split_chunks(valid)
    ihdr = bytearray(chunks[0][1])
    ihdr[0:4] = struct.pack(">I", 1079)
    expect_rejection(assemble([(b"IHDR", bytes(ihdr)), *chunks[1:]]), "png-dimensions", "wrong width")

    ihdr = bytearray(chunks[0][1])
    ihdr[8] = 2
    expect_rejection(assemble([(b"IHDR", bytes(ihdr)), *chunks[1:]]), "png-format", "wrong bit depth")


def verify_structure(valid: bytes) -> None:
    chunks = split_chunks(valid)
    ihdr, idat, iend = chunks
    expect_rejection(assemble([(b"tEXt", b"x"), ihdr, idat, iend]), "png-structure", "IHDR not first")
    expect_rejection(assemble([ihdr, ihdr, idat, iend]), "png-structure", "duplicate IHDR")
    expect_rejection(assemble([ihdr, (b"IDAT", b""), iend]), "png-structure", "empty IDAT")
    expect_rejection(assemble([ihdr, idat]), "png-structure", "missing IEND")
    expect_rejection(assemble([ihdr, (b"ABCD", b"x"), idat, iend]), "png-critical-chunk", "unknown critical chunk")
    expect_rejection(assemble([ihdr, (b"tEXt", b"target=https://private.example"), idat, iend]), "png-ancillary-chunk", "text metadata")
    expect_rejection(assemble([ihdr, (b"acTL", struct.pack(">II", 2, 0)), idat, iend]), "png-ancillary-chunk", "APNG control chunk")

    compressed = idat[1]
    split_idat = [(b"IDAT", bytes([value])) for value in compressed]
    require(len(split_idat) + 2 > MAX_CHUNK_COUNT, "chunk-count fixture is too small")
    expect_rejection(
        assemble([ihdr, *split_idat, iend]),
        "png-chunk-count",
        "excessive chunk count",
    )


def verify_decompression(valid: bytes) -> None:
    chunks = split_chunks(valid)
    ihdr, _idat, iend = chunks
    raw = (b"\x00" + (b"\x12\x34\x56\xff" * PNG_WIDTH)) * PNG_HEIGHT
    extra_output = zlib.compress(raw + b"\x00", 9)
    expect_rejection(assemble([ihdr, (b"IDAT", extra_output), iend]), "png-inflated-length", "extra decompressed output")
    broken = bytearray(chunks[1][1])
    broken[len(broken) // 2] ^= 0xFF
    expect_rejection(assemble([ihdr, (b"IDAT", bytes(broken)), iend]), "png-decompression", "broken zlib stream")


def verify_filter_and_trailing(valid: bytes) -> None:
    chunks = split_chunks(valid)
    ihdr, idat, iend = chunks
    raw = zlib.decompress(idat[1])
    invalid_filter = bytes([5]) + raw[1:]
    expect_rejection(
        assemble([ihdr, (b"IDAT", zlib.compress(invalid_filter, 9)), iend]),
        "png-filter",
        "invalid row filter",
    )
    expect_rejection(valid + b"trailing", "png-trailing-bytes", "trailing bytes")


def verify_size(valid: bytes) -> None:
    oversized = valid + (b"x" * (MAX_ENCODED_LENGTH + 1 - len(valid)))
    expect_rejection(oversized, "png-size", "oversized payload")


def main() -> None:
    valid = make_valid_png()
    require(0 < len(valid) <= MAX_ENCODED_LENGTH, "test fixture unexpectedly exceeds PNG limit")
    verify_valid(valid)
    verify_signature(valid)
    verify_crc(valid)
    verify_dimensions_and_format(valid)
    verify_structure(valid)
    verify_decompression(valid)
    verify_filter_and_trailing(valid)
    verify_size(valid)
    print(f"PNG validation verification passed ({len(valid)}-byte valid fixture).")


if __name__ == "__main__":
    main()
