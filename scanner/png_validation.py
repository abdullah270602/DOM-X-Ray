"""Strict, bounded validation for the PNG poster artifact.

The poster boundary deliberately accepts one narrow PNG profile: an RGBA,
1080 by 1080 image using the standard PNG filter and compression methods.  It
checks the complete chunk envelope before inflating image data, and limits
inflation to one byte beyond the exact scanline size so a compressed expansion
cannot become an unbounded allocation.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_WIDTH = 1080
PNG_HEIGHT = 1080
PNG_BIT_DEPTH = 8
PNG_COLOR_TYPE = 6
PNG_MEDIA_TYPE = "image/png"
MAX_ENCODED_LENGTH = 5_000_000
MAX_CHUNK_COUNT = 2_048
_ROW_LENGTH = 1 + PNG_WIDTH * 4
_INFLATED_LENGTH = PNG_HEIGHT * _ROW_LENGTH


@dataclass(frozen=True, slots=True)
class PngMetadata:
    """Non-payload metadata returned after a PNG crosses the boundary."""

    sha256: str
    byte_length: int
    width: int
    height: int
    media_type: str


# The all-caps spelling is useful to callers that use acronym-style type names.
PNGMetadata = PngMetadata


class PngValidationError(ValueError):
    """A safe, stable error for a PNG that cannot cross the artifact boundary."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        # ``reason`` mirrors the scanner's other content-free policy errors;
        # callers may use either spelling without needing payload details.
        self.reason = code
        self.message = message
        super().__init__(message)


PNGValidationError = PngValidationError


def _reject(code: str, message: str) -> None:
    # Keep this helper as the one construction site for public validation
    # errors.  In particular, never interpolate chunk data or caller bytes.
    raise PngValidationError(code, message)


def _check_chunk_type(chunk_type: bytes) -> None:
    if (
        len(chunk_type) != 4
        or any(not (65 <= value <= 90 or 97 <= value <= 122) for value in chunk_type)
        or not 65 <= chunk_type[2] <= 90
    ):
        _reject("png-framing", "PNG chunk framing is invalid.")


def _validate_chunks(payload: bytes) -> bytes:
    if len(payload) < len(PNG_SIGNATURE) or payload[:8] != PNG_SIGNATURE:
        _reject("png-signature", "PNG signature is invalid.")

    offset = len(PNG_SIGNATURE)
    seen_ihdr = False
    seen_iend = False
    idat_started = False
    idat_finished = False
    idat_parts: list[bytes] = []
    chunk_count = 0
    while offset < len(payload):
        chunk_count += 1
        if chunk_count > MAX_CHUNK_COUNT:
            _reject("png-chunk-count", "PNG contains too many chunks.")
        # A chunk has a four-byte length, four-byte type, data, and four-byte
        # CRC. Check the fixed framing before slicing any variable data.
        if len(payload) - offset < 12:
            _reject("png-framing", "PNG chunk framing is invalid.")
        length = struct.unpack_from(">I", payload, offset)[0]
        chunk_type = payload[offset + 4 : offset + 8]
        _check_chunk_type(chunk_type)
        end = offset + 12 + length
        if end < offset or end > len(payload):
            _reject("png-framing", "PNG chunk framing is invalid.")
        data_start = offset + 8
        data_end = data_start + length
        chunk_data = payload[data_start:data_end]
        expected_crc = struct.unpack_from(">I", payload, data_end)[0]
        actual_crc = zlib.crc32(chunk_type)
        actual_crc = zlib.crc32(chunk_data, actual_crc) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            _reject("png-crc", "PNG chunk CRC is invalid.")

        if not seen_ihdr:
            if chunk_type != b"IHDR":
                _reject("png-structure", "PNG IHDR must be the first chunk.")
            seen_ihdr = True
        elif chunk_type == b"IHDR":
            _reject("png-structure", "PNG IHDR must occur exactly once.")

        # Chromium canvas emits only IHDR, contiguous IDAT chunks, and IEND.
        # Refusing every ancillary chunk also prevents text/URL metadata and
        # APNG control data from crossing the public artifact boundary.
        if chunk_type not in {b"IHDR", b"IDAT", b"IEND"}:
            if chunk_type[0] <= 90:
                _reject("png-critical-chunk", "PNG contains an unknown critical chunk.")
            _reject("png-ancillary-chunk", "PNG contains an unsupported ancillary chunk.")

        if chunk_type == b"IHDR":
            if length != 13:
                _reject("png-ihdr", "PNG IHDR is invalid.")
            width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(">IIBBBBB", chunk_data)
            if width != PNG_WIDTH or height != PNG_HEIGHT:
                _reject("png-dimensions", "PNG dimensions are not supported.")
            if (
                bit_depth != PNG_BIT_DEPTH
                or color_type != PNG_COLOR_TYPE
                or compression != 0
                or filtering != 0
                or interlace != 0
            ):
                _reject("png-format", "PNG pixel format is not supported.")
        elif chunk_type == b"IDAT":
            if idat_finished or length == 0:
                _reject("png-structure", "PNG IDAT chunks must be contiguous and non-empty.")
            idat_started = True
            idat_parts.append(chunk_data)
        elif chunk_type == b"IEND":
            if length != 0 or seen_iend or not idat_started:
                _reject("png-structure", "PNG chunk structure is invalid.")
            seen_iend = True
            offset = end
            if offset != len(payload):
                _reject("png-trailing-bytes", "PNG has trailing bytes.")
            break
        elif idat_started:
            # Any later IDAT would be non-contiguous; this marker lets the
            # next IDAT produce the stable structure error.
            idat_finished = True

        offset = end

    if not seen_iend or not idat_parts:
        _reject("png-structure", "PNG must contain IDAT data and one terminal IEND.")
    return b"".join(idat_parts)


def _inflate_scanlines(compressed: bytes) -> bytes:
    try:
        stream = zlib.decompressobj()
        inflated = stream.decompress(compressed, _INFLATED_LENGTH + 1)
    except zlib.error:
        _reject("png-decompression", "PNG image data cannot be decompressed.")

    # unconsumed_tail means output hit the bound before the compressed input
    # was consumed. unused_data means bytes followed a complete zlib stream.
    if (
        len(inflated) != _INFLATED_LENGTH
        or stream.unconsumed_tail
        or not stream.eof
        or stream.unused_data
    ):
        _reject("png-inflated-length", "PNG inflated length is invalid.")

    for row in range(PNG_HEIGHT):
        if inflated[row * _ROW_LENGTH] > 4:
            _reject("png-filter", "PNG row filter is invalid.")
    return inflated


def validate_png(payload: bytes) -> PngMetadata:
    """Validate *payload* and return stable metadata for the accepted PNG.

    The function intentionally does not return decoded pixels. The inflated
    scanlines are inspected and then discarded so callers cannot accidentally
    persist untrusted image data through this metadata-only boundary.
    """

    if not isinstance(payload, bytes):
        _reject("png-input", "PNG payload must be bytes.")
    encoded_length = len(payload)
    if encoded_length == 0:
        _reject("png-size", "PNG payload must not be empty.")
    if encoded_length > MAX_ENCODED_LENGTH:
        _reject("png-size", "PNG payload exceeds the encoded byte limit.")
    compressed = _validate_chunks(payload)
    _inflate_scanlines(compressed)
    return PngMetadata(
        sha256=hashlib.sha256(payload).hexdigest(),
        byte_length=encoded_length,
        width=PNG_WIDTH,
        height=PNG_HEIGHT,
        media_type=PNG_MEDIA_TYPE,
    )


def validate_png_bytes(payload: bytes) -> PngMetadata:
    """Compatibility alias for callers that name the byte boundary explicitly."""

    return validate_png(payload)


def validate_poster_png(
    payload: bytes,
    *,
    width: int = PNG_WIDTH,
    height: int = PNG_HEIGHT,
    max_byte_length: int = MAX_ENCODED_LENGTH,
) -> PngMetadata:
    """Validate a poster using the renderer's explicit artifact policy.

    The keyword arguments make the renderer-to-validator seam explicit while
    refusing policy drift: this boundary only admits 1080 × 1080 RGBA PNGs and
    never permits a limit above five million encoded bytes.
    """

    if width != PNG_WIDTH or height != PNG_HEIGHT or not isinstance(max_byte_length, int) or not (0 < max_byte_length <= MAX_ENCODED_LENGTH):
        _reject("png-policy", "PNG poster validation policy is unsupported.")
    if not isinstance(payload, bytes):
        _reject("png-input", "PNG payload must be bytes.")
    if len(payload) == 0 or len(payload) > max_byte_length:
        _reject("png-size", "PNG payload exceeds the encoded byte limit.")
    return validate_png(payload)


__all__ = [
    "MAX_CHUNK_COUNT",
    "MAX_ENCODED_LENGTH",
    "PNG_HEIGHT",
    "PNG_MEDIA_TYPE",
    "PNG_SIGNATURE",
    "PNG_WIDTH",
    "PNGMetadata",
    "PngMetadata",
    "PNGValidationError",
    "PngValidationError",
    "validate_png",
    "validate_png_bytes",
    "validate_poster_png",
]
