"""Strict dependency-free validation for the controlled DOM X-Ray MP4 subset."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from fractions import Fraction


MP4_WIDTH = 1080
MP4_HEIGHT = 1080
MP4_DURATION_MS = 5_000
MP4_FRAME_RATE = 30
MP4_FRAME_COUNT = 150
MAX_MP4_BYTES = 8_000_000
MAX_BOX_COUNT = 4_096
IDENTITY_MATRIX = (
    0x00010000,
    0,
    0,
    0,
    0x00010000,
    0,
    0,
    0,
    0x40000000,
)


class Mp4ValidationError(ValueError):
    """Stable fail-closed MP4 validation error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Mp4Metadata:
    media_type: str
    codec: str
    width: int
    height: int
    duration_ms: int
    frame_rate: int
    frame_count: int
    byte_length: int
    sha256: str


@dataclass(frozen=True)
class _Box:
    kind: bytes
    start: int
    content_start: int
    end: int

    @property
    def content_length(self) -> int:
        return self.end - self.content_start


class _BitReader:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self._offset = 0

    def read(self, count: int) -> int:
        if count < 0 or self._offset + count > len(self._payload) * 8:
            _reject("mp4-codec", "MP4 AVC bitstream configuration is truncated")
        value = 0
        for _ in range(count):
            byte = self._payload[self._offset // 8]
            value = (value << 1) | ((byte >> (7 - self._offset % 8)) & 1)
            self._offset += 1
        return value

    def unsigned_exp_golomb(self) -> int:
        leading_zeroes = 0
        while self.read(1) == 0:
            leading_zeroes += 1
            if leading_zeroes > 31:
                _reject("mp4-codec", "MP4 AVC Exp-Golomb value is unbounded")
        suffix = self.read(leading_zeroes) if leading_zeroes else 0
        return (1 << leading_zeroes) - 1 + suffix


def _reject(code: str, message: str) -> None:
    raise Mp4ValidationError(code, message)


def _u16(payload: bytes, offset: int, *, code: str = "mp4-structure") -> int:
    if offset < 0 or offset + 2 > len(payload):
        _reject(code, "MP4 integer escaped its containing box")
    return struct.unpack_from(">H", payload, offset)[0]


def _u32(payload: bytes, offset: int, *, code: str = "mp4-structure") -> int:
    if offset < 0 or offset + 4 > len(payload):
        _reject(code, "MP4 integer escaped its containing box")
    return struct.unpack_from(">I", payload, offset)[0]


def _u64(payload: bytes, offset: int, *, code: str = "mp4-structure") -> int:
    if offset < 0 or offset + 8 > len(payload):
        _reject(code, "MP4 integer escaped its containing box")
    return struct.unpack_from(">Q", payload, offset)[0]


def _i32(payload: bytes, offset: int, *, code: str = "mp4-structure") -> int:
    if offset < 0 or offset + 4 > len(payload):
        _reject(code, "MP4 integer escaped its containing box")
    return struct.unpack_from(">i", payload, offset)[0]


def _i64(payload: bytes, offset: int, *, code: str = "mp4-structure") -> int:
    if offset < 0 or offset + 8 > len(payload):
        _reject(code, "MP4 integer escaped its containing box")
    return struct.unpack_from(">q", payload, offset)[0]


def _boxes(payload: bytes, start: int, end: int) -> list[_Box]:
    if start < 0 or end < start or end > len(payload):
        _reject("mp4-structure", "MP4 box range is invalid")
    result: list[_Box] = []
    cursor = start
    while cursor < end:
        if end - cursor < 8:
            _reject("mp4-trailing-bytes", "MP4 has bytes outside a complete box")
        size32 = _u32(payload, cursor)
        kind = payload[cursor + 4 : cursor + 8]
        if any(value < 0x20 or value > 0x7E for value in kind):
            _reject("mp4-box-type", "MP4 box type is not printable ASCII")
        header = 8
        if size32 == 1:
            if end - cursor < 16:
                _reject("mp4-structure", "MP4 extended box header is truncated")
            size = _u64(payload, cursor + 8)
            header = 16
        elif size32 == 0:
            _reject("mp4-structure", "MP4 unbounded boxes are not accepted")
        else:
            size = size32
        if size < header or cursor + size > end:
            _reject("mp4-structure", "MP4 box length escaped its container")
        result.append(_Box(kind, cursor, cursor + header, cursor + size))
        if len(result) > MAX_BOX_COUNT:
            _reject("mp4-box-count", "MP4 contains too many boxes")
        cursor += size
    if cursor != end:
        _reject("mp4-trailing-bytes", "MP4 has trailing bytes")
    return result


def _children(payload: bytes, box: _Box, *, offset: int = 0) -> list[_Box]:
    start = box.content_start + offset
    if start > box.end:
        _reject("mp4-structure", "MP4 child boxes escaped their parent")
    return _boxes(payload, start, box.end)


def _one(boxes: list[_Box], kind: bytes, *, code: str = "mp4-structure") -> _Box:
    matches = [box for box in boxes if box.kind == kind]
    if len(matches) != 1:
        _reject(code, f"MP4 requires exactly one {kind.decode('ascii')} box")
    return matches[0]


def _full_box(payload: bytes, box: _Box) -> tuple[int, bytes]:
    if box.content_length < 4:
        _reject("mp4-structure", "MP4 full box is truncated")
    version = payload[box.content_start]
    flags = payload[box.content_start + 1 : box.content_start + 4]
    return version, flags


def _rbsp(payload: bytes) -> bytes:
    result = bytearray()
    zeroes = 0
    for value in payload:
        if zeroes >= 2 and value == 0x03:
            zeroes = 0
            continue
        result.append(value)
        zeroes = zeroes + 1 if value == 0 else 0
    return bytes(result)


def _validate_sps(sps: bytes, expected_profile: int, expected_level: int) -> None:
    if len(sps) < 5 or sps[0] & 0x80 or sps[0] & 0x1F != 7:
        _reject("mp4-codec", "MP4 AVC sequence parameter set is malformed")
    bits = _BitReader(_rbsp(sps[1:]))
    profile = bits.read(8)
    bits.read(8)  # constraint flags and reserved bits
    level = bits.read(8)
    bits.unsigned_exp_golomb()  # sequence_parameter_set_id
    if profile != expected_profile or level != expected_level:
        _reject("mp4-codec", "MP4 AVC profile metadata disagrees with its SPS")
    if profile not in {100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135}:
        _reject("mp4-codec", "MP4 AVC profile cannot prove 8-bit 4:2:0 output")
    chroma_format_idc = bits.unsigned_exp_golomb()
    if chroma_format_idc == 3:
        bits.read(1)
    bit_depth_luma_minus8 = bits.unsigned_exp_golomb()
    bit_depth_chroma_minus8 = bits.unsigned_exp_golomb()
    bits.read(1)  # qpprime_y_zero_transform_bypass_flag
    scaling_matrix_present = bits.read(1)
    if (
        chroma_format_idc != 1
        or bit_depth_luma_minus8 != 0
        or bit_depth_chroma_minus8 != 0
        or scaling_matrix_present != 0
    ):
        _reject("mp4-pixel-format", "MP4 AVC stream is not the approved 8-bit 4:2:0 profile")


def _movie_duration(payload: bytes, box: _Box) -> Fraction:
    version, _flags = _full_box(payload, box)
    body = box.content_start
    if version == 0:
        if box.content_length < 100:
            _reject("mp4-duration", "MP4 movie header is truncated")
        timescale = _u32(payload, body + 12, code="mp4-duration")
        duration = _u32(payload, body + 16, code="mp4-duration")
    elif version == 1:
        if box.content_length < 112:
            _reject("mp4-duration", "MP4 movie header is truncated")
        timescale = _u32(payload, body + 20, code="mp4-duration")
        duration = _u64(payload, body + 24, code="mp4-duration")
    else:
        _reject("mp4-duration", "MP4 movie header version is unsupported")
    if timescale == 0:
        _reject("mp4-duration", "MP4 movie timescale is zero")
    return Fraction(duration, timescale)


def _track_geometry(payload: bytes, box: _Box) -> tuple[int, int]:
    version, flags = _full_box(payload, box)
    if flags != b"\x00\x00\x03":
        _reject("mp4-track", "MP4 video track is not enabled in the movie")
    if version == 0:
        matrix_offset = box.content_start + 40
        dimension_offset = box.content_start + 76
        minimum = 84
    elif version == 1:
        matrix_offset = box.content_start + 52
        dimension_offset = box.content_start + 88
        minimum = 96
    else:
        _reject("mp4-track", "MP4 track header version is unsupported")
    if box.content_length < minimum:
        _reject("mp4-track", "MP4 track header is truncated")
    matrix = tuple(_u32(payload, matrix_offset + index * 4) for index in range(9))
    if matrix != IDENTITY_MATRIX:
        _reject("mp4-rotation", "MP4 video track has a transform or rotation")
    width_fixed = _u32(payload, dimension_offset, code="mp4-dimensions")
    height_fixed = _u32(payload, dimension_offset + 4, code="mp4-dimensions")
    if width_fixed & 0xFFFF or height_fixed & 0xFFFF:
        _reject("mp4-dimensions", "MP4 track dimensions are fractional")
    return width_fixed >> 16, height_fixed >> 16


def _media_duration(payload: bytes, box: _Box) -> tuple[int, int]:
    version, _flags = _full_box(payload, box)
    body = box.content_start
    if version == 0:
        if box.content_length < 24:
            _reject("mp4-duration", "MP4 media header is truncated")
        timescale = _u32(payload, body + 12, code="mp4-duration")
        duration = _u32(payload, body + 16, code="mp4-duration")
    elif version == 1:
        if box.content_length < 36:
            _reject("mp4-duration", "MP4 media header is truncated")
        timescale = _u32(payload, body + 20, code="mp4-duration")
        duration = _u64(payload, body + 24, code="mp4-duration")
    else:
        _reject("mp4-duration", "MP4 media header version is unsupported")
    if timescale == 0:
        _reject("mp4-duration", "MP4 media timescale is zero")
    return timescale, duration


def _handler(payload: bytes, box: _Box) -> bytes:
    _full_box(payload, box)
    if box.content_length < 24:
        _reject("mp4-streams", "MP4 handler box is truncated")
    return payload[box.content_start + 8 : box.content_start + 12]


def _validate_sample_description(payload: bytes, box: _Box) -> tuple[int, int]:
    version, flags = _full_box(payload, box)
    if version != 0 or flags != b"\x00\x00\x00" or box.content_length < 16:
        _reject("mp4-codec", "MP4 sample description header is invalid")
    entry_count = _u32(payload, box.content_start + 4, code="mp4-codec")
    if entry_count != 1:
        _reject("mp4-codec", "MP4 must contain one video sample entry")
    entries = _boxes(payload, box.content_start + 8, box.end)
    if len(entries) != 1 or entries[0].kind != b"avc1":
        _reject("mp4-codec", "MP4 video sample entry is not H.264 avc1")
    entry = entries[0]
    if entry.content_length < 78:
        _reject("mp4-codec", "MP4 avc1 sample entry is truncated")
    width = _u16(payload, entry.content_start + 24, code="mp4-dimensions")
    height = _u16(payload, entry.content_start + 26, code="mp4-dimensions")
    frame_count = _u16(payload, entry.content_start + 40, code="mp4-codec")
    depth = _u16(payload, entry.content_start + 74, code="mp4-codec")
    if frame_count != 1 or depth != 0x0018:
        _reject("mp4-codec", "MP4 avc1 visual sample entry is unsupported")
    extensions = _boxes(payload, entry.content_start + 78, entry.end)
    avcc = _one(extensions, b"avcC", code="mp4-codec")
    if avcc.content_length < 7 or payload[avcc.content_start] != 1:
        _reject("mp4-codec", "MP4 AVC configuration is malformed")
    profile = payload[avcc.content_start + 1]
    level = payload[avcc.content_start + 3]
    if profile != 100 or level > 40:
        _reject("mp4-codec", "MP4 is not the approved H.264 High profile envelope")
    avcc_payload = payload[avcc.content_start : avcc.end]
    if avcc_payload[4] & 0x03 != 3:
        _reject("mp4-codec", "MP4 AVC samples do not use four-byte NAL lengths")
    sequence_count = avcc_payload[5] & 0x1F
    if sequence_count != 1:
        _reject("mp4-codec", "MP4 must declare exactly one AVC sequence parameter set")
    cursor = 6
    sequence_length = _u16(avcc_payload, cursor, code="mp4-codec")
    cursor += 2
    if sequence_length == 0 or cursor + sequence_length >= len(avcc_payload):
        _reject("mp4-codec", "MP4 AVC sequence parameter set is truncated")
    sps = avcc_payload[cursor : cursor + sequence_length]
    cursor += sequence_length
    picture_count = avcc_payload[cursor]
    cursor += 1
    if picture_count != 1:
        _reject("mp4-codec", "MP4 must declare exactly one AVC picture parameter set")
    picture_length = _u16(avcc_payload, cursor, code="mp4-codec")
    cursor += 2
    if picture_length == 0 or cursor + picture_length > len(avcc_payload):
        _reject("mp4-codec", "MP4 AVC picture parameter set is truncated")
    pps = avcc_payload[cursor : cursor + picture_length]
    if pps[0] & 0x80 or pps[0] & 0x1F != 8:
        _reject("mp4-codec", "MP4 AVC picture parameter set is malformed")
    _validate_sps(sps, profile, level)
    return width, height


def _sample_timing(payload: bytes, box: _Box) -> tuple[int, int]:
    version, flags = _full_box(payload, box)
    if version != 0 or flags != b"\x00\x00\x00" or box.content_length < 8:
        _reject("mp4-timing", "MP4 decoding-time table is invalid")
    count = _u32(payload, box.content_start + 4, code="mp4-timing")
    if count == 0 or count > 1_024 or box.content_length != 8 + count * 8:
        _reject("mp4-timing", "MP4 decoding-time entry count is invalid")
    sample_count = 0
    total_duration = 0
    for index in range(count):
        offset = box.content_start + 8 + index * 8
        entries = _u32(payload, offset, code="mp4-timing")
        delta = _u32(payload, offset + 4, code="mp4-timing")
        if entries == 0 or delta == 0:
            _reject("mp4-timing", "MP4 decoding-time entry is empty")
        sample_count += entries
        total_duration += entries * delta
    return sample_count, total_duration


def _sample_sizes(payload: bytes, box: _Box) -> tuple[int, int, tuple[int, ...]]:
    version, flags = _full_box(payload, box)
    if version != 0 or flags != b"\x00\x00\x00" or box.content_length < 12:
        _reject("mp4-samples", "MP4 sample-size table is invalid")
    fixed_size = _u32(payload, box.content_start + 4, code="mp4-samples")
    count = _u32(payload, box.content_start + 8, code="mp4-samples")
    if count == 0 or count > 10_000:
        _reject("mp4-samples", "MP4 sample count is outside the trusted envelope")
    if fixed_size:
        if box.content_length != 12:
            _reject("mp4-samples", "MP4 fixed sample-size table has trailing data")
        sizes = (fixed_size,) * count
        return count, fixed_size * count, sizes
    if box.content_length != 12 + count * 4:
        _reject("mp4-samples", "MP4 variable sample-size table is truncated")
    sizes_list: list[int] = []
    for index in range(count):
        size = _u32(payload, box.content_start + 12 + index * 4, code="mp4-samples")
        if size == 0:
            _reject("mp4-samples", "MP4 contains an empty video sample")
        sizes_list.append(size)
    sizes = tuple(sizes_list)
    return count, sum(sizes), sizes


def _chunk_offsets(payload: bytes, box: _Box) -> tuple[int, ...]:
    version, flags = _full_box(payload, box)
    if version != 0 or flags != b"\x00\x00\x00" or box.content_length < 8:
        _reject("mp4-samples", "MP4 chunk-offset table is invalid")
    count = _u32(payload, box.content_start + 4, code="mp4-samples")
    unit = 4 if box.kind == b"stco" else 8
    if count == 0 or count > 10_000 or box.content_length != 8 + count * unit:
        _reject("mp4-samples", "MP4 chunk-offset entry count is invalid")
    read = _u32 if unit == 4 else _u64
    return tuple(read(payload, box.content_start + 8 + index * unit, code="mp4-samples") for index in range(count))


def _samples_per_chunk(payload: bytes, box: _Box, chunk_count: int) -> tuple[int, ...]:
    version, flags = _full_box(payload, box)
    if version != 0 or flags != b"\x00\x00\x00" or box.content_length < 8:
        _reject("mp4-samples", "MP4 sample-to-chunk table is invalid")
    count = _u32(payload, box.content_start + 4, code="mp4-samples")
    if count == 0 or count > chunk_count or box.content_length != 8 + count * 12:
        _reject("mp4-samples", "MP4 sample-to-chunk entry count is invalid")
    entries: list[tuple[int, int]] = []
    for index in range(count):
        offset = box.content_start + 8 + index * 12
        first_chunk = _u32(payload, offset, code="mp4-samples")
        samples = _u32(payload, offset + 4, code="mp4-samples")
        description = _u32(payload, offset + 8, code="mp4-samples")
        if (
            first_chunk == 0
            or first_chunk > chunk_count
            or samples == 0
            or description != 1
            or (entries and first_chunk <= entries[-1][0])
        ):
            _reject("mp4-samples", "MP4 sample-to-chunk entry is invalid")
        entries.append((first_chunk, samples))
    if entries[0][0] != 1:
        _reject("mp4-samples", "MP4 sample-to-chunk mapping does not start at chunk one")
    result: list[int] = []
    entry_index = 0
    for chunk in range(1, chunk_count + 1):
        if entry_index + 1 < len(entries) and chunk >= entries[entry_index + 1][0]:
            entry_index += 1
        result.append(entries[entry_index][1])
    return tuple(result)


def _sync_samples(payload: bytes, boxes: list[_Box], sample_count: int) -> frozenset[int]:
    matches = [box for box in boxes if box.kind == b"stss"]
    if len(matches) != 1:
        _reject("mp4-keyframes", "MP4 requires one sync-sample table")
    box = matches[0]
    version, flags = _full_box(payload, box)
    if version != 0 or flags != b"\x00\x00\x00" or box.content_length < 8:
        _reject("mp4-keyframes", "MP4 sync-sample table is invalid")
    count = _u32(payload, box.content_start + 4, code="mp4-keyframes")
    if count == 0 or count > sample_count or box.content_length != 8 + count * 4:
        _reject("mp4-keyframes", "MP4 sync-sample count is invalid")
    entries = tuple(
        _u32(payload, box.content_start + 8 + index * 4, code="mp4-keyframes")
        for index in range(count)
    )
    if entries[0] != 1 or any(value <= 0 or value > sample_count for value in entries) or tuple(sorted(set(entries))) != entries:
        _reject("mp4-keyframes", "MP4 sync-sample indices are invalid")
    return frozenset(entries)


def _validate_sample_payloads(
    payload: bytes,
    *,
    mdat: _Box,
    sizes: tuple[int, ...],
    offsets: tuple[int, ...],
    per_chunk: tuple[int, ...],
    sync_samples: frozenset[int],
) -> None:
    if len(offsets) != len(per_chunk) or sum(per_chunk) != len(sizes):
        _reject("mp4-samples", "MP4 chunk mapping does not cover every sample")
    sample_index = 0
    idr_samples: set[int] = set()
    for chunk_index, (chunk_offset, samples_in_chunk) in enumerate(zip(offsets, per_chunk)):
        if chunk_offset < mdat.content_start or chunk_offset >= mdat.end:
            _reject("mp4-samples", "MP4 chunk offset escaped media data")
        cursor = chunk_offset
        for _ in range(samples_in_chunk):
            size = sizes[sample_index]
            sample_end = cursor + size
            if sample_end > mdat.end:
                _reject("mp4-samples", "MP4 sample escaped media data")
            nal_cursor = cursor
            has_vcl = False
            has_idr = False
            while nal_cursor < sample_end:
                if sample_end - nal_cursor < 5:
                    _reject("mp4-codec", "MP4 AVC sample has truncated NAL framing")
                nal_length = _u32(payload, nal_cursor, code="mp4-codec")
                nal_cursor += 4
                if nal_length == 0 or nal_cursor + nal_length > sample_end:
                    _reject("mp4-codec", "MP4 AVC NAL length escaped its sample")
                header = payload[nal_cursor]
                nal_type = header & 0x1F
                if header & 0x80 or nal_type not in {1, 5, 6, 7, 8, 9}:
                    _reject("mp4-codec", "MP4 AVC sample contains an unsupported NAL unit")
                has_vcl = has_vcl or nal_type in {1, 5}
                has_idr = has_idr or nal_type == 5
                nal_cursor += nal_length
            if nal_cursor != sample_end or not has_vcl:
                _reject("mp4-codec", "MP4 AVC sample has no complete coded picture")
            sample_number = sample_index + 1
            if has_idr:
                idr_samples.add(sample_number)
            cursor = sample_end
            sample_index += 1
        next_offset = offsets[chunk_index + 1] if chunk_index + 1 < len(offsets) else mdat.end
        if cursor != next_offset:
            _reject("mp4-samples", "MP4 media data is not a contiguous sample sequence")
    if sample_index != len(sizes) or idr_samples != set(sync_samples):
        _reject("mp4-keyframes", "MP4 sync samples do not match AVC IDR pictures")


def _validate_edit_list(payload: bytes, boxes: list[_Box]) -> None:
    edits = [box for box in boxes if box.kind == b"edts"]
    if not edits:
        return
    if len(edits) != 1:
        _reject("mp4-timing", "MP4 contains multiple edit lists")
    elst = _one(_children(payload, edits[0]), b"elst", code="mp4-timing")
    version, flags = _full_box(payload, elst)
    if flags != b"\x00\x00\x00" or elst.content_length < 8:
        _reject("mp4-timing", "MP4 edit list is invalid")
    count = _u32(payload, elst.content_start + 4, code="mp4-timing")
    expected = 8 + count * (12 if version == 0 else 20 if version == 1 else 0)
    if count != 1 or expected != elst.content_length:
        _reject("mp4-timing", "MP4 edit list is outside the approved envelope")
    if version == 0:
        media_time = _i32(payload, elst.content_start + 12, code="mp4-timing")
        rate_offset = elst.content_start + 16
    else:
        media_time = _i64(payload, elst.content_start + 16, code="mp4-timing")
        rate_offset = elst.content_start + 24
    if media_time != 0 or payload[rate_offset : rate_offset + 4] != b"\x00\x01\x00\x00":
        _reject("mp4-timing", "MP4 edit list shifts or scales the video timeline")


def validate_mp4(
    payload: bytes,
    *,
    width: int = MP4_WIDTH,
    height: int = MP4_HEIGHT,
    duration_ms: int = MP4_DURATION_MS,
    frame_rate: int = MP4_FRAME_RATE,
    frame_count: int = MP4_FRAME_COUNT,
    max_byte_length: int = MAX_MP4_BYTES,
) -> Mp4Metadata:
    """Validate one flat, silent, exact-duration H.264 MP4 artifact."""

    if not isinstance(payload, bytes) or len(payload) <= 0 or len(payload) > max_byte_length:
        _reject("mp4-size", "MP4 is empty or exceeds its byte envelope")
    top = _boxes(payload, 0, len(payload))
    if not top or top[0].kind != b"ftyp":
        _reject("mp4-signature", "MP4 does not begin with an ftyp box")
    if any(box.kind not in {b"ftyp", b"free", b"moov", b"mdat"} for box in top):
        _reject("mp4-topology", "MP4 contains an unsupported top-level box")
    ftyp = _one(top, b"ftyp", code="mp4-signature")
    moov = _one(top, b"moov")
    mdat = _one(top, b"mdat")
    if ftyp.content_length < 12 or ftyp.content_length % 4:
        _reject("mp4-signature", "MP4 file-type box is malformed")
    brands = [payload[offset : offset + 4] for offset in range(ftyp.content_start, ftyp.end, 4)]
    if brands[0] not in {b"isom", b"mp42"} or b"avc1" not in brands[2:]:
        _reject("mp4-signature", "MP4 brands do not declare AVC interoperability")

    movie = _children(payload, moov)
    if any(box.kind not in {b"mvhd", b"trak", b"udta"} for box in movie):
        _reject("mp4-topology", "MP4 movie contains an unsupported box")
    if _movie_duration(payload, _one(movie, b"mvhd")) != Fraction(duration_ms, 1_000):
        _reject("mp4-duration", "MP4 movie duration is not exactly five seconds")
    tracks = [box for box in movie if box.kind == b"trak"]
    if len(tracks) != 1:
        _reject("mp4-streams", "MP4 must contain exactly one track")
    track_children = _children(payload, tracks[0])
    if any(box.kind not in {b"tkhd", b"edts", b"mdia"} for box in track_children):
        _reject("mp4-topology", "MP4 track contains an unsupported box")
    track_width, track_height = _track_geometry(payload, _one(track_children, b"tkhd"))
    _validate_edit_list(payload, track_children)

    mdia = _one(track_children, b"mdia")
    media = _children(payload, mdia)
    if any(box.kind not in {b"mdhd", b"hdlr", b"minf"} for box in media):
        _reject("mp4-topology", "MP4 media contains an unsupported box")
    if _handler(payload, _one(media, b"hdlr")) != b"vide":
        _reject("mp4-streams", "MP4 track is not video")
    timescale, media_duration = _media_duration(payload, _one(media, b"mdhd"))
    if Fraction(media_duration, timescale) != Fraction(duration_ms, 1_000):
        _reject("mp4-duration", "MP4 media duration is not exactly five seconds")

    minf = _one(media, b"minf")
    media_information = _children(payload, minf)
    if any(box.kind not in {b"vmhd", b"dinf", b"stbl"} for box in media_information):
        _reject("mp4-topology", "MP4 video media information contains an unsupported box")
    _one(media_information, b"vmhd")
    stbl = _one(media_information, b"stbl")
    samples = _children(payload, stbl)
    allowed_sample_boxes = {b"stsd", b"stts", b"stss", b"stsc", b"stsz", b"stco", b"co64"}
    if any(box.kind not in allowed_sample_boxes for box in samples):
        _reject("mp4-topology", "MP4 sample table contains an unsupported box")
    sample_width, sample_height = _validate_sample_description(payload, _one(samples, b"stsd"))
    timing_count, timing_duration = _sample_timing(payload, _one(samples, b"stts"))
    size_count, total_sample_bytes, sample_sizes = _sample_sizes(payload, _one(samples, b"stsz"))
    offset_boxes = [box for box in samples if box.kind in {b"stco", b"co64"}]
    if len(offset_boxes) != 1:
        _reject("mp4-samples", "MP4 must use exactly one chunk-offset table")
    offsets = _chunk_offsets(payload, offset_boxes[0])
    per_chunk = _samples_per_chunk(payload, _one(samples, b"stsc", code="mp4-samples"), len(offsets))
    sync_samples = _sync_samples(payload, samples, size_count)

    if (track_width, track_height) != (width, height) or (sample_width, sample_height) != (width, height):
        _reject("mp4-dimensions", "MP4 is not the approved square resolution")
    if timing_count != frame_count or size_count != frame_count:
        _reject("mp4-frame-count", "MP4 does not contain exactly 150 video frames")
    if timing_duration != media_duration or Fraction(timing_count * timescale, timing_duration) != frame_rate:
        _reject("mp4-frame-rate", "MP4 is not constant 30 frames per second")
    if total_sample_bytes <= 0 or total_sample_bytes != mdat.content_length:
        _reject("mp4-samples", "MP4 sample sizes exceed media data")
    _validate_sample_payloads(
        payload,
        mdat=mdat,
        sizes=sample_sizes,
        offsets=offsets,
        per_chunk=per_chunk,
        sync_samples=sync_samples,
    )

    return Mp4Metadata(
        media_type="video/mp4",
        codec="avc1",
        width=width,
        height=height,
        duration_ms=duration_ms,
        frame_rate=frame_rate,
        frame_count=frame_count,
        byte_length=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def validate_share_video_mp4(payload: bytes) -> Mp4Metadata:
    return validate_mp4(payload)


__all__ = [
    "MAX_MP4_BYTES",
    "MP4_DURATION_MS",
    "MP4_FRAME_COUNT",
    "MP4_FRAME_RATE",
    "MP4_HEIGHT",
    "MP4_WIDTH",
    "Mp4Metadata",
    "Mp4ValidationError",
    "validate_mp4",
    "validate_share_video_mp4",
]
