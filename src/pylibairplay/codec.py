"""H.264/HEVC bitstream helpers: length-prefixed (AVCC) -> Annex-B.

AirPlay's mirror stream carries access units as length-prefixed NAL units (AVCC):
each NAL is ``BE32 length | NAL bytes``. Most decoders (and the Annex-B world)
want start codes instead. These helpers are pure bitstream format knowledge; no
reverse engineering is involved.

The parameter sets (SPS/PPS) arrive out of band in a separate codec-config message
whose layout :func:`avcc_config_to_annexb`
converts the common avcC box form once that message is parsed.
"""

from __future__ import annotations

START_CODE = b"\x00\x00\x00\x01"


def avcc_to_annexb(data: bytes, length_size: int = 4) -> bytes:
    """Convert a length-prefixed access unit to Annex-B start-code form."""
    out = bytearray()
    i, n = 0, len(data)
    while i + length_size <= n:
        nal_len = int.from_bytes(data[i : i + length_size], "big")
        i += length_size
        if nal_len == 0 or i + nal_len > n:
            break
        out += START_CODE + data[i : i + nal_len]
        i += nal_len
    return bytes(out)


def annexb_nalus(data: bytes):
    """Iterate NAL units from an Annex-B buffer (3- or 4-byte start codes)."""
    i, n = 0, len(data)
    start = None
    while i < n - 2:
        if data[i] == 0 and data[i + 1] == 0 and data[i + 2] == 1:
            if start is not None:
                yield _strip_trailing_zero(data[start:i])
            start = i + 3
            i += 3
        else:
            i += 1
    if start is not None:
        yield _strip_trailing_zero(data[start:])


def _strip_trailing_zero(b: bytes) -> bytes:
    # A 4-byte start code is 00 00 00 01; the leading 00 belongs to the next code.
    return b[:-1] if b.endswith(b"\x00") else b


def avcc_config_to_annexb(avcc: bytes) -> tuple[bytes, int]:
    """Parse an avcC configuration record; return (SPS+PPS as Annex-B, length_size).

    avcC layout (ISO/IEC 14496-15): version(1) profile(1) compat(1) level(1),
    then ``0b111111xx`` where xx+1 is the NAL length size, ``0b111xxxxx`` SPS count,
    then for each SPS a BE16 length + bytes, then PPS count + entries.
    """
    if len(avcc) < 7 or avcc[0] != 1:
        raise ValueError("not an avcC configuration record")
    length_size = (avcc[4] & 0x03) + 1
    out = bytearray()
    i = 5
    num_sps = avcc[i] & 0x1F
    i += 1
    i = _emit_set(avcc, i, num_sps, out)
    num_pps = avcc[i]
    i += 1
    _emit_set(avcc, i, num_pps, out)
    return bytes(out), length_size


def _emit_set(buf: bytes, i: int, count: int, out: bytearray) -> int:
    for _ in range(count):
        ln = int.from_bytes(buf[i : i + 2], "big")
        i += 2
        out += START_CODE + buf[i : i + ln]
        i += ln
    return i


class _Bits:
    """Minimal MSB-first bit reader with H.264 Exp-Golomb (ue/se)."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def u(self, n: int) -> int:
        v = 0
        for _ in range(n):
            byte = self.data[self.pos >> 3] if (self.pos >> 3) < len(self.data) else 0
            v = (v << 1) | ((byte >> (7 - (self.pos & 7))) & 1)
            self.pos += 1
        return v

    def ue(self) -> int:
        z = 0
        while z < 32 and self.u(1) == 0:
            z += 1
        return (1 << z) - 1 + (self.u(z) if z else 0)

    def se(self) -> int:
        k = self.ue()
        return (k + 1) // 2 if k & 1 else -(k // 2)


def _rbsp(nal: bytes) -> bytes:
    """Strip H.264 emulation-prevention (00 00 03) bytes."""
    out = bytearray()
    i = 0
    while i < len(nal):
        if i + 2 < len(nal) and nal[i] == 0 and nal[i + 1] == 0 and nal[i + 2] == 3:
            out += nal[i : i + 2]
            i += 3
        else:
            out.append(nal[i])
            i += 1
    return bytes(out)


def sps_dimensions(sps_nal: bytes) -> tuple[int, int] | None:
    """Decode the visible (cropped) width/height from an H.264 SPS NAL (incl. header)."""
    try:
        b = _Bits(_rbsp(sps_nal[1:]))
        profile = b.u(8)
        b.u(8)  # constraint flags + reserved
        b.u(8)  # level
        b.ue()  # seq_parameter_set_id
        chroma = 1
        if profile in (100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135):
            chroma = b.ue()
            if chroma == 3:
                b.u(1)  # separate_colour_plane_flag
            b.ue()  # bit_depth_luma_minus8
            b.ue()  # bit_depth_chroma_minus8
            b.u(1)  # qpprime_y_zero_transform_bypass_flag
            if b.u(1):  # seq_scaling_matrix_present_flag
                for idx in range(8 if chroma != 3 else 12):
                    if b.u(1):
                        last = nxt = 8
                        for _ in range(16 if idx < 6 else 64):
                            if nxt != 0:
                                nxt = (last + b.se() + 256) % 256
                            last = nxt if nxt != 0 else last
        b.ue()  # log2_max_frame_num_minus4
        poc = b.ue()
        if poc == 0:
            b.ue()
        elif poc == 1:
            b.u(1)
            b.se()
            b.se()
            for _ in range(b.ue()):
                b.se()
        b.ue()  # max_num_ref_frames
        b.u(1)  # gaps_in_frame_num_value_allowed_flag
        w_mbs = b.ue() + 1
        h_map = b.ue() + 1
        frame_mbs_only = b.u(1)
        if not frame_mbs_only:
            b.u(1)  # mb_adaptive_frame_field_flag
        b.u(1)  # direct_8x8_inference_flag
        width = w_mbs * 16
        height = h_map * 16 * (2 - frame_mbs_only)
        if b.u(1):  # frame_cropping_flag
            sub_w = 2 if chroma in (1, 2) else 1
            sub_h = (2 if chroma == 1 else 1) * (2 - frame_mbs_only)
            width -= (b.ue() + b.ue()) * sub_w
            height -= (b.ue() + b.ue()) * sub_h
        if 0 < width <= 8192 and 0 < height <= 8192:
            return width, height
    except Exception:
        pass
    return None
