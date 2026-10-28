"""Legacy FairPlay screen-mirror stream decode.

The screen data port carries a sequence of frames, each a 128-byte header followed
by a payload:

    offset 0  u32  payload length (little-endian)
    offset 4  u16  payload type
    offset 8  u64  timestamp
    ...            (zero padding to 128 bytes)

Payload types:
  * 1       avcC codec config (plaintext) — SPS/PPS.
  * 5       bplist metadata (plaintext) — skipped.
  * 0       video slice (encrypted).
  * 0x1000  IDR keyframe (encrypted).

Encrypted frames (types 0 and 0x1000) are AES-128-CTR with a **continuous** counter
across all encrypted frames in order; plaintext frames are not fed to the cipher. The
key/iv come from the FairPlay-decrypted ekey secret (see receiver):

    key = SHA512("AirPlayStreamKey" + decimal(streamConnectionID) + secret)[:16]
    iv  = SHA512("AirPlayStreamIV"  + decimal(streamConnectionID) + secret)[:16]

Decrypted payloads are AVCC (length-prefixed) H.264; this converts them to Annex-B
and delivers VideoAccessUnits, prepending SPS/PPS on keyframes.
"""
from __future__ import annotations

import hashlib
import logging
import struct
from collections.abc import Callable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import codec
from .types import Codec, VideoAccessUnit

log = logging.getLogger("pylibairplay.screen")

_HDR = 128
_T_VIDEO = 0
_T_CONFIG = 1
_T_META = 5
_T_KEYFRAME = 0x1000


def derive_stream_keys(secret: bytes, stream_connection_id: int) -> tuple[bytes, bytes]:
    """key, iv = SHA512(salt + secret)[:16] with the AirPlayStreamKey/IV salts.

    The streamConnectionID is a u64 on the wire, but plistlib decodes it as a signed
    int; the salt uses the unsigned decimal form, so negative IDs are wrapped."""
    sid = str(stream_connection_id & 0xFFFF_FFFF_FFFF_FFFF).encode()
    key = hashlib.sha512(b"AirPlayStreamKey" + sid + secret).digest()[:16]
    iv = hashlib.sha512(b"AirPlayStreamIV" + sid + secret).digest()[:16]
    return key, iv


class ScreenStream:
    """Decrypts + reframes the screen data port into VideoAccessUnits."""

    def __init__(self, key: bytes, iv: bytes,
                 on_video: Callable[[VideoAccessUnit], None],
                 width: int = 1920, height: int = 1080) -> None:
        self._dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        self.on_video = on_video
        self.width = width
        self.height = height
        self._buf = bytearray()
        self._sps_pps = b""
        self._length_size = 4
        self.frames = 0
        self.bad_frames = 0  # encrypted frames that didn't decrypt to valid AVCC

    def feed(self, data: bytes) -> None:
        self._buf += data
        while len(self._buf) >= _HDR:
            ln = struct.unpack_from("<I", self._buf, 0)[0]
            typ = struct.unpack_from("<H", self._buf, 4)[0]
            if len(self._buf) < _HDR + ln:
                break
            ts = struct.unpack_from("<Q", self._buf, 8)[0]
            payload = bytes(self._buf[_HDR:_HDR + ln])
            del self._buf[:_HDR + ln]
            self._frame(typ, payload, ts)

    def _frame(self, typ: int, payload: bytes, ts: int) -> None:
        if typ == _T_CONFIG:
            try:
                self._sps_pps, ls = codec.avcc_config_to_annexb(payload)
                if ls:
                    self._length_size = ls
                for nal in codec.annexb_nalus(self._sps_pps):
                    if nal and (nal[0] & 0x1f) == 7:  # SPS
                        dims = codec.sps_dimensions(nal)
                        if dims:
                            self.width, self.height = dims
                        break
                log.info("screen: avcC config (%d B SPS/PPS, lengthSize=%d, %dx%d)",
                         len(self._sps_pps), self._length_size, self.width, self.height)
            except Exception:
                log.exception("screen: bad avcC config")
            return
        if typ == _T_META:
            return  # bplist metadata (e.g. volume) — not video
        if typ not in (_T_VIDEO, _T_KEYFRAME):
            log.warning("screen: unknown frame type %#x (%d B)", typ, len(payload))
            return
        clear = self._dec.update(payload)   # continuous AES-CTR
        try:
            annexb = codec.avcc_to_annexb(clear, self._length_size)
        except Exception:
            log.exception("screen: bad AVCC frame")
            return
        if payload and not annexb:
            # Garbage after decrypt: almost always a wrong stream key/iv. Drop it rather
            # than hand the decoder empty access units, and say so loudly.
            self.bad_frames += 1
            if self.bad_frames == 1 or self.bad_frames % 300 == 0:
                log.error("screen: %d encrypted frame(s) did not decrypt to valid H.264 "
                          "(wrong stream key?)", self.bad_frames)
            return
        keyframe = typ == _T_KEYFRAME or _has_idr(annexb)
        data = (self._sps_pps + annexb) if (keyframe and self._sps_pps) else annexb
        self.frames += 1
        self.on_video(VideoAccessUnit(
            data=data, codec=Codec.H264, pts=ts / 1_000_000_000.0,
            keyframe=keyframe, width=self.width, height=self.height))


def _has_idr(annexb: bytes) -> bool:
    for nal in codec.annexb_nalus(annexb):
        if nal and (nal[0] & 0x1f) == 5:
            return True
    return False
