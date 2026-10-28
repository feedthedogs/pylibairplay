"""Screen-mirror decode: key derivation + AES-CTR + AVCC->AnnexB framing (spec 20)."""
import hashlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pylibairplay.screen import ScreenStream, derive_stream_keys


def _frame(typ, payload, ts=0):
    hdr = struct.pack("<IHH", len(payload), typ, 0) + struct.pack("<Q", ts) + b"\x00" * (128 - 16)
    return hdr + payload


def test_derive_stream_keys_vector():
    # Regression vector captured + verified against a real iOS 26 session.
    secret = bytes.fromhex("5ce185ed6794eaf347ccf0a5185f3304")
    key, iv = derive_stream_keys(secret, 5888081060092986532)
    assert key.hex() == "28ec6e4688d3a21ff49b4b6454b917a4"
    assert iv.hex() == "bdcac77a0ddbadcca5fb8b58bc58bfcc"


def test_derive_stream_keys_negative_connection_id():
    # Real iOS 26 session whose streamConnectionID decoded (via plistlib) as negative.
    # The salt uses the unsigned u64 decimal; signed "-708..." yields garbage video.
    secret = bytes.fromhex("83fa7bd6b2374bbcc52c18e66491eaf0")
    scid = -7083386902552555596
    key, iv = derive_stream_keys(secret, scid)
    assert (key, iv) == derive_stream_keys(secret, scid + (1 << 64))
    assert key.hex() == "13c930ae1d220f2d09c626ac6bbb511f"
    assert iv.hex() == "75f9ca0999f9f54bc411094acc866469"
    # First 8 bytes of that session's 21151-byte IDR payload decrypt to AVCC len + IDR NAL.
    clear = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor().update(bytes.fromhex("6507cbc69097cc90"))
    assert struct.unpack(">I", clear[:4])[0] == 21151 - 4
    assert clear[4] & 0x1F == 5


def test_screen_stream_decrypts_and_reframes():
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    # Two encrypted video NALs (AVCC: 4-byte big-endian length + NAL), one continuous CTR.
    nal1 = b"\x65" + b"\xaa" * 20       # IDR slice
    nal2 = b"\x41" + b"\xbb" * 10       # non-IDR slice
    avcc1 = struct.pack(">I", len(nal1)) + nal1
    avcc2 = struct.pack(">I", len(nal2)) + nal2
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    e1 = enc.update(avcc1)
    e2 = enc.update(avcc2)

    aus = []
    ss = ScreenStream(key, iv, aus.append)
    # type 5 (metadata) and type 1 handling: a stray metadata frame must NOT desync the CTR
    ss.feed(_frame(5, b"bplist00stuff"))
    ss.feed(_frame(0x1000, e1))        # keyframe
    ss.feed(_frame(0, e2))             # delta
    assert len(aus) == 2
    assert aus[0].keyframe and aus[0].data == b"\x00\x00\x00\x01" + nal1
    assert not aus[1].keyframe and aus[1].data == b"\x00\x00\x00\x01" + nal2


def test_screen_stream_reassembles_split_frames():
    key, iv = bytes(16), bytes(16)
    nal = b"\x41" + b"\xcd" * 30
    avcc = struct.pack(">I", len(nal)) + nal
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(avcc)
    frame = _frame(0, enc)
    aus = []
    ss = ScreenStream(key, iv, aus.append)
    # feed one byte at a time — the buffer must reassemble the 128-byte header + payload
    for i in range(len(frame)):
        ss.feed(frame[i:i + 1])
    assert len(aus) == 1 and aus[0].data == b"\x00\x00\x00\x01" + nal


def test_sps_dimensions_vector():
    # Real SPS from an iOS 26 mirror session (498x1080, verified vs PyAV decode).
    from pylibairplay import codec
    sps = bytes.fromhex("27640020ac13145020022788966e021a0204")
    assert codec.sps_dimensions(sps) == (498, 1080)


def test_screen_stream_updates_dims_from_config():
    import struct
    from pylibairplay.screen import ScreenStream
    # avcC config box wrapping the real SPS/PPS.
    sps = bytes.fromhex("27640020ac13145020022788966e021a0204")
    pps = bytes.fromhex("28ee3cb0")
    avcc = (b"\x01" + sps[1:4] + b"\xff\xe1" + struct.pack(">H", len(sps)) + sps
            + b"\x01" + struct.pack(">H", len(pps)) + pps)
    hdr = struct.pack("<IHH", len(avcc), 1, 0) + b"\x00" * (128 - 8)
    ss = ScreenStream(bytes(16), bytes(16), lambda au: None)
    ss.feed(hdr + avcc)
    assert (ss.width, ss.height) == (498, 1080)
