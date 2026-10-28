"""HKDF-SHA512 checked against RFC 5869... but RFC 5869's vectors are SHA-256.

We instead verify HKDF-SHA512 against an independent reference computed with
Python's hashlib primitives inline here (extract then expand), plus structural
properties. The inline reference is written from the RFC 5869 equations, not from
the module under test.
"""

import hashlib
import hmac

from pylibairplay.keys import hkdf_sha512


def _ref(ikm, salt, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes((i,)), hashlib.sha512).digest()
        out += t
        i += 1
    return out[:length]


def test_matches_reference():
    ikm = bytes(range(22))
    salt = bytes(range(13))
    info = b"AirPlayStreamKey"
    for length in (16, 32, 64, 100):
        assert hkdf_sha512(ikm, salt, info, length) == _ref(ikm, salt, info, length)


def test_length_and_determinism():
    k1 = hkdf_sha512(b"secret", b"salt", b"info", 32)
    k2 = hkdf_sha512(b"secret", b"salt", b"info", 32)
    assert k1 == k2 and len(k1) == 32
    assert hkdf_sha512(b"secret", b"salt", b"other", 32) != k1


def test_mirror_and_control_key_shapes():
    from pylibairplay.keys import control_channel_keys, mirror_stream_key, hkdf_sha512

    secret = bytes(range(32))
    r, w = control_channel_keys(secret)
    assert len(r) == 32 and len(w) == 32 and r != w

    # mirror salt is the literal label followed by the decimal stream id
    mk = mirror_stream_key(secret, 1234567890123)
    expect = hkdf_sha512(secret, b"DataStream-Salt1234567890123",
                         b"DataStream-Output-Encryption-Key", 32)
    assert mk == expect and len(mk) == 32
