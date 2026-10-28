"""HKDF (RFC 5869, SHA-512) key derivations for AirPlay.

The salt/info label strings are protocol constants observed in the firmware. They are reproduced here because they must match
exactly on the wire. Everything else is standard RFC 5869.

Actual key lengths and which salt pairs with which info are confirmed per
milestone; the helpers below take the labels as arguments so the
session code stays the single source of truth for those pairings.
"""

from __future__ import annotations

import hashlib
import hmac


def hkdf_sha512(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Extract-and-Expand with SHA-512."""
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes((counter,)), hashlib.sha512).digest()
        out += t
        counter += 1
    return bytes(out[:length])


# Protocol label constants.
PAIR_SETUP_SALT = b"Pair-Setup-Encrypt-Salt"
PAIR_SETUP_INFO = b"Pair-Setup-Encrypt-Info"
PAIR_SETUP_CONTROLLER_SIGN_SALT = b"Pair-Setup-Controller-Sign-Salt"
PAIR_SETUP_CONTROLLER_SIGN_INFO = b"Pair-Setup-Controller-Sign-Info"
PAIR_SETUP_ACCESSORY_SIGN_SALT = b"Pair-Setup-Accessory-Sign-Salt"
PAIR_SETUP_ACCESSORY_SIGN_INFO = b"Pair-Setup-Accessory-Sign-Info"
MFI_PAIR_SETUP_SALT = b"MFi-Pair-Setup-Salt"
MFI_PAIR_SETUP_INFO = b"MFi-Pair-Setup-Info"
PAIR_VERIFY_SALT = b"Pair-Verify-Encrypt-Salt"
PAIR_VERIFY_INFO = b"Pair-Verify-Encrypt-Info"
CONTROL_SALT = b"Control-Salt"
CONTROL_WRITE_INFO = b"Control-Write-Encryption-Key"
CONTROL_READ_INFO = b"Control-Read-Encryption-Key"
DATASTREAM_SALT = b"DataStream-Salt"
DATASTREAM_OUT_INFO = b"DataStream-Output-Encryption-Key"
DATASTREAM_IN_INFO = b"DataStream-Input-Encryption-Key"


def session_channel_key(shared: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return hkdf_sha512(shared, salt, info, length)


def control_channel_keys(pairing_secret: bytes) -> tuple[bytes, bytes]:
    """(read_key, write_key) for the encrypted control channel, receiver POV.

    Confirmed in AirPlayReceiver ``airplayReqProcessor_createEncryptionContext``: salt ``Control-Salt``, 32-byte keys.
    """
    read = hkdf_sha512(pairing_secret, CONTROL_SALT, CONTROL_READ_INFO, 32)
    write = hkdf_sha512(pairing_secret, CONTROL_SALT, CONTROL_WRITE_INFO, 32)
    return read, write


def mirror_stream_key(pairing_secret: bytes, stream_connection_id: int) -> bytes:
    """32-byte screen-mirror key, confirmed in ``_ScreenSetup`` / ``_GetDataStreamSecurityKeys``.

    salt = ``b"DataStream-Salt" + ascii(decimal(streamConnectionID))``,
    info = ``DataStream-Output-Encryption-Key`` (the only key screen mirroring derives).
    """
    salt = DATASTREAM_SALT + str(stream_connection_id).encode()
    return hkdf_sha512(pairing_secret, salt, DATASTREAM_OUT_INFO, 32)
