"""Encrypted session framing for the control channel after pair-verify.

This is the HomeKit "secure session" construction (HAP spec §6.5.2), which AirPlay
reuses for the post-pairing control channel:

* Each direction has its own 32-byte ChaCha20-Poly1305 key (from HKDF, see keys.py).
* A message is sent as ``LE16 length | ChaCha20-Poly1305(plaintext) | 16-byte tag``.
* The 2-byte little-endian length is also the AAD.
* The nonce is a 96-bit value: 32 zero bits followed by a 64-bit little-endian
  message counter that increments per message, per direction.

Whether AirPlay's mirror/data streams reuse this exact framing or the
``DataStream-*`` keys with a different nonce rule is confirmed at M4.
This module covers the control channel.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAX_BLOCK = 0xFFFF


class SecureChannel:
    """Length-prefixed ChaCha20-Poly1305 framing with per-direction counters."""

    def __init__(self, read_key: bytes, write_key: bytes) -> None:
        self._read = ChaCha20Poly1305(read_key)
        self._write = ChaCha20Poly1305(write_key)
        self._read_counter = 0
        self._write_counter = 0
        self._buf = bytearray()

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return b"\x00\x00\x00\x00" + counter.to_bytes(8, "little")

    def encrypt(self, plaintext: bytes) -> bytes:
        """Frame one application message (splitting into <=64KB blocks)."""
        out = bytearray()
        for i in range(0, len(plaintext), MAX_BLOCK) or [0]:
            block = plaintext[i : i + MAX_BLOCK]
            aad = len(block).to_bytes(2, "little")
            ct = self._write.encrypt(self._nonce(self._write_counter), block, aad)
            self._write_counter += 1
            out += aad + ct
        return bytes(out)

    def feed(self, data: bytes) -> list[bytes]:
        """Add received bytes; return any fully-decrypted blocks.

        Blocks are reassembled across TCP reads. Callers concatenate the returned
        blocks to rebuild an application message.
        """
        self._buf += data
        blocks: list[bytes] = []
        while len(self._buf) >= 2:
            length = int.from_bytes(self._buf[:2], "little")
            frame_end = 2 + length + 16
            if len(self._buf) < frame_end:
                break
            aad = bytes(self._buf[:2])
            ct = bytes(self._buf[2:frame_end])
            pt = self._read.decrypt(self._nonce(self._read_counter), ct, aad)
            self._read_counter += 1
            blocks.append(pt)
            del self._buf[:frame_end]
        return blocks
