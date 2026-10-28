"""TLV8 encoding, as used by HomeKit pairing and AirPlay's pair-setup/verify.

Source: HomeKit Accessory Protocol specification, "TLV8" section. Each item is
``type (1 byte) | length (1 byte) | value (length bytes)``. A value longer than
255 bytes is split into consecutive fragments that share the same type byte; a
reader concatenates runs of the same type. A zero-length item is valid and is
used as a separator between two items that would otherwise merge.

This module is implemented from the public spec and depends on nothing else.
"""

from __future__ import annotations

from enum import IntEnum

FRAGMENT = 255


class Tag(IntEnum):
    """The HAP/pairing TLV types used by AirPlay. (HAP Table 5-6.)"""

    METHOD = 0x00
    IDENTIFIER = 0x01
    SALT = 0x02
    PUBLIC_KEY = 0x03
    PROOF = 0x04
    ENCRYPTED_DATA = 0x05
    STATE = 0x06
    ERROR = 0x07
    RETRY_DELAY = 0x08
    CERTIFICATE = 0x09
    SIGNATURE = 0x0A
    PERMISSIONS = 0x0B
    FRAGMENT_DATA = 0x0C
    FLAGS = 0x13
    SEPARATOR = 0xFF


def encode(items: list[tuple[int, bytes]] | dict[int, bytes]) -> bytes:
    """Encode (type, value) items. Values > 255 bytes are fragmented."""
    pairs = items.items() if isinstance(items, dict) else items
    out = bytearray()
    for t, value in pairs:
        value = bytes(value)
        if len(value) == 0:
            out += bytes((t, 0))
            continue
        for i in range(0, len(value), FRAGMENT):
            chunk = value[i : i + FRAGMENT]
            out += bytes((t, len(chunk))) + chunk
    return bytes(out)


def decode(data: bytes) -> dict[int, bytes]:
    """Decode to {type: value}, concatenating fragments of the same type.

    Note: a run is broken by a zero-length SEPARATOR item, matching HAP. If the
    same type legitimately appears twice (separated), the second occurrence
    overwrites the first in the returned dict; use :func:`decode_ordered` when
    order or duplicates matter.
    """
    result: dict[int, bytes] = {}
    prev_type: int | None = None
    for t, value in _iter(data):
        if value == b"" and t == Tag.SEPARATOR:
            prev_type = None
            continue
        if t == prev_type:
            result[t] += value
        else:
            result[t] = value
        prev_type = t
    return result


def decode_ordered(data: bytes) -> list[tuple[int, bytes]]:
    """Decode to an ordered list, merging only adjacent same-type fragments."""
    items: list[tuple[int, bytes]] = []
    for t, value in _iter(data):
        if items and items[-1][0] == t and value != b"":
            items[-1] = (t, items[-1][1] + value)
        else:
            items.append((t, value))
    return items


def _iter(data: bytes):
    i, n = 0, len(data)
    while i < n:
        if i + 2 > n:
            raise ValueError("truncated TLV8 header")
        t, length = data[i], data[i + 1]
        i += 2
        if i + length > n:
            raise ValueError("truncated TLV8 value")
        yield t, data[i : i + length]
        i += length
