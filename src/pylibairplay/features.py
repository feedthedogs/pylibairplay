"""AirPlay feature flags advertised in the ``_airplay._tcp`` TXT record (``features=``).

The flag meanings are documented in the public openairplay/airplay-spec "features"
page; the exact bit each receiver must set to be offered screen mirroring without
FairPlay is confirmed during M1. Names below are
from the public spec; any bit whose role we depend on is cross-checked against the
firmware.

The value is a 64-bit field, usually printed as two 32-bit hex halves joined by a
comma, e.g. ``features=0x5A7FFFF7,0x1E``.
"""

from __future__ import annotations

from enum import IntFlag


class Feature(IntFlag):
    VIDEO = 1 << 0
    PHOTO = 1 << 1
    VIDEO_FAIR_PLAY = 1 << 2
    VIDEO_VOLUME_CONTROL = 1 << 3
    VIDEO_HTTP_LIVE_STREAMING = 1 << 4
    SLIDESHOW = 1 << 5
    SCREEN = 1 << 7  # screen mirroring
    SCREEN_ROTATE = 1 << 8
    AUDIO = 1 << 9
    AUDIO_REDUNDANT = 1 << 11
    FP_SAPv2pt5_AES_GCM = 1 << 12
    PHOTO_CACHING = 1 << 13
    AUTHENTICATION4 = 1 << 14  # MFi-SAP
    METADATA_FEATURE1 = 1 << 15
    METADATA_FEATURE2 = 1 << 16
    METADATA_FEATURE0 = 1 << 17
    AUDIO_FORMAT1 = 1 << 18
    AUDIO_FORMAT2 = 1 << 19
    AUDIO_FORMAT3 = 1 << 20
    AUDIO_FORMAT4 = 1 << 21
    AUTH_FAIRPLAY = 1 << 23
    # High half (bits 32+)
    SUPPORTS_UNIFIED_PAIR_SETUP_AND_MFI = 1 << 27
    SUPPORTS_SET_PEERS_EXTENDED = 1 << 28
    SUPPORTS_AP_SYNC = 1 << 32
    SUPPORTS_WAKE_ON_LAN1 = 1 << 33
    HOMEKIT_PAIRING = 1 << 38
    SUPPORTS_TRANSIENT_PAIRING = 1 << 48
    SUPPORTS_CORE_UTILS_PAIRING_AND_ENCRYPTION = 1 << 51
    SUPPORTS_BUFFERED_AUDIO = 1 << 40
    SUPPORTS_PTP = 1 << 41


def format_features(value: int) -> str:
    """Render as the two-part hex used in TXT records."""
    lo = value & 0xFFFFFFFF
    hi = (value >> 32) & 0xFFFFFFFF
    return f"0x{lo:X},0x{hi:X}"


def parse_features(text: str) -> int:
    """Parse ``0xLO,0xHI`` or a single ``0x...`` value."""
    parts = [p.strip() for p in text.split(",")]
    if len(parts) == 2:
        lo = int(parts[0], 16)
        hi = int(parts[1], 16)
        return (hi << 32) | lo
    return int(parts[0], 16)
