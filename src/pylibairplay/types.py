"""Public data types handed to callbacks. Stable API surface, protocol-independent."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Codec(str, Enum):
    H264 = "h264"
    HEVC = "hevc"


@dataclass(frozen=True)
class VideoAccessUnit:
    """One decoded-ready access unit from the mirror stream."""

    data: bytes  # Annex-B start-code form, parameter sets prepended on keyframes
    codec: Codec
    pts: float  # presentation time in seconds (source clock)
    keyframe: bool
    width: int
    height: int


@dataclass(frozen=True)
class SessionInfo:
    device_name: str  # e.g. "Alex's iPhone"
    model: str | None  # e.g. "iPhone17,3"
    width: int
    height: int


class EndReason(str, Enum):
    CLIENT_STOPPED = "client_stopped"  # user stopped mirroring
    TIMEOUT = "timeout"  # lost heartbeat
    ERROR = "error"
