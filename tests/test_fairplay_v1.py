"""Pure-Python FairPlay v1 replies vs real iOS 26 sessions (tests/vectors, spec 90)."""

import json
from pathlib import Path

import pytest

from pylibairplay.fairplay_v1 import FP_PHASE1_REPLIES, phase1_reply, phase2_reply

# Recorded from live iOS sessions; machine-local and not committed, so the
# vector-driven tests skip (empty parameter set) when the file is absent.
_VECTORS_PATH = Path(__file__).parent / "vectors" / "fairplay_v1.json"
VECTORS = json.loads(_VECTORS_PATH.read_text()) if _VECTORS_PATH.exists() else []


@pytest.mark.parametrize("v", VECTORS)
def test_phase2_reply_matches_live_session(v):
    assert phase2_reply(bytes.fromhex(v["p2"])) == bytes.fromhex(v["p2_reply"])


@pytest.mark.parametrize("v", VECTORS)
def test_phase1_request_is_cached(v):
    p1 = bytes.fromhex(v["p1"])
    assert p1[14] == v["selector"]
    assert len(phase1_reply(p1)) == 142


def test_phase2_reply_rejects_non_phase2():
    assert phase2_reply(b"") == b""
    assert phase2_reply(bytes.fromhex(next(iter(FP_PHASE1_REPLIES)))) == b""
    p2 = bytearray(b"FPLY\x03\x01\x03" + bytes(157))  # well-formed phase-2 shape (164 B)
    assert len(phase2_reply(bytes(p2))) == 32
    p2[6] = 0x01
    assert phase2_reply(bytes(p2)) == b""


@pytest.mark.parametrize("v", VECTORS)
def test_ekey_layout(v):
    """FPLY hdr(12) | u32 0 | 16 B | u32 0x10 | 20 B | 16 B — constant across sessions."""
    ekey = bytes.fromhex(v["ekey"])
    assert len(ekey) == 72
    assert ekey[:12] == bytes.fromhex("46504c59010201000000003c")
    assert ekey[12:16] == b"\x00\x00\x00\x00" and ekey[32:36] == b"\x00\x00\x00\x10"
