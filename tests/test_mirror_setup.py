"""SETUP for a screen stream derives the mirror key and returns a data port."""
import plistlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pylibairplay import keys
from pylibairplay.rtsp.server import Request
from pylibairplay.session import ControlSession, STREAM_TYPE_SCREEN


def _req(method, uri, body=b""):
    return Request(method, uri, "RTSP/1.0", {"content-length": str(len(body))}, body)


def test_screen_setup_derives_key_and_returns_port():
    captured = {}
    def on_setup(key, scid):
        captured["key"] = key; captured["scid"] = scid
        return 55555
    s = ControlSession(Ed25519PrivateKey.generate(), "AA:BB:CC:DD:EE:FF",
                       info_provider=lambda: {}, on_setup=on_setup)
    s.pairing_secret = bytes(range(32))  # pretend pairing done
    body = plistlib.dumps({"streams": [{"type": STREAM_TYPE_SCREEN, "streamConnectionID": 42}]},
                          fmt=plistlib.FMT_BINARY)
    resp = s.handle(_req("SETUP", "rtsp://x/stream", body))
    out = plistlib.loads(resp.body)
    assert out["streams"][0]["type"] == STREAM_TYPE_SCREEN
    assert out["streams"][0]["dataPort"] == 55555
    assert captured["scid"] == 42
    assert captured["key"] == keys.mirror_stream_key(bytes(range(32)), 42)


def test_phase1_setup_without_streams_acks():
    s = ControlSession(Ed25519PrivateKey.generate(), "d", info_provider=lambda: {})
    body = plistlib.dumps({"timingProtocol": "NTP"}, fmt=plistlib.FMT_BINARY)
    resp = s.handle(_req("SETUP", "rtsp://x", body))
    assert resp.status == 200 and "timingPort" in plistlib.loads(resp.body)
