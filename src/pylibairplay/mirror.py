"""Mirror data-port server (stream type 110).

Confirmed from firmware: the screen SETUP opens a
TCP ``dataPort``; the stream is encrypted with a single 32-byte key =
HKDF(pairing_secret, "DataStream-Salt"+streamConnectionID, "DataStream-Output-Encryption-Key").

The exact on-the-wire framing on that port (AEAD choice, nonce rule, per-frame
header) is the last piece being pinned. Rather than guess silently, this server:

* optionally dumps the raw received bytes to a file for offline analysis
  (``capture_path``), and
* attempts the most likely scheme — the same length-prefixed ChaCha20-Poly1305
  framing the control channel uses (rtsp/secure.py), treating each decrypted block
  as a mirror payload — logging what it finds.

A single live test with ``capture_path`` set reveals the real format, after which
:meth:`_parse_payload` is finalized. The public callback contract is already stable.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Callable

from . import codec
from .rtsp.secure import SecureChannel
from .types import Codec, SessionInfo, VideoAccessUnit

log = logging.getLogger("pylibairplay.mirror")


class MirrorServer:
    def __init__(
        self,
        key: bytes,
        on_video: Callable[[VideoAccessUnit], None],
        on_session: Callable[[SessionInfo], None] = lambda i: None,
        bind: str = "0.0.0.0",
        capture_path: str | None = None,
    ) -> None:
        self.key = key
        self.on_video = on_video
        self.on_session = on_session
        self.bind = bind
        self.capture_path = capture_path
        self._sock = socket.create_server((bind, 0))
        self.port: int = self._sock.getsockname()[1]
        self._task: asyncio.Task | None = None
        self._sps_pps = b""

    def start(self) -> int:
        """Begin accepting on the data port; return the port number for the SETUP reply."""
        self._sock.listen(1)
        self._sock.setblocking(False)
        self._task = asyncio.get_event_loop().create_task(self._serve())
        log.info("mirror data port listening on %d", self.port)
        return self.port

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
        self._sock.close()

    async def _serve(self) -> None:
        loop = asyncio.get_event_loop()
        conn, addr = await loop.sock_accept(self._sock)
        log.info("mirror stream connected from %s", addr)
        capture = open(self.capture_path, "wb") if self.capture_path else None
        # Mirror stream uses one key for both read and write; try control-style framing.
        channel = SecureChannel(read_key=self.key, write_key=self.key)
        try:
            while True:
                data = await loop.sock_recv(conn, 65536)
                if not data:
                    break
                if capture:
                    capture.write(data)
                    capture.flush()
                for block in self._safe_feed(channel, data):
                    self._handle_payload(block)
        except asyncio.CancelledError:
            pass
        finally:
            if capture:
                capture.close()
            conn.close()
            log.info("mirror stream ended")

    def _safe_feed(self, channel: SecureChannel, data: bytes) -> list[bytes]:
        try:
            return channel.feed(data)
        except Exception as e:
            # Wrong framing/nonce — surface it loudly; capture file holds the truth.
            log.warning("mirror decrypt failed (%s); framing needs confirming from capture", e)
            return []

    def _handle_payload(self, payload: bytes) -> None:
        au = self._parse_payload(payload)
        if au is not None:
            self.on_video(au)

    def _parse_payload(self, payload: bytes) -> VideoAccessUnit | None:
        """Turn one decrypted payload into a VideoAccessUnit.

        Placeholder pending the capture: assumes an AVCC length-prefixed access unit.
        Finalized after the first live capture confirms the header layout.
        """
        if not payload:
            return None
        annexb = codec.avcc_to_annexb(payload)
        if not annexb:
            return None
        data = self._sps_pps + annexb if self._sps_pps else annexb
        return VideoAccessUnit(data=data, codec=Codec.H264, pts=0.0, keyframe=False, width=0, height=0)
