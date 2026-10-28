"""Public async AirPlay screen-mirroring receiver.

Ties together: mDNS advertisement (discovery.py), the control connection
(session.py over an asyncio stream, with the encrypted framing from rtsp/secure.py
once paired), and the mirror data port (mirror.py, M4).

Usage::

    rx = Receiver(name="My Screen")
    rx.on_video = lambda au: ...        # VideoAccessUnit
    await rx.serve()
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
from collections.abc import Callable
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .discovery import Advertiser, ReceiverInfo
from .fairplay_v1 import FP_PHASE1_REPLIES, phase1_reply, phase2_reply
from .mfi import MFiCredentials
from .mirror import MirrorServer
from .rtsp.secure import SecureChannel
from .rtsp.server import MessageParser, Request, Response
from .session import ControlSession
from .types import EndReason, SessionInfo, VideoAccessUnit

log = logging.getLogger("pylibairplay")

def _stable_device_id(name: str) -> str:
    h = hashlib.sha256(name.encode()).digest()
    return ":".join(f"{b:02X}" for b in h[:6])


class Receiver:
    def __init__(
        self,
        name: str = "pylibairplay",
        port: int = 7000,
        identity: Ed25519PrivateKey | None = None,
        bind: str = "0.0.0.0",
        capture_path: str | None = None,
        pin: str = "3939",
        state_path: str | None = None,
        legacy: bool = False,
        fp_capture_path: str | None = None,
        fp_emu_dir: str | None = None,
        fp_emu_python: str | None = None,
        setup_capture_path: str | None = None,
        fp_vectors_path: str | None = None,
        mfi: MFiCredentials | None = None,
    ) -> None:
        self.name = name
        self.port = port
        self.bind = bind
        self.capture_path = capture_path  # dump raw mirror bytes for M4 analysis
        self.pin = pin.encode()
        # Legacy FairPlay (/fp-setup) capture mode: advertise the legacy AirPlay-1
        # feature set so iOS uses the legacy screen path, and record its /fp-setup
        # requests to fp_capture_path (JSONL) for the whitebox emulator.
        self.legacy = legacy
        # Optional MFi certificate + signer. When set (and not legacy) the receiver takes the
        # AirPlay 2 pairing path: it advertises transient pairing and proves the certificate
        # at pair-setup M4, so no FairPlay emulation is needed (spec 60 Finding 7).
        self.mfi = mfi
        if mfi is not None and legacy:
            raise ValueError("mfi credentials apply to the AirPlay 2 path; do not combine with legacy=True")
        if mfi is not None:
            try:
                mfi.check()
            except Exception as e:  # unusual containers may not parse locally; iOS is the judge
                log.warning("MFi credentials failed the local self-check: %s", e)
        self.fp_capture_path = fp_capture_path
        # Optional live FairPlay phase-2 via the firmware whitebox emulator.
        # fp_emu_dir = directory with the extracted AirPlayReceiver + sibling dylibs;
        # fp_emu_python = interpreter with unicorn/lief/capstone. Machine-local interop.
        self.fp_emu_dir = fp_emu_dir
        self.fp_emu_python = fp_emu_python
        self._fp_emu = None               # FairPlayEmulator (started in serve())
        self._fp_last_phase1: bytes | None = None
        self._fp_last_phase2: bytes | None = None
        self._fp_last_phase2_reply: bytes | None = None
        # Optional: append one JSON line per mirror session with the full FairPlay v1
        # test vector {p1, p2, p2_reply, ekey, eiv, secret, scid} (spec 90 corpus).
        self.fp_vectors_path = fp_vectors_path
        # Optional: dump raw SETUP plist bodies (hex, one per line) for offline analysis
        # of the legacy mirror stream descriptors / ekey.
        self.setup_capture_path = setup_capture_path
        # Legacy mirroring event/timing servers (opened in serve()).
        self._event_server: asyncio.Server | None = None
        self._event_port = 0
        self._timing_transport = None
        self._timing_port = 0
        self._ntp_task: asyncio.Task | None = None
        self._peer_host: str | None = None    # iOS IP (from the control connection)
        self._local_host: str | None = None   # our IP as iOS sees it
        self._screen_server: asyncio.Server | None = None
        self._screen_task: asyncio.Task | None = None
        self._screen_ekey: bytes | None = None
        self._screen_eiv: bytes | None = None
        self._screen = None            # ScreenStream (decrypt + reframe), set on stream SETUP
        self._disp_w = 1920
        self._disp_h = 1080
        self._client_name = "iPhone"
        self._client_model: str | None = None
        # Persistent state: a stable accessory identity + paired controllers, so
        # iOS can pair-verify after a one-time PIN pair-setup and across restarts.
        self._state_path = Path(state_path or (Path.home() / ".pylibairplay" / "state.json"))
        self.credentials: dict[bytes, bytes] = {}
        self.identity = identity or self._load_or_create_identity()
        self.device_id = _stable_device_id(name)
        # Callbacks (set by the user).
        self.on_video: Callable[[VideoAccessUnit], None] = lambda au: None
        self.on_session: Callable[[SessionInfo], None] = lambda info: None
        self.on_end: Callable[[EndReason], None] = lambda reason: None
        self._advertiser: Advertiser | None = None
        self._server: asyncio.Server | None = None
        self._mirror: MirrorServer | None = None

    def _load_or_create_identity(self) -> Ed25519PrivateKey:
        import json

        try:
            data = json.loads(self._state_path.read_text())
            for cid_hex, ltpk_hex in data.get("credentials", {}).items():
                self.credentials[bytes.fromhex(cid_hex)] = bytes.fromhex(ltpk_hex)
            return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["identity_seed"]))
        except (FileNotFoundError, KeyError, ValueError):
            key = Ed25519PrivateKey.generate()
            self._save_state(key)
            return key

    def _save_state(self, identity: Ed25519PrivateKey | None = None) -> None:
        import json

        identity = identity or self.identity
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._state_path.write_text(
            json.dumps(
                {
                    "identity_seed": identity.private_bytes_raw().hex(),
                    "credentials": {c.hex(): k.hex() for c, k in self.credentials.items()},
                },
                indent=2,
            )
        )

    def _on_pair(self, controller_id: bytes, ltpk: bytes) -> None:
        self.credentials[controller_id] = ltpk
        self._save_state()
        log.info("stored pairing for controller %s (total paired: %d)",
                 controller_id.decode("latin1")[:20], len(self.credentials))

    def info_plist(self) -> dict:
        """The GET /info response, modeled on a real AP2 screen-mirroring receiver
        (a licensed third-party TV, iOS 26). iOS reads this before deciding how to run the
        session, so it must advertise the AP2 session capabilities: PTP timing
        (PTPInfo), a detailed display, audio latencies, and statusFlags=0x244.
        FairPlay/HLS (playbackCapabilities) is for video casting, not mirroring, so
        it is omitted.
        """
        from .discovery import DEFAULT_FEATURES, LEGACY_FEATURES, FULL_AP2_FEATURES

        pk = self.identity.public_key().public_bytes_raw()
        if self.legacy:
            # Legacy /info: AirPlay-1 feature set (steers iOS to the /fp-setup screen
            # path) PLUS a `displays` array — screen mirroring needs the receiver's
            # display geometry, or iOS tears down after RECORD without a stream setup.
            return {
                "deviceID": self.device_id,
                "name": self.name,
                "model": "AppleTV3,2",
                "manufacturer": "pylibairplay",
                "sourceVersion": "220.68",
                "protocolVersion": "1.1",
                "pi": self.device_id,
                "pk": pk,
                "statusFlags": 0x4,
                "features": int(LEGACY_FEATURES),
                "keepAliveLowPower": True,
                # iOS reads displayCapabilities from GetInfo to decide the mirror
                # geometry (sender logs "Display capabilities in GetInfo response").
                "displayCapabilities": {
                    "widthPixels": 1920,
                    "heightPixels": 1080,
                    "widthPixelsMax": 1920,
                    "heightPixelsMax": 1080,
                    "widthPhysical": 0,
                    "heightPhysical": 0,
                    "overscanned": False,
                    "maxFPS": 60,
                    "features": 0x07,
                },
                "displays": [
                    {
                        "uuid": self.device_id,
                        "widthPixels": 1920,
                        "heightPixels": 1080,
                        "width": 1920,
                        "height": 1080,
                        "widthPhysical": 0,
                        "heightPhysical": 0,
                        "refreshRate": 60,
                        "maxFPS": 60,
                        "overscanned": False,
                        "rotation": False,
                        "features": 0x07,
                        "primaryInputDevice": 1,
                    }
                ],
            }
        return {
            "deviceID": self.device_id,
            "name": self.name,
            "model": "AppleTV3,2",
            "manufacturer": "pylibairplay",
            "sourceVersion": "377.40.00",
            "protocolVersion": "1.1",
            "pi": self.device_id,
            "pk": pk,
            # 0x244 set bit 9 (0x200)=OneTimePairingRequired, which steered iOS to the
            # MFi one-time PIN flow (Method=1, unsatisfiable). Cleared -> 0x44 to aim
            # for a Method=0 CoreUtils pair-setup.
            "statusFlags": 0x44,
            "features": int(FULL_AP2_FEATURES if self.mfi else DEFAULT_FEATURES),
            "keepAliveLowPower": True,
            "keepAliveSendStatsAsBody": True,
            "activeInterfaceType": 0,
            "PTPInfo": "AirPlay;3.6.0.72",
            "audioLatencies": [
                {"type": 100, "inputLatencyMicros": 0, "outputLatencyMicros": 0},
                {"type": 100, "audioType": "default", "inputLatencyMicros": 0, "outputLatencyMicros": 0},
            ],
            "displays": [
                {
                    "uuid": self.device_id,
                    "widthPixels": 1920,
                    "heightPixels": 1080,
                    "width": 1920,
                    "height": 1080,
                    "widthPhysical": 0,
                    "heightPhysical": 0,
                    "refreshRate": 60,
                    "maxFPS": 60,
                    "overscanned": False,
                    "rotation": False,
                    "features": 0x07,
                    "primaryInputDevice": 1,
                }
            ],
        }

    async def serve(self) -> None:
        from .discovery import DEFAULT_FEATURES, LEGACY_FEATURES, FULL_AP2_FEATURES

        pk = self.identity.public_key().public_bytes_raw()
        info = ReceiverInfo(
            name=self.name, device_id=self.device_id, public_key=pk, port=self.port,
            features=int(LEGACY_FEATURES if self.legacy else FULL_AP2_FEATURES if self.mfi else DEFAULT_FEATURES),
            legacy=self.legacy, mfi=self.mfi is not None,
        )
        if self.legacy:
            log.warning("LEGACY fp-setup capture mode: advertising AirPlay-1 features=%s%s",
                        hex(LEGACY_FEATURES),
                        f"; capturing to {self.fp_capture_path}" if self.fp_capture_path else "")
        if self.legacy and self.fp_emu_dir:
            from .fairplay import FairPlayEmulator
            self._fp_emu = FairPlayEmulator(self.fp_emu_dir, python_exe=self.fp_emu_python)
            # Warm-up blocks ~35s; run it off the event loop so advertising isn't delayed.
            await asyncio.get_running_loop().run_in_executor(None, self._fp_emu.start)
        # Legacy screen mirroring: pre-open the event (TCP) + timing (UDP) servers so the
        # control SETUP can hand iOS real ports (eventPort:0 causes an immediate teardown).
        if self.legacy:
            self._event_server = await asyncio.start_server(self._handle_event, self.bind, 0)
            self._event_port = self._event_server.sockets[0].getsockname()[1]
            self._timing_transport, self._timing_port = await self._open_timing_udp()
            log.warning("mirroring: event port %d, timing port %d",
                        self._event_port, self._timing_port)
        self._advertiser = Advertiser(info)
        await self._advertiser.start()
        self._server = await asyncio.start_server(self._handle_control, self.bind, self.port)
        log.info("pylibairplay '%s' advertising on port %d", self.name, self.port)
        try:
            async with self._server:
                await self._server.serve_forever()
        finally:
            if self._advertiser:
                await self._advertiser.stop()
            if self._fp_emu is not None:
                self._fp_emu.stop()

    async def close(self) -> None:
        if self._server:
            self._server.close()
        if self._advertiser:
            await self._advertiser.stop()
        if self._fp_emu is not None:
            self._fp_emu.stop()
        if self._ntp_task is not None:
            self._ntp_task.cancel()
        if self._event_server is not None:
            self._event_server.close()
        if self._timing_transport is not None:
            self._timing_transport.close()

    def _write_fp_vector(self, ekey: bytes, eiv: bytes | None, secret: bytes,
                         scid: int) -> None:
        """Append this session's FairPlay v1 test vector (random session material only:
        no device name/MAC) to ``fp_vectors_path`` for the pure-Python work (spec 90)."""
        if not self.fp_vectors_path:
            return
        import json
        p1, p2 = self._fp_last_phase1 or b"", self._fp_last_phase2 or b""
        rec = {
            "selector": p1[14] if len(p1) > 14 else None,
            "p1": p1.hex(), "p2": p2.hex(),
            "p2_reply": (self._fp_last_phase2_reply or b"").hex(),
            "ekey": ekey.hex(), "eiv": (eiv or b"").hex(),
            "secret": secret.hex(), "scid": scid,
        }
        try:
            with open(self.fp_vectors_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            log.warning("FairPlay vector written to %s", self.fp_vectors_path)
        except Exception:
            log.exception("failed to write FairPlay vector")

    def _fp_capture(self, uri: str, headers: dict, body: bytes) -> bytes:
        """Record an iOS /fp-setup request and return a FairPlay response.

        For the legacy FairPlay v1 **phase-1** request (a fixed, session-independent
        probe) we return a pre-computed 142-byte reply so iOS proceeds to **phase 2**.
        That reply was GENERATED by emulating the user's own firmware whitebox
        (``pylibairplay/fp_emu.py``) — not copied from any GPL receiver — and it
        matches the known public FairPlay v1 phase-1 reply structure (``FPLY 0301 02``).
        The phase-2 reply is computed in pure Python (``fairplay_v1.phase2_reply``); the
        firmware emulator is only needed later, to decrypt the SETUP ekey."""
        import json
        import time

        et = headers.get("x-apple-et") or headers.get("X-Apple-ET")
        reply = phase1_reply(body)
        # Track the message phase (byte 6: 0x01 = phase-1, 0x03 = phase-2).
        phase = body[6] if len(body) > 6 and body[:4] == b"FPLY" else None
        if phase == 0x01:
            self._fp_last_phase1 = body         # remember for the ekey decrypt replay
        elif phase == 0x03:
            self._fp_last_phase2 = body         # remember for the ekey decrypt
            reply = phase2_reply(body)          # pure: header + echo (spec 90)
            if reply:
                self._fp_last_phase2_reply = reply
                log.warning("FP-SETUP %s: phase-2 reply (%d bytes)", uri, len(reply))
        rec = {
            "ts": time.time(),
            "uri": uri,
            "x_apple_et": et,
            "req_len": len(body),
            "req_hex": body.hex(),
            "reply_len": len(reply),
        }
        if self.fp_capture_path:
            try:
                with open(self.fp_capture_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
            except Exception:
                log.exception("failed to write fp capture")
        if reply:
            log.warning("FP-SETUP %s: phase-%s request -> %d-byte reply", uri,
                        {0x01: "1", 0x03: "2"}.get(phase, "?"), len(reply))
        else:
            log.warning("FP-SETUP %s: no reply for this request (%d bytes); captured "
                        "for analysis", uri, len(body))
        return reply

    def _on_control_setup(self, request: dict) -> dict:
        """Legacy mirroring control SETUP: start the NTP timing client to iOS and return
        the receiver's event port + timing peer info (firmware adds eventPort +
        timingPeerInfo; it runs an NTP client to the sender's timingPort — spec 20)."""
        # Remember the device for SessionInfo (shown by an application's status display).
        self._client_name = request.get("name") or "iPhone"
        self._client_model = request.get("model")
        ios_timing_port = int(request.get("timingPort", 0) or 0)
        if ios_timing_port and self._peer_host:
            try:
                self._start_ntp_client(self._peer_host, ios_timing_port)
            except Exception:
                log.exception("failed to start NTP client")
        peer_info = {
            "Addresses": [self._local_host] if self._local_host else [],
            "ID": self.device_id,
            "SupportsClockPortMatchingOverride": True,
        }
        # Return both the port form and the peer-info form; iOS uses whichever it needs.
        return {"eventPort": self._event_port, "timingPort": self._timing_port,
                "timingPeerInfo": peer_info}

    def _start_ntp_client(self, host: str, port: int) -> None:
        """Send NTP client requests to iOS's timing server so the clock channel is live."""
        if self._timing_transport is None:
            return

        async def _query():
            import struct
            import time as _t
            while True:
                try:
                    # Minimal NTPv4 client packet (LI=0,VN=4,Mode=3); transmit ts filled.
                    pkt = bytearray(48)
                    pkt[0] = 0x23
                    tx = _t.time() + 2208988800.0  # unix -> NTP epoch
                    secs = int(tx)
                    frac = int((tx - secs) * (1 << 32))
                    struct.pack_into(">II", pkt, 40, secs, frac)
                    self._timing_transport.sendto(bytes(pkt), (host, port))
                except Exception:
                    return
                await asyncio.sleep(2.0)

        if self._ntp_task is None or self._ntp_task.done():
            self._ntp_task = asyncio.get_event_loop().create_task(_query())
            log.warning("NTP timing client -> %s:%d", host, port)

    def _on_screen_stream(self, stream: dict, ekey: bytes | None, eiv: bytes | None) -> dict:
        """Open a data server for a legacy screen stream (type 110); return its dataPort.
        Decrypt the ekey via the emulator, derive the per-stream AES-CTR key/iv, and build
        the ScreenStream that turns the data port into VideoAccessUnits. Socket opened
        synchronously so the port is known for the reply."""
        import socket
        sock = socket.create_server((self.bind, 0))
        port = sock.getsockname()[1]
        sock.listen(1)
        sock.setblocking(False)
        self._screen_ekey, self._screen_eiv = ekey, eiv
        self._screen = None
        scid = int(stream.get("streamConnectionID", 0))
        if (self._fp_emu is not None and ekey and self._fp_last_phase1 and self._fp_last_phase2):
            try:
                from .screen import ScreenStream, derive_stream_keys
                secret = self._fp_emu.decrypt_ekey(self._fp_last_phase1, self._fp_last_phase2, ekey)
                if len(secret) == 16:
                    key, iv = derive_stream_keys(secret, scid)
                    self._screen = ScreenStream(key, iv, self._deliver_video,
                                                width=self._disp_w, height=self._disp_h)
                    log.warning("screen: decrypt ready (scid=%d, key=%s…)", scid, key.hex()[:12])
                    self._write_fp_vector(ekey, eiv, secret, scid)
                else:
                    log.error("screen: ekey decrypt failed (got %d bytes)", len(secret))
            except Exception:
                log.exception("screen: failed to set up decrypt")

        async def _serve():
            srv = await asyncio.start_server(self._handle_screen_data, sock=sock)
            self._screen_server = srv
            async with srv:
                await srv.serve_forever()

        self._screen_task = asyncio.get_event_loop().create_task(_serve())
        log.warning("screen data port %d (ekey=%dB eiv=%dB)", port,
                    len(ekey) if ekey else 0, len(eiv) if eiv else 0)
        try:
            self.on_session(SessionInfo(device_name=self._client_name, model=self._client_model,
                                        width=self._disp_w, height=self._disp_h))
        except Exception:
            log.exception("on_session callback failed")
        return {"dataPort": port, "streamID": 1}

    def _deliver_video(self, au: VideoAccessUnit) -> None:
        if self._screen is not None and self._screen.frames <= 3:
            log.warning("screen: video AU #%d keyframe=%s %dB %dx%d",
                        self._screen.frames, au.keyframe, len(au.data), au.width, au.height)
        try:
            self.on_video(au)
        except Exception:
            log.exception("on_video callback failed")

    async def _handle_screen_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        log.warning("screen data connected from %s", peer)
        total = 0
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                total += len(data)
                if self.capture_path:
                    with open(self.capture_path, "ab") as f:
                        f.write(data)
                if self._screen is not None:
                    self._screen.feed(data)
        except Exception:
            log.exception("screen data error")
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            n = self._screen.frames if self._screen is not None else 0
            log.warning("screen data from %s closed (%d bytes, %d video AUs)", peer, total, n)
            self._screen = None
            try:
                self.on_end(EndReason.CLIENT_STOPPED)
            except Exception:
                log.exception("on_end callback failed")

    async def _handle_event(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Accept the mirroring event channel; log what iOS sends (control plists)."""
        peer = writer.get_extra_info("peername")
        log.warning("event channel connected from %s", peer)
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                log.info("event: %d bytes %s", len(data), data[:48].hex())
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            log.info("event channel from %s closed", peer)

    async def _open_timing_udp(self):
        """Open a UDP socket for NTP timing; log requests. Returns (transport, port)."""
        class _Timing(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                log.info("timing: %d bytes from %s %s", len(data), addr, data[:32].hex())
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            _Timing, local_addr=(self.bind, 0))
        port = transport.get_extra_info("sockname")[1]
        return transport, port

    async def _handle_control(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        local = writer.get_extra_info("sockname")
        if peer:
            self._peer_host = peer[0]
        if local:
            self._local_host = local[0]
        # Cycle candidate transient passwords across iOS's retry connections so we can
        # discover which one iOS uses (logged on success).
        log.info("control connection from %s", peer)
        session = ControlSession(
            self.identity, self.device_id, info_provider=self.info_plist,
            on_setup=self._on_setup, pin=self.pin,
            credentials=self.credentials, on_pair=self._on_pair,
            on_pin_requested=lambda: log.warning("*** ENTER THIS PIN ON THE iPHONE: %s ***", self.pin.decode()),
            fp_capture=self._fp_capture if self.legacy else None,
            setup_capture_path=self.setup_capture_path,
            on_control_setup=self._on_control_setup if self.legacy else None,
            on_screen_stream=self._on_screen_stream if self.legacy else None,
            mfi=self.mfi,
        )
        parser = MessageParser()
        secure: SecureChannel | None = None
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    log.info("%s closed by peer (secure=%s)", peer, secure is not None)
                    break
                if secure is not None:
                    # Post-pairing: log raw bytes to see what iOS sends (encrypted? plaintext? FIN?).
                    log.info("post-encrypt read: %d bytes, head=%s", len(data), data[:32].hex())
                # Once paired, the stream is encrypted; decrypt into plaintext messages.
                try:
                    chunks = [data] if secure is None else secure.feed(data)
                except Exception as e:
                    log.warning("secure.feed failed (%s); raw head=%s", e, data[:48].hex())
                    chunks = []
                for chunk in chunks:
                    for req in parser.feed(chunk):
                        log.info(
                            "<- %s %s %s (ct=%s len=%d)",
                            req.method, req.uri, req.protocol, req.content_type, len(req.body),
                        )
                        try:
                            resp = session.handle(req)
                        except Exception:
                            log.exception("handler error for %s %s", req.method, req.uri)
                            resp = Response(500, "Internal Server Error")
                        # The response to the message that armed encryption is still sent
                        # in plaintext; only subsequent messages use the new channel.
                        await self._write(writer, resp, req, secure)
                        log.info("-> %s %s (len=%d)%s", resp.status, resp.reason, len(resp.body),
                                 " [encrypting next]" if secure is None and session.secure else "")
                        if secure is None and session.secure is not None:
                            secure = session.secure
        except (ConnectionError, asyncio.IncompleteReadError):
            log.info("%s connection reset", peer)
        except Exception:
            log.exception("control connection error (%s)", peer)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            self.on_end(EndReason.CLIENT_STOPPED)

    async def _write(
        self, writer: asyncio.StreamWriter, resp: Response, req: Request, secure: SecureChannel | None
    ) -> None:
        # Echo the request's protocol (HTTP/1.1 for /info and pairing, RTSP/1.0 for
        # the mirroring flow) so iOS's HTTP client keeps the connection alive.
        resp.protocol = req.protocol
        raw = resp.encode(cseq=req.cseq)
        if secure is not None:
            raw = secure.encrypt(raw)
        writer.write(raw)
        await writer.drain()

    def _on_setup(self, mirror_key: bytes, stream_connection_id: int) -> int:
        """Called by the session on screen SETUP; start the mirror data port, return it."""
        self._mirror = MirrorServer(
            mirror_key,
            on_video=self.on_video,
            on_session=self.on_session,
            bind=self.bind,
            capture_path=self.capture_path,
        )
        return self._mirror.start()


def _main() -> None:
    import argparse

    parser = argparse.ArgumentParser("pylibairplay", description="AirPlay screen-mirroring receiver (test harness)")
    parser.add_argument("--name", default="pylibairplay", help="AirPlay name shown on the phone")
    parser.add_argument("--port", type=int, default=7000, help="control port")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--capture", help="dump raw mirror data-port bytes to this file (for protocol analysis)")
    parser.add_argument("--pin", default="3939", help="pairing PIN to enter on the iPhone (first time)")
    parser.add_argument("--mfi-cert", help="MFi certificate (PEM/DER) for the AirPlay 2 path; needs --mfi-key")
    parser.add_argument("--mfi-key", help="private key (PEM) matching --mfi-cert")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    if bool(args.mfi_cert) != bool(args.mfi_key):
        parser.error("--mfi-cert and --mfi-key must be given together")
    mfi = MFiCredentials.from_pem_files(args.mfi_cert, args.mfi_key) if args.mfi_cert else None

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(name)s %(message)s")
    rx = Receiver(name=args.name, port=args.port, bind=args.bind, capture_path=args.capture, pin=args.pin, mfi=mfi)

    frames = 0

    def on_video(au: VideoAccessUnit) -> None:
        nonlocal frames
        frames += 1
        if frames <= 5 or frames % 30 == 0:
            log.info("video au #%d: %d bytes codec=%s", frames, len(au.data), au.codec)

    rx.on_video = on_video
    rx.on_session = lambda info: log.info("session: %s", info)
    log.info("Starting. On the phone: Control Centre > Screen Mirroring > '%s'", args.name)
    if not rx.credentials:
        log.warning("*** First time: when the iPhone asks for a code, enter PIN: %s ***", rx.pin.decode())
    else:
        log.info("Already paired with %d device(s); no PIN needed.", len(rx.credentials))
    try:
        asyncio.run(rx.serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    _main()
