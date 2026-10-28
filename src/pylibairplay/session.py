"""Per-connection control session: routes control messages, owns pairing state.

This wires discovery → pairing → encrypted control channel. Stream SETUP (type 110)
and the mirror data port are M4 and are stubbed here with clear TODOs. The routing
mirrors AirPlayReceiver ``airplayReqProcessor_HandleRequest``.
"""

from __future__ import annotations

import logging
import plistlib
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import keys
from .mfi import MFiCredentials
from .pairing import tlv8
from .pairing.setup import PairingError, PairSetupServer, PairVerifyServer
from .pairing.tlv8 import Tag
from .rtsp.secure import SecureChannel
from .rtsp.server import Request, Response

log = logging.getLogger("pylibairplay")

STREAM_TYPE_SCREEN = 110  # 0x6e, confirmed in _ScreenSetup


class ControlSession:
    """Drives one control connection. Transport-agnostic: feed it requests, get
    responses and optional outbound raw bytes (for the encrypted-channel flip)."""

    def __init__(
        self,
        identity: Ed25519PrivateKey,
        device_id: str,
        info_provider: Callable[[], dict],
        on_setup: Callable[[bytes, int], int] | None = None,
        pin: bytes = b"3939",
        credentials: dict[bytes, bytes] | None = None,
        on_pair: Callable[[bytes, bytes], None] | None = None,
        on_pin_requested: Callable[[], None] | None = None,
        fp_capture: Callable[[str, dict, bytes], bytes] | None = None,
        setup_capture_path: str | None = None,
        on_control_setup: Callable[[dict], dict] | None = None,
        on_screen_stream: Callable[[dict, bytes | None, bytes | None], dict] | None = None,
        mfi: MFiCredentials | None = None,
    ) -> None:
        self.identity = identity
        self.device_id = device_id
        self.info_provider = info_provider
        # on_setup(mirror_key, stream_connection_id) -> data_port
        self.on_setup = on_setup
        self.pin = pin
        # Shared, persistent store of paired controllers: {controller_id: ed25519_ltpk}.
        self.credentials = credentials if credentials is not None else {}
        self.on_pair = on_pair  # called with (controller_id, ltpk) to persist a new pairing
        self.on_pin_requested = on_pin_requested  # called on /pair-pin-start to show the PIN
        # fp_capture(uri, headers, body) -> response bytes. Legacy FairPlay (/fp-setup)
        # capture mode: records iOS's request and returns a response (empty until the
        # whitebox emulator is wired).
        self.fp_capture = fp_capture
        self.setup_capture_path = setup_capture_path
        # on_control_setup(request_plist) -> {"eventPort":…, "timingPort":…}: opens the
        # event/timing servers for a legacy mirroring control SETUP (no streams array).
        self.on_control_setup = on_control_setup
        # on_screen_stream(stream, ekey, eiv) -> {"dataPort":…, "streamID":…}: opens the
        # legacy screen data server (raw capture + AES decrypt when the key is available).
        self.on_screen_stream = on_screen_stream
        self.fp_ekey: bytes | None = None   # FairPlay-wrapped stream key from SETUP
        self.fp_eiv: bytes | None = None    # AES IV from SETUP
        self.pairing_secret: bytes | None = None
        self.secure: SecureChannel | None = None
        self._setup = PairSetupServer(pin=pin, identity=identity, device_id=device_id.encode(), mfi=mfi)
        self._verify: PairVerifyServer | None = None

    def handle(self, req: Request) -> Response:
        method = req.method.upper()
        uri = req.uri.split("?")[0]
        if method == "GET_PARAMETER":
            # text/parameters query (e.g. "volume\r\n") -> text reply, not the info plist.
            body = (req.body or b"").decode("latin1")
            if "volume" in body:
                return Response(200, "OK", {"Content-Type": "text/parameters"},
                                b"volume: 0.000000\r\n")
            return Response(200, "OK", {"Content-Type": "text/parameters"}, b"")
        if uri == "/info":
            return self._info()
        if uri == "/pair-pin-start":
            return self._pair_pin_start(req)
        if uri == "/pair-setup":
            return self._pair_setup(req)
        if uri == "/pair-verify":
            return self._pair_verify(req)
        if uri in ("/fp-setup", "/fp-setup2"):
            return self._fp_setup(req, uri)
        if method == "SETUP":
            return self._setup_streams(req)
        if method in {"RECORD", "SET_PARAMETER", "TEARDOWN", "FLUSH", "OPTIONS"} or uri == "/feedback":
            if req.body and (req.headers.get("Content-Type", "").endswith("plist")
                             or req.body[:1] == b"b"):
                try:
                    self._log_plist(method, plistlib.loads(req.body))
                except Exception:
                    log.warning("%s body (%d bytes): %s", method, len(req.body), req.body[:64].hex())
            elif req.body:
                log.warning("%s body (%d bytes): %s", method, len(req.body), req.body[:64].hex())
            return Response(200, "OK")
        return Response(501, "Not Implemented")

    def _fp_setup(self, req: Request, uri: str) -> Response:
        """Legacy FairPlay (/fp-setup[2]) request. Log + capture iOS's exact bytes;
        return the response from ``fp_capture`` (empty until the whitebox emulator is
        wired, so iOS likely won't proceed past phase 1 — but we capture the request,
        which is what feeds the emulator)."""
        et = req.headers.get("x-apple-et", "?")
        body = req.body or b""
        log.warning("FP-SETUP %s: X-Apple-ET=%s len=%d body=%s%s",
                    uri, et, len(body), body[:64].hex(), "…" if len(body) > 64 else "")
        resp = b""
        if self.fp_capture is not None:
            try:
                resp = self.fp_capture(uri, dict(req.headers), body) or b""
            except Exception:
                log.exception("fp_capture handler failed")
        return Response(200, "OK", {"Content-Type": "application/octet-stream"}, resp)

    def _pair_pin_start(self, req: Request) -> Response:
        """iOS asks the receiver to display its PIN before PIN pair-setup."""
        log.info("pair-pin-start: iOS wants PIN pairing")
        if self.on_pin_requested:
            self.on_pin_requested()
        return Response(200, "OK")

    # ---- handlers ----------------------------------------------------------
    def _info(self) -> Response:
        body = plistlib.dumps(self.info_provider(), fmt=plistlib.FMT_BINARY)
        return Response(200, "OK", {"Content-Type": "application/x-apple-binary-plist"}, body)

    def _pair_setup(self, req: Request) -> Response:
        decoded = tlv8.decode(req.body)
        state = decoded.get(Tag.STATE, b"?")
        # Full TLV inventory per message — the decisive datum for the post-M4 blocker
        # is iOS's exact Method (type 0) and Flags (0x13) in M1.
        tlv_types = ",".join(f"0x{t:02x}({len(v)})" for t, v in tlv8.decode_ordered(req.body))
        if state == b"\x01":
            hkp = req.headers.get("x-apple-hkp", "?")
            flags = decoded.get(Tag.FLAGS, b"")
            method = decoded.get(Tag.METHOD, b"")
            log.info(
                "pair-setup M1: X-Apple-HKP=%s method=%s flags=%s (transient=%s) tlvs=[%s]",
                hkp, method.hex() or "none", flags.hex() or "none",
                bool(int.from_bytes(flags or b"\0", "little") & 0x10), tlv_types,
            )
        log.info("pair-setup request state M%s tlvs=[%s]",
                 state[0] if state != b"?" else "?", tlv_types)
        try:
            resp = self._setup.handle(req.body)
        except PairingError as e:
            log.warning("pair-setup failed (pin=%r): %s", self._setup.pin, e)
            self._dump_srp_debug()
            return self._tlv_error(e)
        # PIN pairing: persist the controller's identity so later pair-verify works.
        if self._setup.controller_id and self._setup.controller_ltpk:
            self.credentials[self._setup.controller_id] = self._setup.controller_ltpk
            if self.on_pair:
                self.on_pair(self._setup.controller_id, self._setup.controller_ltpk)
            log.warning("*** PIN PAIRING COMPLETE *** controller %s stored; reconnect will pair-verify",
                        self._setup.controller_id.decode("latin1")[:20])
        # Transient pairing: SRP key is the session secret, arm encryption now.
        elif self._setup.pairing_secret is not None:
            self.pairing_secret = self._setup.pairing_secret
            self._enable_control_encryption()
            log.warning("*** TRANSIENT PAIR-SETUP COMPLETE *** control channel encrypted next")
        return self._tlv_response(resp)

    def _setup_streams(self, req: Request) -> Response:
        """Handle a SETUP plist. For a screen stream (type 110), derive the mirror
        key from streamConnectionID and open the data port."""
        try:
            request = plistlib.loads(req.body) if req.body else {}
        except Exception:
            return Response(400, "Bad Request")
        self._log_plist("SETUP", request)
        if self.setup_capture_path:
            try:
                with open(self.setup_capture_path, "a", encoding="utf-8") as f:
                    f.write(req.body.hex() + "\n")
            except Exception:
                log.exception("failed to write SETUP capture")
        # Stash the FairPlay-encrypted stream key material for later ekey->AES decrypt.
        if request.get("ekey"):
            self.fp_ekey = bytes(request["ekey"])
        if request.get("eiv"):
            self.fp_eiv = bytes(request["eiv"])
        streams = request.get("streams")
        if not streams:
            # Combined control SETUP (no streams array) — legacy screen mirroring. iOS
            # needs real event/timing ports here or it tears down. Open them via the
            # callback and reply with the receiver's ports.
            ports = {"eventPort": 0, "timingPort": 0}
            if self.on_control_setup is not None:
                try:
                    ports.update(self.on_control_setup(request) or {})
                except Exception:
                    log.exception("on_control_setup failed")
            log.warning("control SETUP (mirroring=%s) -> %s",
                        request.get("isScreenMirroringSession"), ports)
            return self._plist_response(ports)
        out_streams = []
        for stream in streams:
            if stream.get("type") == STREAM_TYPE_SCREEN:
                scid = int(stream.get("streamConnectionID", 0))
                data_port = 0
                if self.pairing_secret is not None and self.on_setup is not None:
                    # AP2 pairing path: mirror key from the pairing secret.
                    key = keys.mirror_stream_key(self.pairing_secret, scid)
                    data_port = self.on_setup(key, scid)
                    out_streams.append({"type": STREAM_TYPE_SCREEN, "dataPort": data_port})
                elif self.on_screen_stream is not None:
                    # Legacy FairPlay path: open a data server; key comes from ekey/eiv.
                    out = self.on_screen_stream(stream, self.fp_ekey, self.fp_eiv) or {}
                    out.setdefault("type", STREAM_TYPE_SCREEN)
                    out_streams.append(out)
                    data_port = out.get("dataPort", 0)
                else:
                    out_streams.append({"type": STREAM_TYPE_SCREEN, "dataPort": 0})
                log.warning("screen stream setup: streamConnectionID=%s dataPort=%s", scid, data_port)
            else:
                out_streams.append({"type": stream.get("type"), "dataPort": 0})
        return self._plist_response({"streams": out_streams})

    @staticmethod
    def _summ(v, depth=0):
        """Summarize a plist value: dicts/lists recursed; bytes shown as len+hex
        (full for small, head for large) so ekey/eiv/stream fields are visible in logs."""
        if isinstance(v, dict):
            return {k: ControlSession._summ(val, depth + 1) for k, val in v.items()}
        if isinstance(v, (list, tuple)):
            return [ControlSession._summ(x, depth + 1) for x in v]
        if isinstance(v, (bytes, bytearray)):
            h = bytes(v).hex()
            return f"<{len(v)}B {h if len(v) <= 64 else h[:128] + '…'}>"
        return v

    def _log_plist(self, tag: str, obj) -> None:
        try:
            log.warning("%s plist: %s", tag, self._summ(obj))
        except Exception:
            log.exception("failed to summarize %s plist", tag)

    def _dump_srp_debug(self) -> None:
        """Append full SRP values from a failed attempt to srp_debug.jsonl for
        offline analysis of iOS's exact SRP convention (debug only)."""
        s = self._setup._srp
        if s is None or not self._setup.last_A or not self._setup.last_proof:
            return
        import json

        rec = {
            "pin": self._setup.pin.decode("latin1"),
            "username": "Pair-Setup",
            "salt": s.salt.hex(),
            "b": format(s._b, "x"),
            "B": s.B.to_bytes(384, "big").hex(),
            "A": self._setup.last_A.hex(),
            "proof": self._setup.last_proof.hex(),
        }
        try:
            with open("srp_debug.jsonl", "a") as f:
                f.write(json.dumps(rec) + "\n")
            log.info("wrote SRP debug record (pin=%r) to srp_debug.jsonl", self._setup.pin)
        except Exception:
            log.exception("failed to write srp_debug")

    def _plist_response(self, obj: dict) -> Response:
        body = plistlib.dumps(obj, fmt=plistlib.FMT_BINARY)
        return Response(200, "OK", {"Content-Type": "application/x-apple-binary-plist"}, body)

    def _pair_verify(self, req: Request) -> Response:
        state = tlv8.decode(req.body).get(Tag.STATE, b"?")
        state_n = state[0] if state != b"?" else "?"
        if state_n == 1:
            log.info("pair-verify M1: X-Apple-HKP=%s", req.headers.get("x-apple-hkp", "?"))
        log.info("pair-verify request state M%s", state_n)
        # A fresh M1 starts a new verify exchange (iOS may retry on the same socket).
        # Resolve the controller's stored LTPK from our persistent pairings.
        if state_n == 1 or self._verify is None:
            self._verify = PairVerifyServer(
                identity=self.identity,
                device_id=self.device_id.encode(),
                peer_resolver=lambda cid: self.credentials.get(cid),
            )
        try:
            resp = self._verify.handle(req.body)
        except PairingError as e:
            log.warning("pair-verify failed: %s", e)
            return self._tlv_error(e)
        # Arm encryption only after a *completed* verify (M4), never after M2.
        if self._verify.completed and self._verify.shared_secret is not None:
            self.pairing_secret = self._verify.shared_secret
            self._enable_control_encryption()
            log.info("pair-verify complete; control channel encrypted next")
        return self._tlv_response(resp)

    # ---- helpers -----------------------------------------------------------
    def _enable_control_encryption(self) -> None:
        """Arm the encrypted control channel using Control-Salt keys (spec 20).

        The HKDF labels are controller-oriented: "Control-Read"/"Control-Write" name
        the *controller's* read/write keys. As the receiver we are the other end, so
        we decrypt the controller's writes with the "Control-Write" key and encrypt
        our responses with the "Control-Read" key. Confirmed against the
        cidermill-airplay EncryptedTransport oracle (sealed request decrypts cleanly).
        """
        assert self.pairing_secret is not None
        ctrl_read, ctrl_write = keys.control_channel_keys(self.pairing_secret)
        self.secure = SecureChannel(read_key=ctrl_write, write_key=ctrl_read)

    @staticmethod
    def _tlv_response(body: bytes) -> Response:
        return Response(200, "OK", {"Content-Type": "application/octet-stream"}, body)

    @staticmethod
    def _tlv_error(err: PairingError) -> Response:
        body = tlv8.encode({Tag.STATE: b"\x02", Tag.ERROR: bytes((err.tlv_error & 0xFF,))})
        return Response(200, "OK", {"Content-Type": "application/octet-stream"}, body)
