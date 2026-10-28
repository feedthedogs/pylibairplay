"""Minimal live test: advertise a receiver and decode the first mirrored frames.

Run, then on the iPhone open Control Centre > Screen Mirroring and pick the name.

    uv run --extra net python examples/dump_frames.py --name "Test Screen" --capture mirror.bin

With PyAV installed (``uv run --with av ...``) it will try to decode and save the
first keyframe to ``frame.jpg``. ``--capture`` always dumps the raw data-port bytes,
which is what we use to finalize the mirror framing.

Legacy FairPlay capture: ``--fp-capture fp.jsonl`` (implies ``--legacy``) advertises
the legacy AirPlay-1 feature set so iOS takes the ``/fp-setup`` screen path, and
records each ``/fp-setup`` request (hex, X-Apple-ET) to the JSONL file. Those bytes
feed the whitebox emulator. We don't yet return a
valid FairPlay response, so iOS may stop after the first request — capturing it is the
goal. Example::

    uv run --extra net python examples/dump_frames.py --name "pyair test" --fp-capture fp.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import logging

from pylibairplay import MFiCredentials, Receiver
from pylibairplay.types import VideoAccessUnit


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="Test Screen")
    ap.add_argument("--port", type=int, default=7000)
    ap.add_argument("--capture", help="dump raw mirror bytes here")
    ap.add_argument("--pin", default="3939")
    ap.add_argument("--legacy", action="store_true",
                    help="advertise the legacy AirPlay-1 feature set to steer iOS to the legacy "
                         "FairPlay /fp-setup path")
    ap.add_argument("--fp-capture", help="JSONL file to record iOS's /fp-setup requests "
                                         "(implies --legacy)")
    ap.add_argument("--fp-emu-dir", help="directory with extracted AirPlayReceiver + sibling "
                                         "dylibs; enables LIVE FairPlay phase-2 via the firmware "
                                         "whitebox emulator (implies --legacy; machine-local)")
    ap.add_argument("--fp-emu-python", help="interpreter with unicorn/lief/capstone for the "
                                            "emulator subprocess (default: current python)")
    ap.add_argument("--mfi-cert", help="your MFi certificate (PEM/DER): use the AirPlay 2 path "
                                       "instead of FairPlay emulation (needs --mfi-key)")
    ap.add_argument("--mfi-key", help="private key (PEM) for --mfi-cert")
    ap.add_argument("--setup-capture", help="dump raw SETUP plist bodies (hex) here for "
                                            "offline analysis of the mirror stream / ekey")
    ap.add_argument("--fp-vectors", help="append one JSON FairPlay test vector per mirror "
                                         "session here (p1/p2/p2_reply/ekey/eiv/secret/scid; "
                                         "needs --fp-emu-dir)")
    ap.add_argument("--save-frame", help="decode (PyAV) and save the latest video frame to "
                                         "this path (overwritten), e.g. frame.png")
    ap.add_argument("--save-interval", type=float, default=1.0,
                    help="min seconds between saved frames (default 1.0)")
    ap.add_argument("--save-h264", help="append the decoded Annex-B H.264 elementary stream here")
    args = ap.parse_args()
    if bool(args.mfi_cert) != bool(args.mfi_key):
        ap.error("--mfi-cert and --mfi-key must be given together")
    if args.fp_capture or args.fp_emu_dir:
        args.legacy = True
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    mfi = MFiCredentials.from_pem_files(args.mfi_cert, args.mfi_key) if args.mfi_cert else None
    rx = Receiver(name=args.name, port=args.port, capture_path=args.capture, pin=args.pin,
                  legacy=args.legacy, fp_capture_path=args.fp_capture,
                  fp_emu_dir=args.fp_emu_dir, fp_emu_python=args.fp_emu_python,
                  setup_capture_path=args.setup_capture, fp_vectors_path=args.fp_vectors, mfi=mfi)
    import time as _time
    seen = {"n": 0, "saved": 0, "last_save": 0.0}

    dec = None
    try:
        import av
        dec = av.CodecContext.create("h264", "r")
    except Exception:
        dec = None

    def on_video(au: VideoAccessUnit) -> None:
        seen["n"] += 1
        if seen["n"] <= 3 or seen["n"] % 120 == 0:
            logging.info("access unit %d: %d bytes, keyframe=%s %dx%d",
                         seen["n"], len(au.data), au.keyframe, au.width, au.height)
        # Raw Annex-B elementary stream (reliable fallback for offline decoding).
        if args.save_h264:
            with open(args.save_h264, "ab") as f:
                f.write(au.data)
        # Decode every AU (inter-frame prediction); save the LATEST frame at most every
        # save_interval seconds (overwrites the same path) so the PNG tracks the screen.
        if dec is not None and args.save_frame:
            try:
                for frame in dec.decode(av.Packet(au.data)):
                    now = _time.monotonic()
                    if now - seen["last_save"] >= args.save_interval:
                        import numpy as _np  # noqa: F401
                        from PIL import Image
                        Image.fromarray(frame.to_ndarray(format="rgb24")).save(args.save_frame)
                        seen["last_save"] = now
                        seen["saved"] += 1
                        if seen["saved"] <= 2 or seen["saved"] % 10 == 0:
                            logging.info("*** saved frame %d -> %s (%dx%d) ***",
                                         seen["saved"], args.save_frame, frame.width, frame.height)
            except Exception as e:
                if seen["n"] % 120 == 0:
                    logging.warning("decode/save failed: %r", e)

    rx.on_video = on_video
    rx.on_session = lambda info: logging.info("connected: %s", info)
    logging.info("Advertising %r. Mirror to it; if asked for a code, enter PIN: %s", args.name, args.pin)
    if dec is None:
        logging.info("(install PyAV for decoding: uv run --with av ...)")
    try:
        asyncio.run(rx.serve())
    except KeyboardInterrupt:
        logging.info("stopped after %d access units", seen["n"])


if __name__ == "__main__":
    main()
