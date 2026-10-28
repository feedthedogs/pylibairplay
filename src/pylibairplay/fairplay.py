"""Client for the local FairPlay whitebox emulator (``pylibairplay/fp_emu.py serve``).

The FairPlay v1 ``/fp-setup`` handshake replies are computed in pure Python
(``fairplay_v1``); this emulator is only needed for the one step with no portable
reimplementation — decrypting the legacy screen SETUP ``ekey`` into its 16-byte stream secret.
It is **machine-local interop tooling**, not a shippable feature: it runs the user's own
extracted firmware (which must be present) via a Python venv that has ``unicorn``/``lief``/
``capstone``. It ships no Apple code.

The emulator runs as a long-lived subprocess: it warms up once (~35s: map the dylibs,
patch PAC, snapshot a clean post-init baseline) and then answers each ``ekey`` request in
~0.3 s. Protocol over stdio: write ``"ekey <phase1_hex> <phase2_hex> <ekey_hex>\n"``, read
one line ``"OK <secret_hex>"`` or ``"ERR <msg>"``.
"""
from __future__ import annotations

import logging
import subprocess
import sys
import threading
from pathlib import Path

log = logging.getLogger("pylibairplay")


class FairPlayEmulator:
    """Manages the ``fp_emu.py serve`` worker subprocess.

    Parameters
    - ``dylib_dir``: directory holding the extracted ``AirPlayReceiver`` + sibling dylibs.
    - ``python_exe``: interpreter with ``unicorn``/``lief``/``capstone`` installed
      (defaults to the current interpreter).
    - ``fp_emu_py``: path to ``fp_emu.py`` (defaults to the copy installed with this package).
    """

    def __init__(self, dylib_dir: str, python_exe: str | None = None,
                 fp_emu_py: str | None = None, warm_timeout: float = 180.0) -> None:
        self.dylib_dir = str(Path(dylib_dir))
        self.python_exe = python_exe or sys.executable
        if fp_emu_py is None:
            fp_emu_py = str(Path(__file__).resolve().with_name("fp_emu.py"))
        self.fp_emu_py = fp_emu_py
        self.warm_timeout = warm_timeout
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Launch the worker and block until it prints READY (warm-up complete)."""
        receiver = str(Path(self.dylib_dir) / "AirPlayReceiver")
        if not Path(receiver).exists():
            raise FileNotFoundError(f"AirPlayReceiver dylib not found at {receiver}")
        log.warning("FairPlay emulator: warming up (%s serve) — this takes ~35s...",
                    self.fp_emu_py)
        self._proc = subprocess.Popen(
            [self.python_exe, self.fp_emu_py, receiver, "serve", "fast"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
        # Wait for READY (skip the mapping/patch chatter on stdout).
        import time
        deadline = time.time() + self.warm_timeout
        while time.time() < deadline:
            line = self._proc.stdout.readline()
            if not line:
                raise RuntimeError("FairPlay emulator exited during warm-up")
            if line.strip() == "READY":
                log.warning("FairPlay emulator ready (ekey decrypt ~0.3s)")
                return
        raise TimeoutError("FairPlay emulator did not become ready in time")

    def decrypt_ekey(self, phase1_req: bytes, phase2_req: bytes, ekey: bytes) -> bytes:
        """Return the 16-byte FairPlay-decrypted stream secret for the SETUP ekey, using
        the session established by this connection's phase1/phase2. Returns b"" on error."""
        if self._proc is None or self._proc.poll() is not None:
            log.error("FairPlay emulator not running")
            return b""
        line = f"ekey {phase1_req.hex()} {phase2_req.hex()} {ekey.hex()}\n"
        with self._lock:
            try:
                self._proc.stdin.write(line)
                self._proc.stdin.flush()
                resp = self._proc.stdout.readline().strip()
            except (BrokenPipeError, OSError) as e:
                log.error("FairPlay emulator write/read failed: %s", e)
                return b""
        if resp.startswith("OK "):
            return bytes.fromhex(resp[3:]) if len(resp) > 3 else b""
        log.error("FairPlay emulator ekey error: %s", resp)
        return b""

    def stop(self) -> None:
        if self._proc is not None:
            with self._lock:
                try:
                    self._proc.terminate()
                except Exception:
                    pass
            self._proc = None
