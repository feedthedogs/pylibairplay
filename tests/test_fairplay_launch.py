import subprocess
import sys

from pylibairplay.fairplay import FairPlayEmulator


def test_emulator_runs_isolated_so_package_modules_cannot_shadow_the_stdlib(tmp_path, monkeypatch) -> None:
    (tmp_path / "AirPlayReceiver").write_bytes(b"")
    seen: list[list[str]] = []

    class Boom(Exception):
        pass

    def fake_popen(cmd, **kw):
        seen.append(cmd)
        raise Boom

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    emu = FairPlayEmulator(str(tmp_path), python_exe=sys.executable)
    try:
        emu.start()
    except Boom:
        pass
    assert seen and seen[0][1] == "-I"
    assert seen[0][2].endswith("fp_emu.py")
