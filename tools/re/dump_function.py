"""Dump named functions (and their callers) from a cached Ghidra project.

Usage::

    python tools/re/dump_function.py <dylib> <project_location> <project_name> <out_dir> <name-substr>...

Writes <out_dir>/<function>.c for each matching function and each of its callers,
reusing the already-analyzed program in the project (fast; no re-analysis).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pyghidra

pyghidra.start()


def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_")[:80]


def main() -> None:
    dylib, proj_loc, proj_name, out_dir, *needles = sys.argv[1:]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with pyghidra.open_program(dylib, project_location=proj_loc, project_name=proj_name, analyze=False) as flat:
        program = flat.getCurrentProgram()
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        decomp = DecompInterface()
        decomp.openProgram(program)
        fm = program.getFunctionManager()

        def dump(fn, tag=""):
            res = decomp.decompileFunction(fn, 60, monitor)
            if res.decompileCompleted():
                name = slug(fn.getName())
                (out_dir / f"{tag}{name}.c").write_text(res.getDecompiledFunction().getC(), encoding="utf-8")
                return True
            return False

        matches = [fn for fn in fm.getFunctions(True) if any(n in fn.getName() for n in needles)]
        print("matched:", [str(fn.getName()) for fn in matches])
        for fn in matches:
            dump(fn)
            for caller in fn.getCallingFunctions(monitor):
                dump(caller, tag="caller_")


if __name__ == "__main__":
    main()
