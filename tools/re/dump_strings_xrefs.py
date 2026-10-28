"""PyGhidra script: for each protocol string of interest, find the functions that
reference it, and emit their decompilation to a per-function .c file.

We read Apple's own receiver/sender code only to *describe* the
protocol; we never copy it into the library.

Run (outside the repo, against the user's own firmware)::

    GHIDRA_INSTALL_DIR=... python tools/re/dump_strings_xrefs.py <dylib> <out_dir>

Outputs <out_dir>/<string-slug>/<function>.c plus an index.json.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pyghidra

pyghidra.start()  # boot the embedded JVM before importing ghidra.*

# Strings that anchor the parts of AirPlay we need to describe.
TARGETS = [
    "DataStream-Salt",
    "DataStream-Output-Encryption-Key",
    "DataStream-Input-Encryption-Key",
    "AirPlayStreamKey",
    "AirPlayStreamIV",
    "Control-Salt",
    "Control-Write-Encryption-Key",
    "Control-Read-Encryption-Key",
    "Pair-Setup-Encrypt-Salt",
    "Pair-Verify-Encrypt-Salt",
    "streamConnectionID",
    "SupportsCoreUtilsPairingAndEncryption",
    "SupportsTransientPairing",
    "APKeyHolderCoreUtilsCreate",
    "APKeyHolderLegacyCreate",
]


def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_")


def main() -> None:
    binary, out_dir = sys.argv[1], Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    index: dict[str, list[dict]] = {}

    # Persist the analyzed program in a project so reruns skip auto-analysis.
    proj_loc = str(Path(sys.argv[3]) if len(sys.argv) > 3 else out_dir.parent / "ghidra_proj")
    with pyghidra.open_program(
        binary, project_location=proj_loc, project_name="airplay", analyze=True
    ) as flat:
        program = flat.getCurrentProgram()
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        decomp = DecompInterface()
        decomp.openProgram(program)
        listing = program.getListing()
        fm = program.getFunctionManager()
        memory = program.getMemory()

        # Map each defined string to its address.
        for target in TARGETS:
            index[target] = []
            hits = find_string_addrs(program, target)
            funcs = set()
            for addr in hits:
                for ref in program.getReferenceManager().getReferencesTo(addr):
                    fn = fm.getFunctionContaining(ref.getFromAddress())
                    if fn is not None:
                        funcs.add(fn)
            tdir = out_dir / slug(target)
            tdir.mkdir(exist_ok=True)
            for fn in sorted(funcs, key=lambda f: f.getEntryPoint().getOffset()):
                res = decomp.decompileFunction(fn, 60, monitor)
                if not res.decompileCompleted():
                    continue
                name = fn.getName()
                (tdir / f"{slug(name)}.c").write_text(res.getDecompiledFunction().getC(), encoding="utf-8")
                index[target].append({"function": name, "entry": str(fn.getEntryPoint())})

    (out_dir / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
    print(json.dumps({k: len(v) for k, v in index.items()}, indent=2))


def find_string_addrs(program, text):
    """Addresses of defined string data whose value contains ``text``."""
    addrs = []
    for data in program.getListing().getDefinedData(True):
        try:
            if not data.hasStringValue():
                continue
            value = data.getValue()
            if value is not None and text in str(value):
                addrs.append(data.getAddress())
        except Exception:
            continue
    return addrs


if __name__ == "__main__":
    main()
