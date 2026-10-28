"""Decompile named symbols from a large dylib WITHOUT full auto-analysis.

Full Ghidra analysis of AirPlaySender (67 MB) takes hours. This imports the binary
once into a project (no analysis), then for each requested symbol disassembles from
its entry, creates a function and decompiles it. Callees show up by symbol name when
the extracted dylib keeps its symbol table.

Usage::

    python tools/re/decomp_symbols.py <dylib> <project_location> <project_name> <out_dir> <regex>...

Matching is against symbol names (leading underscore included).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pyghidra

pyghidra.start()


def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_")[:100]


def main() -> None:
    dylib, proj_loc, proj_name, out_dir, *patterns = sys.argv[1:]
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    regexes = [re.compile(p) for p in patterns]

    with pyghidra.open_program(dylib, project_location=proj_loc, project_name=proj_name, analyze=False) as flat:
        program = flat.getCurrentProgram()
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.app.cmd.function import CreateFunctionCmd
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.symbol import SymbolType
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        decomp = DecompInterface()
        decomp.openProgram(program)

        targets = []
        for sym in st.getAllSymbols(True):
            name = str(sym.getName())
            if ".cold." in name:
                continue
            if any(r.search(name) for r in regexes):
                targets.append(sym)
        print("matched", len(targets))

        tx = program.startTransaction("decomp_symbols")
        try:
            for sym in targets:
                addr = sym.getAddress()
                if not addr.isMemoryAddress():
                    continue
                fn = fm.getFunctionAt(addr)
                if fn is None:
                    DisassembleCommand(addr, None, True).applyTo(program, monitor)
                    CreateFunctionCmd(addr).applyTo(program, monitor)
                    fn = fm.getFunctionAt(addr)
                if fn is None:
                    print("  could not create", sym.getName())
                    continue
                res = decomp.decompileFunction(fn, 180, monitor)
                if res.decompileCompleted():
                    path = out / f"{slug(str(sym.getName()))}.c"
                    path.write_text(res.getDecompiledFunction().getC(), encoding="utf-8")
                    print(addr, sym.getName(), "->", path.name)
                else:
                    print("  decompile failed", sym.getName(), res.getErrorMessage())
        finally:
            program.endTransaction(tx, True)


if __name__ == "__main__":
    main()
