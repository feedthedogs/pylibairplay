"""Query a cached Ghidra project: list functions, decompile them, or find strings.

Usage::

    python tools/re/ghidra_query.py <dylib> <project_location> <project_name> <out_dir> \
        <cmd> <regex>...

Commands:
  funcs   <regex>...   print functions whose names match
  decomp  <regex>...   decompile matching functions to <out_dir>/<name>.c
  strings <regex>...   print defined strings that match, with referencing functions;
                       also decompiles each referencing function to <out_dir>

The program must already be analyzed in the project (first run of
dump_strings_xrefs.py does that); this opens it with analyze=False.
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
    dylib, proj_loc, proj_name, out_dir, cmd, *patterns = sys.argv[1:]
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    regexes = [re.compile(p) for p in patterns]

    with pyghidra.open_program(dylib, project_location=proj_loc, project_name=proj_name, analyze=False) as flat:
        program = flat.getCurrentProgram()
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        fm = program.getFunctionManager()
        decomp = DecompInterface()
        decomp.openProgram(program)

        def dump(fn) -> None:
            res = decomp.decompileFunction(fn, 120, monitor)
            if res.decompileCompleted():
                path = out / f"{slug(str(fn.getName()))}.c"
                path.write_text(res.getDecompiledFunction().getC(), encoding="utf-8")
                print("  wrote", path.name)

        if cmd in ("funcs", "decomp"):
            for fn in fm.getFunctions(True):
                name = str(fn.getName())
                if any(r.search(name) for r in regexes):
                    print(fn.getEntryPoint(), name)
                    if cmd == "decomp":
                        dump(fn)
        elif cmd == "strings":
            listing = program.getListing()
            refman = program.getReferenceManager()
            seen = set()
            for data in listing.getDefinedData(True):
                if not data.hasStringValue():
                    continue
                val = str(data.getValue())
                if not any(r.search(val) for r in regexes):
                    continue
                users = set()
                for ref in refman.getReferencesTo(data.getAddress()):
                    fn = fm.getFunctionContaining(ref.getFromAddress())
                    if fn is not None:
                        users.add(fn)
                    else:
                        # CFString objects: follow one more hop
                        for ref2 in refman.getReferencesTo(ref.getFromAddress()):
                            fn2 = fm.getFunctionContaining(ref2.getFromAddress())
                            if fn2 is not None:
                                users.add(fn2)
                print(repr(val), "->", sorted(str(f.getName()) for f in users))
                for fn in users:
                    if fn.getEntryPoint() not in seen:
                        seen.add(fn.getEntryPoint())
                        dump(fn)
        elif cmd == "fnat":
            # Decompile the function(s) CONTAINING each given address (hex).
            af = program.getAddressFactory()
            for pat in patterns:
                a = af.getAddress(pat if pat.startswith("0x") else "0x" + pat)
                fn = fm.getFunctionContaining(a)
                print(pat, "->", fn.getName() if fn else None,
                      fn.getEntryPoint() if fn else None)
                if fn is not None:
                    dump(fn)
        elif cmd == "callers":
            # Find functions that call the given address(es) (hex). Decompile each caller.
            refman = program.getReferenceManager()
            af = program.getAddressFactory()
            seen = set()
            for pat in patterns:
                target = af.getAddress(pat if pat.startswith("0x") else "0x" + pat)
                callers = set()
                for ref in refman.getReferencesTo(target):
                    fn = fm.getFunctionContaining(ref.getFromAddress())
                    if fn is not None:
                        callers.add(fn)
                print(pat, "called by ->", sorted(f"{f.getEntryPoint()} {f.getName()}" for f in callers))
                for fn in callers:
                    if fn.getEntryPoint() not in seen:
                        seen.add(fn.getEntryPoint())
                        dump(fn)
        else:
            raise SystemExit(f"unknown command {cmd}")


if __name__ == "__main__":
    main()
