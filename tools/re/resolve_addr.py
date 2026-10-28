"""Resolve what lives at given addresses in a cached Ghidra program: the string/
symbol a data pointer refers to, and the function at a code address.

Usage::

    python tools/re/resolve_addr.py <dylib> <proj_loc> <proj_name> <addr>...
"""
from __future__ import annotations

import sys
import pyghidra

pyghidra.start()


def main() -> None:
    dylib, proj_loc, proj_name, *addrs = sys.argv[1:]
    with pyghidra.open_program(dylib, project_location=proj_loc, project_name=proj_name, analyze=False) as flat:
        program = flat.getCurrentProgram()
        af = program.getAddressFactory()
        listing = program.getListing()
        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        mem = program.getMemory()

        def at(a_str: str):
            a = af.getAddress(a_str)
            print(f"\n== {a_str} ==")
            sym = st.getPrimarySymbol(a)
            print("symbol:", sym.getName() if sym else None)
            fn = fm.getFunctionContaining(a)
            print("function:", fn.getName() if fn else None)
            data = listing.getDataAt(a)
            if data is not None:
                print("data:", data.getDataType(), "=", data.getValue())
            # Try to read a pointer and the string it points to
            try:
                ptr = mem.getLong(a)
                pa = af.getAddress(hex(ptr & 0xFFFFFFFFFFFF))
                sdata = listing.getDataAt(pa)
                if sdata is not None and sdata.hasStringValue():
                    print("  ->points to string:", repr(str(sdata.getValue())))
                else:
                    # maybe a CFString: deref +0x10 for the char*
                    print("  ptr:", hex(ptr), "-> data:", sdata.getDataType() if sdata else None)
            except Exception as e:
                print("  (no ptr)", e)

        for a in addrs:
            at(a)


if __name__ == "__main__":
    main()
