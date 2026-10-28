"""FairPlay whitebox emulation worker (SETUP ``ekey`` decrypt).

Loads the user's own ``AirPlayReceiver`` dylib (extracted from their firmware) plus the
siblings it calls into a Unicorn ARM64 emulator and drives Apple's FairPlay v1 whitebox
to decrypt the legacy screen-mirroring SETUP ``ekey`` into its 16-byte stream secret.
This is interop RE tooling: it runs the user's firmware on the user's machine; it ships
no Apple code.

The FairPlay v1 ``/fp-setup`` handshake replies are now computed in pure Python
(``pylibairplay.fairplay_v1``); the emulator is only needed for the one step with no
portable reimplementation — decrypting the ``ekey`` via ``_OowSGu``.

Usage::

    python -m pylibairplay.fp_emu <AirPlayReceiver dylib> serve [fast]

It maps the dylibs, patches PAC in memory, warms the one-time whitebox init and snapshots
a clean baseline (~35s), prints ``READY``, then answers requests on stdin, one per line::

    ekey <phase1_hex> <phase2_hex> <ekey_hex>   ->   OK <16-byte-secret-hex>

(``phase1``/``phase2`` are the two ``/fp-setup`` request bodies iOS sent on this
connection — needed to replay the whitebox session state the ekey decrypt consumes.)
Each request takes ~0.3s.
"""
from __future__ import annotations

import sys
import lief
from unicorn import *
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

PAGE = 0x4000
STACK_BASE = 0x1_0000_0000
STACK_SIZE = 0x40000
SCRATCH = 0x2_0000_0000      # context/arg buffers
SCRATCH_SIZE = 0x40000
RET_MAGIC = 0x9_9999_0000    # sentinel LR; run() stops emu here
ZERO_FILL = 0x3_0000_0000    # lazily-mapped zero pages for unmapped reads

PTHREAD_ONCE = 0x1e2ea92dc

# External libc stubs, keyed by resolved address. kind in {malloc,calloc,free,memcpy,...}.
STUBS: dict[int, str] = {}

# Cross-dylib stub-island redirects {island_addr: real_target}. A `bl <island>` in one
# dylib lands in a dsc STUB_TEXT island that `br`s to the real symbol in another; we
# don't map islands, so redirect straight to the resolved target. Resolve with
# `ipsw dyld disass <cache> --vaddr <island>`.
STUB_REDIRECT: dict[int, int] = {
    0x2486107f0: 0x2279de158,  # -> AirPlaySupport!_APCUGetFairPlayHWInfoEx
}

# CF / MobileGestalt stubs used by APCUGetFairPlayHWInfoEx (seeds the FP context with
# the device UDID from MGCopyAnswer("UniqueDeviceID")). Addresses are stub islands.
FAKE_CFSTR = 0x5_0000_0000           # sentinel CFString handle MGCopyAnswer returns
UDID = b"00008130000012345678001E"   # placeholder device UDID (hex-parsed by the init)
STUBS.update({
    0x22d0e3250: "mgcopyanswer",
    0x22d0e1c00: "cfgettypeid",
    0x22d0e1fa0: "cfstringgettypeid",
    0x22d0e1f20: "cfstringgetcstring",
    0x22d0e43d0: "strlcpy",
    0x22d0e37c0: "ret0",   # _LogCategory_Initialize -> 0
    0x22d0e1cf0: "ret0",   # CFRelease
    0x0: "ret1",           # sscanf("%2hhx") hex-pair validator (null GOT slot) -> 1
    0x18f06bf94: "arc4random",
    0x232db5d7c: "mmap",
    0x18f06afa8: "sysconf",   # page size
    0x18f0684cc: "gettimeofday",
    0x18ec7b9cc: "malloc",    # libsystem_malloc!_malloc — NULL return smashed the stack
    0x248613510: "stackfail", # __stack_chk_fail stub island — halt loudly if ever reached
})


def align_down(x): return x & ~(PAGE - 1)
def align_up(x): return (x + PAGE - 1) & ~(PAGE - 1)


# FairPlay v1 whitebox entry points (AirPlayReceiver, iOS 26.6): see
# airplayReqProcessor_requestProcessFPSetup.
APCU_FP_HWINFO = 0x2279de158  # AirPlaySupport!_APCUGetFairPlayHWInfoEx (ctx init)
CP2G1B9RO = 0x2455a54d0  # _cp2g1b9ro(&state, ctx) : create FP state from ctx
MIB5YOCT = 0x245597b04   # _Mib5yocT(mode, ctx, state, in, inlen, &out, &outlen, &flag)
OOWSGU = 0x2455a0b04     # _OowSGu(state, ekey, ekeylen, &out, &outlen): decrypts the ekey
FREE_FPSTATE = 0x2455a9374  # _IPaI1oem5iL(state): free FP state back to the whitebox pool
HEAP = 0x4_0000_0000     # bump allocator for malloc stubs
HEAP_SIZE = 0x200000

VAMASK = (1 << 48) - 1
ONCE_SENTINEL = 0x9_9999_2000   # fake LR for a pthread_once init routine


def main() -> None:
    path = sys.argv[1]
    mode_arg = sys.argv[2]
    import os, time as _time
    _T0 = _time.perf_counter()
    _timing = ("timing" in sys.argv) or bool(os.environ.get("FP_TIMING"))

    def _lap(label):
        if _timing:
            print(f"[t+{_time.perf_counter() - _T0:5.1f}s] {label}")

    if mode_arg != "serve":
        print(f"ERR usage: fp_emu.py <AirPlayReceiver> serve [fast]  (got mode {mode_arg!r})")
        return

    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    try:
        uc.ctl_set_cpu_model(UC_CPU_ARM64_MAX)  # enable LSE atomics (swpal/cas/ldadd), etc.
    except Exception as e:
        print("cpu model set failed (continuing):", e)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    # Map several extracted dylibs so cross-dylib calls resolve (path points at one;
    # its siblings are loaded from the same dir). Order: receiver first.
    dylib_dir = os.path.dirname(path)
    names = ["AirPlayReceiver", "AirPlaySupport", "CoreUtils", "AirPlaySender"]
    mapped_pages = set()   # page-aligned addresses already mapped (O(1) overlap check)
    text_ranges = []
    code_sections = []   # __text SECTION ranges (code only — for PAC patching)
    for name in names:
        fp = os.path.join(dylib_dir, name)
        if not os.path.exists(fp):
            continue
        b = lief.MachO.parse(fp).at(0)
        for seg in b.segments:
            va, vsz = seg.virtual_address, seg.virtual_size
            if va == 0 or vsz == 0:
                continue
            base, end = align_down(va), align_up(va + vsz)
            for pg in range(base, end, PAGE):
                if pg not in mapped_pages:
                    uc.mem_map(pg, PAGE); mapped_pages.add(pg)
            content = bytes(seg.content)
            if content:
                uc.mem_write(va, content)
            if seg.name.startswith("__TEXT"):
                text_ranges.append((va, va + vsz))
        for sec in b.sections:
            if sec.name == "__text" and sec.virtual_address:
                code_sections.append((sec.virtual_address, sec.virtual_address + sec.size))
        print(f"mapped {name}")
    _lap("dylibs mapped")

    def is_internal(a):
        return any(lo <= a < hi for lo, hi in text_ranges)

    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_map(SCRATCH, SCRATCH_SIZE)
    uc.mem_map(ZERO_FILL, 0x400000)
    uc.mem_map(HEAP, HEAP_SIZE)
    uc.mem_map(FAKE_CFSTR, PAGE)
    sp = STACK_BASE + STACK_SIZE - 0x1000
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_LR, RET_MAGIC)

    state = {"ext_calls": {}, "heap": HEAP, "ext": set()}

    def apply_kind(kind):
        """Perform a libc/CF/MobileGestalt stub's side effects and return
        (x0_or_None, control). control is None (normal) or 'stop' (stackfail -> abort)."""
        a0 = uc.reg_read(UC_ARM64_REG_X0)
        a1 = uc.reg_read(UC_ARM64_REG_X1)
        a2 = uc.reg_read(UC_ARM64_REG_X2)
        x0 = None
        if kind == "stackfail":
            print(f"  !! __stack_chk_fail reached (stack canary smashed) at "
                  f"pc={uc.reg_read(UC_ARM64_REG_PC):#x}")
            state["stackfail"] = True
            return (None, "stop")
        if kind == "malloc":
            x0 = state["heap"]; state["heap"] += (a0 + 0xf) & ~0xf
            uc.mem_write(x0, b"\x00" * a0)   # zero (whitebox relies on fresh-zero memory)
        elif kind == "calloc":
            n = a0 * a1; x0 = state["heap"]; state["heap"] += (n + 0xf) & ~0xf
            uc.mem_write(x0, b"\x00" * n)
        elif kind in ("memcpy", "memmove"):
            uc.mem_write(a0, bytes(uc.mem_read(a1, a2))); x0 = a0
        elif kind == "memset":
            uc.mem_write(a0, bytes([a1 & 0xff]) * a2); x0 = a0
        elif kind == "bzero":
            uc.mem_write(a0, b"\x00" * a1)
        elif kind == "free":
            pass
        elif kind == "mgcopyanswer":
            x0 = FAKE_CFSTR
        elif kind in ("cfgettypeid", "cfstringgettypeid"):
            x0 = 1
        elif kind == "cfstringgetcstring":
            uc.mem_write(a1, UDID + b"\x00"); x0 = 1
        elif kind == "strlcpy":
            src = bytes(uc.mem_read(a1, 64)).split(b"\x00")[0]
            uc.mem_write(a0, src + b"\x00"); x0 = len(src)
        elif kind == "ret1":
            x0 = 1
        elif kind == "ret0":
            x0 = 0
        elif kind == "arc4random":
            x0 = 0x9E3779B9
        elif kind == "sysconf":
            x0 = 0x4000
        elif kind == "gettimeofday":
            if a0:
                uc.mem_write(a0, b"\x00" * 16)
            x0 = 0
        elif kind == "mmap":
            n = (a1 + PAGE - 1) & ~(PAGE - 1)
            ptr = (state["heap"] + PAGE - 1) & ~(PAGE - 1)
            for pg in range(ptr, ptr + n, PAGE):
                try:
                    uc.mem_map(pg, PAGE)
                except Exception:
                    pass
            uc.mem_write(ptr, b"\x00" * n)
            state["heap"] = ptr + n; x0 = ptr
        return (x0, None)

    def hook_unmapped(uc, access, address, size, value, _):
        # Lazily map external shared-cache globals/pages as zero.
        pg = align_down(address)
        state["ext"].add(pg)
        try:
            uc.mem_map(pg, PAGE)
            return True
        except Exception:
            return False

    def patch_pac(sections):
        """Rewrite PAC instructions in the mapped __text to non-PAC equivalents so the
        code runs natively without a per-instruction hook: pac*/aut*/xpac* -> NOP,
        braa/brab -> br, blraa/blrab -> blr, retaa/retab -> ret. The stored pointer tables
        are already clean VAs, so the authenticated branches are equivalent to plain ones.
        ARM64 is fixed 4-byte, so a linear sweep is exact (we step over undecodable words)."""
        def regn(tok):
            tok = tok.strip().lower()
            if tok == "lr":
                return 30
            if tok in ("xzr", "wzr", "sp"):
                return 31
            return int(tok[1:])
        n = 0
        for lo, hi in sections:
            data = bytes(uc.mem_read(lo, hi - lo))
            off, L = 0, len(data)
            while off < L:
                advanced = False
                for ins in md.disasm(data[off:], lo + off):
                    mn, enc = ins.mnemonic, None
                    if mn in ("retaa", "retab"):
                        enc = 0xd65f03c0                                   # ret
                    elif mn[:4] in ("braa", "brab"):
                        enc = 0xd61f0000 | (regn(ins.op_str.split(",")[0]) << 5)   # br Xn
                    elif mn[:5] in ("blraa", "blrab"):
                        enc = 0xd63f0000 | (regn(ins.op_str.split(",")[0]) << 5)   # blr Xn
                    elif mn[:3] in ("pac", "aut") or mn[:4] == "xpac":
                        enc = 0xd503201f                                   # nop
                    if enc is not None:
                        uc.mem_write(ins.address, enc.to_bytes(4, "little")); n += 1
                    off = ins.address - lo + ins.size
                    advanced = True
                if not advanced:
                    off += 4
        return n

    def stub_hook(uc, address, size, _):
        # External dispatch via a per-address UC_HOOK_CODE: fires only at the few stub
        # target addresses (mapped with a `ret`). Setting PC in a code hook reliably
        # redirects execution. LR already holds the correct return (native bl/br set it).
        tgt = address
        if tgt == ONCE_SENTINEL:
            uc.reg_write(UC_ARM64_REG_X0, 0)   # pthread_once returns 0 after the routine
            # Heap high-water after the one-time init: per-session heap resets to here so
            # init's allocations persist and each session's state lands at the same address.
            state["heap_post_init"] = state["heap"]
            uc.reg_write(UC_ARM64_REG_PC, state.pop("once_real_ret", RET_MAGIC))
            return
        ret = uc.reg_read(UC_ARM64_REG_LR) & VAMASK
        state["ext_calls"][tgt] = state["ext_calls"].get(tgt, 0) + 1
        if tgt in STUB_REDIRECT:
            uc.reg_write(UC_ARM64_REG_PC, STUB_REDIRECT[tgt]); return
        if tgt == PTHREAD_ONCE:
            routine = uc.reg_read(UC_ARM64_REG_X1) & VAMASK
            done = state.setdefault("once_done", set())
            if routine not in done and is_internal(routine):
                print(f"  pthread_once -> run init routine {routine:#x}")
                done.add(routine)
                state["once_real_ret"] = ret
                uc.reg_write(UC_ARM64_REG_LR, ONCE_SENTINEL)
                uc.reg_write(UC_ARM64_REG_PC, routine)
            else:
                uc.reg_write(UC_ARM64_REG_X0, 0)
                uc.reg_write(UC_ARM64_REG_PC, ret)
            return
        kind = STUBS.get(tgt)
        if kind:
            x0, ctrl = apply_kind(kind)
            if ctrl == "stop":
                uc.emu_stop(); return
            if x0 is not None:
                uc.reg_write(UC_ARM64_REG_X0, x0)
            uc.reg_write(UC_ARM64_REG_PC, ret); return
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, ret)

    import time as _t
    _t0 = _t.perf_counter()
    npatch = patch_pac(code_sections)
    print(f"patched {npatch} PAC instrs across {len(code_sections)} __text "
          f"sections in {_t.perf_counter() - _t0:.1f}s")
    # Map each external target page and plant a `ret`, then hook each target address.
    RETBYTES = (0xd65f03c0).to_bytes(4, "little")
    targets = set(STUBS) | set(STUB_REDIRECT) | {PTHREAD_ONCE, ONCE_SENTINEL}
    for t in targets:
        pg = align_down(t)
        if pg not in mapped_pages:
            uc.mem_map(pg, PAGE); mapped_pages.add(pg)
        uc.mem_write(t, RETBYTES)
        uc.hook_add(UC_HOOK_CODE, stub_hook, begin=t, end=t)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_unmapped)

    def run(entry, args):
        for reg, v in zip([UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                           UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7], args):
            uc.reg_write(reg, v)
        uc.reg_write(UC_ARM64_REG_LR, RET_MAGIC)
        state["resume"] = None
        pc = entry
        while True:
            uc.emu_start(pc, RET_MAGIC, timeout=120 * 1_000_000)  # safety ceiling
            if state["resume"] is not None:
                tgt, lr = state["resume"]
                state["resume"] = None
                if lr is not None:
                    uc.reg_write(UC_ARM64_REG_LR, lr)
                if tgt == RET_MAGIC or tgt == 0:
                    break
                pc = tgt
                continue
            break
        return uc.reg_read(UC_ARM64_REG_X0)

    _lap("hooks installed")

    # --- serve: warm once, then decrypt the SETUP ekey per request on stdin ----------
    CTX = SCRATCH
    STATE_SLOT = SCRATCH + 0x10000
    IN1 = SCRATCH + 0x18000
    IN2 = SCRATCH + 0x1c000
    OUT_SLOT = SCRATCH + 0x20000
    OUTLEN_SLOT = SCRATCH + 0x20010
    FLAG_SLOT = SCRATCH + 0x20020
    state_ptr = 0

    def operate(inbuf, inlen):
        uc.mem_write(OUT_SLOT, b"\x00" * 8)
        uc.mem_write(OUTLEN_SLOT, b"\x00" * 8)
        uc.mem_write(FLAG_SLOT, b"\x00")
        run(MIB5YOCT, [3, CTX, state_ptr, inbuf, inlen, OUT_SLOT, OUTLEN_SLOT, FLAG_SLOT])

    def run_ekey(p1, p2, ekey):
        # Establish the session (handshake) then _OowSGu(state, ekey) -> 16-byte secret
        # (the FairPlay-decrypted stream key that seeds the screen key derivation).
        uc.mem_write(SCRATCH, b"\x00" * 0x28000)
        uc.mem_write(IN1, p1); uc.mem_write(IN2, p2)
        EKB = SCRATCH + 0x22000
        uc.mem_write(EKB, ekey)
        run(APCU_FP_HWINFO, [CTX, 0, 0, 0, 0, 0, 0, 0])
        run(CP2G1B9RO, [STATE_SLOT, CTX, 0, 0, 0, 0, 0, 0])
        nonlocal state_ptr
        state_ptr = int.from_bytes(uc.mem_read(STATE_SLOT, 8), "little")
        operate(IN1, len(p1)); operate(IN2, len(p2))   # phase1+phase2: establish keys
        O = SCRATCH + 0x24000; OL = SCRATCH + 0x24010
        uc.mem_write(O, b"\x00" * 8); uc.mem_write(OL, b"\x00" * 8)
        r = run(OOWSGU, [state_ptr, EKB, len(ekey), O, OL, 0, 0, 0])
        op = int.from_bytes(uc.mem_read(O, 8), "little")
        ol = int.from_bytes(uc.mem_read(OL, 4), "little")
        secret = bytes(uc.mem_read(op, ol)) if r == 0 and 0 < ol < 0x100 and op else b""
        if state_ptr:
            run(FREE_FPSTATE, [state_ptr, 0, 0, 0, 0, 0, 0, 0])
        return secret

    # Warm-up: HWInfo + cp2g1b9ro (triggers the one-time whitebox init) + free. This
    # leaves a clean post-init baseline with no per-session mutations, which we snapshot
    # and restore before each real session so every session starts identical.
    snap = []
    if not os.environ.get("FP_NOWARM"):
        uc.mem_write(SCRATCH, b"\x00" * 0x28000)
        try:
            run(APCU_FP_HWINFO, [CTX, 0, 0, 0, 0, 0, 0, 0])
            run(CP2G1B9RO, [STATE_SLOT, CTX, 0, 0, 0, 0, 0, 0])
            sp0 = int.from_bytes(uc.mem_read(STATE_SLOT, 8), "little")
            if sp0:
                run(FREE_FPSTATE, [sp0, 0, 0, 0, 0, 0, 0, 0])
        except UcError:
            pass
        snap = [(b, bytes(uc.mem_read(b, e - b + 1))) for (b, e, _p) in uc.mem_regions()]
    _lap("warm + snapshot done")

    print("READY", flush=True)   # signal warm-up complete
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            parts = line.split()
            _ts = _time.perf_counter()
            if parts[0] == "ekey":
                # ekey <phase1_hex> <phase2_hex> <ekey_hex> -> 16-byte stream secret
                p1, p2, ek = (bytes.fromhex(parts[1]), bytes.fromhex(parts[2]),
                              bytes.fromhex(parts[3]))
                if not os.environ.get("FP_NORESTORE"):
                    for b, data in snap:
                        uc.mem_write(b, data)
                out = run_ekey(p1, p2, ek)
            else:
                print("ERR unknown request (expected: ekey <p1> <p2> <ekey>)", flush=True)
                continue
            if _timing:
                print(f"  [ekey {1000*(_time.perf_counter()-_ts):.0f} ms]", flush=True)
            print("OK " + out.hex(), flush=True)
        except Exception as e:
            print("ERR " + str(e).replace("\n", " "), flush=True)


if __name__ == "__main__":
    main()
