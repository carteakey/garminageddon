#!/usr/bin/env python3
# f4b_strrefs.py - find Thumb/ARM code that loads a given string VA via a
# literal pool in a raw ARM binary (base 0). F4b tool.
# Usage: f4b_strrefs.py <binary> <va_hex> [va_hex ...]
import struct, sys

def find_all(blob, p):
    out=[]; s=0
    while True:
        i=blob.find(p,s)
        if i<0: break
        out.append(i); s=i+1
    return out

def thumb_ldr_literal_targets(data, lo, hi, lit):
    """return code addrs of Thumb LDR-literal / ADR instructions in [lo,hi)
    whose effective address == lit"""
    res = []
    for off in range(lo & ~1, hi, 2):
        h = struct.unpack_from('<H', data, off)[0]
        # LDR T1: 01001 Rt(3) imm8
        if (h & 0xF800) == 0x4800:
            eff = ((off + 4) & ~3) + (h & 0xFF) * 4
            if eff == lit:
                res.append((off, 'ldrt1'))
        # LDR T2: F8DF imm12
        elif (h & 0xFFFF) == 0xF8DF:
            imm = struct.unpack_from('<H', data, off+2)[0]
            eff = off + 4 + imm
            if eff == lit:
                res.append((off, 'ldrt2'))
        # ADR T1 (ADD Rd, PC, imm8): 1010 1 Rd imm8
        elif (h & 0xF800) == 0xA000:
            eff = ((off + 4) & ~3) + (h & 0xFF) * 4
            if eff == lit:
                res.append((off, 'adrt1'))
        # ADR T2/T3 32-bit: ADDW/SUBW Rd, PC, imm12 (F20x 0xxx / F2Ax 0xxx)
        elif (h & 0xFBFF) in (0xF200, 0xF2A0):
            h2 = struct.unpack_from('<H', data, off+2)[0]
            if (h2 & 0x8000) == 0:
                i_bit = (h >> 10) & 1
                imm3 = (h >> 12) & 7
                imm8 = h2 & 0xFF
                imm12 = (i_bit << 11) | (imm3 << 8) | imm8
                if (h & 0xFBFF) == 0xF200:
                    eff = off + 4 + imm12
                    kind = 'addw'
                else:
                    eff = off + 4 - imm12
                    kind = 'subw'
                if eff == lit:
                    res.append((off, kind))
    return res

def arm_ldr_literal_targets(data, lo, hi, lit):
    res = []
    for off in range(lo & ~3, hi, 4):
        w = struct.unpack_from('<I', data, off)[0]
        cond = w >> 28
        if cond == 0xF: continue
        if (w & 0x0F7F0000) == 0x051F0000:  # LDR Rt, [PC, #imm]
            imm = w & 0xFFF
            eff = off + 8 + imm
            if eff == lit:
                res.append((off, 'arm'))
    return res

def find_function_start(data, addr, maxback=0x2000):
    """scan back for a Thumb push {..,lr} (B5xx) or 32-bit push (E92Dxxxx) prologue"""
    a = addr & ~1
    lo = max(0, a - maxback)
    # crude: walk back halfword by halfword, look for B5xx push or E92D
    cands = []
    for off in range(a, lo, -2):
        h = struct.unpack_from('<H', data, off)[0]
        if (h & 0xFF00) == 0xB500:  # push {..., lr}
            cands.append(off)
            if len(cands) >= 1:
                return off
    return None

def main():
    path = sys.argv[1]
    data = open(path, 'rb').read()
    n = len(data)
    for va in sys.argv[2:]:
        va = int(va, 16)
        print("=== VA 0x%08x ===" % va)
        # 1) PC-relative ADR/ADDW/SUBW referencing the VA directly (no pool word)
        lo = max(0, va - 0x1100)
        hi = min(n, va + 0x1100)
        for off, kind in thumb_ldr_literal_targets(data, lo, hi, va):
            if kind in ('adrt1', 'addw', 'subw'):
                fs = find_function_start(data, off)
                print("  pcrel@0x%08x (%s) func_start~%s" % (off, kind, hex(fs) if fs else '?'))
        # 2) literal pools containing the VA + LDR code reading them
        lits = find_all(data, struct.pack('<I', va))
        for L in lits:
            lo2 = max(0, L - 0x1100)
            t = thumb_ldr_literal_targets(data, lo2, min(n, L+4), L)
            a = arm_ldr_literal_targets(data, lo2, min(n, L+4), L)
            if t or a:
                for off, kind in t + a:
                    fs = find_function_start(data, off)
                    print("  lit@0x%08x  code@0x%08x (%s) func_start~%s" % (L, off, kind, hex(fs) if fs else '?'))
            else:
                print("  lit@0x%08x  (no direct LDR found in preceding 4KB)" % L)

if __name__ == '__main__':
    main()
