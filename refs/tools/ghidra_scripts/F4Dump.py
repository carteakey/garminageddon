# -*- coding: utf-8 -*-
# F4Dump.py - Ghidra headless post-script for Garmin nüvi 2595 bootloader (F4)
# Dumps: strings + xrefs for key update-flow terms, function list, decompilation
# of every function that references those strings. Run via analyzeHeadless -postScript.
# @category: Garmin.F4
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = "/tmp/f4_out"
try:
    args = getScriptArgs()
    if args and args[0]:
        OUT = args[0]
except:
    pass
if not os.path.isdir(OUT):
    os.makedirs(OUT)

prog = currentProgram
fm = prog.getFunctionManager()
listing = prog.getListing()
monitor = ConsoleTaskMonitor()

print("=== F4Dump: program=%s lang=%s imageBase=%s" % (prog.getName(), prog.getLanguage().getLanguageID(), prog.getImageBase()))

KEY_TERMS = [
    "GARMIN", "GUPDATE", ".GCD", "/Garmin/", ".System", "GCD",
    "hecksum", "valid", "gcd_rd_end", "record descriptor", "Unknown Descriptor",
    "Unknown ID", "product_nmbr", "crypt_key", "min_vrsn", "cur_vrsn", "erase_flag",
    "Software Version", "006-B", "UpdateDeviceConfig", "last_id", "ldr.bin",
    "update.txt", "update.log", "Updater", "pckd_prtnum", "id_pgm", "id_chksm",
    "id_ignore", "bmap_data", "external_data", "rom_data", "bb_data",
    "Long Text Warning", "dset_type", "lng_dset_len", "int_dset_len",
    "update_device", "Unable to open file", "GCD_log", "Descriptor",
]

# ---- collect defined strings ----
strings = []  # (addr, text)
di = listing.getDefinedData(True)
for d in di:
    try:
        dt = d.getDataType().getName().lower()
        if "string" in dt or "char" in dt:
            v = d.getValue()
            if v is None:
                continue
            s = str(v)
            if len(s) >= 3:
                strings.append((d.getAddress(), s, d.getLength()))
    except:
        pass
print("defined strings collected: %d" % len(strings))

with open(os.path.join(OUT, "strings.txt"), "w") as f:
    for a, s, ln in strings:
        f.write("%s len=%d %r\n" % (a, ln, s))

# ---- function list ----
with open(os.path.join(OUT, "functions.txt"), "w") as f:
    for fn in fm.getFunctions(True):
        body = fn.getBody()
        f.write("%s %s size=%d\n" % (fn.getEntryPoint(), fn.getName(), body.getNumAddresses()))

# ---- find key strings and their xrefs ----
refmgr = prog.getReferenceManager()
hits = {}  # term -> list of (straddr, text, [fromaddrs])
for a, s, ln in strings:
    for t in KEY_TERMS:
        if t in s:
            froms = []
            for r in refmgr.getReferencesTo(a):
                ft = r.getFromAddress()
                froms.append("%s(%s)" % (ft, r.getReferenceType()))
            hits.setdefault(t, []).append((str(a), s, froms))
            break  # one term per string is enough

with open(os.path.join(OUT, "string_xrefs.txt"), "w") as f:
    for t in sorted(hits):
        for sa, s, froms in hits[t]:
            f.write("[%s] @%s %r\n    refs: %s\n" % (t, sa, s, ", ".join(froms) if froms else "NONE"))

# ---- decompile functions containing refs to key strings ----
targets = set()   # function entry addresses
detail = []       # human-readable mapping
for t, lst in hits.items():
    for sa, s, froms in lst:
        for fr in froms:
            faddr_str = fr.split("(")[0]
            try:
                faddr = prog.getAddressFactory().getAddress(faddr_str)
            except:
                continue
            fn = fm.getFunctionContaining(faddr)
            if fn:
                targets.add(fn.getEntryPoint().toString())
                detail.append("string %s %r -> ref at %s -> func %s %s" % (sa, s[:60], faddr_str, fn.getEntryPoint(), fn.getName()))
            else:
                detail.append("string %s %r -> ref at %s -> (no function)" % (sa, s[:60], faddr_str))

with open(os.path.join(OUT, "target_funcs.txt"), "w") as f:
    for d in detail:
        f.write(d + "\n")

# decompile
dec = DecompInterface()
dec.openProgram(prog)
with open(os.path.join(OUT, "decompiled.c"), "w") as f:
    for te in sorted(targets):
        addr = prog.getAddressFactory().getAddress(te)
        fn = fm.getFunctionAt(addr)
        if fn is None:
            continue
        res = dec.decompileFunction(fn, 90, monitor)
        f.write("\n/* ==================== %s %s ==================== */\n" % (te, fn.getName()))
        if res.decompileCompleted():
            f.write(res.getDecompiledFunction().getC())
        else:
            f.write("/* decompile failed: %s */\n" % res.getErrorMessage())
print("=== F4Dump done: %d target functions decompiled -> %s" % (len(targets), OUT))
