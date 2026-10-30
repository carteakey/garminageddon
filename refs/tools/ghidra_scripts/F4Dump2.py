# -*- coding: utf-8 -*-
# F4Dump2.py - UTF-16LE/ASCII string hunt + xref dump for Garmin bootloader (F4)
# Searches the ORIGINAL file bytes on disk for key terms (avoids Ghidra memory
# read issues), maps file offsets to addresses (raw binary @ base 0), then uses
# Ghidra only for reference lookup. Output: /tmp/f4_out/term_addrs.txt
# @category: Garmin.F4
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = "/tmp/f4_out"
BIN = None
args = getScriptArgs()
if args:
    if args[0]:
        OUT = args[0]
    if len(args) > 1:
        BIN = args[1]
if not os.path.isdir(OUT):
    os.makedirs(OUT)

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()

print("=== F4Dump2: imageBase=%s bin=%s" % (prog.getImageBase(), BIN))

TERMS = [
    "GARMIN", "GUPDATE", ".GCD", "/Garmin/", "/.System/", ".System/RemoteSW/",
    "Checksum failure", "Checksum is valid", "GCD image is", "NOT valid",
    "gcd_rd_end", "no record descriptor", "Too many record descriptors",
    "Unknown Descriptor", "Unknown ID", "product_nmbr", "crypt_key", "min_vrsn",
    "cur_vrsn", "erase_flag", "Software Version", "UpdateDeviceConfig",
    "last_id.bin", "ldr.bin", "update.txt", "update.log", "pckd_prtnum",
    "id_pgm_strt", "id_chksm", "id_ignore", "bmap_data", "external_data",
    "rom_data", "bb_data", "Long Text Warning", "text_data", "dset_type",
    "lng_dset_len", "int_dset_len", "update_device_Spawn", "GCD_log",
    "Unable to open file", "Checksum is the wrong size", "jepp_data",
    "audio_data", "rgn data", "dInput file is not a valid GCD",
    "006-B%04d-00", "006-D1338", "105-01925", "MRUSfTUUt", "B095300",
    "write_last_id", "last ID", "crypt", "signature", "Signing",
]

def find_all(pattern, blob):
    out = []
    start = 0
    while True:
        i = blob.find(pattern, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out

# image base from Ghidra (should be 0)
ib = prog.getImageBase().getOffset()

data = open(BIN, "rb").read() if BIN else b""

lines = []
func_targets = set()
term_map = []  # (term, addrstr, refs)

for term in TERMS:
    for enc, tag in (("utf-16-le", "u16"), ("ascii", "asc")):
        if tag == "asc" and len(term) < 8:
            continue
        try:
            pat = term.encode(enc)
        except:
            continue
        for o in find_all(pat, data):
            addr_off = ib + o
            astr = "%08x" % addr_off
            ad = af.getAddress(astr)
            refs = []
            try:
                for r in prog.getReferenceManager().getReferencesTo(ad):
                    refs.append("%s:%s" % (r.getFromAddress(), r.getReferenceType()))
                    fn = fm.getFunctionContaining(r.getFromAddress())
                    if fn:
                        func_targets.add(fn.getEntryPoint().toString())
                        term_map.append((term, astr, fn.getEntryPoint().toString(), fn.getName()))
            except:
                pass
            lines.append("%-28s %s %-4s refs=[%s]" % (term, astr, tag, ", ".join(refs) if refs else "NONE"))

with open(os.path.join(OUT, "term_addrs.txt"), "w") as f:
    f.write("\n".join(lines))
with open(os.path.join(OUT, "term_funcs.txt"), "w") as f:
    for t in term_map:
        f.write("%s %s -> %s %s\n" % t)

print("=== F4Dump2 done: %d term hits, %d target funcs" % (len(lines), len(func_targets)))
