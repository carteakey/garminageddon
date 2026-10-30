# -*- coding: utf-8 -*-
# F4Xref.py - print all references TO given addresses (code xrefs). Args: outdir, addr...
# @category: Garmin.F4
import os
args = getScriptArgs()
OUT = args[0]
prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
lines = []
for s in args[1:]:
    ad = af.getAddress(s)
    refs = []
    for r in prog.getReferenceManager().getReferencesTo(ad):
        fn = fm.getFunctionContaining(r.getFromAddress())
        refs.append("%s(%s) in %s" % (r.getFromAddress(), r.getReferenceType(), fn))
    lines.append("TO %s:\n  %s" % (s, "\n  ".join(refs) if refs else "NONE"))
with open(os.path.join(OUT, "xrefs_out.txt"), "a") as f:
    f.write("\n".join(lines) + "\n")
print("=== F4Xref done")
