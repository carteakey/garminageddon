# -*- coding: utf-8 -*-
# F4List.py - dump raw instruction listing for an address range (thumb or arm as
# currently decoded). Args: outdir, start, end (hex).
# @category: Garmin.F4
import os
args = getScriptArgs()
OUT = args[0]
start = args[1]
end = args[2]
prog = currentProgram
af = prog.getAddressFactory()
listing = prog.getListing()
a = af.getAddress(start)
b = af.getAddress(end)
with open(os.path.join(OUT, "list_%s_%s.txt" % (start, end)), "w") as f:
    it = listing.getInstructions(a, True)
    for ins in it:
        ia = ins.getAddress()
        if ia is not None and ia.subtract(b) > 0:
            break
        refs = ""
        for r in prog.getReferenceManager().getReferencesFrom(ia):
            refs += " -> %s(%s)" % (r.getToAddress(), r.getReferenceType())
        f.write("%s  %-40s%s\n" % (ia, ins, refs))
print("=== F4List done")
