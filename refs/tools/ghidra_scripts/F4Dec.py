# -*- coding: utf-8 -*-
# F4Dec.py - decompile given functions (+1 level callers/callees) to dec2.c
# Args: outdir, then hex addresses (entry points), e.g.:
#   F4Dec.py /tmp/f4_out 00000814 0000076e ...
# @category: Garmin.F4
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
OUT = args[0] if args else "/tmp/f4_out"
seeds = args[1:] if len(args) > 1 else []

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
monitor = ConsoleTaskMonitor()

dec = DecompInterface()
dec.openProgram(prog)

todo = set()
for s in seeds:
    ad = af.getAddress(s)
    fn = fm.getFunctionAt(ad)
    if fn is None:
        fn = fm.getFunctionContaining(ad)
    if fn:
        todo.add(fn.getEntryPoint().toString())
    else:
        print("seed %s: no function" % s)

done = set()
rounds = 0
out = open(os.path.join(OUT, "dec2.c"), "w")
related = []  # (seed, addr, name, kind)
while todo and rounds < 2:
    nxt = set()
    for te in sorted(todo):
        if te in done:
            continue
        done.add(te)
        ad = af.getAddress(te)
        fn = fm.getFunctionAt(ad)
        if fn is None:
            continue
        res = dec.decompileFunction(fn, 120, monitor)
        out.write("\n/* ============ %s %s ============ */\n" % (te, fn.getName()))
        if res.decompileCompleted():
            out.write(res.getDecompiledFunction().getC())
        else:
            out.write("/* decompile failed: %s */\n" % res.getErrorMessage())
        # callers (one level up from seeds and their callers)
        called = set()
        callers = set()
        try:
            for c in fn.getCalledFunctions(monitor):
                called.add(c.getEntryPoint().toString())
            for r in prog.getReferenceManager().getReferencesTo(ad):
                cf = fm.getFunctionContaining(r.getFromAddress())
                if cf:
                    callers.add(cf.getEntryPoint().toString())
        except:
            pass
        for c in called:
            related.append((te, c, "callee"))
            if rounds == 0:
                nxt.add(c)
        for c in callers:
            related.append((te, c, "caller"))
            if rounds == 0:
                nxt.add(c)
    todo = nxt
    rounds += 1
out.close()
with open(os.path.join(OUT, "related.txt"), "w") as f:
    for te, c, k in related:
        f.write("%s %s %s\n" % (te, k, c))
print("=== F4Dec done: %d functions -> %s/dec2.c" % (len(done), OUT))
