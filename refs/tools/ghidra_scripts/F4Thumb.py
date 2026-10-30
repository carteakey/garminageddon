# -*- coding: utf-8 -*-
# F4Thumb.py - force THUMB disassembly at given entry addresses, create functions,
# re-run auto-analysis on the touched code, so ARM-misparsed Garmin Thumb code fixes.
# Args: (ignored), then hex addresses...
# @category: Garmin.F4
from ghidra.app.cmd.disassemble import ArmDisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.util import PseudoDisassembler

args = getScriptArgs()
addrs = args[1:] if len(args) > 1 else []
prog = currentProgram
af = prog.getAddressFactory()
fm = prog.getFunctionManager()
monitor = getMonitor()

fixed = 0
for s in addrs:
    ad = af.getAddress(s)
    if ad is None:
        print("bad addr %s" % s)
        continue
    fn = fm.getFunctionAt(ad)
    if fn is not None:
        print("%s already a function" % s)
        continue
    cmd = ArmDisassembleCommand(ad, None, True)  # thumb = True
    ok = cmd.applyTo(prog, monitor)
    if not ok:
        print("%s thumb disasm failed" % s)
        continue
    cfn = CreateFunctionCmd(ad)
    ok2 = cfn.applyTo(prog, monitor)
    print("%s thumb disasm=%s createfn=%s" % (s, ok, ok2))
    fixed += 1
print("=== F4Thumb: fixed %d entries" % fixed)
