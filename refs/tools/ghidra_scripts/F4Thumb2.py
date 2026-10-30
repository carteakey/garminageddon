# -*- coding: utf-8 -*-
# F4Thumb2.py - clear misparsed code in given [start,end] ranges, set TMode=1,
# re-disassemble as THUMB, create function at range start, then run analyzer.
# Args: outdir(ignored) then "start:end" hex ranges...
# @category: Garmin.F4
import math
from ghidra.app.cmd.disassemble import ArmDisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.plugin.core.analysis import AutoAnalysisManager

args = getScriptArgs()
ranges = args[1:] if len(args) > 1 else []
prog = currentProgram
af = prog.getAddressFactory()
fm = prog.getFunctionManager()
listing = prog.getListing()
monitor = getMonitor()
ctx = prog.getProgramContext()
treg = ctx.getRegister("TMode")
print("TMode register: %s" % treg)

from java.math import BigInteger

for rs in ranges:
    a, b = rs.split(":")
    start = af.getAddress(a)
    end = af.getAddress(b)
    # remove any functions covering the range
    f = fm.getFunctionContaining(start)
    while f is not None:
        fm.removeFunction(f.getEntryPoint())
        f = fm.getFunctionContaining(start)
    # clear code
    listing.clearCodeUnits(start, end, True, monitor)
    # set TMode=1 across range
    ctx.setValue(treg, start, end, BigInteger.ONE)
    # disassemble as thumb
    cmd = ArmDisassembleCommand(start, None, True)
    ok = cmd.applyTo(prog, monitor)
    # create function
    ok2 = CreateFunctionCmd(start).applyTo(prog, monitor)
    print("%s-%s clear+thumb=%s fn=%s" % (a, b, ok, ok2))

# re-run auto analysis
mgr = AutoAnalysisManager.getAnalysisManager(prog)
mgr.reAnalyzeAll(None)
mgr.startAnalysis(monitor)
print("=== F4Thumb2 done")
