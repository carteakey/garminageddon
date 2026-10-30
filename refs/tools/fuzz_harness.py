#!/usr/bin/env python3
"""fuzz_harness.py — inject/collect harness for nüvi 2595 parser fuzzing (F5, T1 vector).

SUBCOMMANDS
  baseline   Snapshot the device crash oracle (.System/Diag/Shutdowns/ + shutdown.log) into
             refs/fuzz-corpus/baseline/. READ-ONLY (mounts ro). Run once now; re-run any time.
  inject     Copy ONE mutant file onto the device over a READ-WRITE mount, then unmount with
             sync, then print the manual test procedure for the user. WRITES TO THE DEVICE —
             only run this deliberately: it prompts for the word INJECT unless --yes.
  collect    Re-mount ro, diff the crash oracle against the baseline, report NEW records
             (cause codes, registers, RTL trap lines). Exit code: 0 clean, 2 = new RTL_Trap,
             3 = new non-trap records, 1 = error.

Device access policy (ground rules):
  * baseline/collect mount the device READ-ONLY (udisksctl --options ro).
  * ONLY inject mounts read-write, and it unmounts (after sync) before returning.
  * inject never overwrites an existing device file without --force.

Oracle facts (02-RECON.md): parser crashes append RTL_Trap records to
  /<mnt>/.System/Diag/Shutdowns/*.html (UTF-16) + shutdown.log (framed ParserVersion 3 records:
  UnitId, Time, SystemVersion, RTL_Trap_Info, Exception_Info registers, Error_Cause).
  Cause codes seen: 1=RTL trap, 2=low battery, 3=unknown, 8=abnormal powerdown.
Bonus: Voice/*.sum = plain u32 LE additive checksum of the matching .vpm (verified on 2 stock
  voices) — inject forges it so a mutated .vpm passes the loader's integrity gate.

Examples:
  python3 fuzz_harness.py baseline
  python3 fuzz_harness.py inject --file /tmp/mut/Garmin_Asia.m0003.jpg
  python3 fuzz_harness.py inject --file /tmp/mut/Michelle_256K.trunc.m0007.vpm --yes
  python3 fuzz_harness.py collect
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]          # .../garminageddon
DEFAULT_BASELINE = REPO / "refs/fuzz-corpus/baseline"
DEFAULT_LEDGER = REPO / "refs/fuzz-corpus/injected.log"
DEVICE_LABEL = "GARMIN"
SHUTDOWN_DIR = ".System/Diag/Shutdowns"
SHUTDOWN_LOG = "shutdown.log"

# target dir on device per mutant type
TARGETS = {
    ".gpx": "Garmin/GPX",          # per 03-ATTACK-SURFACE.md: imported at boot
    ".jpg": "Pictures",
    ".jpeg": "Pictures",
    ".vpm": "Voice",               # + forged .sum (see forge_sum)
    ".srf": "Vehicle",
    ".typ": "Garmin",              # experimental: standalone TYP likely ignored (needs img embed)
}


# ---------------------------------------------------------------------------
# device / mount plumbing

_MOUNTED_HERE = None   # mount target created by this process (unmounted on exit if set)


def run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if p.returncode != 0:
        raise RuntimeError("command failed: %s\n%s%s" % (" ".join(cmd), p.stdout, p.stderr))
    return p.stdout.strip()


def find_device():
    """Return block device path for the volume labelled GARMIN (e.g. /dev/sdc)."""
    out = subprocess.run(["lsblk", "-rno", "NAME,LABEL,FSTYPE,TYPE"],
                         capture_output=True, text=True).stdout
    hits = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] == DEVICE_LABEL and parts[3] in ("disk", "part"):
            hits.append("/dev/" + parts[0])
    if not hits:
        raise RuntimeError("no block device labelled %r found — plug the nüvi in (USB)" % DEVICE_LABEL)
    if len(hits) > 1:
        raise RuntimeError("ambiguous devices labelled %r: %s" % (DEVICE_LABEL, hits))
    return hits[0]


def mount_state(dev):
    """-> (target, options) if mounted else (None, None)."""
    p = subprocess.run(["findmnt", "-n", "-o", "TARGET,OPTIONS", "--source", dev],
                       capture_output=True, text=True)
    if p.returncode != 0 or not p.stdout.strip():
        return None, None
    tgt, opts = p.stdout.strip().split(None, 1)
    return tgt, opts


def mount_ro(dev):
    global _MOUNTED_HERE
    tgt, opts = mount_state(dev)
    if tgt and "ro" in opts.split(","):
        return tgt
    if tgt:
        print("[harness] device is mounted read-write (%s) — remounting READ-ONLY for this "
              "read-only operation" % tgt)
        run(["udisksctl", "unmount", "-b", dev])
        tgt = None
    out = run(["udisksctl", "mount", "-b", dev, "--options", "ro"])
    m = re.search(r"at (.+)$", out)
    tgt = m.group(1) if m else None
    if not tgt:
        tgt, _ = mount_state(dev)
    _MOUNTED_HERE = tgt
    print("[harness] mounted ro at %s" % tgt)
    return tgt


def mount_rw(dev):
    """inject-mode only: ensure a read-write mount; return target."""
    global _MOUNTED_HERE
    tgt, opts = mount_state(dev)
    if tgt and "ro" not in opts.split(","):
        print("[harness] using existing read-write mount at %s" % tgt)
        return tgt
    if tgt:
        print("[harness] device mounted ro — unmounting and re-mounting READ-WRITE (inject mode)")
        run(["udisksctl", "unmount", "-b", dev])
    out = run(["udisksctl", "mount", "-b", dev])
    m = re.search(r"at (.+)$", out)
    tgt = m.group(1) if m else None
    if not tgt:
        tgt, _ = mount_state(dev)
    _MOUNTED_HERE = tgt
    print("[harness] mounted rw at %s" % tgt)
    return tgt


def unmount(dev):
    global _MOUNTED_HERE
    tgt, _ = mount_state(dev)
    if tgt:
        run(["sync"])
        run(["udisksctl", "unmount", "-b", dev])
        print("[harness] synced + unmounted %s" % dev)
        if _MOUNTED_HERE == tgt:
            _MOUNTED_HERE = None


# ---------------------------------------------------------------------------
# oracle reading / record parsing

def read_oracle(mnt):
    """-> (files: {name: (size, mtime)}, log_bytes)"""
    sd = Path(mnt) / SHUTDOWN_DIR
    files = {}
    for f in sorted(sd.iterdir()):
        if f.is_file():
            st = f.stat()
            files[f.name] = (st.st_size, int(st.st_mtime))
    log = (sd / SHUTDOWN_LOG).read_bytes() if (sd / SHUTDOWN_LOG).exists() else b""
    return files, log


# Quirk (verified against device log): records contain the LITERAL string "|NEWLINE|"
# instead of real newlines, and timestamps are not zero-padded ("2014-5-2 9:43:23").
FIELD_RES = {
    "UnitId": re.compile(rb"UnitId: \{(\d+)"),
    "Time": re.compile(rb"Time: \{(?:\|NEWLINE\|)?\s*(\d{4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}:\d{1,2})"),
    "SystemVersion": re.compile(rb"SystemVersion: \{(?:\|NEWLINE\|)?\s*([^}\s|]+)"),
    "Error_Cause": re.compile(rb"Error_Cause: \{(\d+)"),
    "PackageName": re.compile(rb"PackageName: \{(?:\|NEWLINE\|)?\s*([^}\s|]+)"),
    "Error_Number": re.compile(rb"Error Number: (0x[0-9A-Fa-f]+)"),
    "RTL_Trap_Info": re.compile(rb"RTL_Trap_Info: \{([^}]*)"),
    "Backtrace": re.compile(rb"Backtrace: \{([^}]*)"),
    "registers": re.compile(rb"Registers:?(.*?)CPSR|Registers:?(.*)$", re.S),
}


def split_records(log: bytes):
    """shutdown.log = back-to-back framed records starting 'RECORD_SIZE: {N}ParserVersion 3'."""
    chunks = log.split(b"RECORD_SIZE: {")
    return [b"RECORD_SIZE: {" + c for c in chunks[1:]]  # chunk[0] is any leading garbage


def parse_record(rec: bytes):
    d = {"_sha": hashlib.sha256(rec).hexdigest()[:16], "_size": len(rec)}
    for k, rx in FIELD_RES.items():
        m = rx.search(rec)
        if not m:
            continue
        v = next((g for g in m.groups() if g is not None), b"")
        if k == "registers":
            vals = re.findall(rb"0x[0-9A-Fa-f]+", v)[:24]
            d["reg_nonzero"] = sum(1 for x in vals if int(x, 16) != 0)
            d["reg_count"] = len(vals)
        else:
            d[k] = v.decode("utf-8", "replace").replace("|NEWLINE|", " ").strip()
    return d


def summarize_log(log: bytes):
    return [parse_record(r) for r in split_records(log)]


def parse_trap_html(path: Path):
    """Extract the juicy fields from a UTF-16 *_RTL_Trap.html record."""
    raw = path.read_bytes()
    try:
        txt = raw.decode("utf-16")
    except UnicodeDecodeError:
        txt = raw.decode("utf-16-le", "replace")
    out = {"file": path.name}
    for k, rx in {
        # actual markup: <b><font ...>Error Number: </font></b><font color="#FF0000">6E5D8017</font>
        "error_number": r"Error Number:.*?<font[^>]*>([0-9A-Fa-f]{8})</font>",
        "rtl_line": r"RTL Information Line:.*?<br />(.*?)<br />",
        "task_id": r"Task ID:\s*</b>(.*?)<",
        "uptime": r"Uptime:\s*</b>(.*?)<",
        "error_date": r"Error Date:\s*</b>(.*?)<",
    }.items():
        m = re.search(rx, txt, re.S)
        out[k] = m.group(1).strip() if m else None
    out["call_stack"] = re.findall(r"0x[0-9A-Fa-f]{8} : 0x[0-9A-Fa-f]{4}", txt)[:20]
    return {k: v for k, v in out.items() if v not in (None, [], "")}


CAUSE_NAMES = {"1": "RTL trap (software crash)", "2": "low battery", "3": "unknown/other",
               "8": "abnormal powerdown"}


# ---------------------------------------------------------------------------
# subcommand: baseline

def cmd_baseline(args):
    dev = find_device()
    mnt = mount_ro(dev)
    files, log = read_oracle(mnt)
    records = summarize_log(log)
    unit_ids = sorted({r.get("UnitId", "?") for r in records})
    snap = {
        "captured": dt.datetime.now().isoformat(timespec="seconds"),
        "device": dev, "mount": mnt, "unit_ids_in_log": unit_ids,
        "shutdown_dir": SHUTDOWN_DIR,
        "files": {n: {"size": s, "mtime": t} for n, (s, t) in sorted(files.items())},
        "file_count": len(files),
        "log_size": len(log),
        "log_records": len(records),
        "log_record_hashes": [r["_sha"] for r in records],
        "log_causes": {c: sum(1 for r in records if r.get("Error_Cause") == c)
                       for c in sorted({r.get("Error_Cause", "?") for r in records})},
    }
    blob = json.dumps(snap, indent=2, sort_keys=True).encode()
    snap["snapshot_sha256"] = hashlib.sha256(blob).hexdigest()

    out = Path(args.baseline)
    out.mkdir(parents=True, exist_ok=True)
    (out / "baseline.json").write_bytes(blob)
    (out / "shutdown.log.snapshot").write_bytes(log)
    with open(out / "listing.txt", "w") as f:
        f.write("# %s — %s on %s (mounted ro at %s)\n" % (snap["captured"], SHUTDOWN_DIR, dev, mnt))
        f.write("# %d files, log %d B / %d records, causes=%s\n" %
                (len(files), len(log), len(records), snap["log_causes"]))
        for n, (s, t) in sorted(files.items()):
            f.write("%12d  %s  %s\n" % (s, dt.datetime.fromtimestamp(t).isoformat(" "), n))

    print(json.dumps({k: v for k, v in snap.items() if k not in ("log_record_hashes", "files")}, indent=2))
    print("\nbaseline written to %s\nsnapshot sha256: %s" % (out, snap["snapshot_sha256"]))
    maybe_unmount(dev, args)


def maybe_unmount(dev, args):
    """baseline/collect: unmount only if this process created the mount."""
    if getattr(args, "leave_mounted", False):
        return
    if _MOUNTED_HERE is not None:
        unmount(dev)


# ---------------------------------------------------------------------------
# subcommand: inject

def forge_sum(data: bytes) -> bytes:
    """Voice/*.sum = u32 LE additive sum of the .vpm bytes (verified on 2 stock voices)."""
    return (sum(data) & 0xFFFFFFFF).to_bytes(4, "little")


def cmd_inject(args):
    mutant = Path(args.file).resolve()
    if not mutant.is_file():
        sys.exit("no such mutant file: %s" % mutant)
    data = mutant.read_bytes()
    mmd5 = hashlib.md5(data).hexdigest()

    ext = mutant.suffix.lower()
    target = args.target
    if target == "auto":
        target = TARGETS.get(ext)
        if target is None:
            sys.exit("don't know where a %r file goes; pass --target {gpx,jpeg,voice,vehicle,garmin}" % ext)
    print("=" * 72)
    print("INJECT MODE — this will WRITE to the nüvi's mass storage:")
    print("  file:   %s (%d B, md5 %s)" % (mutant, len(data), mmd5))
    print("  dest:   /%s/%s" % (target, mutant.name))
    if ext == ".vpm":
        print("  plus:   /Voice/%s.sum (forged additive-sum32 checksum)" % mutant.stem)
    print("=" * 72)
    if not args.yes:
        ans = input('Type INJECT to write to the device, anything else to abort: ').strip()
        if ans != "INJECT":
            sys.exit("aborted — nothing written.")

    dev = find_device()
    mnt = mount_rw(dev)
    dest_dir = Path(mnt) / target
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / mutant.name
    if dest.exists() and not args.force:
        sys.exit("REFUSING: %s already exists on device (rollback first, or --force to overwrite)" % dest)

    with open(dest, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    extra = []
    if ext == ".vpm":
        sdest = dest_dir / (mutant.stem + ".sum")
        if sdest.exists() and not args.force:
            sys.exit("REFUSING: %s already exists (use --force)" % sdest)
        with open(sdest, "wb") as f:
            f.write(forge_sum(data))
            f.flush()
            os.fsync(f.fileno())
        extra.append(str(sdest))

    subprocess.run(["sync"], check=False)
    time.sleep(0.5)
    subprocess.run(["sync"], check=False)

    ledger = {"ts": dt.datetime.now().isoformat(timespec="seconds"),
              "mutant": str(mutant), "md5": mmd5, "size": len(data),
              "dest": "/" + target + "/" + mutant.name, "extra": extra,
              "device": dev, "strategy_hint": args.note or ""}
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    with open(args.ledger, "a") as f:
        f.write(json.dumps(ledger) + "\n")

    if not args.keep_mounted:
        unmount(dev)
    else:
        print("[harness] --keep-mounted: leaving %s mounted (run 'sync' is already done)" % mnt)

    print(json.dumps(ledger, indent=2))
    print("""
==================== YOUR PART (device is unplugged-ready) ====================
1. Physically UNPLUG the nüvi from this computer.
2. POWER IT ON (external/car power or battery — note it may be low).
3. Let it BOOT and run the trigger for this file type:
     .gpx  -> just booting imports Garmin/GPX/*.gpx; also Settings > Tracks/My Data
     .jpg  -> Pictures > open the file / start the slideshow
     .vpm  -> Settings > Language/Voice > select the new voice; play any prompt
     .srf  -> Settings > Map & Vehicle > vehicle icon > pick the new one
     .typ  -> (experimental) reboot with map view open
4. OBSERVE and note ONE of:  normal  |  reboot loop / no boot  |  hang / freeze  |
   crash+restart  |  app error dialog  |  weird behaviour (describe).
5. PLUG IT BACK IN here, then run:
     python3 refs/tools/fuzz_harness.py collect
6. Record the outcome (mutant name, observed behaviour, collect result) in
   refs/fuzz-corpus/results.md. Rollback = delete the injected file (see PLAN.md).
===============================================================================""")


# ---------------------------------------------------------------------------
# subcommand: collect

def cmd_collect(args):
    dev = find_device()
    mnt = mount_ro(dev)
    files, log = read_oracle(mnt)
    records = summarize_log(log)

    bdir = Path(args.baseline)
    base = json.loads((bdir / "baseline.json").read_text())
    base_hashes = set(base.get("log_record_hashes", []))
    base_files = base.get("files", {})

    new_files = [n for n in files if n not in base_files]
    # compare size only (mtime format drift on FAT is noise); shutdown.log growth is
    # handled by the record diff below, not here
    grown = [n for n in files if n in base_files and n != SHUTDOWN_LOG
             and files[n][0] != base_files[n]["size"]]
    new_records = [r for r in records if r["_sha"] not in base_hashes]
    log_grew = len(records) > base.get("log_records", 0)

    report = {
        "collected": dt.datetime.now().isoformat(timespec="seconds"),
        "baseline": {"captured": base.get("captured"), "sha256": base.get("snapshot_sha256"),
                     "files": base.get("file_count"), "log_records": base.get("log_records")},
        "now": {"files": len(files), "log_records": len(records), "log_size": len(log)},
        "log_grew": log_grew,
        "new_files": new_files, "changed_files": grown,
        "new_records": new_records,
        "traps": [r for r in new_records if r.get("Error_Cause") == "1"],
        "trap_html": [],
    }
    for n in new_files:
        if "RTL_Trap" in n:
            report["trap_html"].append(parse_trap_html(Path(mnt) / SHUTDOWN_DIR / n))

    # --- human report
    print("oracle diff vs baseline %s (snapshot %s)" % (report["baseline"]["captured"],
                                                        (report["baseline"]["sha256"] or "")[:16]))
    print("  files: %d -> %d   log records: %d -> %d" %
          (report["baseline"]["files"], len(files), report["baseline"]["log_records"], len(records)))
    verdict = 0
    if report["traps"] or report["trap_html"]:
        verdict = 2
    elif new_records or new_files or log_grew:
        verdict = 3
    if log_grew:
        print("\nNOTE: shutdown.log grew (%d -> %d records) even though all records match"
              " known hashes — the device shut down again (identical content, e.g. another"
              " RTC-reset/powerdown burst). Correlate with your inject session." %
              (base.get("log_records", 0), len(records)))
    if new_files:
        print("\nNEW FILES in %s:" % SHUTDOWN_DIR)
        for n in new_files:
            print("  + %s (%d B)" % (n, files[n][0]))
    if grown:
        print("\nCHANGED FILES (size):")
        for n in grown:
            print("  * %s %s -> %d B" % (n, base_files[n]["size"], files[n][0]))
    if new_records:
        print("\nNEW shutdown.log records (%d):" % len(new_records))
        for r in new_records:
            cause = r.get("Error_Cause", "?")
            print("  + %s  cause=%s (%s)  ver=%s  reg_nonzero=%s/%s  rtl_info=%r" %
                  (r.get("Time", "?"), cause, CAUSE_NAMES.get(cause, "?"),
                   r.get("SystemVersion", "?"), r.get("reg_nonzero", "?"), r.get("reg_count", "?"),
                   (r.get("RTL_Trap_Info") or "")[:80]))
    if report["trap_html"]:
        print("\nNEW RTL_Trap HTML records (parsed):")
        for t in report["trap_html"]:
            print("  + %s\n    error=%s uptime=%s task=%s\n    rtl_line=%s\n    stack=%s" %
                  (t["file"], t.get("error_number"), t.get("uptime"), t.get("task_id"),
                   t.get("rtl_line"), " <- ".join(t.get("call_stack", [])[:8]) or "(none)"))
    if verdict == 0:
        print("\nRESULT: no new oracle records — clean run for whatever was injected last.")
    elif verdict == 2:
        print("\nRESULT: *** NEW RTL_Trap RECORD(S) — parser crash captured. ***")
        print("  Save the mutant that produced it (see refs/fuzz-corpus/injected.log),")
        print("  rename to e.g. CRASH-<name>, and re-run once to confirm reproducibility.")
    else:
        print("\nRESULT: new non-trap record(s) (powerdown/low-battery class). Weak/ambiguous")
        print("  signal — correlate timing with your inject session before claiming a crash.")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
        print("\nfull diff -> %s" % args.json)
    maybe_unmount(dev, args)
    sys.exit(verdict)


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("baseline", help="snapshot crash oracle (READ-ONLY)")
    b.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    b.add_argument("--leave-mounted", action="store_true")
    b.set_defaults(fn=cmd_baseline)

    i = sub.add_parser("inject", help="WRITE one mutant to the device (user-invoked!)")
    i.add_argument("--file", required=True, help="mutant file produced by fuzz_mutate.py")
    i.add_argument("--target", default="auto",
                   choices=["auto", "gpx", "jpeg", "voice", "vehicle", "garmin"],
                   help="device dir; auto = by extension (default)")
    i.add_argument("--yes", action="store_true", help="skip the INJECT prompt (still logs)")
    i.add_argument("--force", action="store_true", help="allow overwriting an existing device file")
    i.add_argument("--keep-mounted", action="store_true", help="do not unmount after copy")
    i.add_argument("--note", default="", help="free-text note into the ledger (e.g. batch id)")
    i.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    i.set_defaults(fn=cmd_inject)

    c = sub.add_parser("collect", help="diff crash oracle vs baseline (READ-ONLY)")
    c.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    c.add_argument("--json", default=None, help="also write full diff report JSON here")
    c.add_argument("--leave-mounted", action="store_true")
    c.set_defaults(fn=cmd_collect)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
