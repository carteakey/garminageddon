#!/usr/bin/env python3
"""gcd_tool.py — parse / build / verify Garmin GCD firmware update files.

v2 (2026-10-30): corrected record framing per H. Oppmann, "Garmin GCD Firmware
Update File Format" (2026-08-31, refs/protocol/GCD_Format.pdf):
    record = u16 RecordID | u16 Length | byte[Length]   (all LE)
    header = "GARMIN" + u16 version, records start at 0x08.
Supersedes the v1 framing in unpack_garmin.py (which misread CheckPoint+header
as a "sync+len+type" triple — kept only for history).

Record IDs (infrastructure): 0x0001 CheckPoint (additive byte-sum to 0x00),
0x0002 Filler, 0x0003 PartNumber (9-byte 6-bit-coded), 0x0005 Copyright,
0x0006 FirmwareDescriptorType, 0x0007 FirmwareDescriptor, 0xFFFF End.
Other IDs = Firmware Data records (streams grouped by ID).

Firmware stream obfuscation: XOR byte given in the Firmware Descriptor
(Field ID 10, byte type). Payload container format = "Garmin BIN" (separate doc).

Usage:
  gcd_tool.py parse <file.gcd>              # full annotated parse + checkpoint verification
  gcd_tool.py roundtrip <file.gcd> [out]    # parse -> rebuild -> byte-identical check
  gcd_tool.py extract <file.gcd> <outdir>   # dump de-XORed firmware streams
"""
import struct
import sys
from pathlib import Path

INFRA = {
    0x0001: "CheckPoint",
    0x0002: "Filler",
    0x0003: "PartNumber",
    0x0005: "Copyright",
    0x0006: "FwDescType",
    0x0007: "FwDescriptor",
    0xFFFF: "End",
}

FW_DATA_NAMES = {
    0x0008: "boot.bin", 0x02BD: "fw_all.bin", 0x0401: "external_data.bin",
    0x0505: "firmware.BIN", 0x0510: "logo", 0x0533: "dskimg_0533.img",
    0x0566: "files.bin", 0x057F: "resources_057F.bin", 0x059E: "resources_059E.bin",
    0x05A5: "TTF font XOR 0x76", 0x0555: "fw_0555.bin",
}

FIELD_NAMES = {
    3: "end-of-list", 7: "value:31B", 8: "fw length (ushort)",
    9: "HWID", 10: "XOR / RecordID", 11: "erase flag", 12: "min version / ?",
    13: "SW version", 14: "?", 15: "?", 16: "?", 17: "?", 18: "?", 19: "?",
    20: "version20", 21: "remote sw version / fw length", 22: "value22",
    23: "len part1", 24: "len part2", 25: "len part3", 26: "dest address",
    32: "value32",
}
FIELD_SIZES = {0x00: 1, 0x10: 2, 0x20: 4, 0x40: 31, 0x50: 0}


def decode_part_number(b):
    """9 bytes -> 12-char part number via 6-bit codes (+0x20), per doc [1]."""
    bits = "".join(f"{x:08b}" for x in reversed(b))
    out = ""
    for i in range(0, 72, 6):
        out += chr(int(bits[i:i + 6], 2) + 0x20)
    return out


def parse_records(d):
    """Yield (offset, rid, content). Header = d[:8]."""
    if d[:6] != b"GARMIN":
        raise ValueError(f"bad magic {d[:6]!r}")
    version = struct.unpack("<H", d[6:8])[0]
    pos = 8
    while pos + 4 <= len(d):
        rid, rlen = struct.unpack("<HH", d[pos:pos + 4])
        content = d[pos + 4:pos + 4 + rlen]
        if len(content) < rlen:
            raise ValueError(f"truncated record at 0x{pos:x}")
        yield pos, rid, content
        pos += 4 + rlen
        if rid == 0xFFFF:
            break


def parse_file_split(d):
    """Return (records, tail_bytes, end_offset). Tail = bytes after the END record
    (main-firmware GCDs carry a 260-B post-END trailer: 4x0xFF magic + 256 B;
    bootloader checks only the 4-byte magic — F4, FUN_000007cc @0x7cc)."""
    recs = []
    pos = 8
    end_pos = None
    for off, rid, content in parse_records(d):
        recs.append((off, rid, content))
        pos = off + 4 + len(content)
        if rid == 0xFFFF:
            end_pos = pos
    tail = d[end_pos:] if end_pos is not None else b""
    return recs, tail, end_pos


def parse_descriptor_fields(content, type_list):
    """Return list of (field_id, ftype, raw_value) for a FwDescriptor (ID 7)."""
    vals, pos = [], 0
    for fid, ftype in type_list:
        size = FIELD_SIZES[ftype]
        raw = content[pos:pos + size]
        pos += size
        if ftype == 0x50:
            break
        vals.append((fid, ftype, raw))
    return vals


def parse_file(d):
    info = {"version": struct.unpack("<H", d[6:8])[0], "records": [], "checkpoint_errors": [],
            "streams": {}, "xor_bytes": set(), "descriptors": []}
    # CheckPoint invariant: sum of ALL file bytes from 0x00 (incl. "GARMIN"+version header)
    # up to and including the CheckPoint record == 0x00 (mod 256). Doc confirmed empirically.
    running_sum = sum(d[:8]) & 0xFF
    pending_types = None
    for off, rid, content in parse_records(d):
        rec = {"off": off, "id": rid, "len": len(content)}
        running_sum = (running_sum + sum(d[off:off + 4 + len(content)])) & 0xFF
        if rid == 0x0001:
            rec["note"] = "checkpoint byte 0x%02x, cumulative sum now 0x%02x %s" % (
                content[0], running_sum, "OK" if running_sum == 0 else "*** MISMATCH ***")
            if running_sum != 0:
                info["checkpoint_errors"].append(hex(off))
        elif rid == 0x0002:
            rec["note"] = "filler (%d zero bytes)" % len(content) if not any(content) else "NON-ZERO filler?"
        elif rid == 0x0003:
            rec["note"] = "part number: %s" % decode_part_number(content) if len(content) == 9 else f"HWID raw {content.hex()}"
        elif rid == 0x0005:
            rec["note"] = "copyright: %r" % content.decode("ascii", "replace")
        elif rid == 0x0006:
            pending_types = [(content[i], content[i + 1]) for i in range(0, len(content), 2)]
            rec["note"] = "desc type fields: " + ", ".join(
                f"({fid},{ftype:#04x} {FIELD_NAMES.get(fid,'?')})" for fid, ftype in pending_types)
        elif rid == 0x0007:
            vals = parse_descriptor_fields(content, pending_types or [])
            # field 10 appears twice: byte-type = XOR obfuscation, ushort-type = RecordID
            xor = next((raw[0] for fid, ft, raw in vals if fid == 10 and ft == 0x00), 0)
            recid = next((struct.unpack("<H", raw)[0] for fid, ft, raw in vals
                          if fid == 10 and ft == 0x10), None)
            fwlen = next((struct.unpack("<I", raw)[0] for fid, ft, raw in vals
                          if fid == 21 and ft == 0x20), None)
            info["xor_bytes"].add(xor)
            info["descriptors"].append({"off": off, "values": [(f, ft, r.hex()) for f, ft, r in vals],
                                        "data_record_id": recid, "stream_len": fwlen})
            rec["note"] = "descriptor: xor=0x%02x data_rec_id=%s stream_len=%s" % (xor, recid, fwlen)
        else:
            if rid == 0xFFFF:
                rec["note"] = "END"
            else:
                info["streams"].setdefault(rid, []).append((off, content))
                rec["note"] = "fw data stream 0x%04x %s (chunk %d, %d B)" % (
                    rid, FW_DATA_NAMES.get(rid, "?"), len(info["streams"][rid]), len(content))
        info["records"].append(rec)
    return info


def cmd_parse(path):
    d = Path(path).read_bytes()
    info = parse_file(d)
    print(f"{Path(path).name}: {len(d)} B, format V{info['version']//100}.{info['version']%100}")
    for r in info["records"]:
        print(f"  0x{r['off']:06x} id=0x{r['id']:04x} {INFRA.get(r['id'], 'FwData'):13s} len={r['len']:<6} {r.get('note','')}")
    if info["checkpoint_errors"]:
        print(f"  !! checkpoint MISMATCHES at: {info['checkpoint_errors']}")
    else:
        print(f"  all checkpoints verified (cumulative byte-sum == 0x00)")
    return info


def cmd_roundtrip(path, out=None):
    d = Path(path).read_bytes()
    recs, tail, _ = parse_file_split(d)
    rebuilt = bytearray(b"GARMIN") + struct.pack("<H", struct.unpack("<H", d[6:8])[0])
    for _, rid, content in recs:
        rebuilt += struct.pack("<HH", rid, len(content)) + content
    rebuilt += tail  # preserve post-END trailer (incl. 4x0xFF magic)
    rebuilt = bytes(rebuilt)
    ok = rebuilt == d
    print(f"roundtrip {Path(path).name}: rebuilt {len(rebuilt)} B vs {len(d)} B -> "
          f"{'BYTE-IDENTICAL ✓' if ok else 'DIFFERS ✗'}")
    if tail:
        magic_ok = tail[:4] == b"\xff\xff\xff\xff"
        print(f"  post-END tail preserved: {len(tail)} B, FF-magic {'✓' if magic_ok else '✗ ' + tail[:4].hex()}")
    if not ok:
        for i, (a, b) in enumerate(zip(d, rebuilt)):
            if a != b:
                print(f"  first diff at 0x{i:x}: {a:02x} vs {b:02x}")
                break
        else:
            print(f"  length differs: original has {len(d) - len(rebuilt)} extra bytes")
    if out:
        Path(out).write_bytes(rebuilt)
    return ok


def cmd_extract(path, outdir):
    d = Path(path).read_bytes()
    info = parse_file(d)
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    xors = info["xor_bytes"] or {0}
    xor = sorted(xors)[0]
    for rid, chunks in info["streams"].items():
        stream = b"".join(c for _, c in chunks)
        dec = bytes(b ^ xor for b in stream)
        name = f"{FW_DATA_NAMES.get(rid, 'stream')}_0x{rid:04x}_deXORed.bin"
        (outdir / name).write_bytes(dec)
        (outdir / name.replace("deXORed", "raw")).write_bytes(stream)
        print(f"stream 0x{rid:04x}: {len(chunks)} chunks, {len(stream)} B, xor=0x{xor:02x} -> {outdir/name}")
    return len(info["streams"])


def cmd_bump_version(path, out, new_ver):
    """Patch Firmware Descriptor SW-version field (ID 13, ushort) to new_ver
    (major*100+minor), recompute ALL CheckPoint bytes, preserve everything else
    (payloads, trailer). This makes the device see an upgrade while flashing
    byte-identical payloads."""
    d = bytearray(Path(path).read_bytes())
    recs, tail, _ = parse_file_split(bytes(d))
    patched = 0
    pending_types = None
    rebuild = bytearray(b"GARMIN") + d[6:8]
    running = sum(d[:8]) & 0xFF
    for off, rid, content in recs:
        c = bytearray(content)
        if rid == 0x0006:
            pending_types = [(content[i], content[i + 1]) for i in range(0, len(content), 2)]
        elif rid == 0x0007 and pending_types:
            pos = 0
            for fid, ftype in pending_types:
                size = FIELD_SIZES[ftype]
                if fid == 3 and ftype == 0x50:
                    break
                if fid == 13 and ftype == 0x10:
                    struct.pack_into("<H", c, pos, new_ver & 0xFFFF)
                    patched += 1
                pos += size
        elif rid == 0x0001 and len(c) == 1:
            hdr = struct.pack("<HH", rid, len(c))
            c[0] = (-(running + sum(hdr))) & 0xFF   # content cancels header+prior sum
            running = 0                              # invariant: cumulative sum == 0
            rebuild += hdr + bytes(c)
            continue
        chunk = struct.pack("<HH", rid, len(c)) + bytes(c)
        running = (running + sum(chunk)) & 0xFF   # actual byte values, not counts
        rebuild += chunk
    rebuild += tail
    Path(out).write_bytes(bytes(rebuild))
    print(f"bumped {patched} descriptor SW-version field(s) to {new_ver} ({new_ver//100}.{new_ver%100})")
    print(f"wrote {out}: {len(rebuild)} B (orig {len(d)} B)")

    # self-verify with the parser
    info = parse_file(bytes(rebuild))
    if info["checkpoint_errors"]:
        print(f"!! checkpoint verification FAILED at {info['checkpoint_errors']}")
        return False
    print(f"checkpoint verification: ALL OK ({len(info['records'])} records)")
    for desc in info["descriptors"]:
        print(f"  descriptor @0x{desc['off']:x}: data_rec_id={desc['data_record_id']} stream_len={desc['stream_len']}")
    return True


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "parse":
        cmd_parse(sys.argv[2])
    elif cmd == "roundtrip":
        cmd_roundtrip(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    elif cmd == "extract":
        cmd_extract(sys.argv[2], sys.argv[3])
    elif cmd == "bump-version":
        cmd_bump_version(sys.argv[2], sys.argv[3], int(sys.argv[4], 0))
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
