#!/usr/bin/env python3
"""GCD (Garmin firmware container) record walker + CheckPoint validator.

Framing per H. Oppmann, "Garmin GCD Firmware Update File Format" (2026-08-31),
repo copy: refs/protocol/GCD_Format.txt

  header:  "GARMIN" + u16 fmtver + ... + u16 len @0x35 + copyright @0x37
  record:  u16 record_id | u16 record_len | byte[record_len]
  ID 0x0001 CheckPoint (len 1): sum of ALL file bytes up to & incl. this byte == 0 (mod 256)
  ID 0x0002 Filler, 0x0003 PartNumber/HWID, 0x0005 Copyright,
  0x0006 Firmware Descriptor Type, 0x0007 Firmware Descriptor, 0xFFFF End (len 0)
"""
import sys

def u16(b, o): return b[o] | (b[o+1] << 8)
def u32(b, o): return b[o] | (b[o+1] << 8) | (b[o+2] << 16) | (b[o+3] << 24)

def decode_pn9(raw):
    """9-byte compressed part number -> 12 chars (6-bit codes + 0x20)."""
    bits = 0
    nbits = 0
    out = []
    for byte in reversed(raw):
        bits = (bits << 8) | byte
        nbits += 8
        while nbits >= 6:
            nbits -= 6
            code = (bits >> nbits) & 0x3F
            out.append(chr(code + 0x20))
    return "".join(out)

def parse_desc_fields(content):
    """Parse (field_id, type) pairs from a Firmware Descriptor Type record."""
    fields = []
    for i in range(0, len(content) - 1, 2):
        fid, ftype = content[i], content[i+1]
        if ftype == 0x50:
            break
        fields.append((fid, ftype))
    return fields

def parse_desc_values(content, fields):
    """Walk the Firmware Descriptor record values per the declared field layout."""
    vals = {}
    off = 0
    size = {0x00: 1, 0x10: 2, 0x20: 4, 0x40: 31}
    for fid, ftype in fields:
        if ftype not in size or off + size[ftype] > len(content):
            break
        n = size[ftype]
        raw = content[off:off+n]
        off += n
        if n == 1:
            vals[f"byte:{fid}"] = raw[0]
        elif n == 2:
            vals[f"u16:{fid}"] = u16(raw, 0)
        elif n == 4:
            vals[f"u32:{fid}"] = u32(raw, 0)
        else:
            vals[f"raw:{fid}"] = raw.hex()
    return vals, off

def main(path):
    data = open(path, "rb").read()
    print(f"== {path}")
    print(f"size: {len(data)}")
    if data[:6] != b"GARMIN":
        print("BAD MAGIC"); return 1
    print(f"container version: {u16(data,6)}.{u16(data,8)}  fmt0x{u16(data,10):04x} 0x{u16(data,12):04x}")
    cplen = u16(data, 0x35)
    print(f"copyright @0x37 ({cplen}B): {data[0x37:0x37+cplen].decode('ascii', 'replace')}")
    off = 0x37 + cplen
    print(f"records begin @0x{off:x}")

    checksums_ok = []
    checksums_bad = []
    streams = {}   # record_id -> bytes total
    desc = None
    desctype = None
    nrec = 0
    while off + 4 <= len(data):
        rid = u16(data, off)
        rlen = u16(data, off + 2)
        content_off = off + 4
        if content_off + rlen > len(data):
            print(f"  !! truncated record id=0x{rid:04x} len={rlen} @0x{off:x}")
            break
        content = data[content_off:content_off + rlen]
        nrec += 1
        note = ""
        if rid == 0x0001 and rlen == 1:
            s = sum(data[:content_off + 1]) & 0xFF
            ok = (s == 0)
            (checksums_ok if ok else checksums_bad).append((off, content[0]))
            note = f"CheckPoint byte=0x{content[0]:02x} sum-check {'OK' if ok else 'FAIL(sum=%02x)' % s}"
        elif rid == 0x0002:
            note = f"Filler {rlen}B"
        elif rid == 0x0003 and rlen == 9:
            note = f"PartNumber: {decode_pn9(content)!r} (raw {content.hex()})"
        elif rid == 0x0003 and rlen == 2:
            note = f"HWID record: {u16(content,0)}"
        elif rid == 0x0005:
            note = f"Copyright: {content.decode('ascii','replace')[:60]!r}"
        elif rid == 0x0006:
            desctype = parse_desc_fields(content)
            note = f"DescType: {len(desctype)} fields " + " ".join(f"{fid}/0x{ft:02x}" for fid, ft in desctype)
        elif rid == 0x0007:
            if desctype:
                vals, used = parse_desc_values(content, desctype)
                desc = vals
                note = f"Descriptor: {vals}"
            else:
                note = f"Descriptor (no preceding type record) raw={content.hex()[:80]}"
        elif rid == 0xFFFF:
            note = "END record"
            print(f"  @0x{off:08x} id=0x{rid:04x} len={rlen:<6} {note}")
            off = content_off + rlen
            break
        else:
            streams[rid] = streams.get(rid, 0) + rlen
            note = f"Data record (stream)"
        if nrec <= 12 or rid in (0x0001, 0x0003, 0x0006, 0x0007, 0xFFFF):
            print(f"  @0x{off:08x} id=0x{rid:04x} len={rlen:<6} {note}")
        off = content_off + rlen

    print(f"walked {nrec} records, ended @0x{off:x} (file end 0x{len(data):x}, slack {len(data)-off}B)")
    print(f"CheckPoint records: {len(checksums_ok)} OK, {len(checksums_bad)} BAD")
    if desc:
        hwid = desc.get(9)
        swv = desc.get(13)
        xor = desc.get(10) if isinstance(desc.get(10), int) and desc.get(10, 0) < 256 else None
        ln = desc.get(21)
        print(f"HWID={hwid}  SW version field13={swv} ({(swv or 0)//100}.{(swv or 0)%100:02d})  XOR obfuscation byte={xor}  declared fw length={ln}")
        for fid in (20, 21, 12, 26):
            if fid in desc and fid != 21:
                print(f"  field {fid}: {desc[fid]}")
    if streams:
        print("firmware streams (record_id -> total bytes):")
        for rid, total in sorted(streams.items()):
            print(f"  0x{rid:04x}: {total}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
