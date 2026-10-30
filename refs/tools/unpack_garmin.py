#!/usr/bin/env python3
"""unpack_garmin.py — unpacker for Garmin 'GCD' container files ("GARMIN firmware (version 1.0)").

Format reverse-engineered 2026-10-30 from the nüvi 2595 RemoteSW blobs (Operation GARMINAGEDDON,
see findings/2026-10-30-F2-gcd-unpacker.md). No external dependencies.

Layout (empirical):
  0x00  6B   magic "GARMIN"
  0x06  2B   0x64 0x00  (constant across samples)
  0x08  u16  1                    (version?)
  0x0A  u16  1                    (version?)
  0x0C  u16  732                  (constant across samples; meaning TBD)
  0x0E  u16  5376 (0x1500)        (constant across samples; meaning TBD)
  0x10  34B   zeros
  0x32  2B   0x03 0x00 ...        (see samples)
  0x36  ~B   0x10d4 5c13 0445 0d14 4105 00 — 11B constant-ish blob (CRC? flags?)
  0x35  u16  length of copyright string
  0x37  ...  copyright ASCII ("Copyright 1996-2012 by Garmin Ltd. or its subsidiaries.")
  0x6E  records begin (copyright_off + copyright_len).

Record:
  0x00  4B   sync pattern 01 00 01 00
  0x04  u16  payload length (LE)
  0x06  u8   record type
  0x07  ...  payload
Known types: 0x00 = metadata (header block @0x6E = mostly zeros; @0x1000 = part-number block,
contains ASCII part number e.g. "006B090100" and templates like "006-B%04d-00"),
0x2D = bulk data (firmware image, padded sections), 0xFF = end trailer (last 9 bytes:
01 00 01 00 XX ff ff 00 00 — NOT a real record; treat specially).
Sections are zero-padded, often to 0x1000-ish boundaries.

The companion 006B048201.BIN is NOT this container — it is raw AVR firmware (ATmega,
JMP vector at 0x00) for the GTM FM traffic receiver brick.

Usage: unpack_garmin.py <file.gcd> [outdir]     (outdir default: <file>.unpack/)
"""
import struct
import sys
import re
from pathlib import Path

SYNC = b"\x01\x00\x01\x00"


def entropy(b):
    if not b:
        return 0.0
    from collections import Counter
    import math
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def parse_header(d):
    if d[:6] != b"GARMIN":
        raise ValueError(f"bad magic: {d[:6]!r}")
    h = {
        "magic": "GARMIN",
        "f0_06": d[6:8].hex(),
        "u16_08": struct.unpack("<H", d[8:10])[0],
        "u16_0A": struct.unpack("<H", d[10:12])[0],
        "u16_0C": struct.unpack("<H", d[12:14])[0],
        "u16_0E": struct.unpack("<H", d[14:16])[0],
    }
    idx = d.find(b"Copyright")
    if idx > 0:
        slen = struct.unpack("<H", d[idx - 2:idx])[0]
        h["copyright_off"] = idx
        h["copyright"] = d[idx:idx + slen].decode("ascii", "replace")
        h["records_start"] = idx + slen  # string ends here; the 0x6E in samples
    return h


def walk_records(d, start):
    """Yield (offset, type, payload_len, payload). Ends at the 9-byte end-trailer."""
    recs = []
    pos = start
    while pos + 7 <= len(d):
        if d[pos:pos + 4] != SYNC:
            # scan forward to next sync (sections are zero-padded; syncs are sparse)
            nxt = d.find(SYNC, pos)
            if nxt < 0 or nxt == len(d) - 9:
                # no more framed records: everything to the end-trailer is bulk data
                trailer_at = len(d) - 9
                if d[trailer_at:trailer_at + 4] == SYNC and d[trailer_at + 6] == 0xFF:
                    recs.append(("bulk", pos, trailer_at - pos, d[pos:trailer_at]))
                    recs.append(("end", trailer_at, 9, d[trailer_at:trailer_at + 9]))
                break
            recs.append(("pad", pos, nxt - pos, None))
            pos = nxt
            continue
        rlen = struct.unpack("<H", d[pos + 4:pos + 6])[0]
        rtype = d[pos + 6]
        if rtype == 0xFF and rlen >= 0xFF00:  # end trailer: 01 00 01 00 XX ff ff 00 00
            recs.append(("end", pos, 9, d[pos:pos + 9]))
            break
        payload = d[pos + 7:pos + 7 + rlen]
        recs.append((rtype, pos, rlen, payload))
        pos = pos + 7 + rlen
    return recs


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    src = Path(sys.argv[1])
    outdir = Path(sys.argv[2]) if len(sys.argv) > 2 else src.with_suffix(src.suffix + ".unpack")
    d = src.read_bytes()

    h = parse_header(d)
    print(f"{src.name}: {len(d)} bytes (0x{len(d):x})")
    for k, v in h.items():
        print(f"  hdr {k}: {v}")

    start = h.get("records_start", 0x6E)
    # sanity: is records_start a sync?
    if d[start:start + 4] != SYNC:
        start = d.find(SYNC, 0x60)
    recs = walk_records(d, start)

    outdir.mkdir(parents=True, exist_ok=True)
    n = 0
    for kind, off, ln, payload in recs:
        if kind == "pad":
            print(f"  [pad]   @0x{off:06x} {ln} bytes to next record")
            continue
        if kind == "bulk":
            n += 1
            name = f"bulk{n:02d}_off0x{off:06x}.bin"
            (outdir / name).write_bytes(payload)
            strings = re.findall(rb"[ -~]{6,}", payload)
            print(f"  [bulk]  @0x{off:06x} len={ln} entropy={entropy(payload):.2f} -> {name}")
            if strings:
                print(f"          strings: {strings[:6]}")
            continue
        if kind == "end":
            print(f"  [end]   @0x{off:06x} trailer: {payload.hex()}")
            continue
        n += 1
        name = f"rec{n:02d}_type0x{kind:02x}_off0x{off:06x}.bin"
        (outdir / name).write_bytes(payload)
        strings = re.findall(rb"[ -~]{6,}", payload)
        ent = entropy(payload)
        print(f"  [rec]   @0x{off:06x} type=0x{kind:02x} len={ln} entropy={ent:.2f} -> {name}")
        if strings:
            print(f"          strings: {strings[:5]}")
        if ln < 400:
            print(f"          hexdump: {payload[:80].hex()}")
    print(f"  extracted {n} records -> {outdir}/")


if __name__ == "__main__":
    main()
