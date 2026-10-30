#!/usr/bin/env python3
"""fuzz_mutate.py — deterministic, structure-aware-ish mutator for nüvi 2595 parser fuzzing (F5, T1 vector).

Design goals (see refs/fuzz-corpus/PLAN.md):
  * Deterministic: mutant i for a given --rng and seed file is byte-identical on every run.
    RNG stream for mutant i = random.Random(rng_seed ^ md5(seed) ^ i_rotated) — re-running the
    same command reproduces the exact same corpus (important: an injected mutant that crashed
    the device must be reproducible from the ledger without keeping big outputs around).
  * Generic mutation operators (bit/byte flips, interesting values, truncation, chunk delete,
    extension) plus per-format operators keyed on extension:
      .gpx  XML-aware: broken tags, huge attr values, coordinate edge cases (NaN/1e9999/huge),
            entity/DOCTYPE bombs, encoding-decl corruption
      .jpg  marker-aware: segment length fields -> 0x0000/0xFFFF, SOF dims -> 65535x65535 / 0x0,
            strip EOI, corrupt DQT, COM bomb
      .vpm  header corruption in first 0x40 bytes (encrypted body — treat as opaque)
      .srf  "GARMIN BITMAP 01" TLV walker: corrupt type/len fields (0, 0xFFFFFFFF, len±1)
      .typ  "GARMIN TYP" subfile: header_len u16, magic, u32 offset/size fields in first header
  * Output size bounded (seed*2 + 256 KB max) to keep the corpus sane (<50 MB total budget).

Usage:
  fuzz_mutate.py SEED... --out DIR [-n N] [--rng SEED] [--strategies a,b,c | --strategies all]
  fuzz_mutate.py refs/fuzz-corpus/seeds --out /tmp/mut -n 20 --rng 1

Never touches the device. Inject with fuzz_harness.py inject (user-invoked only).
"""

import argparse
import hashlib
import json
import os
import random
import sys
from pathlib import Path

MAX_OUT_SIZE = 256 * 1024 + 2 * 1024 * 1024  # hard cap per mutant

# ---------------------------------------------------------------------------
# interesting values
INTERESTING8 = [0x00, 0x01, 0x0A, 0x0D, 0x20, 0x7F, 0x80, 0xFE, 0xFF]
INTERESTING16 = [0x0000, 0x0001, 0x0002, 0x007F, 0x0080, 0x00FF, 0x0100, 0x7FFF,
                 0x8000, 0xFFFE, 0xFFFF]
INTERESTING32 = [0x00000000, 0x00000001, 0x00000002, 0x0000007F, 0x00000080,
                 0x000000FF, 0x00000100, 0x00007FFF, 0x00008000, 0x0000FFFF,
                 0x00010000, 0x00100000, 0x7FFFFFFE, 0x7FFFFFFF, 0x80000000,
                 0x80000001, 0xFFFFFF00, 0xFFFFFFFE, 0xFFFFFFFF]
GPX_COORD_EDGE = [b"NaN", b"nan", b"-nan", b"1e9999", b"-1e9999", b"0", b"-1",
                  b"99999999999999999", b"-99999999999999999", b"1.7976931348623157e309",
                  b"0x41", b"INF", b"-INF", b"1e-999"]
XML_ENCODINGS = [b'UTF-16', b'UTF-32', b'UCS-4', b'ISO-8859-1', b'SHIFT_JIS', b'nonsense-8']


# ---------------------------------------------------------------------------
# generic operators (each returns (data, description))

def op_bitflip(d, rng):
    n = rng.randint(1, 16)
    desc_bits = []
    b = bytearray(d)
    for _ in range(n):
        if not b:
            break
        off = rng.randrange(len(b))
        bit = rng.randrange(8)
        b[off] ^= 1 << bit
        desc_bits.append("%d:%d" % (off, bit))
    return bytes(b), "bitflip x%d [%s]" % (n, ",".join(desc_bits[:5]) + ("..." if n > 5 else ""))


def op_byteflip(d, rng):
    b = bytearray(d)
    n = min(rng.randint(1, 64), max(1, len(b)))
    mode = rng.choice(["zero", "ff", "rand"])
    offs = rng.sample(range(len(b)), n) if len(b) >= n else list(range(len(b)))
    for off in offs:
        b[off] = {"zero": 0x00, "ff": 0xFF, "rand": rng.randrange(256)}[mode]
    return bytes(b), "byteflip x%d mode=%s" % (n, mode)


def op_interesting8(d, rng):
    b = bytearray(d)
    n = rng.randint(1, 8)
    for _ in range(n):
        if not b:
            break
        off = rng.randrange(len(b))
        b[off] = rng.choice(INTERESTING8)
    return bytes(b), "interesting8 x%d" % n


def _write_int(b, off, val, width):
    if off + width > len(b):
        return False
    b[off:off + width] = val.to_bytes(width, "little")
    return True


def op_interesting_int(d, rng):
    b = bytearray(d)
    width = rng.choice([2, 2, 4, 4, 4])
    off = rng.randrange(max(1, len(b) - width)) if len(b) > width else 0
    pool = INTERESTING16 if width == 2 else INTERESTING32
    val = rng.choice(pool)
    _write_int(b, off, val, width)
    return bytes(b), "int%d 0x%X @0x%X" % (width * 8, val, off)


def op_length_bomb(d, rng):
    """Write huge / negative-ish / zero 'length' dwords at semi-random offsets —
    the classic 'trust the declared length' parser bug."""
    b = bytearray(d)
    val = rng.choice([0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFF, 0x7FFF, 0x0000,
                      0xFFFFFFF0, 0x00010000, 0x00100000])
    width = 4 if val > 0xFFFF else rng.choice([2, 4])
    n = rng.randint(1, 3)
    offs = []
    for _ in range(n):
        off = rng.randrange(max(1, len(b) - width)) if len(b) > width else 0
        if _write_int(b, off, val, width):
            offs.append(off)
    return bytes(b), "length-bomb 0x%X(w=%d) @%s" % (val, width, ",".join("0x%X" % o for o in offs))


def op_truncate(d, rng):
    if len(d) < 8:
        return b"", "truncate (tiny seed)"
    if rng.random() < 0.5:
        sz = max(1, int(len(d) * rng.uniform(0.05, 0.95)))
    else:
        sz = rng.choice([1, 8, 16, 64, 512, 4096, 65536])
    return d[:min(sz, len(d))], "truncate to %d/%d B" % (min(sz, len(d)), len(d))


def op_chunkdel(d, rng):
    if len(d) < 64:
        return op_truncate(d, rng)
    span = int(len(d) * rng.uniform(0.05, 0.4))
    off = rng.randrange(0, len(d) - span)
    return d[:off] + d[off + span:], "chunkdel %d B @0x%X" % (span, off)


def op_extend(d, rng):
    n = rng.choice([16, 64, 4096, 65536, rng.randint(1, 262144)])
    fill = rng.choice([b"\x00", b"\xFF", bytes(rng.randrange(256) for _ in range(64)) * (n // 64 + 1)])
    return d + fill[:n], "extend +%d B (%s)" % (n, "rand" if len(fill) > 4 else fill[:1].hex())


def op_havoc(d, rng):
    """2-5 random generic ops composed."""
    cur, descs = d, []
    for _ in range(rng.randint(2, 5)):
        cur, ds = rng.choice([op_bitflip, op_byteflip, op_interesting8, op_interesting_int,
                              op_length_bomb, op_chunkdel])(cur, rng)
        descs.append(ds)
    return cur, "havoc{%s}" % "; ".join(descs[:3])


# ---------------------------------------------------------------------------
# format-aware operators

def op_gpx_tag_break(d, rng):
    """Drop a random closing tag / insert a stray '<' — XML well-formedness stress."""
    b = bytearray(d)
    if rng.random() < 0.5:
        closes = [m for m in range(len(b)) if b[m:m + 2] == b"</"]
        if closes:
            off = rng.choice(closes)
            end = b.find(b">", off)
            if end != -1:
                del b[off:end + 1]
                return bytes(b), "gpx: dropped closing tag @0x%X" % off
    off = rng.randrange(len(b) + 1)
    b[off:off] = b"<"
    return bytes(b), "gpx: stray '<' @0x%X" % off


def op_gpx_coord_edge(d, rng):
    """Replace a coordinate/numeric payload with an edge-case string."""
    needles = [b"<gpxtpx:hr>", b"<ele>", b"<speed>", b"<course>", b"<lat>", b"<lon>",
               b"<extensions>", b"<trkpt ", b"<wpt ", b"<time>"]
    hits = []
    for nd in needles:
        start = 0
        while True:
            i = d.find(nd, start)
            if i == -1:
                break
            hits.append(i)
            start = i + 1
    if not hits:
        return op_interesting_int(d, rng)
    off = rng.choice(hits)
    gt = d.find(b">", off)
    val = rng.choice(GPX_COORD_EDGE)
    if gt != -1:
        return d[:gt + 1] + val + d[gt + 1:], "gpx: coord edge %r @0x%X" % (val, off)
    return op_interesting_int(d, rng)


def op_gpx_attr_bomb(d, rng):
    """Inflate an attribute value to 64KB-1MB of 'A' (buffer-size trust) or inject huge int."""
    tag = rng.choice([b"<trkpt ", b"<wpt ", b"<gpx ", b"<extensions>"])
    i = d.find(tag)
    if i == -1:
        return op_byteflip(d, rng)
    n = rng.choice([1024, 65536, 262144, 1048576])
    return d[:i] + tag + b' fuzz="' + b"A" * n + b'"' + d[i + len(tag):], \
        "gpx: attr bomb %d B on %r" % (n, tag.decode())


def op_gpx_entity_bomb(d, rng):
    """DOCTYPE + recursive entity (billion-laughs style) injected after the XML decl."""
    bomb = (b'<!DOCTYPE bomb [\n'
            b'<!ENTITY a "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">\n'
            b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
            b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
            b'<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">\n'
            b'<!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">\n'
            b'<!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">\n'
            b']>\n'
            b'<!-- &f;&f;&f;&f;&f;&f; -->\n')
    anchor = d.find(b"?>")
    pos = anchor + 2 if anchor != -1 else 0
    return d[:pos] + bomb + d[pos:], "gpx: DOCTYPE/entity bomb after decl"


def op_gpx_encoding(d, rng):
    """Corrupt the XML declaration encoding — charset confusion stress."""
    enc = rng.choice(XML_ENCODINGS)
    import re
    m = re.search(rb'encoding="[^"]*"', d)
    if not m:
        return op_gpx_tag_break(d, rng)
    return d[:m.start()] + b'encoding="' + enc + b'"' + d[m.end():], \
        "gpx: encoding decl -> %r" % enc.decode()


def _jpeg_markers(d):
    """Yield (offset, marker) for all standalone markers with a following length field."""
    out = []
    i = 2  # skip SOI
    while i + 4 <= len(d):
        if d[i] != 0xFF:
            break
        m = d[i + 1]
        if m in (0xD8, 0xD9, 0x01) or 0xD0 <= m <= 0xD7:  # no length field
            i += 2
            continue
        ln = (d[i + 2] << 8) | d[i + 3]
        out.append((i, m, ln))
        i += 2 + ln
        if m == 0xDA:  # SOS — entropy data follows, stop structure walk
            break
    return out


def op_jpeg_marker_len(d, rng):
    ms = _jpeg_markers(d)
    if not ms:
        return op_byteflip(d, rng)
    off, m, _ = rng.choice(ms)
    b = bytearray(d)
    val = rng.choice([0x0000, 0x0001, 0x0003, 0x7FFF, 0xFFFF])
    b[off + 2:off + 4] = val.to_bytes(2, "big")
    return bytes(b), "jpeg: marker FF%02X len -> 0x%04X @0x%X" % (m, val, off)


def op_jpeg_sof_dims(d, rng):
    ms = [t for t in _jpeg_markers(d) if 0xC0 <= t[1] <= 0xCF and t[1] not in (0xC4, 0xC8, 0xCC)]
    if not ms:
        return op_jpeg_marker_len(d, rng)
    off, m, _ = ms[0]
    b = bytearray(d)
    h, w = rng.choice([(0xFFFF, 0xFFFF), (0, 0), (0x8000, 0x8000), (1, 0xFFFF), (0xFFFF, 1)])
    b[off + 5:off + 7] = h.to_bytes(2, "big")
    b[off + 7:off + 9] = w.to_bytes(2, "big")
    return bytes(b), "jpeg: SOF FF%02X dims -> %dx%d" % (m, w, h)


def op_jpeg_strip_eoi(d, rng):
    i = d.rfind(b"\xFF\xD9")
    if i == -1:
        return op_truncate(d, rng)
    return d[:i], "jpeg: strip EOI"


def op_jpeg_dqt(d, rng):
    ms = [t for t in _jpeg_markers(d) if t[1] == 0xDB]
    if not ms:
        return op_byteflip(d, rng)
    off, m, ln = rng.choice(ms)
    b = bytearray(d)
    for _ in range(rng.randint(4, 32)):
        b[off + rng.randrange(4, min(ln, len(b) - off))] = rng.choice(INTERESTING8)
    return bytes(b), "jpeg: DQT corrupt @0x%X" % off


def op_jpeg_com_bomb(d, rng):
    """Insert a COM segment with a huge payload right after SOI."""
    n = rng.choice([4096, 65536, 262144])
    n = min(n, 0xFFFF - 2)  # marker length field is u16 — can't express bigger
    seg = b"\xFF\xFE" + ((n + 2).to_bytes(2, "big")) + b"A" * n
    return d[:2] + seg + d[2:], "jpeg: COM bomb %d B" % n


def op_srf_tlv(d, rng):
    """car_blue.srf = 'GARMIN BITMAP 01' + (u32 type, u32 len, value)* — corrupt one TLV."""
    if len(d) < 24:
        return op_truncate(d, rng)
    hdr_ok = d[:16] == b"GARMIN BITMAP 01"
    tlvs = []
    off = 16
    while off + 8 <= len(d) and len(tlvs) < 64:
        t = int.from_bytes(d[off:off + 4], "little")
        l = int.from_bytes(d[off + 4:off + 8], "little")
        tlvs.append((off, t, l))
        if l > len(d):  # already corrupt / not a clean TLV stream
            break
        off += 8 + l
    if tlvs and rng.random() < 0.8:
        toff, t, l = rng.choice(tlvs)
        b = bytearray(d)
        which = rng.choice(["type", "len"])
        val = rng.choice([0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, (l + 1) if which == "len" else 0x100,
                          (max(0, l - 1)) if which == "len" else 0xFF])
        b[toff + (0 if which == "type" else 4):toff + 8] = val.to_bytes(4, "little")
        return bytes(b), "srf: TLV(%s of type=0x%X len=%d) -> 0x%X @0x%X" % (which, t, l, val, toff)
    # header corruption
    b = bytearray(d)
    off = rng.randrange(0, 16)
    b[off] = rng.choice(INTERESTING8)
    tag = " (header corrupt %r)" % ("hdr-magic" if not hdr_ok else "field@0x%X" % off)
    return bytes(b), "srf: header byte @0x%X%s" % (off, tag)


def op_typ_header(d, rng):
    """TYP subfile: u16 header_len @0, 'GARMIN TYP' @2, then u32 section offset/size pairs."""
    b = bytearray(d)
    if len(b) >= 4 and rng.random() < 0.35:
        what = rng.random()
        if what < 0.5:
            b[0:2] = rng.choice([0x0000, 0xFFFF, 0x7FFF, 0x0100]).to_bytes(2, "little")
            return bytes(b), "typ: header_len -> %s" % b[0:2].hex()
        b[2:12] = rng.choice([b"GARMIN TXP", b"GARMN TYP\0", b"\x00" * 10, b"GARMIN TYP!"])
        return bytes(b), "typ: magic corrupt"
    # corrupt a u32 in the header (section offsets/sizes live in the first header_len bytes)
    hlen = int.from_bytes(d[0:2], "little") if len(d) >= 2 else 0xA4
    hlen = min(max(hlen, 0x10), len(b) - 4) if len(b) > 0x14 else max(0x10, len(b) - 4)
    off = rng.randrange(0x0C, min(hlen, len(b) - 4))
    val = rng.choice(INTERESTING32)
    b[off:off + 4] = val.to_bytes(4, "little")
    return bytes(b), "typ: u32 @0x%X -> 0x%08X" % (off, val)


def op_vpm_header(d, rng):
    """Voice .vpm header is obfuscated — corrupt first 0x40 bytes (magic/len/section fields)."""
    b = bytearray(d)
    n = rng.randint(1, 4)
    for _ in range(n):
        off = rng.randrange(0, min(0x40, len(b)))
        if rng.random() < 0.6:
            b[off] = rng.choice(INTERESTING8)
        else:
            w = rng.choice([2, 4])
            val = rng.choice(INTERESTING16 if w == 2 else INTERESTING32)
            _write_int(b, off, val, w)
    return bytes(b), "vpm: header corrupt x%d (first 0x40 B)" % n


# ---------------------------------------------------------------------------
GENERIC = {
    "bitflip": op_bitflip, "byteflip": op_byteflip, "interesting8": op_interesting8,
    "interesting_int": op_interesting_int, "length_bomb": op_length_bomb,
    "truncate": op_truncate, "chunkdel": op_chunkdel, "extend": op_extend,
    "havoc": op_havoc,
}
FORMAT = {
    "gpx": {"gpx_tag_break": op_gpx_tag_break, "gpx_coord_edge": op_gpx_coord_edge,
            "gpx_attr_bomb": op_gpx_attr_bomb, "gpx_entity_bomb": op_gpx_entity_bomb,
            "gpx_encoding": op_gpx_encoding},
    "jpg": {"jpeg_marker_len": op_jpeg_marker_len, "jpeg_sof_dims": op_jpeg_sof_dims,
            "jpeg_strip_eoi": op_jpeg_strip_eoi, "jpeg_dqt": op_jpeg_dqt,
            "jpeg_com_bomb": op_jpeg_com_bomb},
    "vpm": {"vpm_header": op_vpm_header},
    "srf": {"srf_tlv": op_srf_tlv},
    "typ": {"typ_header": op_typ_header},
}
EXT_TO_FMT = {".gpx": "gpx", ".xml": "gpx", ".jpg": "jpg", ".jpeg": "jpg",
              ".vpm": "vpm", ".srf": "srf", ".typ": "typ"}


def strategies_for(seed: Path, want: str):
    ext = seed.suffix.lower()
    fmt = EXT_TO_FMT.get(ext)
    names = list(GENERIC)
    if fmt:
        names += list(FORMAT[fmt])
    if want == "all":
        return names
    picked = [s for s in want.split(",") if s.strip()]
    bad = [s for s in picked if s not in names]
    if bad:
        sys.exit("unknown strategy for %s: %s (available: %s)" % (seed.name, ",".join(bad), ",".join(names)))
    return picked


def mutate(seed: Path, data: bytes, strat: str, rng: random.Random):
    fn = GENERIC.get(strat) or FORMAT[EXT_TO_FMT[seed.suffix.lower()]][strat]
    out, desc = fn(data, rng)
    return out[:MAX_OUT_SIZE], desc + ("" if len(out) <= MAX_OUT_SIZE else " [capped at %d B]" % MAX_OUT_SIZE)


def mutant_rng(rng_seed: int, seed_md5: bytes, idx: int) -> random.Random:
    h = hashlib.sha256(b"%d|%s|%d" % (rng_seed, seed_md5, idx)).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def main():
    ap = argparse.ArgumentParser(description="deterministic structure-aware-ish mutator (F5)")
    ap.add_argument("seeds", nargs="+", help="seed file(s) or directory (recursed by extension)")
    ap.add_argument("--out", required=True, help="output directory (created if missing)")
    ap.add_argument("-n", "--num", type=int, default=10, help="number of mutants to emit (default 10)")
    ap.add_argument("--rng", type=lambda x: int(x, 0), default=0, help="RNG seed (default 0); change for a new batch")
    ap.add_argument("--strategies", default="all", help="comma list or 'all' (default all)")
    ap.add_argument("--dry-run", action="store_true", help="print plan, write nothing")
    args = ap.parse_args()

    seeds = []
    for s in args.seeds:
        p = Path(s)
        if p.is_dir():
            seeds += sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in EXT_TO_FMT)
        elif p.is_file():
            seeds.append(p)
        else:
            sys.exit("no such seed: %s" % s)
    if not seeds:
        sys.exit("no usable seeds found (known exts: %s)" % ",".join(sorted(EXT_TO_FMT)))

    outdir = Path(args.out)
    if not args.dry_run:
        outdir.mkdir(parents=True, exist_ok=True)
        manifest = outdir / "manifest.jsonl"

    made = 0
    for i in range(args.num):
        seed = seeds[i % len(seeds)]           # round-robin: N outputs spread across seeds
        data = seed.read_bytes()
        smd5 = hashlib.md5(data).digest()
        rng = mutant_rng(args.rng, smd5, i)
        strats = strategies_for(seed, args.strategies)
        strat = strats[rng.randrange(len(strats))]
        out, desc = mutate(seed, data, strat, rng)
        omd5 = hashlib.md5(out).hexdigest()
        name = "%s.m%04d%s" % (seed.stem, i, seed.suffix.lower())
        print("%-34s <- %-28s %-18s %8d B  md5 %s  %s" %
              (name, seed.name, strat, len(out), omd5, desc))
        if args.dry_run:
            continue
        (outdir / name).write_bytes(out)
        with open(manifest, "a") as mf:
            mf.write(json.dumps({
                "mutant": name, "seed": str(seed), "seed_md5": smd5.hex(),
                "strategy": strat, "desc": desc, "rng": args.rng, "idx": i,
                "size": len(out), "md5": omd5}) + "\n")
        made += 1
    if not args.dry_run:
        print("\n%d mutants -> %s (manifest.jsonl updated)" % (made, outdir))


if __name__ == "__main__":
    main()
