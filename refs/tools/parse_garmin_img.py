#!/usr/bin/env python3
"""parse_garmin_img.py — Garmin IMG (DSKIMG) container parser for Operation GARMINAGEDDON.

Read-only. Prints: DSKIMG header fields, the FAT (directory) records, the
subfile table (name/type/offset/size/blocks), per-subfile common headers, and
deep-parses TRE subfiles (map ID, bounding box, sections, hash).

Format references (verified against mkgmap source, GPL):
  - OSM wiki "OSM Map On Garmin/IMG File Format"
  - mkgmap: imgfmt/sys/{ImgFS,ImgHeader,Dirent,Directory,BlockTable}.java
Field layout of a FAT record (512-byte slot, little-endian):
  0x00 u8  used flag (0x01 = slot in use)
  0x01 8s  subfile name (space padded)
  0x09 3s  extension/type (TRE, RGN, LBL, ...)
  0x0C u32 file size in bytes (part 0 only)
  0x10 u8  flag (0x03 = special directory self-reference entry)
  0x11 u16 part number (file split into parts of <=240 blocks)
  0x20 u16[240] block numbers (in file block-size units), 0xFFFF = unused
Header layout (512 bytes):
  0x00 u8  XOR obfuscation byte (if != 0, whole file is XORed with it)
  0x08 u16 version (major | minor<<8)
  0x0A u8  update month, 0x0B u8 update year (+1900 if >=0x63 else +2000)
  0x0E u8  gmapsupp flag, 0x0F u8 checksum (sum of all bytes mod 256 == 0)
  0x10 7s  "DSKIMG\\0",  0x41 7s "GARMIN\\0"
  0x18 u16 sectors, 0x1A u16 heads, 0x1C u16 cylinders (fake MBR geometry)
  0x40 u8  directory start block (512-byte units)
  0x49 20s map description, 0x65 30s description continuation
  0x61 u8  block size exponent1 (0x09), 0x62 u8 exponent2 -> bs = 2^(E1+E2)
  0x1FE u16 0x55AA partition signature
"""
import argparse
import struct
import sys


def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def s24(b, o):
    v = b[o] | (b[o + 1] << 8) | (b[o + 2] << 16)
    if v & 0x800000:
        v -= 0x1000000
    return v


def cstr(b, o, n, pad=b' '):
    raw = b[o:o + n]
    return raw.split(b'\x00')[0].decode('latin1').rstrip(' ')


class Subfile:
    def __init__(self, name, ext):
        self.name = name
        self.ext = ext
        self.size = None
        self.parts = {}          # part -> [blocks]
        self.flags = set()

    @property
    def blocks(self):
        out = []
        for part in sorted(self.parts):
            out.extend(self.parts[part])
        return out

    @property
    def nblocks(self):
        return len(self.blocks)

    @property
    def data_offset(self):
        return self.blocks[0] if self.blocks else None


def parse_header(f):
    f.seek(0)
    hdr = f.read(512)
    if len(hdr) < 512:
        sys.exit('file too small')
    xor = hdr[0]
    if xor:
        hdr = bytes(x ^ xor for x in hdr)
    year = hdr[0x0B]
    year = year + 1900 if year >= 0x63 else year + 2000
    h = {
        'xor_byte': xor,
        'version': '%d.%02d' % (hdr[0x08], hdr[0x09]),
        'update_month': hdr[0x0A],
        'update_year': year,
        'gmapsupp_flag': hdr[0x0E],
        'checksum': hdr[0x0F],
        'header_checksum_ok': (sum(hdr[:0x0F]) + hdr[0x0F]) % 256 == 0,
        'signature': hdr[0x10:0x17],
        'garmin_sig': hdr[0x41:0x48],
        'sectors': u16(hdr, 0x18),
        'heads': u16(hdr, 0x1A),
        'cylinders': u16(hdr, 0x1C),
        'unknown_20_3f': hdr[0x20:0x40],
        'dir_start_block': hdr[0x40],
        'description': cstr(hdr, 0x49, 20) + cstr(hdr, 0x65, 30),
        'desc_0x49': cstr(hdr, 0x49, 20),
        'desc_0x65': cstr(hdr, 0x65, 30),
        'block_size_exp': (hdr[0x61], hdr[0x62]),
        'block_size': 1 << (hdr[0x61] + hdr[0x62]),
        'unknown_63_64': hdr[0x63:0x65],
        'marker_84': hdr[0x84:0x8A],
        'partsig': u16(hdr, 0x1FE),
        'created': '%04d-%02d-%02d %02d:%02d:%02d' % (
            u16(hdr, 0x39), hdr[0x3B], hdr[0x3C], hdr[0x3D], hdr[0x3E], hdr[0x3F]),
    }
    return hdr, h


def read_fat(f, h):
    """Walk 512-byte directory slots starting at dir_start_block*512."""
    dirstart = h['dir_start_block']
    f.seek(dirstart * 512)
    subs = {}
    order = []
    special = None
    current = None
    n_used = 0
    n_empty = 0
    for slotno in range(0, 4096):
        pos = (dirstart + slotno) * 512
        f.seek(pos)
        slot = f.read(512)
        if len(slot) < 512 or slot[0] != 1:
            n_empty += 1
            if n_empty > 16:
                break
            continue
        n_empty = 0
        n_used += 1
        name = cstr(slot, 1, 8, pad=b'\x00')
        ext = cstr(slot, 9, 3)
        size = u32(slot, 0x0C)
        flag = slot[0x10]
        part = u16(slot, 0x11)
        blocks = []
        for i in range(240):
            v = u16(slot, 0x20 + 2 * i)
            if v == 0xFFFF:
                break
            blocks.append(v)
        if flag == 3 and not name:
            special = {'size': size, 'blocks': blocks, 'slots_used': n_used}
            continue
        key = (name, ext)
        if key not in subs:
            subs[key] = Subfile(name, ext)
            order.append(key)
        s = subs[key]
        if part == 0:
            s.size = size
        s.parts[part] = blocks
    return special, [subs[k] for k in order]


def parse_common_header(buf):
    if len(buf) < 0x15:
        return None
    ln = u16(buf, 0)
    magic = buf[2:12]
    if magic[:6] != b'GARMIN':
        return None
    t = magic[6:].decode('latin1')
    return {
        'header_len': ln,
        'type': t,
        'created': '%04d-%02d-%02d %02d:%02d:%02d' % (
            u16(buf, 0x0E), buf[0x10], buf[0x11], buf[0x12], buf[0x13], buf[0x14]),
    }


def parse_tre(f, off, blocksize, size):
    f.seek(off)
    hdr = f.read(0x100)
    out = {}
    ch = parse_common_header(hdr)
    out['common'] = ch
    out['bounds_n/s/e/w'] = (s24(hdr, 0x15), s24(hdr, 0x1B), s24(hdr, 0x19), s24(hdr, 0x1E))
    out['tre1_off/sz'] = (u32(hdr, 0x21), u32(hdr, 0x25))
    out['tre2_off/sz'] = (u32(hdr, 0x29), u32(hdr, 0x2D))
    out['tre3_off/sz'] = (u32(hdr, 0x31), u32(hdr, 0x35))
    out['copyright_rec_size'] = u16(hdr, 0x39)
    out['flags_0x3f'] = hdr[0x3F]
    if len(hdr) >= 0x8A:
        out['mapid_0x74'] = u32(hdr, 0x74)
        out['hash_0x9a'] = hdr[0x9A:0xAA].hex()
    return out


def parse_gmp(f, off):
    """GMP tile: header has u32 file-internal offsets to TRE/RGN/LBL/NET/NOD."""
    f.seek(off)
    hdr = f.read(0x60)
    ch = parse_common_header(hdr)
    out = {'common': ch}
    if ch and ch['type'].strip() == 'GMP':
        names = ['unk15', 'TRE', 'RGN', 'LBL', 'NET', 'NOD', 'DEM?']
        for i, nm in enumerate(names):
            o = 0x15 + 4 * i
            if o + 4 <= ch['header_len']:
                v = u32(hdr, o)
                if v:
                    out[nm + '_off'] = v
        tre_off = out.get('TRE_off')
        if tre_off:
            out['tre'] = parse_tre(f, off + tre_off, 0, 0)
    return out


def parse_mps(f, off, size):
    """MPS: sequence of blocks [id u8][len u16][body]."""
    f.seek(off)
    data = f.read(size)
    out = []
    pos = 0
    while pos + 3 <= len(data):
        bid = data[pos]
        blen = u16(data, pos + 1)
        body = data[pos + 3:pos + 3 + blen]
        rec = {'id': '0x%02x' % bid, 'len': blen}
        if bid == 0x4C and len(body) >= 10:      # MapBlock
            rec['kind'] = 'map'
            rec['pid'] = u16(body, 0)
            rec['fid'] = u16(body, 2)
            rec['map_number'] = u32(body, 4)
            z = body[8:].split(b'\x00')
            rec['series'] = z[0].decode('latin1', 'replace') if z else ''
            if len(z) > 1:
                rec['map_desc'] = z[1].decode('latin1', 'replace')
            if len(z) > 2:
                rec['area'] = z[2].decode('latin1', 'replace')
        elif bid == 0x46 and len(body) >= 4:     # ProductBlock (mkgmap: BLOCK_TYPE 0x46)
            rec['kind'] = 'product'
            rec['pid'] = u16(body, 0)
            rec['fid'] = u16(body, 2)
            z = body[4:].split(b'\x00')
            if z:
                rec['prod_desc'] = z[0].decode('latin1', 'replace')
        elif bid == 0x50 and len(body) >= 4:     # unknown; contains FID (observed on gmapprom)
            rec['kind'] = 'unk50'
            rec['u16_0'] = u16(body, 0)
            rec['fid'] = u16(body, 2)
            rec['rest'] = body[4:].hex()
        elif bid == 0x55:                        # 25-char alphanumeric code (unlock coupon?)
            rec['kind'] = 'code55'
            rec['code'] = body.split(b'\x00')[0].decode('latin1', 'replace')
        elif bid == 0x56:                        # MapsetBlock (mkgmap: BLOCK_TYPE 0x56)
            rec['kind'] = 'mapset'
            z = body.split(b'\x00')
            if z:
                rec['mapset_name'] = z[0].decode('latin1', 'replace')
        out.append(rec)
        pos += 3 + blen
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('img', help='path to .img file')
    ap.add_argument('--full-checksum', action='store_true',
                    help='verify whole-file checksum (slow for big files)')
    ap.add_argument('--tre', metavar='N', type=int, default=0,
                    help='deep-parse the first N TRE/GMP subfiles')
    args = ap.parse_args()

    with open(args.img, 'rb') as f:
        hdr, h = parse_header(f)
        import os
        print('=' * 78)
        print('FILE: %s  (%d bytes = %.1f MB)' % (args.img, os.path.getsize(args.img),
                                                  os.path.getsize(args.img) / 2**20))
        print('=' * 78)
        print('DSKIMG header:')
        print('  xor_byte          : 0x%02x %s' % (h['xor_byte'],
              '(file NOT xored)' if h['xor_byte'] == 0 else '(ALL DATA XORed!)'))
        print('  version           : %s   update: %04d-%02d' %
              (h['version'], h['update_year'], h['update_month']))
        print('  gmapsupp flag 0x0E: %d' % h['gmapsupp_flag'])
        print('  checksum 0x0F     : 0x%02x (header sum check: %s)' %
              (h['checksum'], 'OK' if h['header_checksum_ok'] else 'FAIL'))
        print('  signature         : %r / %r' % (h['signature'], h['garmin_sig']))
        print('  fake geometry s/h/c: %d/%d/%d' % (h['sectors'], h['heads'], h['cylinders']))
        print('  unknown 0x20-0x3F : %s' % h['unknown_20_3f'].hex() or '(zeros)')
        print('  dir start block   : %d -> FAT at 0x%X' % (h['dir_start_block'], h['dir_start_block'] * 512))
        print('  description 0x49  : %r' % h['desc_0x49'])
        print('  description 0x65  : %r' % h['desc_0x65'])
        print('  block size        : %d (2^%d+%d, exp1@0x61 exp2@0x62)' %
              (h['block_size'], h['block_size_exp'][0], h['block_size_exp'][1]))
        print('  unknown 0x63-0x64 : %s  marker 0x84: %s  created 0x39: %s' %
              (h['unknown_63_64'].hex(), h['marker_84'].hex(), h['created']))
        print('  partition sig     : 0x%04X' % h['partsig'])

        if args.full_checksum:
            f.seek(0)
            total = 0
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                total = (total + sum(chunk)) & 0xFF
            print('  whole-file checksum: 0x%02x (%s)' % (total, 'OK' if total == 0 else 'FAIL'))

        special, subs = read_fat(f, h)
        bs = h['block_size']

        print()
        print('FAT (directory): special self-entry size=%s bytes, blocks=%s' %
              (special['size'] if special else '?', special['blocks'] if special else '?'))
        print()
        print('SUBFILE TABLE (%d subfiles, block size %d):' % (len(subs), bs))
        print('-' * 78)
        print('%-12s %-5s %10s %12s %8s  %s' % ('name', 'type', 'size B', 'offset', 'blocks', 'common header'))
        print('-' * 78)
        tre_off = None
        mps = None
        for s in subs:
            off = s.data_offset * bs if s.data_offset is not None else None
            f.seek(off)
            head = f.read(512)
            ch = parse_common_header(head)
            if s.ext.upper() == 'TRE' and tre_off is None:
                tre_off = off
            if s.ext.upper() == 'MPS':
                mps = (off, s.size)
            hdrdesc = ''
            if ch:
                hdrdesc = 'len=0x%x "GARMIN %s" %s' % (ch['header_len'], ch['type'], ch['created'])
            else:
                f.seek(off)
                raw = f.read(16)
                hdrdesc = raw.hex() + ' ' + ''.join(chr(c) if 32 <= c < 127 else '.' for c in raw)
            print('%-12s %-5s %10d %12s %8d  %s' %
                  (s.name, s.ext, s.size or 0, '0x%X' % off if off is not None else '?',
                   s.nblocks, hdrdesc))
        print('-' * 78)
        total_data = sum((s.size or 0) for s in subs)
        print('total subfile bytes: %d' % total_data)
        from collections import Counter
        cnt = Counter(s.ext for s in subs)
        print('type counts:', dict(sorted(cnt.items())))

        if args.tre:
            # deep-parse TRE subfiles (or GMP-internal TREs)
            n = 0
            for s in subs:
                ext = s.ext.upper()
                if ext == 'TRE' or ext == 'GMP':
                    off = s.data_offset * bs
                    t = parse_tre(f, off, bs, s.size) if ext == 'TRE' else parse_gmp(f, off)
                    print()
                    print('%s.%s at 0x%X:' % (s.name, s.ext, off))
                    for k, v in t.items():
                        print('  %-18s: %s' % (k, v))
                    n += 1
                    if n >= args.tre:
                        break

        if tre_off is not None:
            print()
            print('TRE details (first TRE at 0x%X):' % tre_off)
            t = parse_tre(f, tre_off, bs, 0)
            for k, v in t.items():
                print('  %-18s: %s' % (k, v))
        if mps:
            print()
            print('MPS blocks (map set description) at 0x%X:' % mps[0])
            for rec in parse_mps(f, mps[0], mps[1]):
                print('  %s' % rec)


if __name__ == '__main__':
    main()
