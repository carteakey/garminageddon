import sys, hashlib, os

def u16(b, o): return b[o] | (b[o+1] << 8)

def main(path, outdir):
    data = open(path, "rb").read()
    os.makedirs(outdir, exist_ok=True)
    cplen = u16(data, 0x35)
    off = 0x37 + cplen
    spans = {0x0008: [], 0x02BD: []}
    while off + 4 <= len(data):
        rid = u16(data, off); rlen = u16(data, off+2)
        c = off + 4
        if rid in spans:
            spans[rid].append((c, rlen))
        if rid == 0xFFFF:
            end = c + rlen
            break
        off = c + rlen
    for rid, name in ((0x0008, "boot.bin"), (0x02BD, "fw_all.bin")):
        out = bytearray()
        for c, l in spans[rid]:
            out += data[c:c+l]
        p = os.path.join(outdir, name)
        open(p, "wb").write(out)
        print(f"{name}: {len(out)}B  sha256={hashlib.sha256(out).hexdigest()}  md5={hashlib.md5(out).hexdigest()}")
    tail = data[end:]
    open(os.path.join(outdir, "tail_after_end.bin"), "wb").write(tail)
    print(f"tail_after_end: {len(tail)}B  sha256={hashlib.sha256(tail).hexdigest()}  md5={hashlib.md5(tail).hexdigest()}")

main(sys.argv[1], sys.argv[2])
