# 2026-10-30 — F2b: GCD format SOLVED (parser + builder proven)

**Task:** F2 follow-ups (framing correction, checksum RE, builder) — main session
**Status:** DONE. `refs/tools/gcd_tool.py` replaces v1 `unpack_garmin.py` (deprecated).

## What happened

The F3-downloaded doc (H. Oppmann, "Garmin GCD Firmware Update File Format" 2026-08-31,
`refs/protocol/GCD_Format.pdf` + extracted `GCD_Format.txt`) provided the true record framing,
which my v1 parse had mis-modeled. Everything was then **empirically verified against all 4
RemoteSW blobs**.

## The real format (doc + our blobs agree)

```
header:  "GARMIN" + u16 version (0x0064 = V1.0)          — 8 bytes, records start at 0x08
record:  u16 RecordID | u16 Length | byte[Length]        — all LE, records tile the file
```

Record IDs (infrastructure): `0x0001` CheckPoint · `0x0002` Filler · `0x0003` PartNumber ·
`0x0005` Copyright · `0x0006` FwDescriptorType · `0x0007` FwDescriptor · `0xFFFF` End.
Everything else = Firmware Data records (stream chunks, ≤0xFFFF each, usually ≤0xFF00).

Blob anatomy (all four identical in shape):

| Offset | Record | Content |
|---|---|---|
| 0x08 | CheckPoint (1 B) | additive checksum |
| 0x0D | Filler (21 B) | zeros |
| 0x26 | PartNumber (9 B) | **6-bit-coded → decodes to `010-10037-00`** (universal remote-sw updater PN) |
| 0x33 | Copyright (55 B) | ASCII |
| 0x6E | CheckPoint (1 B) | |
| 0x73 | Filler (3,977 B) | zeros → pads to 0x1000 |
| 0x1000 | CheckPoint (1 B) | |
| 0x1005 | FwDescType (10 B) | fields: (11 erase,byte) (10 XOR,byte) (10 RecordID,ushort) (21 fwlen,uint) (3 end) |
| 0x1013 | FwDescriptor (8 B) | **xor=0x01, data_rec_id=0x0401 (`external_data.bin`), stream_len** |
| 0x101F | FwData 0x0401 | stream_len bytes (107300: 2 chunks, 65344+256 = 65600 ✓) |
| end−9 | CheckPoint + End | `01 00 01 00 XX | ff ff 00 00` |

## Verified claims

1. **CheckPoint algorithm confirmed empirically**: sum of ALL file bytes from 0x00 (including
   the 8-byte header) up to and including the CheckPoint record ≡ 0x00 (mod 256). All 11
   checkpoints across 4 blobs verify. (Tool initially mis-summed by excluding the header —
   doc is right.)
2. **Round-trip parse→rebuild is BYTE-IDENTICAL on all 4 blobs** — the builder is proven.
3. **Part-number 6-bit coding** (doc §compressed part number) decodes correctly.
4. **XOR obfuscation field = 0x01 is NOT applied to these streams** — raw stream already
   contains plaintext strings ("Error Count", "EEProm Error Count=", "GTM3G Software Version
   3.10", "GTMxx 3.20", module part number "006B090100" at offset ~16). Treat XOR semantics
   as stream-dependent; verify per-stream by string sanity, don't blind-deXOR.
5. **Streams are NOT compressed** — entropy 6.5 is just code. Payload = raw module firmware
   image with its own tiny header.

## Payload identification (bonus)

All four 0x0401 streams = **GTM FM-traffic-receiver module firmware** (GTM 3G 3.10 / GTMxx
3.20 variants). RemoteSW/ = firmware the nüvi keeps so it can flash the external GTM brick
in the car power cable. Consistent with the standalone `006B048201.BIN` (AVR, "GTMxx 5.50").

## T2 (crafted GUPDATE.GCD) status after this

Have: full record grammar · checkpoint algorithm (forgeable) · part-number coding ·
proven builder (`gcd_tool.py roundtrip`) · descriptor field vocabulary.
Remaining: main-firmware .gcd structure (needs F1 image — main FW uses record IDs like
0x0505 fw_all.bin, 0x0566 files.bin per doc table) · HWID check semantics · bootloader
acceptance logic (F4 Ghidra). **No crypto barriers remain in the container layer.**

## Artifacts

- `refs/tools/gcd_tool.py` — parse / roundtrip / extract (v2, correct framing)
- `refs/remote-sw/gcdv2/` — extracted raw streams (4 blobs)
- `unpack_garmin.py` — DEPRECATED (v1 framing kept for history)

## Open questions

- Why does descriptor XOR=0x01 not apply to these streams? (other streams/devices may differ)
- HWID field (ID 9) presence/semantics for main-firmware GCDs
- Garmin_BIN_Format doc (same author) — fetch for stream-internal format details
