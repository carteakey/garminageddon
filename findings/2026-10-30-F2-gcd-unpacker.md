# 2026-10-30 — F2: GARMIN (GCD) container unpacked

**Task:** F2 (container unpacker)
**Agent/Run:** main session
**Status:** container layer DONE; payload decompression = open follow-up

## What was done

Empirical format RE on the 4 RemoteSW `.gcd` blobs, iterated with analysis scripts, then
`refs/tools/unpack_garmin.py` (stdlib-only). Validated on all 4 blobs. Extractions archived
under `refs/remote-sw/<blob>.unpack/`.

## Container format (validated)

```
HEADER
  0x00  "GARMIN" (6B magic)
  0x06  64 00                     constant
  0x08  u16 1                     version?
  0x0A  u16 1                     version?
  0x0C  u16 732                   constant, TBD
  0x0E  u16 5376 (0x1500)         constant, TBD
  0x10  zeros + small constants; @0x2C ~16B constant-ish blob (flags/CRC?)
  0x35  u16 len; @0x37 copyright ASCII ("Copyright 1996-2008|2012 by Garmin Ltd. ...")
  0x6E  records begin

RECORD:  4B sync "01 00 01 00" | u16 len (LE) | u8 type | payload
END:     last 9 bytes: 01 00 01 00 XX ff ff 00 00  (type=0xFF, len=0xFFXX; XX varies per file:
         67 / 9d / 09 / 06 — possibly checksum low byte)
```

**Structure of all 4 samples:**

| Offset | Record | Content |
|---|---|---|
| 0x6E | type 0x00, 583–588 B | near-zero (entropy 0.04); payload = `89 0f` + zeros. Descriptor/header record |
| 0x1000 | type 0x00, 1636 B | **software identity + string table**: ASCII part number (`006B090100`…), printf template `006-B%04d-00`, `Missing`, test patterns (`AAAAAA`, `((((( `) |
| 0x50AE (only 006B107300) | type 0x2D, 22,275 B | dense data, entropy 6.02 |
| after last rec → end | **bulk data** (unframed) | entropy 2.49–6.75 |
| end-9 | trailer | `01 00 01 00 XX ff ff 00 00` |

Zero-padding between records commonly to 0x1000-ish boundaries. **Payloads are NOT encrypted**
(entropy ≤ ~7, plaintext strings throughout). The bulk is likely compressed (needs identification —
candidates: Garmin's own LZ variant; try `lzss`/`lzh` signatures and byte-histogram analysis).

## Security-relevant nuggets

1. **Update-device matching is an ASCII part-number string inside an unencrypted metadata record**
   (`006B090100`, template `006-B%04d-00`). Forging a `.gcd` that a nüvi considers "its" update =
   write the right string in the right record. Consistent with checksum-not-signature hypothesis (T2).
2. The full container grammar is now reproducible → a **crafted .gcd builder** is feasible once the
   payload compression is identified and the checksum algorithm (header @0x2C? trailer XX?) is RE'd.
3. `006B048201.BIN` is NOT this container: raw **AVR firmware** (ATmega; `0c94 ce09` = JMP vector,
   32,768 B, 0xFF tail) — the GTM FM traffic-receiver brick runs an 8-bit AVR.

## Artifacts

| File | md5 |
|---|---|
| 006B048201.BIN | ffe9e0d4458ab3aa46626bbe7393dc28 |
| 006B090100.GCD | 84d08697b3beac3d3335561c346a6e40 |
| 006B107300.GCD | 61efa42be4ffd3754197b6aeabd53a68 |
| 006B125700.gcd | 18ec5f13b59ccb42d59d03359c2813c6 |
| 006B139900.gcd | d9c103ab471592cae4e04c55441501ce |

Tool: `refs/tools/unpack_garmin.py` · Extractions: `refs/remote-sw/*.unpack/`

## Open questions / handoff

- Identify bulk/0x2D record compression (entropy 6–7 with short strings ⇒ compressed; try Garmin
  LZ variants, then treat as "random data with structure" and diff two versions of the same module
  if we ever get them).
- RE the header checksum (@0x2C region) + trailer byte XX — needed for a valid crafted .gcd (T2).
- Map `006B090100/107300/125700/139900` part numbers to actual peripherals (BT? FM tuner? sensor MCU?).
- When main firmware (F1) lands: same unpacker applies; expect bigger record zoo incl. flash-loader
  and the actual GarminOS image → Ghidra (F4).
