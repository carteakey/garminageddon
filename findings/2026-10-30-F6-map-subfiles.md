# 2026-10-30 — Map format recon: IMG subfile tables + .gma license blob

**Task:** F6 (map format recon)
**Agent/Run:** agent run, 2026-10-30
**Status:** done

## What was done

- Built `refs/tools/parse_garmin_img.py` — full read-only parser for the Garmin IMG/DSKIMG container: header fields, FAT (directory) walk, subfile table, common subfile headers, TRE deep-parse (map ID / bounds / sections / hash), GMP tile parsing (internal TRE/RGN/LBL/NET/NOD offsets), MPS block parsing (product/FID/PID/map numbers/mapset names).
- Format confirmed against two sources rather than guessed: OSM wiki `OSM_Map_On_Garmin/IMG_File_Format` + `TRE_Subfile_Format`, and **mkgmap source** (`imgfmt/sys/{ImgFS,ImgHeader,Dirent,Directory,BlockTable}.java`, `imgfmt/mps/*`, fetched from GitHub) — every offset below validated against all three device files.
- Ran the parser on all three map images; outputs kept in `/tmp/gmapprom_full.txt`, `/tmp/gmapsupp_full.txt`, `/tmp/gmapbmap_full.txt` (regenerate any time with the tool).
- Empirical RE of `.gma` (`/tmp/parse_gma.py`): magic, header fields, entropy profile, section-length arithmetic, ID search.
- Device read-only throughout (`vfat ro` mount); nothing written to the device; no payloads extracted (header structures only).

## Artifacts

| File | Hash (md5) | Source |
|---|---|---|
| `/run/media/kchauhan/GARMIN/.System/767993418.gma` (2,600 B) | `6be34e69c24d88c8272069d2ac312269` | device |
| `/run/media/kchauhan/GARMIN/.System/gmapbmap.img` (51,003,392 B) | `4a613a4269c9a4d2def715038b4cf7d0` | device |
| `/run/media/kchauhan/GARMIN/Garmin/gmapsupp.img` (523,018,240 B) | `38a474ec5bb5f71996074e91fac8cf0b` | device |
| `/run/media/kchauhan/GARMIN/.System/gmapprom.img` (2,004,221,952 B) | `e5f6c99d14845666b6e7698e67e931b6` | device |
| `refs/tools/parse_garmin_img.py` | — | written this run |

## Results / conclusions

### 1. IMG/DSKIMG container format (verified on all 3 files)

512-byte header at 0x0000 (all little-endian):

| Off | Type | Meaning (this run's values) |
|---|---|---|
| 0x00 | u8 | XOR obfuscation byte — 0x00 on all 3 files (**no XOR encryption**) |
| 0x08 | u16 | map version major.minor (`major \| minor<<8`): gmapprom **20.14** ("2014"), gmapsupp 1.00, gmapbmap 5.01 |
| 0x0A | u8,u8 | update month, year (year: +1900 if >=0x63 else +2000): gmapprom 2013-04 |
| 0x0E | u8 | gmapsupp flag (0 on all) |
| 0x0F | u8 | checksum — **sum of ALL file bytes mod 256 == 0** (verified: gmapprom 0x00, gmapbmap 0x00; gmapsupp 0x19 — mkgmap doesn't pad; mkgmap comment: "checksum is not checked" by devices) |
| 0x10 | 7s | `DSKIMG\0` (demo maps: `DSDIMG\0`) |
| 0x18/1A/1C | u16 x3 | fake MBR geometry sectors/heads/cylinders (gmapprom 32/128/966) |
| 0x20–0x38 | 25 B | **Garmin-authored maps only**: quasi-random IDs (see §5); zeros in mkgmap files |
| 0x39 | u16+5B | creation timestamp y(u16)-mo-d h:m:s (gmapprom 2013-04-23 13:22:03; gmapsupp 2026-10-28 = our install) |
| 0x40 | u8 | **directory start block** (512-B units): 2 (gmapsupp) / 8 (others) |
| 0x41 | 7s | `GARMIN\0` |
| 0x49 / 0x65 | 20s / 30s | map description part 1 / continuation |
| 0x61, 0x62 | u8, u8 | block size exponents E1=0x09, E2: **block size = 2^(E1+E2)** → 8192 (gmapsupp) / 4096 (gmapbmap) / 32768 (gmapprom) |
| 0x63–0x64 | 2 B | unknown (ffff / 66f9 / 0040) |
| 0x83–0x84 | 2 B | `AD DE` marker in Garmin-authored files; zeros in mkgmap files |
| 0x1BE– | — | fake MBR partition entry |
| 0x1FE | u16 | `55 AA` partition signature (why `file(1)` says "DOS/MBR boot sector") |

**Filestore (FAT):** contiguous 512-byte directory slots starting at `byte@0x40 * 512`. The whole directory area is itself tracked as a pseudo-file ("special entry": name = 11 spaces, flag byte@0x10 = 0x03) whose 240-slot block table lists the blocks it occupies. Every slot:

| Off | Type | Meaning |
|---|---|---|
| 0x00 | u8 | 0x01 = slot in use |
| 0x01 | 8s | subfile name (mkgmap left-pads short names with '0') |
| 0x09 | 3s | extension/type (TRE, RGN, LBL, NET, NOD, MDR, MD2, SRT, DEM, GMP, TYP, TRF, MPS) |
| 0x0C | u32 | file size in bytes (part 0 only) |
| 0x10 | u8 | flag (0x03 = directory self-reference) |
| 0x11 | u16 | part number (files > 240 blocks continue in further slots) |
| 0x20 | u16[240] | **block numbers in file-block-size units**, 0xFFFF = unused |

Subfile data = `block_number * block_size`. Max file = 65534 blocks — that's why gmapprom (1.87 GB) uses 32 KB blocks. A file's block runs are interleaved with FAT slots in the gaps.

### 2. Subfile tables

**gmapprom.img — "CN North America NT" / "2014.10 ALL", FID 2920 (0xB68), PID 1, block size 32768, 184 subfiles, no XOR, no TRE/RGN at top level (NT "GMP-tile" layout):**

| Subfile | Type | Size B | Offset | Blocks | Notes |
|---|---|---|---|---|---|
| 00002920 | MD2 | 6,112,672 | 0x30000 | 187 | MDR-index v2, header 0xEC B, no GARMIN magic; own header: u32 len + date 2013-04-23 12:00:21 + counters |
| 00002920 | MDR | 113,618,329 | 0x608000 | 3468 | address/search DB (11 % of the whole map), hdr 0x2C4 |
| 00002920 | SRT | 981 | 0x7268000 | 1 | codepage/collation |
| 00002920 | TRF | 25,235,615 | 0x7270000 | 771 | traffic format data (hdr 0x49) |
| I0000B68 | TYP | 1,925,814 | 0x8A88000 | 59 | Garmin draw style **named after FID 0xB68** |
| I1136F74 … | GMP | 0.4–24.6 MB each | 0x8C60000… | 12–750 | **178 GMP tiles**, names I+hex tile id |
| MAPSOURC | MPS | 20,784 | 0x77758000 | 1 | region index (see below) |

- GMP tile = mini-map: 53-byte header (`GARMIN GMP`) with **u32 file-internal offsets: TRE@0x19, RGN@0x1D, LBL@0x21, NET@0x25, NOD@0x29**, plus copyright strings ("Copyright Garmin Ltd. or its subsidiaries…").
- GMP-internal TRE (e.g. tile I1136F74): header 0x111 B, map ID @0x74 = 0x1136F74 = 18,050,932 (**tile name = TRE map ID in hex**), 16-byte hash @0x9A, bounds in map units, flags bit0 = detailed/routable.
- MAPSOURC.MPS blocks: **178 MapBlocks (0x4C, one per GMP tile)** — series **"City Navigator North America NT 2014.1"**, region map numbers 431595–432167 with names incl. **"TORONTO, ONTARIO" (431606)**, "LONDON, ONTARIO" (431614), "VANCOUVER, BRITISH COLUMBIA" (431608), "JAMAICA", "PUERTO RICO"; plus:
  - ProductBlock (0x46): PID 1, FID 2920, "CN North America NT 2014.10"
  - **MapsetBlock (0x56): "CN North America NT 2014.10 ALL" ← the name the device shows for this map**
  - unk 0x50: `1, 2920, 8, 1` (contains FID)
  - **0x55 block: `<UNLOCK_CODE_REDACTED>` — a 25-character Garmin unlock-style coupon code in PLAINTEXT** (classic Garmin unlock code length; cf. legacy `.unl` files). Interesting RE artifact — see open questions.

**gmapsupp.img — "north-america/canada" + "/ontario osm/latin1 BBBike.org", FID 4815 (0x12CF), PID 1, block size 8192, 778 subfiles, classic TRE/RGN layout (mkgmap/BBBike build 2026-10-28):**

| Subfile | Type | Count | Notes |
|---|---|---|---|
| MAKEGMAP | MPS | 1 | 14,770 B: 155 MapBlocks (FID 4815, PID 1, map numbers **21230001–21230155**, series "series name", areas "Area 21230001"…), ProductBlock (0x46): PID 1, FID 4815, desc "ontario     style=osm", MapsetBlock (0x56): **"OSM map set"** |
| 00004815 | MDR | 1 | 9,392,260 B, named by FID |
| 21230001…21230155 | RGN/TRE/LBL/NET/NOD | 5 × 155 | per-tile subfiles named by map number (decimal); TRE hdr 0xBC, map ID @0x74 = 21230001… = map number ✓ |

**gmapbmap.img — "Worldwide Autoroute" + "DEM Basemap,NR", block size 4096, 14 subfiles = 3 products in one file:**

| Subfile | Type | Size B | Offset | TRE map ID @0x74 |
|---|---|---|---|---|
| WX_AMR | RGN/TRE/LBL | 124,406 / 1,148 / 105,272 | 0x9000 / 0x28000 / 0x29000 | 8249559 (0x7DE0D7) |
| DCW_DEMT | RGN/TRE/LBL/DEM | 71,849 / 2,260 / 2,657 / 19,932 | 0x43000… | 8249563 (0x7DE0DB) |
| F005701V | RGN/TRE/LBL/NET/NOD/SRT/DEM | 11.8 MB / 109 KB / 1.86 MB / 1.25 MB / 4.4 MB / 921 / 31.1 MB | 0x5C000… | 8336064 (0x7F32C0) |

### 3. TRE header fields (map identity — what the device shows in myMaps)

MPS block types (verified vs mkgmap `imgfmt/mps/*`): 0x4C = MapBlock (`u16 PID, u16 FID, u32 mapNumber, z-string series, z-string desc, z-string area, u32 hexNumber, u32 0`), 0x46 = ProductBlock (`u16 PID, u16 FID, z-string desc`), 0x56 = MapsetBlock (z-string name), 0x50/0x55 = Garmin-only (unk / 25-char code). MPS records: `[u8 type][u16 len][body]`, strings NUL-terminated.

Subfile common header: `u16 header_len` + `"GARMIN TRE"` (10 s) + `0x01 0x00` + creation y(u16)-mo-d h:m:s. Then: bounds N/E/S/W (signed 24-bit map units) @0x15, TRE1 levels off/sz @0x21, TRE2 subdivisions @0x29, TRE3 copyright @0x31, flags @0x3F (bit0 = detailed/routable — gmapprom tiles have it, basemap doesn't), **map ID (u32) @0x74**, **16-byte map-ID hash @0x9A** (from OSM wiki TRE page; confirmed present in all TREs incl. GMP-internal).

- gmapsupp/gmapbmap (mkgmap and old-Garmin) TRE hashes show a weak pattern: last 8 bytes = 4-byte dword repeated (`…e5e02aed e5e02aed`). gmapprom GMP-TRE hashes are full-entropy (`9373813ba5f42edd7cf78ff292f31ddc`) — real Garmin algorithm. Potential authenticity marker.
- FID/PID live in the MPS (and MD2/MDR headers), not in the TRE. Subfile *names* encode them: `%08d` of map number (mkgmap), FID for MDR/MD2 (`00002920*`), FID hex for TYP (`I0000B68`), tile id hex for GMP.

### 4. .gma license blob (767993418.gma, 2,600 B) — "Garmin Map Activation"

Full hexdump in `/tmp/gma_full.txt`. Confirmed structure:

- `0x00`: magic **"GARMIN GMA"** (10 s), `0x0A`: u16 version = **1**.
- `0x0C–0x13`: u16 stream `4, 20, 0, 2580` — 2580 = body length (0x14 → EOF exactly).
- `0x14–0x27`: u16 stream `4, 20, 0, 256, 276, 0, 2048, 2324, 0, 256` — section table. Arithmetic locks it: **256 + 2048 + 256 = 2560 = data bytes @0x28→EOF (0xA28) exactly**, and cumulative fields check out (276 = 20+256, 2324 = 20+256+2048, 2580 = 20+2560).
- `0x28–0x127` (256 B): high-entropy block — size = **2048-bit RSA signature** candidate.
- `0x128–0x927` (2048 B): 8 × 256-B high-entropy blocks (block-start bytes c5/68/98/a8/2e/23/24/ec — uniform random, no RSA padding pattern) — key/signature material.
- `0x928–0xA27` (256 B): third high-entropy block.
- No zero-runs anywhere in the body (entropy 5.6–5.9/8 per 64-B window = encrypted or compressed material).
- **Not found in plaintext anywhere in the blob:** FID 2920 (0xB68), FID 4815, map numbers, tile IDs, or the filename value 767993418 (0x2DD406CA) — product/map references are inside the protected material (or absent).
- Community context (gpspower.net "gma — What's inside?!"): GMA = signature/authentication file complementing the legacy `.unl` unlock codes; forging tools ("gmafaker") exist in gated forums; no public spec or parser found on GitHub (file(1) has no GMA magic either — our empirical layout above appears to be the only on-device documentation we have).
- RE-able next steps in §Open questions. Note: file date 2014-05-02 = same day as the unit's recorded `ERR_RTL_TRAP` crash — device was mid-map-update.

### 5. Structural comparison: gmapprom vs gmapsupp vs gmapbmap

| Aspect | gmapprom (Garmin NT) | gmapsupp (mkgmap OSM) | gmapbmap (Garmin basemap) |
|---|---|---|---|
| Layout | GMP tiles + MD2/MDR/SRT/TRF/TYP/MPS | classic RGN/TRE/LBL/NET/NOD/MPS/MDR | classic, 3 products in one img |
| Block size | 32768 | 8192 | 4096 |
| XOR byte | 0 (not encrypted) | 0 | 0 |
| Whole-file checksum | **0x00 verified (Garmin pads to zero)** | **0x19 (≠0 — mkgmap doesn't pad)** | **0x00 verified (Garmin pads to zero)** |
| Header 0x20–0x38 IDs | **present** (Garmin-only) | zeros | **present** |
| Header AD DE marker @0x83 | **present** | zeros | **present** |
| TRE hash @0x9A | full entropy | weak repeat pattern | weak repeat pattern |
| License | 767993418.gma | none needed | none (built-in) |
| subfile naming | FID/tile-id hex | map-number decimal | mnemonic (WX_AMR…) |

Takeaways for the exploit/RE track: the container is plain (no encryption at IMG level); all copy-protection lives in (a) the .gma signature material checked by GarminOS and (b) possibly the TRE hash. Garmin-authored imgs are padded so that the byte-sum of the whole file ≡ 0 (mod 256) — an easy-to-satisfy integrity marker to preserve if we ever modify an img; mkgmap ignores it (gmapsupp sums to 0x19), which doubles as an authorship fingerprint. The NT map's 113 MB MDR is the biggest structured parse target in the map stack.

## Open questions / handoff

1. **.gma field semantics** — confirm interpretation of the `4, 20, 0` u16s and the roles of the 256/2048/256 sections (RSA-2048 sig + 8 keys? which is the map unlock key?). Get a second .gma (any Garmin map download, or ask user to install any free Garmin map to SD) and diff headers; or capture a .gma + .unl pair from a known unlocked map.
2. **Filename 767993418** — provenance unknown (not FID/PID/map number in any encoding we tried). Check the SD-card/.System for referenced names in GarminDevice.xml / GARMIN.gpi; candidates: JCV/SID/ASR license id.
3. **MPS 0x55 code `<UNLOCK_CODE_REDACTED>`** — 25-char alphanumeric unlock-style code stored in plaintext in gmapprom's MPS. Relation to the .gma (does the .gma key material derive from/verify this?) = prime RE target; also compare with the user's original purchase certificate if available.
4. **MD2 header** (0xEC bytes, no GARMIN magic) — not decoded; needed if we ever parse the MDR index. OSM wiki MDR page + gmaptool are the refs.
5. **TRF** (25 MB traffic) — header parse glitch (year read as 0113): layout differs; low priority.
6. **TRE hash @0x9A algorithm** — mkgmap `MapValues.java` has the mkgmap variant; whether the nüvi *verifies* it (vs ignoring like checksums) is testable by flipping a byte on a throwaway copy on SD (never on the device).
7. **gmapprom header IDs @0x20–0x38** (incl. unix-time-like u32 @0x24 and 8-byte value @0x30) — purpose unknown; likely Garmin build/registration identifiers.
8. ~~Whole-file checksum verification~~ — DONE: gmapbmap 0x00, gmapprom 0x00 (Garmin pads to zero), gmapsupp 0x19 (mkgmap doesn't).
