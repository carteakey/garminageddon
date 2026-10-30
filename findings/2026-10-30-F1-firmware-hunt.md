# 2026-10-30 — F1: Official firmware hunt — COMPLETE (14/14 versions secured)

**Task:** F1 (firmware hunt, roadmap item)
**Agent/Run:** agent run 2026-10-30
**Status:** DONE. The complete known version series of part **006-B1371-00** (6.30 → 8.30, 14 files) plus the 2495LT-GLONASS sibling are downloaded, hash-recorded, and structurally validated. No flashing performed; nothing was written to the device.

## What was done

1. Probed Garmin's own infrastructure (webservice/rgn/download/support hosts; ~50 URL-guess variants). Found the live CDN naming pattern via a MirGarmin listing + GPSPower posts: `https://download.garmin.com/software/<model>_GCDFile__<vXXX>.gcd`.
2. **8.30 still lives on Garmin's own CDN** (verified twice, same etag). All older versions are purged from Garmin (404 across every probed version number 2.30–8.20, multiple name variants).
3. Recovered the full version series from the **Wayback Machine capture of the legendary "Perry" mirror** (`gawisp.com/perry/nuvi/`, snapshots 2016-04-24, listed 2020-07-03): 12 additional versions, HTTP 200 each. gawisp.com itself is ISP-parked today (serves HTTP 200 soft-404 HTML for every path — verified by magic-byte check before noticing; do not trust it).
4. Wrote `refs/tools/verify_gcd.py` — a GCD record walker per the Oppmann format doc (`refs/protocol/GCD_Format.txt`): parses header/records, **verifies every CheckPoint additive byte-sum** (sum of all file bytes up to and including the checkpoint byte ≡ 0 mod 256), decodes Firmware Descriptors (HWID, SW version, stream length, XOR byte), hashes streams. Ran it on all 15 files: **HWID=1371 and internal SW version match the filename on every file; 45/45 CheckPoint checks pass.**
5. Extracted per-version `boot.bin` (record ID 0x0008) and `fw_all.bin` (0x02BD) streams via `refs/tools/extract_gcd_streams.py`; hashes below.

## Primary URLs

- **LIVE (Garmin CDN, latest release):**
  `https://download.garmin.com/software/nuvi24x5and25x5_GCDFile__830.gcd` — HTTP 200, 50,201,232 B, `Last-Modified: Mon, 03 Oct 2016 15:42:59 GMT`, `ETag: "2fe0290-53df7cc65e6c0"`, content-type application/octet-stream (Cloudflare fronted).
- **Historical versions (Wayback raw-content endpoint, `id_` = original bytes):**
  `https://web.archive.org/web/<ts>id_/http://gawisp.com/perry/nuvi/nuvi24x5and25x5_GCDFile__<v>.gcd`
  Snapshot timestamps used (all 2016-04-24 series): 810→170825, 800→191926, 790→183219, 780→163225, 770→154723, 760→180838, 750→215959, 720→160046, 710→155613, 700→215525, 660→215314, 630→172420.
- Naming convention: `nuvi24x5and25x5` = the whole 24x5/25x5 family shares part 006-B1371-00; GLONASS 2495LT is its own part (sibling below). Older Garmin link style confirmed by GPSPower: same pattern (e.g. `..._GCDFile__630.gcd`).

## Artifacts

All under `refs/firmware/` (one directory per part+version; `streams/` subdirs hold extracted boot.bin + tail; fw_all.bin extracted only for 8.20/8.30/sibling to save disk — regenerate with the extractor as needed). Hash sheet: `refs/firmware/hashes.txt`.

| Version | File | Size (B) | sha256 (first 16) | md5 |
|---|---|---|---|---|
| 6.30 | nuvi24x5and25x5_GCDFile__630.gcd | 50,044,644 | 8558d4449cdc1c79 | fd7a4bf41d5d91d91cea399b23480aee |
| 6.60 | …__660.gcd | 50,047,284 | d74fe3d1b2dacd5a | da2ff7b64f5b770b49a4308a01be86d4 |
| 7.00 | …__700.gcd | 50,118,444 | eecb300a5a56195a | 3273c5638264ad5a952a8c23fb1dffb5 |
| 7.10 | …__710.gcd | 50,156,592 | 1b2c2401190a4e00 | 15ba086455305be0f718ac015fe29ae0 |
| 7.20 | …__720.gcd | 50,157,632 | b88d817709f30940 | 8b58c10f9828bb108ed30957c7cd000 |
| 7.50 | …__750.gcd | 50,039,572 | cc8b4c8188ee4065 | 599156338da245f270a53b4bcda831af |
| 7.60 | …__760.gcd | 50,042,156 | 065265634ba598a9 | ba14c887ac8c4fbbcee1a8478cba2102 |
| 7.70 | …__770.gcd | 50,042,164 | 8b1d485867d1ed21 | 0b2e22de0c2d08b004648999cb8ccd3a |
| 7.80 | …__780.gcd | 50,042,164 | b58cc9e609237282 | 75a85978c07bd9dfafb7fe9d5adc624a |
| 7.90 | …__790.gcd | 50,098,760 | 2d305c7f5f53e0e6 | c022acb7a37d6cc003aaa97411e1236a |
| 8.00 | …__800.gcd | 50,097,992 | 87dc8da6d612396b | fa9a609c88c2c39ec24be2c2e99a7e1b |
| 8.10 | …__810.gcd | 50,200,720 | 39384154e8cfe4d5 | d1c4dee6a8e05001a3b94889befb7c9f |
| **8.20** (= device) | …__820.gcd | 50,200,720 | **52625603c9b3ba52** | edb455d3a2c849bae850a7ff1e8eb59e |
| 8.30 (latest) | …__830.gcd | 50,201,232 | 0cd5f029712b0fcf | 3a51dad1eac240a7685137a265fbb578 |
| sibling 006-B1445-00 (2495LT GLONASS) 8.30 | nuvi2495LTGLONASS_GCDFile__830.gcd | 50,253,968 | 3e4280523467c7d4 | cc010e22f15daf4406639ad65e2a28c2 |

Full sha256 for all files in `refs/firmware/hashes.txt` — table truncated for readability.

Sibling provenance: `https://download.garmin.com/software/nuvi2495LTGLONASS_GCDFile__830.gcd` (HTTP 200, live).

### Per-file structural validation (all 15 files)

- Record walk clean header→END under Oppmann framing; no inter-record slack.
- CheckPoint records: **3 per file, all additive-sum checks PASS** (byte values e.g. 0x4b @0x6e, 0x64 @0x1000, final one before END).
- Firmware Descriptor: HWID=**1371**, SW version field = file version (830/820/…/630). Sibling: HWID=**1445** (matches community note that GLONASS 2495LT is a different HWID).
- Streams: `0x0008` boot.bin + `0x02bd` fw_all.bin; declared lengths match stream totals exactly; **XOR obfuscation byte = 0x00** (streams not XORed).

### boot.bin (bootloader) evolution — T2 material

14 distinct boot.bin binaries, size monotonic 745,620 → 772,408 B:

| Ver | boot.bin sha256 (16) | Ver | boot.bin sha256 (16) |
|---|---|---|---|
| 6.30 | a7c15345eee181d7 | 7.70 | a31df586b8b4fe45 |
| 6.60 | 0007cc9c88572091 | 7.80 | af728e5edc763584 |
| 7.00 | 4ca87a96c3c126c7 | 7.90 | 90fbb0d6af7197f5 |
| 7.10 | 9aa7395eb3c1e716 | 8.00 | bdf3a860e21a88df |
| 7.20 | 4979a1486210d34d | 8.10 | ffe7cde1a1b23a41 |
| 7.50 | 2339d2d5929d0082 | 8.20 | e67995ec8f77894b |
| 7.60 | 3b1579977687db99 | 8.30 | 7296b3eb4ad0a4b1 |

Full hashes + extracted copies in each `refs/firmware/006-B1371-00_<v>/streams/boot.bin`.

## Results / conclusions

1. **F1 goal met: every published version of the official 006-B1371-00 GCD is now offline in the repo**, the device's own version (8.20) and the final release (8.30) both served straight from Garmin's CDN / a 2016 snapshot of a famous mirror, all internally consistent (part number, HWID, checksums).
2. **The update path is fully file-based** (confirming F3): GCD renamed `GUPDATE.GCD` → device applies it at boot (preboot stage) → deletes it. Community mechanics: file goes to `.System/` per the device's own GarminDevice.xml (ubuntuusers wiki says `/Garmin` — both are reported to work; `.System` is what GarminDevice.xml declares). **Downgrade trick** (for installing ≤8.20 over a newer-reporting unit): edit `SoftwareVersion` in `.System/system.xml` and `Garmin/GarminDevice.xml` to a value below the target firmware (ubuntuusers.de/Garmin/Firmware).
3. **New T2-critical observation — undocumented 260-byte trailer:** every main-firmware GCD has 260 B after the END record (`ff ff ff ff` + 256 B high-entropy), while the small peripheral GCDs (RemoteSW) end exactly at END (0 slack). The trailer differs per file (content-derived, hash/signature-sized) but all three CheckPoints already pass without it — so it is NOT covered by the additive-sum rule. Candidates: per-file signature/MAC, random anti-collision padding, or flash-footer metadata. **F4 must check whether the bootloader reads the file tail — if it verifies this block, the "checksum-only" T2 assumption needs revision.** Extracted as `streams/tail_after_end.bin` per version (8.20: md5 394baacb64e7897615c3b5472ce89ff2).
4. **F2 correction (record framing):** the "4-byte sync `01 00 01 00` + len + type" framing in 02-RECON/F2 findings is a misread. Correct framing (Oppmann): records are `u16 record_id | u16 record_len | content`; the recurring `01 00 01 00` is actually **CheckPoint records (ID=0x0001, len=1)** sprinkled through the file, and F2's "trailer byte XX" is simply the file's **last CheckPoint byte** (now additively verified). With this framing each file walks perfectly 0x6e → END with zero slack. Recommend F2 rebase `refs/tools/unpack_garmin.py` onto `refs/tools/verify_gcd.py` framing.
5. Negative results (documented for the record): `webservice.garmin.com`, `rgn.garmin.com` — dead (connection fail); `download.garmin.com/software/` — only latest versions kept (every older version 404, incl. all 22 known release numbers of this part under 13 name variants); `gawisp.com` — ISP-parked, returns HTTP 200 + HTML error page for everything (soft-404 trap; magic-byte check caught it); `gmaptool.eu` — 403 to non-browser clients; `gpsarchive.net` — dead; NaviTotal/GPSPower attachments — registration-gated, no URLs exposed; Wayback CDX/availability APIs — intermittent (offline banner / 504 / 429) but snapshot playback worked reliably all session.

## Open questions / handoff

- **260-byte tail after END** (above) — resolve in F4 by finding tail-read code in boot.bin; also diff tails across the 14 versions for structure.
- F4: 14 boot.bin samples ready for Ghidra diffing — the update-verification routine and the GUPDATE.GCD application logic live there. Start with 8.20 (device's version) vs 8.30.
- F2: adopt the corrected framing; the GCDs here (with known HWID/SW/lengths) are far better unit tests than the 4 small RemoteSW blobs. Note peripheral GCDs have no PartNumber/HWID descriptor — their identity record is the ASCII one F2 already found at 0x1000.
- The old-version GCDs (6.30 era) may use an earlier container/copyright era (all still "Copyright 1996-2013" header — uniform). No version-specific anomalies observed.
- Optionally mirror `nuvi24x5and25x5_GCDFile__830.gcd` provenance in 01-DOSSIER when T2 work begins (the 8.20 file is the exact one the device declares in GarminDevice.xml).
