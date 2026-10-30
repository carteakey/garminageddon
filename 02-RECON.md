# 02 — Recon Findings (filesystem phase — COMPLETE)

Device mounted read-only at `/run/media/kchauhan/GARMIN` during all of this. No writes to device except the OSM map install (documented in 01-DOSSIER).

## RemoteSW/ — peripheral firmware (5 blobs, 208 KB total)

All wrapped in the same **`GARMIN` container**. Header observed (hex, identical across files except length/copyright fields):

```
00000000: 4741 524d 494e 6400 0100 0100 dc02 0015  GARMINd.........
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0300 0900 10d4 5c13 0445  ............\..E
00000030: 0d14 4105 0037 0043 6f70 7972 6967 6874  ..A..7.Copyright
00000040: 2031 3939 362d 3230 3132 2062 7920 4761  1996-2012 by Ga
...
```

- Magic `GARMIN` + `d\x00`, then small header (lengths @0x0E, type/section fields @0x26–0x2B, CRC-ish @0x2C, then length-prefixed ASCII copyright).
- `file(1)` calls it "GARMIN firmware (version 1.0)".
- Payload after header is the firmware binary — **unencrypted as far as we can tell** (version printf-templates visible in strings).

| File | Size | Identification |
|---|---|---|
| `006B048201.BIN` | 32,768 B | **"GTMxx Software Version 5.50"** — FM traffic receiver module firmware (the GTM brick in the car power cable, not the unit) |
| `006B090100.GCD` | 36,972 B | peripheral update (copyright 1996-2012) |
| `006B107300.GCD` | 69,744 B | peripheral update (copyright 1996-2008) |
| `006B125700.gcd` | 24,684 B | peripheral update (copyright 1996-2008) |
| `006B139900.gcd` | 26,732 B | peripheral update (copyright 1996-2008) |

Likely candidates: BT module firmware, FM tuner, sensor hub. Exact part-number ↔ module mapping = open item.

**Key negative result:** the *main* GarminOS image is NOT on the visible filesystem. It lives in a protected NAND partition, updatable only via the Garmin USB update protocol (WebUpdater/Express). Corollary: firmware acquisition → official `.gcd` download, no hardware needed.

## Diagnostics — the built-in forensics channel

`/.System/Diag/`:

- `GarminError.xml` — full identity + the one recorded software crash: **2014-05-02, `ERR_RTL_TRAP`, error `0x6E5D8017`**, message `gpk\tsk_emb_lib\tsk_mem_mmu.c 503, INVALID task handle.` Includes 16 ARM registers.
- `Shutdowns/` — 27 shutdown records (`*.html`, UTF-16) + `shutdown.log` (ParserVersion 3 records, `RECORD_SIZE` framing, fields: UnitId, Time, SystemVersion, RTL_Trap_Info, Exception_Info, Error_Cause).
- Cause codes observed: 1 = RTL trap, 2 = low battery, 3 = (unknown), 8 = abnormal powerdown.
- **This is our fuzzing oracle:** parser crashes on-device should produce new RTL_Trap records we can read back over mass storage. A closed feedback loop with zero solder.
- `sys_log1.bin` — 2,097,152 B binary. Strings pass = noise (compressed or raw RAM dump). Needs format knowledge (likely obtainable from firmware RE).
- `GarminOS.log` — power-down events 2014–2021.
- `Garmin/GarminDevice.xml` declares a **`BatteryLog`** DataType in `.System/Diag` — device can generate battery logs on request (via diag menu/protocol; not present as a file).

## Data assets (RE-able without hardware)

| Path | Size | What |
|---|---|---|
| `.System/ASR/` | ~930 MB | Voice-command acoustic models + dictionaries (048UHSL*.ASR/.SRX, *.srd). Proprietary SR engine — parser attack surface + offline RE material |
| `.System/SID/` | ~900 MB | Junction-view imagery databases (D2656110A.sid 495 MB, D3157090A.sid 320 MB, D3406080A.sid 101 MB) |
| `.System/JCV/` | — | Junction view data |
| `.System/SQLite/*.db` | ~8 MB | Plain SQLite (recent searches, custom POIs). Readable now |
| `/GPX/` | 40 MB | Track logs incl. Archive/ — the user's actual 2012–2021 driving history |
| Map `.img` + `.gma` | 2 GB | Garmin map container format; `.gma` license blob (map-unlock crypto, historically weak) |

## Tools/notes for next phases

- `binwalk` not installed on host. Host: CachyOS (Arch-based), zsh. `pacman -S gpsbabel` available for USB protocol work; Ghidra needs install (AUR or ghidra package).
- GCD files from Garmin servers use the same `GARMIN` container as RemoteSW blobs — the unpacker we write works on both.
- Firmware part number to hunt: **`006-B1371-00`** (SW 8.20 current; older versions also valuable).
