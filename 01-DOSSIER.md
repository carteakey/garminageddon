# 01 — Device Dossier

## Identity

| Field | Value |
|---|---|
| Model | Garmin nüvi 2595 (2012, 5" 480×272 resistive touch, BT handsfree, voice command) |
| USB VID:PID | `091e:255b` (live-verified 2026-10-30; usb.ids: "Nuvi 2505LM" — 25x5 family shares it. `091e:455b` previously recorded here was wrong: not in usb.ids, never observed) |
| UnitId / serial | `<UNIT_ID>` (matches serial `<SERIAL>` in sysfs) |
| Software part number | `006-B1371-00` |
| Firmware | Software Version **8.20** (last updated era: 2012–2014) |
| PCB string | `nuvi 2595 C2p2 A V8 8GB 128MB N TI` |
| SoC / RAM | TI ARM (per PCB string), 128 MB RAM, 8 GB NAND |
| OS | **GarminOS** — proprietary embedded RTOS. NOT Linux, NOT Android. Crash strings reference `gpk\tsk_emb_lib\tsk_mem_mmu.c` |
| Bootloader | No public unlock. 2012-era Garmin updates believed checksummed, not signature-verified (basis of the old patched-firmware scene) |

## USB enumeration state

- Mass-storage mode (current, default on connection): **single interface** `1-2:1.0`, class `08` (MSC). One USB configuration. Device class 0x00, no string descriptors except iSerial.
- Garmin proprietary vendor protocol interface: **does not exist on this family** — F3 research (2026-10-30, `findings/2026-10-30-F3-usb-protocol.md`) found no mode switch and no 0xFF interface in any state: official 2405/2505-series manual, GPSBabel docs+source, `GarminDevice.xml` (update path = `.System/GUPDATE.GCD` via mass storage) and live enumeration all agree. WebUpdater/myDashboard uses mass storage only.
- Block devices: `/dev/sdc` = internal 7.2 GB FAT32 (label `GARMIN`); `/dev/sdd` = microSD slot (empty, 0 B).
- Mount: `udisksctl mount -b /dev/sdc --options ro` → `/run/media/kchauhan/GARMIN`.

## Storage map (as of 2026-10-30)

```
/.System/                    main system partition (visible)
  gmapprom.img               2.0 GB — City Navigator map, version 2014 (PN 006-D2338-13)
  gmapbmap.img               51 MB  — basemap (PN 006-F0057-01, v501)
  gmaptz.img                 time zones
  767993418.gma              map license blob (.GMA unlock system)
  RemoteSW/                  peripheral firmware (see 02-RECON.md)
  ASR/                       ~930 MB voice-command acoustic models (048UHSL*.ASR/.SRX, en_US/es_US/fr_CA .srd)
  SID/                       ~900 MB junction-view imagery (D*.sid)
  JCV/                       junction view data
  SQLite/                    dbs (system.db, recent_searches.db, ...)
  Diag/                      ← forensic goldmine, see 02-RECON.md
  Logs/UIStats.log           UI usage stats
/Garmin/                     user-visible Garmin dir
  gmapsupp.img               ← OSM Ontario map we installed (2026-10-30), md5 38a474ec5bb5f71996074e91fac8cf0b, 523 MB
  GarminDevice.xml           device capabilities + BatteryLog DataType declaration
  ASR/pbd_cache/             POI search cache
  Diag/GarminOS.log          power-down log (2014–2021)
/GPX/                        Current.gpx, Position.gpx, Archive/ (40 MB of tracks)
/Tracker/, /Voice/, /Vehicle/, /Themes/, /Pictures/, /Text/, /Help/, /Tutorials/
```

Free space: ~2.4 GB (7.3 GB total). Full-Canada OSM map (2.5 GB) does NOT fit alongside gmapprom; Ontario (523 MB) does.

## Battery forensics (verdict: end of life)

- 13 low-battery forced shutdowns (cause code 2) 2016–2019, in rapid-retry clusters (e.g. 3 within 8 min on 2016-12-17).
- RTC-reset records logged with year **2126** ⇒ battery sat fully dead repeatedly; device deep-discharged since last session **2021-12-27**.
- Expect minutes of runtime; swelling risk before case opening; recommend replacement (Garmin P/N 361-00051-xx) or removal for kiosk duty.
- Shutdown cause codes observed in logs: `1` = RTL trap (sw crash), `2` = low battery, `8` = abnormal powerdown.

## Usage history context

In active use ~2012–2021 (crash on 2014-05-02 is the only software crash on record). Left in a drawer since Dec 2021. Map was never updated past 2014 until our OSM install.
