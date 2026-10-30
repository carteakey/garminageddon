# 2026-10-30 — F4b: The GUPDATE.GCD gate in GarminOS — scan is EVENT-driven (volume/media events), no version gate exists; why the device ignores the file at plain boot

**Task:** F4b (follow-up to F4) — explain the empirical no-update result (official 8.20 GCD, and later a
SW-900-bumped GCD, both as GUPDATE.GCD in /.System/ AND /Garmin/, GarminDevice.xml 820→630 spoofed,
2 power cycles → no update screen, files untouched, no diag records)
**Agent/Run:** agent run 2026-10-30
**Status:** DONE (static RE, 100 % offline). Root cause identified: **the GUPDATE check is not a boot-time
scan — it runs inside an event-driven volume/media subsystem and never fires on a plain power cycle.**

## What was done

- Reused the F4 toolchain (Adoptium JDK 21 + Ghidra 11.4.2 in ~/garminageddon-tools, capstone 5.0.9 in
  /tmp/pylibs). Ghidra project for boot.bin intact at /tmp/ghidra_proj/F4; a full fw_all.bin import
  (F4B) was started but superseded — all decisive code was read with capstone Thumb disassembly +
  a new scanner (`refs/tools/f4b_strrefs.py`) that finds **ADR/ADDW/SUBW PC-relative string references**
  (the key trick: fw_all is base-0 linked, ARMv5, and references these strings via ADR, NOT via literal
  pools or MOVW/MOVT — there are zero MOVT instructions in the whole 49 MB image, and no u32 anywhere
  equals any of the string VAs).
- Verified the brief's coordinates: all four sites are real UTF-16 strings in **fw_all.bin** (the
  "boot.bin 0x735554/0x761882" coordinates in the task brief are bad — those offsets are garbage bytes
  in both binaries; the real boot.bin GUPDATE strings are 0xb3942/0xba01a from F4).
- Traced each site to its consumer function, then up through dispatchers to the event pump, and
  identified every gate on the path.

## The four sites and their consumers

| Site (fw_all) | String | Consumer (ADR xref) | Role |
|---|---|---|---|
| 0x4eab4 / 0x4eae0 / 0x4eaec | /.System/GUPDATE.GCD, %d:%s, /Garmin/GUPDATE.GCD | FUN_4e9a4 (refs 0x4e9cc/0e/da) | volume-path composer + file open/read for the update check (module copy 1, "core") |
| 0x527cc / 0x52804 | same pair | FUN_523f8 (refs 0x52412/36) ← dispatcher-A FUN_52858 ← event pump FUN_5297e @0x52a64 | same logic, module copy 2 |
| 0x2f9b64 / 0x2f9b90 | /.System/GUPDATE.GCD, %d:%s (near GUI PageMainMenu strings) | FUN_2f9a9c (refs 0x2f9abc/e4) ← event handler FUN_2f9bd2 | module copy 3, handles events 0xE/0xF |
| 0x19177c (+ .GCD 0x1915b8) | GUPDATE.GCD in the RemoteSW/`006B%04d00` part-number table region | FUN_19123c (ref 0x1913d0), FUN_1911d6 | RemoteSW/BTM update-config database (per-device updater table: RoadsideAssist, TrafficProvider, 006-D1283 BTM …) — GUPDATE.GCD is one entry in the "files the updater knows" list |

All three module copies are the SAME logic compiled into three subsystems (fw_all, like boot.bin,
contains duplicated code regions).

## The verified flow (GarminOS side)

1. **Trigger — events, not boot.** The chain is driven by an event/message pump (FUN_5297e region):
   events carry an ID; the volume selector byte **'J' (0x4A) / 'K' (0x4B)** is resolved from the event
   via lookup tables (0x524be/0x1eff74-based, 16-entry volume table). Events 0xE/0xF (media/volume
   events) are special-cased (routed to forwarders 0x2e930e/0x2e971c in pump 0x5297e; handled with a
   state-debounce in module copy 3's handler FUN_2f9bd2: last-state global vs current state compare,
   skip if unchanged). For other events, dispatcher-A FUN_52858 runs the GUPDATE chain. Nothing in this
   subsystem runs unconditionally at power-on.
2. **Scan:** compose `"%d:%s"` volume-prefixed path → `N:/.System/GUPDATE.GCD` (selector 0) or
   `N:/Garmin/GUPDATE.GCD` (selector 1) via 0x3d4a32 (varargs sprintf-family); **open** (0x3d5b56),
   stat/seek/read 256-byte chunks (0x3d5a08/0x3d5cfe/0x3d59ce), wstring compare (0x4fbc8), close.
3. **Verify — FUN_4b6d4** (GarminOS's twin of boot.bin's FUN_00000814): volume/handle validity check
   (0x9e5b8), open + 6-byte `"GARMIN"` magic memcmp (0x4b62e), record walk with **additive CheckPoint
   sum** (identical algorithm), END record len 0, then **FUN_4b68c = instruction-for-instruction twin of
   boot.bin's 4×FF tail check** (reads 4 bytes past END; memcmp 0xFFFFFFFF; <4 trailing bytes = pass).
   Verdict logged to **`0:/Debug/GCD_log.txt`** with the exact same string vocabulary as the preboot
   (`Checksum is valid.`, `GCD image is %s` + `valid./NOT valid.`, descriptor field names).
4. **Apply — FUN_4a154** (twin of boot.bin's FUN_000001c8): descriptor walk (fields crypt_key 0xA,
   erase 0xB, dset_type 0x100A, fwlen 0x2015, product_nmbr 0x1009, min_vrsn 0x100C, cur_vrsn 0x100D);
   **HWID gate: `product_nmbr == 0 || product_nmbr == *(u16*)HWID_global`** (1371); writable streams
   0x14/0x15/0x64/0xC4/0x3C1 → writer 0x4b32c; **record 8 (boot block) → event 0x517f2(2,0,0,0)** =
   hand-off to the preboot (which then applies it — F4's message-0xA3 path); completion posts
   0x4a142(3,0,0,0xFF) + 0x517f2(0,1,0,0).
5. **NO VERSION COMPARISON EXISTS.** min_vrsn/cur_vrsn are parsed, logged to GCD_log.txt, and stored —
   never compared against anything in either the GarminOS apply chain (FUN_4a154) or the preboot chain
   (F4). The `SoftwareVersion` XML tag (string @0xccf11e, unreferenced by ADR/literal — GUI/resource
   region) belongs to the GUI/settings layer (site-3 neighborhood: `0:/.System/GUPDATE.zip`,
   `7PageMainMenu`, GarminDevice.xml) — i.e. the WebUpdater/GUI update flow, not the file scan.

## Why the device ignored our GUPDATE.GCD (root cause)

1. **The scan never ran.** It is event-driven (volume/media events with a resolvable 'J'/'K' selector +
   a state-debounce), not a power-on sweep. A bare power cycle with files on the internal flash never
   produces that event → no open, no parse, no GCD_log.txt write, no diag, files untouched. This
   explains BOTH failed tests identically (official 8.20 and SW-900-bumped): nothing downstream of the
   trigger ever executed.
2. **The version spoof was doubly irrelevant:** (a) flow never started; (b) there is no version
   comparison in the apply path to satisfy — a GCD claiming SW 900 (descriptor field 13) is neither
   required nor checked here. The "downgrade needs system.xml SoftwareVersion edit" community lore
   applies to the GUI/WebUpdater flow, not this scan.
3. Placement (/.System/ vs /Garmin/) was never the problem — both paths are composed and tried.

## Testable predictions / what device-side state must change (ranked)

1. **Check `0:/Debug/GCD_log.txt` after each test.** The OS-side verifier (and preboot) log there.
   Absent entirely ⇒ trigger never fired (confirms root cause). Present with
   `Unable to open file: %s` / `GCD image is … NOT valid.` ⇒ scan ran, failure is downstream.
2. **USB mass-storage session:** connect the nüvi to a PC/host that enumerates the MSC interface with
   GUPDATE.GCD in /.System/ (and /Garmin/) — volume/session events should fire the scan; on session
   close/reboot the apply path can run. (Matches WebUpdater-era behavior and F3's USB dossier.)
3. **SD card:** 'K' is the second volume — insert a FAT-formatted SD containing GUPDATE.GCD; card
   insertion is the classic volume-arrival event. (Garmin's own SD-card update vector.)
4. If both fail: the preboot's service-script path `/Garmin/Updater/update.txt` (command verbs include
   `parse` — "Parsing \"%s\"" — plus copy/del/reboot/fftl/write_last_id; F4 findings) is the remaining
   file-based trigger, or the USB vendor-protocol hand-off (F3) that sends the preboot message 0xA3.
5. Keep product_nmbr=1371 (or 0) in the descriptor — that is the ONLY gate besides checksums+4×FF tail.

## Artifacts

| File | sha256 (first 16) | Note |
|---|---|---|
| refs/tools/f4b_strrefs.py | (committed) | ADR/ADDW/SUBW/literal xref scanner for raw ARM images |
| /tmp/f4b_out/ | — | scratch (disassembly dumps; nothing durable) |
| Ghidra project /tmp/ghidra_proj/F4 | — | boot.bin (reused); fw_all import aborted, capstone used instead |

Derived from: refs/firmware/006-B1371-00_8.20/streams/fw_all.bin
(sha256 d47036a537b2e0b2d28f43d1e48c937000829fb27551b5f2f3b702c3e50fc3dd) and
streams/boot.bin (e67995ec8f77894b7d10831dba5920c1125e37ff22b41ea734181e3f37f38a45).

## Open questions / handoff

- Exact event source that fires the volume scan (likely USB MSC session start/stop or SD insert);
  confirming needs device experiments (predictions above) or deeper RE of the media subsystem
  (0x2e930e/0x2e971c forwarders, the 16-entry volume table at the 0x524be/0x1eff74 lookups).
- Who fills the 'J'/'K' volume-character table and when (boot vs first MSC mount).
- The GUI update flow (GUPDATE.zip, PageMainMenu, SoftwareVersion XML) is unmapped — that's where the
  community's "edit system.xml" lore lives; relevant only if we emulate a WebUpdater session over the
  F3 vendor protocol.
- The 260-byte trailer verdict from F4 is now confirmed on BOTH copies of the verifier (preboot
  FUN_000007cc and GarminOS FUN_4b68c are identical): only 4×FF after END is checked.

## Recommended next move for T2

Static analysis says the file is fine as built (checksums + 4×FF + HWID 1371). The blocker is the
trigger, not the file. Do a controlled device test in this order: (1) baseline power cycle with
GUPDATE.GCD present, then read 0:/Debug/GCD_log.txt; (2) repeat while a USB MSC session is opened and
closed; (3) repeat from SD card. Capture GCD_log.txt and any new diag entries each time. If the USB
session fires the scan, T2's crafted-update delivery mechanism is "file + USB session", and the crafted
GCD needs nothing beyond what the builder already produces.
