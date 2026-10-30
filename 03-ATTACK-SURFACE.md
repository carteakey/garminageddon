# 03 — Attack Surface (ranked, no-solder first)

Context: user's own device; RE/attack work authorized. Goal = code execution in GarminOS (or at minimum: controlled crashes, firmware dump, deep RE). UART/JTAG deferred — software first.

## T1 — Mass-storage file parsers (easiest, reliable feedback)

Every boot/import the device parses attacker-writable files from the FAT volume:

| Parser | Entry path | Notes |
|---|---|---|
| GPX/XML | `Garmin/GPX/*.gpx` imported at boot | XML + coordinate parsing, 2012 C code |
| JPEG | `Pictures/` slideshow | classic image-parser bug class |
| Voice files | `Voice/*.vpm` | custom-voice scene proves format is writable/modifiable |
| Vehicle icons | `Vehicle/*.srf` | small parse surface |
| Map `.img` | `Garmin/*.img` | subfile parsers (MPS/TRE/NOD/RGN) — biggest surface, also reachable via microSD slot (needs cover opened, battery out first) |
| `.gma`/`.unl` | map license blobs | crypto is historically weak (community unlockers) |

**Oracle:** on-device crash ⇒ `RTL_Trap` record appended in `.System/Diag/Shutdowns/` + `shutdown.log`, read back over mass storage. Known-good baseline: 2014 crash `0x6E5D8017`.
**Status:** not started. Needs: harness script (mount ro copy→reboot prompt→collect trap), corpus seeds.

## T2 — Garmin USB vendor protocol (crown jewel)

- Mass-storage mode exposes **no** vendor interface (verified: single MSC interface). Mode switch to Garmin-protocol mode happens with update software — mechanics TBD (research: gpsbabel/garmintools sources, old WebUpdater traces).
- Prize: firmware update path. 2012-era bootloaders believed CRC-only (no signature). If the 2595 accepts a crafted `.gcd` over USB → persistent code execution, case unopened.
- Secondary: protocol likely exposes diag commands (GarminDevice.xml hints: BatteryLog generation, screenshots in some models) = more attack surface + device control.
- **Status:** not started. Needs: protocol RE (gpsbabel source has packet grammar for older devices), mode-switch discovery, libusb fuzzer.

## T3 — Bluetooth HFP/PBAP (user pairing required)

- Target = nüvi's own handsfree stack parsing **AT commands + phone-supplied strings** (caller ID, phonebook entries). 2012-era code.
- Reach: ~10 m, needs pairing (device's phone-setup screen, legacy PIN flow). User must pair a phone/dongle once; then a laptop/BT-dongle can fuzz.
- Realistic: DoS/crash = high probability, quickly. Memory-corruption → exec = hard mode but is the same code-exec win as T2.
- BT *module* firmware may be one of the RemoteSW blobs → offline RE to guide the fuzzing.
- **Status:** not started; blocked on user pairing a device.

## T4 — SD card (semi-hardware)

microSD slot is behind the battery cover → case opening (battery out first — swelling risk). Value: same T1 parsers fed from removable media without touching internal flash; also a persistence channel.

## T5 — Hardware phase (deferred)

- UART test pads: 3.3 V, near-certain present; boot log + possible diag monitor. $2 CP2102 + multimeter + needles.
- JTAG: TI ARM; OpenOCD; firmware dump + arbitrary patching. Needs pads identified (PCB photos, continuity probing).
- EULA/`Diag/html/supported_features.html` and boot-key combos (e.g. top-left corner + power) = on-device service menu — free recon, do before soldering.

## Offline RE track (no device needed — current focus)

1. Acquire official firmware `006-B1371-00` (SW 8.20 ± older revs) as `.gcd` — Garmin servers / community archives.
2. Write `GARMIN` container unpacker (format documented in 02-RECON.md from RemoteSW headers).
3. Ghidra the ARM payload: locate parser entry points (GPX/JPEG/AT), the update-verification code (signature vs CRC), flash layout, and the sys_log format.
4. Cross-reference: RemoteSW blobs (already in hand) are warm-up targets with the same container format.
