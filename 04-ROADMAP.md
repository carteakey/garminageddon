# 04 — Roadmap / open work items

Pick a task, note your claim in `findings/YYYY-MM-DD-<topic>.md`, record hashes for everything.

## Immediate (no hardware)

- [ ] **F1. Firmware hunt** — locate direct download for official nüvi 2595 firmware part `006-B1371-00` (`.gcd`). Try Garmin's own endpoints (support.garmin.com product page, download.garmin.com patterns, old WebUpdater webservice endpoints) and reputable community archives (gpsrchive.com, GPSR forum mirrors, archive.org). Older versions also welcome. Deliver: URL(s), sha256/md5, size, provenance notes. **Claimed 2026-10-30 (first run).**
- [x] **F1. Firmware hunt** — DONE 2026-10-30: **all 14 published versions of 006-B1371-00 secured** (6.30→8.30, incl. device's 8.20) into `refs/firmware/` (870 MB, gitignored — hashes in `refs/firmware/hashes.txt`). 8.30 still live on Garmin CDN; older via Wayback of gawisp.com/perry mirror. All 45 CheckPoints verified, HWID=1371 confirmed. Extracted `boot.bin` (0x0008, ~750 KB — the bootloader, 14 versions for diffing) + `fw_all.bin` (0x02BD, ~49.4 MB GarminOS). **⚠ Undocumented 260-B trailer after END** (4×0xFF + 256 B content-derived) — not checksum-covered; if bootloader verifies it, "checksum-only" needs revision → F4 must resolve. See `findings/2026-10-30-F1-firmware-hunt.md`.
- [x] **F2. GARMIN container unpacker** — DONE 2026-10-30: `refs/tools/unpack_garmin.py`, format validated on all 4 blobs, extractions in `refs/remote-sw/`. See `findings/2026-10-30-F2-gcd-unpacker.md`. Follow-ups: payload compression ID, header/trailer checksum RE, .gcd *builder*.
- [x] **F2b. GCD format solved + builder proven** — DONE 2026-10-30: correct framing (u16 ID + u16 len) per Oppmann doc `refs/protocol/GCD_Format.txt`; CheckPoint additive-sum (incl. 8-B header) verified on 11/11 remote-blob checkpoints + 45/45 main-firmware checkpoints; round-trip byte-identical ×4; remote payloads = raw GTM traffic-receiver firmware (no compression, XOR field not applied). Tool: `refs/tools/gcd_tool.py` (parse/roundtrip/extract) + `verify_gcd.py`. See `findings/2026-10-30-F2b-gcd-format-solved.md`. **Container layer has no crypto barriers left** — open question is only the 260-B trailer (→ F4).
- [x] **F3. USB mode-switch research** — DONE 2026-10-30: **no mode switch exists** — nüvi 24x5/25x5 has no Garmin-protocol USB mode (5-source verdict incl. official manual + device manifest). Packet-layer dossier written (IntfSpec 001-00063-00 Rev G, gpsbabel/garmintools), probe at `refs/tools/probe_garmin_usb.py`. Consequence: T2 crown jewel re-scopes to the mass-storage `.System/GUPDATE.GCD` → bootloader (checksum-only) path. See `findings/2026-10-30-F3-usb-protocol.md`. PID corrected: device enumerates as `091e:255b`, not 455b.
- [ ] **F4. Ghidra setup + first-pass RE** — install Ghidra; import unpacked main firmware payload; identify: load address (search vector table), the update-verification routine (CRC vs signature), string refs to `gpk\tsk_emb_lib\`, file parser entry points. Deliver: function notes + screenshots in findings/.
- [x] **F5. Parser fuzz corpus** — DONE 2026-10-30: offline-ready kit in `refs/fuzz-corpus/` (8 seeds, 3.9 MB, hashes in findings) + `refs/tools/fuzz_mutate.py` (deterministic, format-aware: GPX/JPEG/VPM/SRF/TYP) + `refs/tools/fuzz_harness.py` (baseline/inject/collect; inject is user-invoked only, mount-ro everywhere else). Pre-fuzz baseline captured (27 records, snapshot sha256 c4c51c55…). **Bonus: `Voice/*.sum` = u32 LE additive sum of the .vpm** (verified ×2) — voice parser is fuzzable without an integrity barrier. Loop ready for user cycles; see `refs/fuzz-corpus/PLAN.md` + `findings/2026-10-30-F5-fuzz-kit.md`.
- [x] **F6. Map format recon** — DONE 2026-10-30: `refs/tools/parse_garmin_img.py` (full DSKIMG/FAT/TRE/GMP/MPS parser, validated on all 3 imgs). See `findings/2026-10-30-F6-map-subfiles.md`. Highlights: gmapprom = GMP-tiled NT map FID 2920 (178 tiles, MD2/MDR/TRF/TYP + plaintext 25-char unlock-style code `<UNLOCK_CODE_REDACTED>` in MPS); .gma = "GARMIN GMA" v1, 256+2048+256-byte high-entropy sections (open: field semantics); Garmin imgs pad to zero byte-sum, mkgmap's don't.

## User-assisted

- [ ] **F7.** Bluetooth: pair a phone to the nüvi (Settings → Bluetooth), confirm service list (HFP/PBAP/A2DP?), then we fuzz AT/phonebook fields from host.
- [ ] **F8.** On-device service menu recon: try boot combos (top-left corner + power; also check `Diag/html/supported_features.html`). Photograph menus → findings/.

## Deferred (hardware)

- [ ] **F9.** UART pad hunt (open case, battery out, multimeter, CP2102). Boot log capture → findings/.
- [ ] **F10.** JTAG/OpenOCD dump of protected NAND partition.

## Post-exploitation fun (once we have exec or control)

- Custom boot splash / "your text here" on a 2012 dashboard unit.
- Sys_log format decoder for live triage.
- Weather-station kiosk mode (Path A in README history: rendered forecast JPEGs auto-synced — no exploit needed, ships with OSM map already).
