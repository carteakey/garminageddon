# REA Brief — full RE of the nüvi 24x5/25x5 firmware corpus

Mission: complete RE of the GarminOS image (`fw_all.bin`, ~49.4 MB, ARM32 LE + Thumb, ThreadX-style RTOS)
using the [REA toolchain](https://github.com/morluto/rea) (MCP: Binwalk/Unblob → Ghidra/IDA handoffs).

## What's already known (do NOT re-derive — see findings/)

- **GCD container**: fully solved (u16 ID + u16 len records; CheckPoint = additive byte-sum
  incl. 8-B header; 4×FF trailer rule; HWID gate 1371). Tool: `refs/tools/gcd_tool.py`.
- **Bootloader** (`boot.bin`, 772,408 B, base 0x0): verifier FUN_00000814, trailer check
  FUN_000007cc, apply flow (erase region 14 → deXOR → write), no crypto anywhere.
- **Update trigger is EVENT-driven** (USB session / volume events), not boot-time (F4b).
- fw_all contains: embedded DSKIMG basemap (~0xAEA84E in 8.20), resource-type string tables
  ("GARMIN BITMAP 01"/"GBITMAP"/"GDEMO") in boot.bin @0x50C98+0xA8D18.

## Open targets (priority order)

1. **Boot splash bitmap** — location + format of the power-on logo (Garmin Bitmap variant?
   raw framebuffer? RLE?). Key question for the custom-splash patch.
2. **sys_log1.bin format** (2 MB binary RAM/log dump) — structure for live triage.
3. **GCD record 0x0510 ("logo")** — preboot handler: destination flash address for logos.
4. **File parser functions** (GPX/JPEG/.vpm) — entry points for the fuzz harness feedback loop.
5. **ASR engine** (.System/ASR ~930 MB acoustic models) — format + patchability.
6. **Protobuf services** — fw_all embeds protobuf runtime; enumerate message schemas.

## Assets

- Firmware corpus (14 versions, per-version extracted boot.bin/fw_all.bin): sibling repo
  `garmin-firmware/` (private/Forgejo) — ask the operator for access.
- Working tools in `refs/tools/` (gcd_tool.py parse/roundtrip/bump-version/extract,
  verify_gcd.py, f4b_strrefs.py PC-relative xref scanner).
- The device is live and update-delivery is PROVEN end-to-end (see
  findings/2026-10-30-T2-flashback-test.md) — payload patches ship via GUPDATE.GCD.

## Ground rules

Owner's own device; lawful interoperability research. No redistribution of Garmin binaries.
