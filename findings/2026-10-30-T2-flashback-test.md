# 2026-10-30 — T2 flash-back test: INJECTED, awaiting device apply

**Task:** zero-risk end-to-end proof of the custom-update chain (user approved: "lets make it work first")
**Status:** file injected ✓ — device-side apply PENDING (user executes power-cycle on WALL power)

## What was done (host side)

1. `gcd_tool.py` extended: `parse_file_split()` + round-trip now preserves the post-END trailer.
2. **Official 8.20 GCD rebuilt through our parser+builder: BYTE-IDENTICAL** — 50,200,720 B,
   260-B trailer (FF-magic ✓) preserved.
   - sha256 rebuilt: `52625603c9b3ba521da269be534f9fae8fa4dd3bf4291b80cfc5774ab95680a2`
   - sha256 original (F1's recorded hash): **identical** → the builder reproduces Garmin's
     firmware atom-for-atom.
3. User data backed off device (read-only) → `/home/kchauhan/garminageddon-backups/2026-10-30/`
   (48 MB, 34 files: GPX/ incl. Archive, SQLite DBs, GarminDevice.xml).
4. Injected as `.System/GUPDATE.GCD` (rw mount, cp, sync):
   - on-device sha256 verified `52625603…` ✓, size 50,200,720 ✓
   - unmounted cleanly.

## Expected device behavior (per F4 RE)

- On next boot (USB disconnected), preboot (`boot.bin` 8.20) finds GUPDATE.GCD, walks records,
  CheckPoints pass (additive sums), HWID 1371 ✓, END len 0 ✓, tail FF-magic ✓ → erases flash
  region 14 → deXOR (crypt_key from descriptor; XOR=0 for main fw) → writes fw_all.bin bytes
  (IDENTICAL to what's already there) → Record ID 8 (boot block) skipped → deletes GUPDATE.GCD →
  boots GarminOS 8.20 normally.
- Risk analysis: bytes written = bytes already present; bootloader region untouched; file
  checksums verified at rest and in-flight. Residual risks: power loss mid-flash (mitigated:
  WALL POWER REQUIRED — battery is EOL), unknown GarminOS-side same-version behavior (worst
  case: file ignored/deleted, no flash — still informative).

## USER PROCEDURE (safety-critical)

1. Move the nüvi's cable from laptop to a **WALL USB charger** (NEVER battery-only — the
   5-second unplug gap is safe; the flash only starts at boot on wall power).
2. Power the unit on. Expect an update/progress screen for **several minutes**. DO NOT
   interrupt power during this.
3. Let it reboot to the normal UI. Confirm it behaves normally.
4. Replug to laptop. Then verification (host side): GUPDATE.GCD gone from .System/,
   version still 8.20, no new RTL_Trap records (F5 harness `collect`), normal function.

## Verification checklist (post-apply)

- [ ] `.System/GUPDATE.GCD` consumed (file gone)
- [ ] SoftwareVersion still 8.20
- [ ] No new Shutdowns/ records vs F5 baseline (collect exits 0)
- [ ] Device boots and navigates normally (user confirms)
- [ ] OSM Ontario map still enabled

## Rollback / recovery

- Identical-bytes re-flash is its own rollback. If boot loops: re-drop official
  `nuvi24x5and25x5_GCDFile__820.gcd` as GUPDATE.GCD (preboot re-applies). If unflashable:
  UART/JTAG (F9/F10) — full firmware corpus + boot.bin on hand for rebuild.

---

## RESULT (2026-10-30 15:2x): CHAIN PROVEN END-TO-END ✓

Round 3 (v900) SUCCEEDED:

1. USB-session event (not power-cycle — F4b verdict) fired the scan; preboot accepted the
   v900 file (SW 9.00 claimed / payload = official 8.20), applied it (multiple long boots =
   region-14 flash write), consumed `.System/GUPDATE.GCD`.
2. The `/Garmin/GUPDATE.GCD` second copy caused a re-apply LOOP (each session re-triggered);
   loop broken by deleting remaining file. Lesson: ONE copy only.
3. No new shutdown/crash records through the entire apply+loop saga. Device healthy, boots
   normally, About = 8.20 (payload unchanged, as designed), OSM map intact, version XML
   restored to 820, both trigger locations empty.

**T2 verdict: custom-firmware delivery chain = parser → builder → verifier → preboot → flash
→ reboot. ALL PROVEN ON HARDWARE.** The device now runs firmware we delivered through our own
toolchain. Remaining for arbitrary code: patch fw_all.bin payload itself (needs GarminOS RE —
splash bitmap format first target).
