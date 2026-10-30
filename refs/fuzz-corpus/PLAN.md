# F5 — Parser fuzzing plan (T1: mass-storage file parsers)

**Oracle:** parser crash on the nüvi ⇒ new `RTL_Trap` record in `.System/Diag/Shutdowns/*.html`
(UTF-16, has error number, 16 ARM registers, RTL source line, call stack) + a `shutdown.log`
record with `Error_Cause: 1`. Read back over mass storage — closed feedback loop, no solder.
**Baseline (2026-10-30, pre-fuzzing):** 23 html records + shutdown.log, 27 records,
causes {1:1, 2:13, 8:13}, snapshot sha256 `c4c51c55d89fca7e0cd7fe2ee8c7d730841be4cdcb27531e867cb2d491d65d8c`.
**Rule of the road:** the agent never writes to the device. `fuzz_harness.py inject` is run by
the USER (it prompts for the word `INJECT`). Everything else is read-only.

## Priority order (why this order)

| # | Parser / trigger | Why this position | Trigger (user, on device) |
|---|---|---|---|
| P1 | **GPX import** `Garmin/GPX/*.gpx` | Parsed at EVERY boot → fastest loop, one boot = one test. XML + coordinate parsing, 2012-era C. Files land in user space; boot-skips-on-bad-file means low brick risk. | just boot; then Settings → My Data/Tracks if needed |
| P2 | **JPEG** `Pictures/*.jpg` | Classic image-parser bug class (marker/length/SOF trust). Slideshow + single-photo paths both parse. | Pictures → open file / slideshow |
| P3 | **Voice** `Voice/*.vpm` (+ forged `.sum`) | Loaded on demand (voice select + every spoken prompt). TTS engine = deep parse of proprietary container. `.sum` = plain **u32 LE additive sum** of the .vpm (verified on 2 stock voices) so the harness forges it — the loader's integrity gate does NOT stop us. | Settings → Language & Voice → select new voice → play prompt |
| P4 | **Vehicle icon** `Vehicle/*.srf` | `GARMIN BITMAP 01` + u32 TLVs — we mutate type/len fields semi-intelligently. Small surface, trivial rollback. | Settings → Map & Vehicle → vehicle → pick new icon |
| P5 | **TYP** (map draw styles) | Highest-value graphics surface (draw pipeline runs always) but a standalone `.typ` is probably NOT parsed — must be embedded in an `.img` copy (phase 2: build a small test img with `parse_garmin_img.py` knowledge; never touch `gmapprom.img`). Seed carved + header-validated, so the format work is done. | (phase 2 — not injectable yet) |
| P6 | **Map `.img` subfiles / `.gma`** | Biggest surface (MPS/TRE/NOD/RGN) but slow loop + higher stakes. Route it through the microSD slot (T4) when opened; until then defer to F6 follow-up. | deferred |

Not a fuzz target ever: anything in `.System/` (incl. `GUPDATE.GCD` swaps — that's a separate
planned experiment with its own procedure), `.gcd`, `.gma` on internal flash.

## The loop (user in the loop, one mutant per boot cycle)

One file on the device per cycle = clean attribution. Batch = N cycles.

```bash
# 1. HOST: make a batch (deterministic — same --rng reproduces byte-identical mutants)
python3 refs/tools/fuzz_mutate.py refs/fuzz-corpus/seeds --out /tmp/mut -n 10 --rng 1
#    (or one seed type:  fuzz_mutate.py refs/fuzz-corpus/seeds/jpeg --out /tmp/mut -n 10 --rng 1)

# 2. HOST (user-run; prompts for INJECT): copy ONE mutant to the device
python3 refs/tools/fuzz_harness.py inject --file /tmp/mut/Garmin_Asia.m0003.jpg
#    → mounts rw (udisksctl, no ro), copies, fsync+sync, unmounts, prints the procedure,
#      appends the exact dest+md5 to refs/fuzz-corpus/injected.log

# 3. USER (hands on the device): unplug → power on → trigger (see table above) → observe:
#       normal | silent skip | app error dialog | crash+restart | hang/freeze | reboot loop

# 4. HOST: plug back in, diff the oracle
python3 refs/tools/fuzz_harness.py collect          # exit 0 clean / 3 weak / 2 CRASH
#    → JSON details:  collect --json /tmp/diff.json

# 5. Record the outcome in refs/fuzz-corpus/results.md (mutant, md5, rng seed, behaviour, verdict)
# 6. Rollback the file (below), then next mutant.
```

## Expected signal (what collect tells you)

| Observation | Meaning | Verdict |
|---|---|---|
| New `*_RTL_Trap.html` + `shutdown.log` record `Error_Cause: 1`, non-zero registers | **Parser crash — GOLD.** collect prints error number, RTL source line (`file.c line, msg`), call stack, task id | exit 2 → save mutant as `CRASH-<name>`, re-run once to confirm (deterministic RNG makes this trivial), then hand to Ghidra track (F4) for crash-address triage |
| `Error_Cause: 8` (abnormal powerdown) burst correlated with the inject session | Crash without trap write (watchdog/power) or user unplugged during parse — weak, ambiguous | exit 3 → repeat mutant; only escalate if reproducible |
| No records, but boot hang / reboot loop / UI freeze | Hang (worse than a clean crash — potential DoS class) | no oracle trace; note behaviour in results.md, rollback immediately |
| `shutdown.log` grew with known-hash records | Device shut down again since baseline (e.g. you unplugged power mid-boot) | exit 3, usually noise — correlate |
| Nothing new, device behaves normal | Parser survived (rejected the input) | exit 0 — mundane, next mutant |

**Hang is the one worse-than-crash outcome** (no trap written, device may not boot). Recovery is
assured: the 25x5 enumerates mass storage over USB independent of GarminOS booting — connect to
the PC, delete the injected file. If it must be forced: hold power ~10 s, reconnect.

## Rollback (after every cycle / session)

1. `refs/fuzz-corpus/injected.log` is the ledger — every inject logs dest path + md5.
2. Delete those exact device paths (user action): via the PC file manager over USB, or from the
   device UI (Pictures/vehicle/voice menus support delete).
3. For voice: delete BOTH `X.vpm` and `X.sum`.
4. Verify with `fuzz_harness.py collect` — should be exit 0 again (oracle unchanged by rollback).
5. Nothing we inject is in `.System/`; stock behaviour is restored by deletion alone. If the
   device is ever left in a weird state: power off, let RTC/battery settle, boot once WITHOUT the
   injected file before fuzzing further.

## Corpus / hygiene

- Seeds: `refs/fuzz-corpus/seeds/` (8 files, 3.8 MB, hashes in findings/F5) — committed.
- Mutants are transient: generate into `/tmp`, do not commit except `CRASH-*` keepers.
- `manifest.jsonl` (mutator output) + `injected.log` (harness) = full provenance of anything on
  the device.
- Battery is EOL: fuzz on external/car power, expect sudden cause-2 records (they're baseline
  noise you already know how to read).
