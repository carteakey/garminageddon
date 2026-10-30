# ☢️ Operation GARMINAGEDDON

> Giving a 2012 Garmin nüvi 2595 both a new life (weather station / RPi kiosk) and a second career as an exploit-mining target.
> Motto: *It's not obsolete, it's vintage attack surface.*

## Mission

1. **New life:** OSM maps installed (done), weather-station kiosk mode (planned), RPi-in-the-shell gut job (optional phase 2).
2. **The quest:** full firmware recon → RE → exploitation of GarminOS, prioritizing **no-solder vectors** (USB protocol, mass-storage file parsers, Bluetooth). Hardware phase (UART/JTAG) only when software vectors are exhausted or need it.

## Status board

| Track | Status |
|---|---|
| OSM Ontario map installed + verified | ✅ done 2026-10-30 |
| Battery forensics (verdict: EOL) | ✅ done |
| Filesystem recon (maps/ASR/SID/RemoteSW/diag) | ✅ done |
| Official firmware `.gcd` acquisition | 🔄 in progress |
| GCD container unpacker | ⬜ pending |
| Ghidra analysis of main firmware | ⬜ pending |
| Garmin USB protocol probe (vendor interface) | ⬜ pending |
| Parser fuzzing loop (GPX/JPEG → trap-log oracle) | ✅ kit built 2026-10-30 (baseline captured; awaiting user inject/collect cycles) |
| Bluetooth HFP/AT fuzzing | ⬜ pending (needs user pairing) |
| Hardware phase: UART pads / JTAG | ⬜ future |

## Agent briefing — READ THIS FIRST

- `01-DOSSIER.md` — device identity, state, all identifiers. Everything you cite should match this.
- `02-RECON.md` — findings so far (filesystem, logs, blobs). Don't re-discover what's here.
- `03-ATTACK-SURFACE.md` — ranked vectors + what each needs.
- `04-ROADMAP.md` — open work items. Claim one, say so in your findings file.
- `findings/` — **agents append one file per task**: `YYYY-MM-DD-<topic>.md`. Use `findings/TEMPLATE.md`.
- `refs/` — links, downloaded artifacts, source material.

### Ground rules

1. **The device is read-only by default.** Mount ro. Never write/flash to the nüvi without the user's explicit approval for that exact action.
2. **Record hashes** for every artifact downloaded or copied (md5/sha256).
3. **Cite paths** — device paths as `/run/media/.../GARMIN/...`, host paths absolute.
4. This is the user's own device; RE/attack work is authorized. No third-party targets.
5. Battery warning: 14-year-old pack, deep-discharged since 2021. Do not leave device powered unattended; check for swelling before ANY case opening.
