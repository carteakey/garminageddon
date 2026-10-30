# 2026-10-30 — F3: Garmin USB protocol dossier + mode-switch verdict

**Task:** F3 (USB vendor protocol research + probe, roadmap item "USB mode-switch research")
**Agent/Run:** agent run 2026-10-30 (live probing performed mid-run after gpsbabel 1.10.0 + python-pyusb 1.3.1 were installed)
**Status:** DONE — with a major verdict: **the nüvi 24x5/25x5 family has no Garmin-protocol USB mode to switch into.** The T2 "crown jewel" vector needs re-scoping to the mass-storage GUPDATE.GCD path.

## What was done

- Passive live recon of the connected nüvi (sysfs + libusb descriptor reads + `gpsbabel -i garmin` scans). No packets were sent to the device; nothing was mounted read-write; no file on the device was touched.
- Protocol dossier built from primary sources: official Garmin spec PDF (downloaded), gpsbabel `jeeps/` USB sources, garmintools 0.10 tarball (downloaded, extracted under `refs/protocol/`).
- Mode-switch question answered from 5 independent sources (official manual, GPSBabel docs, gpsbabel source, device's own `GarminDevice.xml`, live enumeration) — all agree: **no vendor interface, no switch, on this family**.
- Wrote + ran `refs/tools/probe_garmin_usb.py` (pyusb with sysfs fallback; handshake code included and spec-correct, but cannot fire on this device).

## 1. Protocol dossier — Garmin USB packet layer (classic, pre-MTP devices)

Canonical sources: **Garmin Device Interface Specification, `001-00063-00 Rev. G`** (in `refs/protocol/iosdk-extracted/IntfSpec.pdf`, from Garmin's official I/O SDK `IOSDK.zip`), gpsbabel `jeeps/gpslibusb.cc` / `jeeps/garminusb.h` / `jeeps/gpsusbsend.cc` / `jeeps/gpsusbread.cc`, garmintools 0.10 `src/usb_comm.c`.

**Wire format (spec §3.2.2, "Table 3 – USB Packet Format")** — 12-byte header, **no checksum** (unlike the serial DLE/ETX framing):

| bytes | meaning |
|---|---|
| 0 | Packet Type: `0x00` = USB protocol layer, `0x14` (=20) = Application layer |
| 1–3 | reserved (0) |
| 4–5 | Packet ID (LE u16) |
| 6–7 | reserved (0) |
| 8–11 | Data Size (LE u32) |
| 12+ | data |

- Buffer sizes: gpsbabel/garmintools cap data at **1024 B** (`garminusb.h` union `dbuf[1024]`); the Windows driver spec uses `MAX_BUFFER_SIZE 4096`; if a write is an exact multiple of the USB packet size, a **zero-length transfer** must follow (spec §3.2.4).
- Session handshake (spec §3.2.3.2/3.2.3.3, gpsbabel `gusb_reset_toggles`): host sends **`Pid_Start_Session = 0x0005`** (type 0x00) — gpsbabel sends it **3×** (comments: reset bulk-out toggle, reset intr-in toggle, start session) — device answers **`Pid_Session_Started = 0x0006`** with payload = **uint32 unit ID**. gpsbabel waits for `pkt_id==6 && datasz==4`, ≤10 tries. garmintools `garmin_start_session` does the same and reads the 16-byte reply (12 hdr + 4).
- Product identification (the "A000/A001-style" handshake — note: there are no A000/A001 *PIDs*; A-numbers are capability tags): host sends application-layer **`Pid_Product_Rqst = 0x00FE`** (gpsbabel: `{20,0,0,0,0xfe,0,...}`), device returns **`Pid_Product_Data = 0x00FF`** (u16 product_id, s16 software_version, ASCII description) and **`Pid_Protocol_Array = 0x00FD`** (triples: 1-char tag + u16 number, e.g. `A010`, `L001`, `D110`). gpsbabel's loop ends on 0xFD. (spec §4.1.1; gpsbabel `gusb_syncup`)
- USB-layer `Pid_Data_Available = 0x0002` (type 0x00): "read the bulk pipe until you get a zero-length USB transfer" (spec §3.2.3.1, gpsbabel `gpsusbread.cc` eats those zero-length bulk packets).
- **Pipe model** (spec §3.2.1): host always writes Bulk OUT; device answers on **Interrupt IN or Bulk IN** (sticky per protocol); host must constantly poll the interrupt pipe. gpsbabel discovers all 3 endpoints from descriptors and fails if any is missing; timeouts `TMOUT_I = TMOUT_B = 5000 ms` (garmintools: 3000 ms). Some devices (276/296) alternate bulk/interrupt per packet (gpsbabel workaround comment).
- Device discovery: gpsbabel requires **`bDeviceClass == 0xFF`** (vendor spec) and says it outright: *"Exclude Mass Storage devices (CO, OR, Nuvi, etc.)"* (`gpslibusb.cc`). garmintools matches VID `0x091e` / PID `0x0003` (protocol-only devices).

## 2. Mode switch — VERDICT: none exists on the nüvi 25x5

Five independent sources, all consistent:

1. **Official owner's manual** for this exact family (nüvi 2405/2505 series OM 190-01355-00_0D, Feb 2012 — downloaded from `static.garmin.com`, `refs/protocol/nuvi_2405_2505_series_OM_EN.pdf`): USB appears only in "Data Management" (file copy/delete, disconnect procedure). There is **no "Interface" setting and no "Garmin Spanner"** in the System Settings chapter (text searched). Contrast: older nüvi 2x5 (2007-era) and 13x0 series manuals do have Interface → Garmin Spanner / USB Mass Storage.
2. **GPSBabel official docs** (gpsbabel.org fmt_garmin.html): nüvi 200…3790T, Zumo, Oregon, Colorado, eTrex x0, GPSMap 62/78 "are supported, but they do not support Garmin communication protocol and don't work with the garmin option" → "read or write GPX files from the mass storage device".
3. **gpsbabel source** (above): protocol driver filters to class-0xFF devices and excludes "Nuvi, etc." mass-storage units.
4. **The device's own manifest** `Garmin/GarminDevice.xml`: every DataType is a file at a filesystem path (`MassStorageMode` container); **zero** mentions of USB protocol/serial/GarminMode; the declared firmware-update channel is `<UpdateFile><PartNumber>006-B1371-00</PartNumber><Version><Major>8</Major><Minor>20</Minor></Version><Path>.System</Path><FileName>GUPDATE.GCD</FileName></UpdateFile>`.
5. **Live enumeration** (this run): device class 0x00, single config, single interface 1-2:1.0 = MSC (`class 08 / subclass 06 / protocol 50`, bulk EP 0x01 OUT + 0x83 IN, 512 B, 500 mA, **no string descriptors except iSerial=5** = `<SERIAL>` = UnitId <UNIT_ID> in hex). `gpsbabel -i garmin -f usb:` → `garmin: Found no Garmin USB devices.` (log in `refs/protocol/logs/`).

So the dossier's assumption "vendor interface appears when talking to WebUpdater-class software" is **false for this unit**: WebUpdater/myDashboard on the 25x5 talks **mass storage only**. Mode switching does exist elsewhere in Garmin-land (context, not applicable here):

- **Watches (Vívosmart HR):** documented private command switches the *protocol-mode* device INTO mass storage: 13-byte packet `14 00 00 00 2f 04 00 00 01 00 00 00 00` = application-layer packet, **PID 0x042F**, 1 data byte `00`, written to bulk OUT (Leberwurscht/vivosmart `send_command.py`, mirrored by mormegil-cz/GarminUsbMassStorageMode). This proves Garmin's private PID scheme rides the same 12-byte header.
- **Handhelds** (Oregon/Colorado/Dakota/eTrex): user picks the mode on-device (Setup → Interface).
- **Newer devices** use MTP instead of UMS (openExpress handles both; still file-based).

A reverse "mass storage → protocol" packet for nüvi is **not documented anywhere public**; if one exists it would be the same scheme (private PID over the MSC bulk pipe — i.e. a SCSI-vendor-command channel). Experimenting with undocumented commands against the nüvi is state-changing and **requires user approval** — left as a commented-out section in the probe.

## 3. Update / diagnostics layer above it

- **The firmware update path needs no packet protocol at all**: per the device manifest (and the WebUpdater/myDashboard flow in the manual: myDashboard → software updates → follow on-screen), the host copies `GUPDATE.GCD` into `.System/` (or the device pulls it) and the **bootloader applies it at next boot**, then removes it. Community scene (navitotal "Universal Firmware Patcher", gpspassion/gpspower threads cited in the GCD format doc) installs patched firmware by renaming to `gupdate.gcd` — i.e. the whole "trusted" chain is filename + in-file checks.
- **GCD integrity = additive checksum, not a signature** (memotech.franken.de "Garmin GCD Firmware Update File Format", H. Oppmann 2026-08-31, `refs/protocol/Garmin_GCD_Format.pdf`): the **CheckPoint record (ID=0x0001, length 1)** holds a byte chosen so the sum of *all file bytes up to and including it* is 0x00 (length-4 variant: "maybe CRC32"). Firmware streams ride in ≤0xFF00-byte data records; `Firmware` section points to the companion `Garmin_BIN_Format` doc. Matches our F2 findings (unencrypted records, part-number string in the clear) → strengthens the "2012 bootloader = checksum-only" hypothesis.
- **Garmin Express-era "diagnostics protocol"**: not applicable to the 2595. Verified from the Express-reimplementation **openExpress** (TomaszBojanowski): device I/O is exclusively `UmsStorage` (GIO-mounted UMS) or `ptp.py` (MTP via gvfs); "diagnostics" are **files** (`Garmin/Debug/err_log.txt`, `Garmin/Debug/dump`, `ErrorShutdownReports`, `KPI`, `RAMDump`...) — nothing packet-based on the wire.
- **"garmin_diagnostics" / "A701"**: searched (GitHub API repo/code search, general web, multiple phrasings) — **no public implementation or documentation found**. The hint in the task brief could not be corroborated; if it exists it's private Garmin-internal material. Recorded as a dead end; the 0x042F watch command is the only concretely documented Express-style private command found.
- The official SDK sample (`USBSDK.c`) speaks the same packet protocol via Garmin's Windows driver (GUID `{2C9C45C2-8E7D-4C08-A12D-816BBAE722C0}`) — irrelevant to nüvi but useful later if we ever meet a protocol-mode Garmin.

## 4. Security assessment (attack-surface re-ranking)

- T2 as written ("vendor protocol → firmware update") is **dead on this hardware**: no vendor interface exists in any documented state of a nüvi 25x5. The USB-facing surface in MSC mode is the standard usb-storage/SCSI path (generic, not Garmin-proprietary).
- The **crown jewel moves to the GUPDATE.GCD → bootloader path over mass storage**: host writes one file to `.System/`, user reboots, bootloader validates (byte-sum/CRC, per Oppmann doc + community patcher practice) and flashes. That is T1-adjacent (file write, no exploit needed — just needs the checksums forged, which F2's unpacker groundwork + Oppmann doc make tractable) — but it is by definition a **state-changing, bricking-risk experiment**: requires user approval, a known-good recovery `.gcd`/`.rgn` path, and fresh power (EOL battery!).
- Side value gained: the full packet grammar is now documented and the probe implements it, so if we ever get a protocol-mode Garmin (e.g. a cheap 60CSx/etrex for lab duty, or a friend's wearable), we're ready.

## 5. Probe — location, design, live output

`refs/tools/probe_garmin_usb.py` (sha256 `9d2bcc91248ef92705fcd649611c53864678b8b6ee388bf38942fd3406f8c635`):

- Enumerates all VID `091e` devices; prints device/config/interface/endpoint/class codes; pyusb backend with graceful sysfs fallback (pure stdlib descriptor parser — works sandboxed and without pyusb).
- Vendor-class (0xFF) interface found → documented passive handshake only: 3× Start Session (PID 5) → Session Started (PID 6, uint32 unit id) → Product Request (PID 0xFE) → Product Data (0xFF) + Protocol Array (0xFD). Interrupt-IN first, honors `Data_Available` → bulk burst → zero-length terminator. 5 s timeouts, ≤10 retries. MSC interfaces are **never written to**; the reverse mode-switch experiment is included **commented out** with an explicit approval requirement.
- Live run (pyusb path): device `091e:255b`, MSC-only, no 0xFF interface → probe correctly declines to send anything. Full outputs: `refs/protocol/logs/probe_pyusb_run.txt`, `probe_sysfs_fallback_run.txt`, `gpsbabel_usb-first.txt` ("Found no Garmin USB devices"), `gpsbabel_usb-list.txt`.

Probe run summary (pyusb backend):

```
device: 001/026  VID:PID 091e:255b  backend=pyusb/libusb
  bDeviceClass=0x00
  serial: <unreadable: The device has no langid (permission issue, ...)>   <- sysfs shows <SERIAL>
  config 1: 1 interface(s), 500 mA
    interface 0: class 0x08 subclass 0x06 protocol 0x50  mass storage
      ep 0x83 in  bulk maxpkt=512
      ep 0x01 out bulk maxpkt=512
  => MASS-STORAGE-ONLY device (no 0xFF interface) ... No packets will be sent to it by this probe.
RESULT: no vendor-class (0xFF) interface present ... classic Garmin packet protocol is NOT reachable.
```

## 6. Next step requires user action

1. **Approve re-scoping T2** in `03-ATTACK-SURFACE.md` to "mass-storage GUPDATE.GCD → bootloader (checksum forging)" as the crown-jewel vector, USB protocol demoted to "N/A on this device (documented)".
2. **Approve (separate task, not this run)** any experimental probing of undocumented mode-switch/SCSI-vendor commands against the nüvi — state-changing, bricking risk, EOL battery. Must be preceded by: fresh/replaced battery or external power, and acquisition of a recovery image + flasher (`F1` firmware hunt + known-good `.rgn`/`.gcd` restore path) first.
3. If a protocol-mode Garmin unit is ever acquired for lab duty: the probe is ready (`python3 refs/tools/probe_garmin_usb.py`, ideally unsandboxed; blacklist `garmin_gps` kernel module if it binds).

## Artifacts

| File | sha256 | Source |
|---|---|---|
| `refs/protocol/IOSDK.zip` | 680fb00b86449ad006e3a309e54b371654ae29e4a82c614dcb0b929d6b8d2402 | garmin.com/support/commProtocol.html (official I/O SDK) |
| `refs/protocol/iosdk-extracted/IntfSpec.pdf` | ca3af376dea0a759afbb6c2dd48b948a6cb90b1e21e3865c50c983157700730a | inside IOSDK.zip — Garmin Device Interface Spec 001-00063-00 Rev. G |
| `refs/protocol/garmintools-0.10.tar.gz` | ffd50b7f963fa9b8ded3223c4786b07906c887ed900de64581a24ff201444cee | Google Code archive (garmintools, D. Bailey) |
| `refs/protocol/Garmin_GCD_Format.pdf` | b32237d06306fae9cc99e49a0cd12c5ceb41e6d65f2273c04853bb10741626eb | memotech.franken.de (H. Oppmann, 2026-08-31) |
| `refs/protocol/nuvi_2405_2505_series_OM_EN.pdf` | 7ee265c594b10fbb7473d8066ab85ab439a6b4eb2e9babac7d80c9a241936d0e | static.garmin.com/pumac (official OM 190-01355-00_0D) |
| `refs/tools/probe_garmin_usb.py` | 9d2bcc91248ef92705fcd649611c53864678b8b6ee388bf38942fd3406f8c635 | this run |
| `refs/protocol/logs/*.txt` | — | live probe/gpsbabel run logs (this run) |

Source code mirrors consulted: gpsbabel master `jeeps/{garminusb.h,gpslibusb.cc,gpsusbsend.cc,gpsusbread.cc}`, `fmt_garmin.html` docs; Leberwurscht/vivosmart `send_command.py`; mormegil-cz/GarminUsbMassStorageMode; TomaszBojanowski/openExpress (`device/storage.py`, `diagnostics.py`, `device/ptp.py`); the-sz.com usbids for 091e (0x255B = "Nuvi 2505LM"; **0x455B absent from usb.ids**).

## Open questions / handoff

- **Dossier correction needed:** live device is `091e:255b` ("Nuvi 2505LM" family PID shared across 25x5), not `091e:455b` (not in usb.ids; never observed). `01-DOSSIER.md` updated this run — verify nothing else was keyed off the old PID.
- 0x455b origin mystery: if the user saw 455b somewhere (another device? a document?), worth 5 minutes to check — but the hardware speaks for itself.
- F2 follow-up synergy: Oppmann's GCD doc gives the record-ID table and CheckPoint semantics — feed into the F2 checksum/payload-compression work and the future `.gcd` builder.
- If we ever need protocol-mode hardware: any 091e:0003 device (eTrex/60CSx/Forerunner, ~$10 used) exercises the whole documented pipeline against our probe.
