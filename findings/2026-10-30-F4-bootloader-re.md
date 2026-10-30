# 2026-10-30 — F4: Bootloader RE — GCD verification flow fully mapped, TRAILER VERDICT: only 4×FF checked, 256 B ignored

**Task:** F4 (roadmap item) — reverse the nüvi 2595 bootloader (boot.bin 8.20), decide T2's trailer question
**Agent/Run:** agent run 2026-10-30
**Status:** DONE. 100 % offline (Ghidra headless + capstone on local binaries); nothing touched the device.

## What was done

1. Built a no-root RE rig in `~/garminageddon-tools/` (host had no java): Adoptium Temurin JDK 21.0.13
   (`dl/jdk21.tar.gz`, sha256 `d7f5d5cf…66d1c`) + **Ghidra 11.4.2 PUBLIC** (`dl/ghidra_11.4.2.zip`,
   sha256 `795a0207…e037a6`; latest Ghidra 12.2 needs Java 25, so 11.4.2 = last JDK-21 release).
   Ghidra project kept in `/tmp/ghidra_proj/F4` (not in repo), boot.bin imported raw at base
   `0x00000000`, processor `ARM:LE:32:v5t`. Auto-analysis 70 s.
2. Wrote 6 headless Jython scripts (committed in `refs/tools/ghidra_scripts/`): F4Dump (strings/xrefs/
   decompile), F4Dump2 (UTF-16LE term hunt against file bytes), F4Dec (targeted decompile + caller/callee
   walk), F4Thumb/F4Thumb2 (force-Thumb re-disassembly of ARM-misparsed regions), F4List (raw instruction
   dump), F4Xref. Ghidra's decompiler output for the key regions was unreliable (mixed ARM/Thumb), so the
   decisive functions were read instruction-by-instruction with **capstone 5.0.9** (wheel unpacked to
   /tmp/pylibs, no pip on host) — all code cites below are from verified Thumb disassembly.
3. Mapped the full update-verification flow (below). Decoded the CheckPoint check and the post-END check
   at instruction level. Decoded the FwDescriptor field vocabulary, the HWID gate, the stream→flash-region
   writer, and the entry chain from the OS message dispatch. Diffed boot.bin 8.20 vs 8.30. Quick recon of
   fw_all.bin. Persisted analysis outputs to `refs/tools/ghidra_analysis/` (hashed below).

## Artifacts

| File | sha256 (first 16) | Source |
|---|---|---|
| refs/tools/ghidra_scripts/F4{Dump,Dump2,Dec,Thumb,Thumb2,List,Xref}.py | (committed scripts) | written this task |
| refs/tools/ghidra_analysis/dec2.c | 6578cc8191403c4f | 35 funcs decompiled (parser/apply/writer) |
| refs/tools/ghidra_analysis/term_addrs.txt | c02d2bd089ac2396 | UTF-16/ASCII term → addr → xrefs |
| refs/tools/ghidra_analysis/term_funcs.txt | bcb800e9d9885018 | term → containing function |
| refs/tools/ghidra_analysis/list_00000a48_00000ab5.txt | dcb00bb5ed88a7e1 | CheckPoint check listing (Ghidra) |
| refs/tools/ghidra_analysis/string_xrefs.txt | dc2399d82b45fac8 | defined-string xref dump |
| refs/tools/ghidra_analysis/related.txt | cc7370e2b469a5f4 | caller/callee graph of key funcs |
| refs/tools/ghidra_analysis/{strings,functions,target_funcs}.txt | see sha256sum output | full dumps |

Tool archives: `~/garminageddon-tools/dl/jdk21.tar.gz` sha256 `d7f5d5cf865a2902b70ff549b97586a7d3f234e016f041ab447ea740c7d66d1c`;
`ghidra_11.4.2.zip` sha256 `795a02076af16257bd6f3f4736c4fc152ce9ff1f95df35cd47e2adc086e037a6`.
capstone wheel `capstone-5.0.9-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` from PyPI.

## Results / conclusions

### 1. THE TRAILER VERDICT (T2-critical)

**The bootloader checks ONLY the first 4 trailer bytes (`FF FF FF FF`) and never reads the other 256.**
No signature, no hash, no crypto anywhere (boot.bin contains no SHA-1/SHA-2/MD5 constants, no AES
sbox, no bignum/RSA code — only CRC32 tables for the FAT layer). The full chain:

- **FUN_00000814** @`0x814` (Thumb) = GCD parse+verify, writes `0:/Debug/GCD_log.txt` (its whole
  string table is the GCD_log vocabulary at `0xaac–0x1154`). Walks records from offset 8 through a
  256-byte streaming buffer (ctx struct; buffer @ctx+0, filepos @ctx+0x110, filesize @ctx+0x114).
- END record (ID 0xFFFF) handling @`0xf34`: requires (a) the running "checkpoint valid" flag [sp+0]==1
  (set on every passed checkpoint), (b) END record length == 0, (c) global error flag r7==0 (any failed
  checkpoint sets it; walk continues but verdict is lost). Only then calls:
- **FUN_000007cc** @`0x7cc` — **the tail check**:
  ```
  0x7d4: str r1,[sp,#4]        ; r1 = -1  → expected dword 0xFFFFFFFF
  0x7da: r5 = [ctx+0x110]      ; file offset just past loaded window (END consumed)
  0x7dc: r3 = [ctx+0x114]      ; file size
  0x7de: if (r5+4 > filesize)  ; fewer than 4 bytes after END
             → if <4 bytes also remain in buffer: return SUCCESS (r4=1)   ; trailer optional!
  0x7f2: FUN_00000610(sp+8, 4, ctx, 0)   ; else READ 4 MORE BYTES from the file
  0x804: memcmp(sp+8, 0xFFFFFFFF, 4)     ; vs FF FF FF FF
         match    → return 1 (valid)
         mismatch → return 0 (image "NOT valid")
  ```
  Verdict print @`0xf80–0xf96`: `"GCD image is %s"` + `"valid."`/`"NOT valid."`; FUN_00000814
  returns FUN_000007cc's result. FUN_000001c8 aborts unless it is nonzero.
- **The 256 content-derived bytes (offset END+4..END+260) are never read by any code path.**
  They are container decoration (per-file unique, entropy 7.16 ≈ random — likely build-system
  randomness or a vendor-side artifact). Official GCDs carry `4×FF + 256 B`; a crafted file can
  reproduce exactly that with 256 zero bytes, or simply end at END (≤3 trailing bytes also pass).
- Uniqueness: the `0x7cc` prologue byte pattern occurs exactly once in the image — the second
  (updater-app) copy of the GCD code at 0x50000+ has no such tail check at all.

### 2. CheckPoint verification (confirmed additive byte-sum)

@`0xa3c–0xa90` in FUN_00000814 (capstone listing, `refs/tools/ghidra_analysis/list_00000a48_00000ab5.txt`):
record length must be 1 (`"Checksum is the wrong size"` otherwise); expected byte =
`(-running_sum) & 0xFF` where running_sum = additive sum of every file byte consumed so far from
offset 0 (header + all record headers + contents, maintained by the read helpers FUN_00000610/
FUN_000006d4); the byte is read from file and compared @`0xa70`. Match → `" - Checksum is valid."`
+ flag; mismatch → `" *** Error:  Checksum failure."` + error flag. This is exactly F2b's
empirical rule (sum inclusive of the cp byte ≡ 0 mod 256) — **fully forgeable, machine-confirmed**.

### 3. Acceptance gates (apply path)

Entry chain: GarminOS/preboot message **0xA3** with payload byte 0x4A/0x4B → **FUN_000091e8**
@`0x91e8` (event dispatcher): requires global state==2, then **FUN_0000927c**(handle) re-checks the
file magic (reads 8 B at offset 0, memcmp 6 B `"GARMIN"`), then **FUN_000001c8**(handle) = the apply:

- **FUN_000001c8** @`0x1c8`: first runs FUN_00000814 (verify, above). If valid, re-walks records
  (direct reads via FUN_00011638) and for each FwDescriptor/record pair:
  - descriptor table (record 6) + values (record 7) parsed with field vocabulary
    (size_code<<12|field): `0x000A`=crypt_key/XOR byte, `0x000B`=erase_flag, `0x100A`=dset_type
    (stream record ID), `0x2015`=fwlen, `0x1009`=**product_nmbr**, `0x100D`=**cur_vrsn**,
    (`0x1008`=int_dset_len, `0x100C`=min_vrsn, `0x1005`=lng_dset_len in the printer), `0x5003`=end.
  - **HWID gate** @`0x350–0x35e`: a stream is applied only if `product_nmbr == 0` (wildcard) or
    `product_nmbr == *(u16*)0x000d19a8` (device HWID RAM global; value set by earlier boot stage,
    outside the 772 KB image). Our GCD's fw_all descriptor: product_nmbr=**1371**, cur_vrsn=**820**
    (decoded from the file @0xbd99b) — matches HWID 1371.
  - Stream routing @`0x30e–0x350`: write-path stream IDs = 0x3C1→region 5, **0x02BD→region 14**,
    0x321→0, 0x381→3, 0x3D5→17, 0x3D6→19, 0x500–0x5FF→region n via FUN_00000170. **Record ID 8
    (the boot block stream) is explicitly SKIPPED** (can't flash the runner) and 0x401
    (external_data, GTM) is skipped (handled elsewhere).
  - **FUN_0000046c** @`0x46c` = the writer: FUN_000115c0 erases the target flash **region**, then
    reads each 4-byte-record-headed chunk of the stream, deXORs with the descriptor's crypt_key
    byte (FUN_000b784; =0 for our GCDs), writes to the region (FUN_0001169e), chunk after chunk,
    until a record header with a different ID appears. Consumes ONLY record-bounded bytes →
    **the trailer never reaches flash**. Sets a success flag consumed by FUN_0001119e (completion
    event) back in FUN_000001c8.
- **No version/downgrade gate in the bootloader.** cur_vrsn/min_vrsn are parsed and logged
  (GCD_log) but never compared in the apply path. The downgrade refusal is **GarminOS-side**:
  fw_all.bin strings `/.System/GUPDATE.GCD`, `/Garmin/GUPDATE.GCD`, `SoftwareVersion`,
  `GarminDevice.xml` (OS scans both dirs, version-checks vs system.xml, then hands the open handle
  to the boot block) — consistent with F1's system.xml SoftwareVersion trick.
- Filename: the boot block itself never opens by name (receives a handle); literal `GUPDATE`+`.GCD`
  UTF-16 strings live in the loader-side resource pool (0xb3938/0xb3942, no direct code refs —
  index-based table). Effective requirement unchanged: `GUPDATE.GCD` in `/.System/` or `/Garmin/`.

### 4. boot.bin basics

ARM32 LE, raw image (no header), load base **0x00000000**: vector @0 = `ldr pc,[pc,#8]` → reset
**0x00080014**; data words 0x0013c932 (stack top), 0x000d19a8/0x000d19aa (HWID global RAM ptr +
ARM/Thumb entry pair). Size 0xBC938 = 772,408 B = exactly the fwlen declared for stream 0x0008.
Mixed ARM (reset/CP15 init at 0x14, 0x80014) + Thumb-2 bulk. ThreadX-style RTOS ("workq_info",
smphr debug strings, ts_main), MNAND/FTL driver, FAT stack, USB, libpng 1.2.18 + zlib (updater UI),
CRC32 tables (no other crypto). Two logical environments: preboot (≈0x0–0x4FFFF, message-driven GCD
apply) + updater app (≈0x50000–0xBC938: PNG UI, `/Garmin/Updater/` update.txt interpreter with
ergn/rrn/xrgn/copy/copydir/fftl/chksum/write_last_id/refresh/copy_image commands, RemoteSW support).
fw_all.bin: same pattern (`ldr pc,[pc,#12]` → 0x80018, stack consts 0x02fa196e/0x00a3890c), GarminOS
(C++/boost strings), FF-padded tail.

### 5. boot.bin 8.20 vs 8.30 (optional item)

Identical size 772,408; only **56 bytes differ in 9 runs**: the "8.20"→"8.30" UTF-16 strings
(@0x519ce, @0xa8f4e), a u16 version constant 0x0334→0x033e (@0x5a5d3), a 4-byte build value
(@0x5ae5d), one config byte (@0xb5e67), and two tiny same-shaped code spots (@0xc8d0, @0x64c68 —
one extra literal). **No verification/parse logic changes** — every conclusion above holds for 8.30.

## Open questions / handoff

- Who exactly sends message 0xA3 and deletes GUPDATE.GCD (GarminOS preboot service) — fw_all side
  not mapped (out of F4 scope); F3's USB/IOP dossier is the place to connect it.
- Device HWID RAM global (0xd19a8) value source (flash config vs compile-time) — irrelevant for T2
  since we use product_nmbr=1371 which the stock files already carry.
- The updater-app GCD parser (0x50000+ copy) not fully mapped; its unique-string set matches the
  preboot parser minus the tail check. Only matters for service-mode update.txt flows.
- Memory map above 0xBC938 (RAM globals/stack) inferred from pointer constants only.

## Recommended next move for T2

Craft the GUPDATE.GCD with the proven builder (`refs/tools/gcd_tool.py`): correct header
`GARMIN     `, records `CheckPoint/Filler/PartNumber/Copyright/FwDescriptorType/FwDescriptor/0x02BD
data/CheckPoint/END` with **all checkpoint bytes recomputed** (additive rule), fw_all descriptor with
product_nmbr=1371 (or 0), cur_vrsn ≥ device version not required by bootloader (OS gate only),
crypt_key=0, stream = payload; terminate with END(len 0) and append **`FF FF FF FF` + 256 arbitrary
bytes** (zero-filled is fine) to byte-match official shape, or no trailer at all. No signature to
forge — the 260-byte trailer is 4 checked FFs + 256 ignored bytes. Test offline against
`refs/tools/verify_gcd.py` + a new tiny `verify_f4.py` re-implementing the two bootloader rules
(additive checkpoints + 4×FF tail) before any device experiment; device test needs user approval
per ground rules.
