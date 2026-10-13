# UGREEN BR8051A02: verified SPI flash access and firmware handoff

Updated 2026-10-12. Read this consolidated document first; older FINDINGS/SPI notes retain historical statements that this hardware evidence supersedes.

## Result and scope

**The original missing SPI transaction map and flash-unlock problem have been resolved experimentally on the investigated dongle.** A verified ROM/SRAM callback read flash identity/SFDP/status, cleared BP temporarily, programmed 16 real nonFF bytes at offset0x40000, read the exact pattern back, erased the 4-KiB test sector to restore its originalFF contents, and restored BP/XIP/interrupt/SRAM state. Complete 512-KiB before/after captures match the original backup byte-for-byte, with 0 differences.

Current flash BP is protected again. No persistent unlock or replacement firmware was installed. PS5 USB Audio→Bluetooth A2DP transmission remains a separate firmware objective; it has not been demonstrated. Do not keep repeating the successful flash test as a prerequisite for USB/audio analysis.

## Chip, USB and Bluetooth identity

| Field | Evidence |
|---|---|
| Chip | BR8051A02; READ_CHIP_VERSION 0x08051A02 |
| USB | VID:PID 33FA:0012; original descriptors report bcdDevice 8891 and HCI class/subclass/protocol E0/01/01 |
| Identity bytes | `42525401021a05087299449502000000000000000000000012850000` |
| Legacy flash ID |8512 |
| Full JEDEC ID |85 60 13, captured by 9F |
| Installed flash compatibility | Full advertised SFDP tables match P25Q40SU V1.8 reference; 512 KiB. Strong SU-compatible evidence, not unique package/silicon revision identification |
| HCI capability probe | Original supplied probe reports Bluetooth 5.0, 220 HCI commands, BR/EDR+LE, clear LE CIS/BIS bits. These capability results were not repeated by the flash tests |
| Manufacturer/build | Original supplied notes: manufacturer 08E7, firmware 2025-04-30 09:14, config_type 1 / esm_type 2 |

The “BT6.0” product label is not a substitute for observed HCI capabilities. No LE Audio or embedded A2DP source implementation has been established. VSC 03 signatures change between reads and must not be used as a stable identity/firmware fingerprint.

## Memory and active mappings

| Region | Verified/observed span |
|---|---|
| ROM capture |00000000–0003FFFF,256 KiB dumped; active call targets and saved pointers also reference 0005xxxx, whose contents/extent still require live verification |
| SRAM |20000000–2000FFFF,64 KiB |
| Flash XIP |10000000–1007FFFF,512 KiB, full live capture verified |
| System/XIP registers |90000000 bank; not the simple SPI FIFO base |
| Transaction aperture |B loaded from2000BFFC; currently10000000. Used as controller MMIO only while XIP is disabled |

**Never probe SRAM at20010000 or above:** the original investigation reports a hang/self-reboot there. Other unmapped reads can also hang; do not scan arbitrary MMIO.

Observed nonblank4-KiB flash sectors:0,1000,2000,3000,7E000,7F000. All other captured bytes areFF, but that alone does not establish ownership. Both saved SRAM snapshots and the fresh hardware test mapping show20000218=7D000,2000021C=7E000,20000220=7F000,20000224=1000. Reserve all three terminal sectors, including blank7D000. The tested fixed scratch sector40000–40FFF lies outside observed boot/patch and this terminal mapping; no complete absence of computed/indirect references is claimed.

Stock SRAMC000 contains active trampolines; **do not overwrite it**. Flash scatter-copy coversC000–E7FF, initialized dataE800–E897, zeroed dataE898–E8EB. Audited callback blobs used2000E900, with actual heap/scatter/stability checks, backups and restoration. Initial stack pointer is2000BE10. Other apparently idle RAM is not automatically free.

## VSC interface and hazardous commands

HCI opcodeFC80; parameters start with subcommand:u16 little-endian. Command Complete events echo opcode/status/subcommand. Use the supplied fragmented-event parser, exact ROM/identity guards and existing USB configuration. Never treat a successful VSC status as proof of flash programming.

| Subcommand | Established use |
|---|---|
|01 |Read identity |
|03 |Read dynamic signature; informational only |
|0F |BUS_READ:addr:u32LE,length:u8; use chunks≤240 bytes |
|0E |BUS_WRITE:addr:u32LE,bytes; used to restore backed-up SRAM |
|02 |WRITE_PATCH:offset:u16LE,bytes; destination2000C000+offset. ROM has no bounds check |
|00,type03 |SW_PATCH callback path; works only with the audited return continuation described below |
|10/11 |Stock FLASH_ERASE/FLASH_WRITE handlers exist; their success responses discard underlying return values. These handlers have not been revalidated by the successful raw-SPI test |
|12 |Flash read reported working in the original investigation; later full images used BUS_READ/XIP |

**Do not invoke:**08 RF_TEMPERATURE_COMP (reported endpoint loss);0D CONFIG_READ with tagFF (reported NULL dereference/hang);09 PARAM_WRITE with the hazardous short payload (reported RAM Bluetooth-address corruption);07 RF_FREQ_TRIM by echoing readback (packing mismatch can corrupt trim). Do not use arbitrary RESET types, chip eraseC7/60, security/OTP erase/program or protection-lock experiments.

## Why flash programming failed and what now works

Firmware gates were already open:200001D0=2,200001C4=0. Changing these RAM gates is unnecessary. Physical RDSR05=7C and35=1A confirmed BP[4:0]=31, WIP/WEL=0, SRP0/SRP1=0, QE1, CMP0, with existing security-lock bits retained. SU configuration15=00 selects the BP/CMP scheme rather than individual block-lock protection.

Volatile50+one-data-byte01 changed05/35/15 from7C/1A/00 to00/1A/00 and restored7C/1A/00. Actual page program and sector erase then succeeded in that temporarily unprotected interval. This identifies a working bypass for observed BP protection; it does not prove BP was the only defect in every earlier host/VSC attempt.

## Recovered SPI transaction map

Names below describe ROM behavior, not official register names. B is read from2000BFFC.

| Address | Recovered role |
|---|---|
|B+00 |Configuration; bits11:10 select TX01, RX10, command-then-RX11 for bases0/10000000 |
|B+04 |RX length minus1; simple TX uses software FIFO count |
|B+08 |Disable0/enable1 around configuration and transactions |
|B+28 |Status:bit0 busy,bit1 TX-write permitted,bit2 completion/drained condition,bit3 RX-read permitted. Exact official bit2 naming remains unknown |
|B+60 |Shared byte FIFO via32-bit accesses; opcode is the first transmitted byte. No separate opcode register in these paths |
|90000010,bit1 |Aperture select:clear→10000000,set→0 |
|90000020,bit8 |XIP mapping enabled |

Hardware observations before/after:90000010=00000000,90000020=00120100,2000BFFC=10000000,20000400=2. The latter is XIP state, not status-register protection.

ROM3FAC callable Thumb pointer3FAD implements `spi_command(opcode, tx, tx_length, rx, rx_length)` with r0–r3 and fifth argument on stack. TX length includes opcode; ROM overwritesTX[0], so TX must be writable. It invokes24AF0, which emits05 and polls WIP, before selecting43CC TX,4500 TX/RX or42F4 RX. Completion/flash-busy loops are unbounded, even though some FIFO loops return timeout-like errors.

44BC(1) enters10CE8 XIP-off;44BC(0) restores via10DA8. Outer10528(1)/10528(0) brackets the entire XIP-off interval; nesting counter is20000404, **not 20000104**. It must initially be0. Do not reproduce this lifecycle using separate host MMIO writes.

ROM24B40 page-program splits at256-byte boundaries and calls41B8 to transmit02+24-bit address+data. ROM24AAC transmits sector erase20;247AE transmits chip eraseC7 and must not be used. **24B9C is two-status-byte WRSR, not erase.** Protection helper24750 sends normalWREN06 plus one-byteWRSR; do not reuse it blindly, particularly on other Puya variants.

## Tested callback and unlock/program lifecycle

WRITE_PATCH sets pending pointer20000540 on its first upload. Stock type03 callback return behavior initially caused a timeout. The tested SRAM routine restores its own registers/stack, clears pending pointer via[r7+4], zeros response byte[r4], then branches to Thumb15AFF (ROM15AFE response-return tail). The dispatcher then returns a normal FC80 Command Complete. This is ROM-specific and requires exact byte guards; never apply it to a different chip blindly.

Recommended order on this device:

1. Identify01/9F/90 and full SFDP; pin ROM/blob and verify full original backup. Capture05/35/15.
2. Enter the tested interrupt/XIP lifecycle; require7C/1A/00 and successful SPI reads.
3. Send50 then01 with **one** data byte00 for volatile BP clear; verify00/1A/00. Do not write SR1/QE/OTP.
4. For array programming/erase, use06 and verify05 WEL; restrict to the reviewed fixed target. Verify actual readback, not a stock VSC success code.
5. Restore the original sector. Send04 WRDI and confirmWIP=WEL=0 **before**50+one-byte01 restoring7C; otherwise refuse WRSR to avoid a nonvolatile status write. Verify7C/1A/00.
6. Restore XIP/interrupt state, normal HCI response, pending pointer and SRAM; compare the full flash image against the baseline.

This sequence is specific to the observed SU-compatible part. Earlier H-series datasheets have different one-byte WRSR behavior. Manufacturer reference: [P25Q40SU V1.8](https://www.puyasemi.com/download_path/%E6%95%B0%E6%8D%AE%E6%89%8B%E5%86%8C/Flash/P25Q40SU_Datasheet_V1.8.pdf), pages28/33/82 checked against the PDF.

**Permanent-risk warning:** array writes/erases are permanent operations. Power loss, incorrect ownership, ROM hangs or an unexpected device variant can leave changes or render recovery impossible. Power-cycling reloads volatile status but does not undo programmed data. Backups do not undo OTP locks and do not guarantee a usable recovery path. Never retry a timed-out callback or overwrite code that might still be executing.

## Hardware evidence

| UTC time | Passed result |
|---|---|
|08:44:57 |Normal-response no-op callback, SRAM restored |
|08:51:16 |JEDEC856013,legacy8512,status7C/1A; state/SRAM restored |
|08:57:27 +09:02:37 |SFDP header/tail,16-byte overlap matches, both advertised tables complete |
|09:21:11 |Volatile BP clear/restore7C→00→7C, SR1 preserved1A |
|09:24:54 |Entire 512-KiB read matches original backup,0 differences |
|09:41:46 |Real16-byte program at40000, exactpattern readback,4-KiB erase, BP/state/SRAM restored, complete before/after images match original |

Actual testpattern: `42525450524f4245a55a00ff96693cc3`. SPI error accumulator0, progress4;05 before both program and erase was02 (WEL bit1). No pattern remains. Saved live before/after captures were independently hashed in this workspace.

## Files and hashes

Original source directory: `<your-working-dir>`. Preserve `dumps/ugreen_bt60_flash.bin`; never replace it with an experimental image. Original SHA256:

```
57bf00666db374101e0bea2c70b7019538d161cc91141c371be7ed20e3124371  dumps/br8051a02_rom.bin
57e59bb32998950b681bc942a212aced1d2f7400a76102ff1f937608fc77b20a  dumps/ram_1.bin
88cb896d6a1915bc90a97a0fe02520c491bbc0d2a9d258158df7aa19e76a4c82  dumps/ram_2.bin
fc09040e89fe39c79905a52c8261047de4ef824aa7e81829380d2385aa2869f1  dumps/ugreen_bt60_flash.bin
ffeeb7447bbcf99e96f48da2a380df063b9d78306290979425475559f8f5a972  barrot_read.py
22a016350b3165145fdd8e7047c9f4f6fcf18ef925db6934cbd994c03e5a2762  hci_probe.py
6007b78d3fbb72a871a6d6a4618418ea2f91eb0810a03190801c2b694de933d7  re_disasm.py
```

The hashes above are of local analysis inputs and are **not** included in this
contribution. The stock flash/ROM/SRAM dumps are the manufacturer's firmware and
are deliberately withheld (copyright); only `barrot_preflight.py` (read-only
probe) and these documentation files are published here. The on-device
mutation/unlock tooling that performed the verified program/erase round-trip is
added separately by the contributor (it must be run and stood behind by whoever
publishes it).

Physical USB steps were executed in a normal Terminal against the real dongle; no
full-firmware emulation is claimed.

## Next firmware investigation

The flash obstacle is now resolved through a tested path. Preserve these proofs and move to an offline feasibility study before installing firmware:

- Recover USB descriptor/control-request dispatch and OUT endpoint/FIFO hooks. ROM 0x16B23 names`sco_bt2usb_rb`; isochronous-USB strings are linked to SCO transport and do not establish USB Audio Class support.
- Locate controller-to-host HCI event/ACL entry points and decide whether a standalone host stack can run on 64-KiB SRAM while intercepting USB audio. Identify buffer/heap/stack demands before changing the active memory layout.
- Establish A2DP-source signaling and SBC encoding support, pairing/key persistence and clock/buffer handling. Stock HCI capability probes alone do not supply these host/profile functions.
- Validate a reversible SRAM USB/audio diagnostic first, then staged PC USB Audio enumeration/data transfer, Bluetooth media output and finally PS5 compatibility. No usable PS5/A2DP firmware, encoder, timing budget or latency result currently exists in this bundle.

## USB/HCI routing follow-up

Offline descriptor and code analysis suggests the stock ROM dump is incomplete
relative to active references into `0x5xxxx`; a 256-KiB ROM boundary is not
established. No USB Audio patch or PS5 audio playback has been tested. This is
future work, not part of this contribution.
