# BR8051A02 SPI controller — offline ROM analysis

> Hardware-validated on one unit: ROM/SRAM callback, XIP transitions, SPI ID/SFDP/status reads, volatile BP clear/restore, and a full flash program/erase/restore round-trip all passed, with before/after 512-KiB images matching the backup byte-for-byte. See `BR8051A02_SPI_FINDINGS.md` for the consolidated verified findings and the recommended lifecycle.

This file documents SPI/flash behavior recovered by **offline** disassembly of a BR8051A02 mask-ROM dump (Capstone). No proprietary ROM bytes are reproduced here — only addresses, behavior, and the recovered calling convention. No USB/device operations were performed to produce this document.

## Findings that change the original handoff

1. **`0x90000000` is the system/XIP control bank, not the FIFO transaction register base used by the ROM routines.** The transaction routines load their base `B` from SRAM word `0x2000BFFC`. Both snapshots contain `B = 0x10000000`. ROM supports `B = 0` as an alternate mapping, controlled by bit 1 of `0x90000010`. With XIP enabled, the same aperture contains flash data. Do not access `B + register_offset` as live MMIO until the ROM has safely transitioned out of XIP.
2. **ROM `0x24B9C` writes two status bytes; it is not erase.** It sends WREN (`0x06`), then `[0x01, low_byte(r0), low_byte(r1)]`. The 4 KiB-style sector erase primitive at `0x24AAC` sends WREN then opcode `0x20` plus a 24-bit address. Actual sector geometry still requires the flash datasheet.
3. **ROM already contains a protection-mask helper at `0x24750`.** It reads status with `0x05`, compares bits masked by `0x7C`, and conditionally performs WREN + a one-status-byte WRSR. This is a useful reference, not authorization or proof that its mask is correct for the installed flash.
4. **FLASH_WRITE status 0 is not proof of a successful SPI transaction.** At `0x15850` the VSC calls the program thunk, then `0x15854` overwrites its result with zero. FLASH_ERASE similarly discards erase-call results before returning zero. Open firmware gates and success status do not establish BP protection. The actual status register must be captured.
5. **The ROM ID reader uses `0x90`, not `0x9F`.** At `0x249E4` it sends `90 00 00 00`, receives two bytes, and returns their big-endian 16-bit value. If the reported `flash_id` comes from this path, `0x8512` is a two-byte legacy ID, not a complete JEDEC ID. Trace its caller before asserting that provenance.

## Register map recovered from instructions

These names describe ROM behavior; they are not vendor-defined register names. All accesses below are 32-bit loads/stores, including FIFO accesses carrying one byte.

| Bank / offset | Observed use | Evidence |
|---|---|---|
| `B + 0x00` | Transfer configuration. For `B` equal to zero or `0x10000000`, bits 11:10 select observed TX (`01`), RX (`10`), and command-then-RX (`11`) modes; bits 23:22 are cleared for the basic transfers. Other bases use bits 9:8 and clear bits 22:21. | `0x43EC–0x43F8`, alternate branch `0x4426–0x4432`; `0x435C–0x4368`; `0x4564–0x456C` |
| `B + 0x04` | Receive count minus one; set for RX and command-then-RX. No TX-length-register write appears in the simple TX path. | `0x4326–0x4328`, `0x452E–0x4534` |
| `B + 0x08` | Controller disable/enable: zero before configuration, one afterward. Not a standalone opcode trigger. | `0x451A`, `0x4536–0x4538`, `0x4016–0x4020` |
| `B + 0x28` | Status: bit 0 busy; bit 1 permits TX FIFO writes; bit 2 is waited on at transaction completion; bit 3 permits RX FIFO reads. Bit 2 is consistent with TX-empty/drained, but its official meaning remains unresolved. | `0x43DC–0x43E0`, `0x440A–0x4414`, `0x400A–0x4014`, `0x457E–0x4588` |
| `B + 0x60` | Shared data FIFO: write each command/payload byte with STR; read with LDR and retain low byte. **The SPI opcode is the first FIFO byte, not a separate command register in these paths.** | `0x4410–0x4414`, `0x4550–0x4554`, `0x4586–0x458A` |
| `0x90000010`, bit 1 | Selects aperture base zero when set, `0x10000000` when clear. | `0x44CE–0x44DA`, `0x10D1E–0x10D24`, `0x4652–0x465C` |
| `0x90000020`, bit 8 | XIP mapping enable/control: cleared on transition out of XIP and set on restoration. A live value with this bit set is not merely a flash-ready indication. | `0x10D26–0x10D2E`, `0x10DC2–0x10DC8` |

Original live observations were `[0x90000010] = 0` and `[0x90000020] = 0x00120100`. Offline SRAM captures confirm `[0x2000BFFC] = 0x10000000`, XIP state `[0x20000400] = 2`, and firmware gates `[0x200001D0] = 2`, `[0x200001C4] = 0` in both snapshots.

## Transaction primitives and calling convention

Recovered AAPCS-style signature for ROM `0x3FAC`:

```c
int spi_command(uint8_t opcode, uint8_t *tx, unsigned tx_len,
                uint8_t *rx, unsigned rx_len);
// r0 = opcode; r1 = tx; r2 = tx_len; r3 = rx;
// fifth argument rx_len is on caller's stack.
// tx_len INCLUDES the opcode byte; tx[0] is overwritten with opcode.
```

Evidence: `0x3FB6` loads the fifth argument after saving eight registers; `0x3FC6` stores the opcode into `tx[0]`. A writable, non-null TX buffer is required, even though later branches test whether TX exists.

The wrapper snapshots configuration, calls the status/busy helper `0x24AF0`, chooses a transfer primitive, waits for status bit 0 clear and bit 2 set, then disables/restores/re-enables configuration:

- `0x43CC`: TX-only, buffer length in `r1`; sends bytes when status bit 1 is set.
- `0x4500`: command/payload followed by RX; `r0=tx`, `r1=tx_len`, `r2=rx`, `r3=rx_len`; programs RX length minus one, sends TX bytes, then drains RX on status bit 3.
- `0x42F4`: RX-only; starts with a zero FIFO write, then drains the requested bytes.
- `0x24AF0`: emits RDSR `0x05` directly through `0x4500` and repeats while returned bit 0 is set, except that `0xFF` terminates polling. It returns zero after this loop and does not positively validate flash presence.

The outer completion and flash-busy loops are unbounded. FIFO polling has timeout-like counters; zero indicates success and one indicates failure in those paths, but the outer layers do not consistently propagate errors. Treat these as implementation observations, not robust execution APIs.

## Page-program and status-register paths

```text
VSC FLASH_WRITE @ 0x157FC
  -> thunk 0x45E4
  -> HAL[0x30] at 0x20000388 = 0x45F1 (Thumb pointer, both SRAM dumps)
  -> wrapper 0x45F0: 0x44BC(1), page_program(), 0x44BC(0)
  -> page splitter 0x24B40: respects 256-byte boundaries
  -> 0x41B8: builds [02, addr>>16, addr>>8, addr, payload...]
  -> 0x24AF0, WREN helper 0x24B88, spi_command 0x3FAC
```

Useful ROM entry points (addresses below are even disassembly addresses; callable Thumb pointers need bit 0 set):

| Address | Behavior |
|---|---|
| `0x24B88` | WREN `0x06` |
| `0x24B9C` | WREN + WRSR `0x01` with two status bytes |
| `0x24750` | RDSR, compare protection mask `0x7C`, optional WREN + one-byte WRSR |
| `0x24AD6` | Sets `r0=0`, tail-calls `0x24750` |
| `0x45CC` | XIP-transition wrapper around `0x24AD6`; an existing candidate unlock wrapper, not tested on hardware |
| `0x248E4` | Sets `r0=0xFF`, tail-calls `0x24750` (sets the helper's protection mask) |
| `0x249E4` | Legacy ID `0x90`, three zero address bytes, two received bytes |
| `0x24A1E` | RDSR `0x05`, receives two bytes into caller buffer |
| `0x24A36` | Read `0x35`, receives one byte |
| `0x24AAC` | WREN + sector erase `0x20` and 24-bit address |
| `0x247AE` | WREN + chip erase `0xC7`; destructive |

Protection helper `0x24750` computes `desired = (argument & 0x1F) << 2`. It reads one status byte, rejects `0xFF`, and returns without writing when `(status & 0x7C) == desired`. Otherwise it issues WREN and WRSR with `(status & ~0x7C) | desired`, preserving the other bits. It does not independently confirm the post-write status. Never assume clearing all five masked bits is correct for this flash part without its datasheet.

## XIP transition requirement

The wrapper `0x44BC(1)` loads the controller aperture base and, when XIP is active, enters `0x10CE8`. That routine clears bit 8 of `0x90000020`, switches/configures the aperture as controller registers, and changes the RAM state at `0x20000400` from 2 to 3. The exit wrapper `0x44BC(0)` waits through `0x24AF0` and calls `0x10DA8`, which restores state/configuration and re-enables bit 8 once state reaches 1. Nested helpers also call `0x10528`, whose complete locking/interrupt semantics were not resolved in this pass.

**Do not implement this as separate host BUS_WRITE operations against the XIP aperture.** Disabling XIP can interrupt flash-resident code or handlers, and host-side writes cannot reproduce the ROM's execution/locking sequence atomically. A diagnostic routine must run entirely from verified ROM/SRAM, with correct entry/exit handling, bounded failure recovery, and no dependencies on flash while XIP is disabled. RAM patch installation/execution mechanics remain to be verified.

## Proposed next diagnostic, not an executed patch

Prepare a ROM/SRAM-resident routine using the established XIP-transition wrapper and the raw command primitive. The intended flash transactions are:

```text
JEDEC ID: tx=[9F],       tx_len=1, rx_len=3
Legacy ID: tx=[90,0,0,0], tx_len=4, rx_len=2  (compare with existing ROM path)
Status 1: tx=[05],       tx_len=1, rx_len=1
```

Use writable TX buffers, reserve RX/result storage in proven-safe SRAM, and retain raw status/error results. These commands are intended to read the flash; installing a patch and switching controller state still mutate device RAM/MMIO. Add any extra status-register reads only after identifying the part. Do not issue WREN/WRSR during this diagnostic.

The remaining work is now narrower: validate the patch execution and XIP/locking lifecycle, read the actual flash ID/status, obtain the exact part datasheet, then decide whether the existing protection helper is appropriate. BP lock remains unconfirmed. A later unlock must preserve unrelated status bits, avoid OTP/permanent-lock fields, verify status afterward, and use a backed-up unused sector for the write test. A contents backup cannot undo permanent lock bits.

The original hazardous VSC prohibitions and SRAM boundary (`0x20010000` and above) remain applicable. No flash content has been changed by this offline analysis.
