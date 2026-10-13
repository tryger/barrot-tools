# BR8051A02 — verified SPI flash access (UGREEN 33FA:0012)

Contribution to [barrot-tools](https://github.com/tryger/barrot-tools) following
up on the flash-write TODO. See the tracking issue:
https://github.com/tryger/barrot-tools/issues/1

## What this is

On a UGREEN "BT6.0" adapter (Barrot **BR8051A02**, USB `33FA:0012`), the root
cause of the silent-no-op `FLASH_WRITE`/`FLASH_ERASE` was identified and a
working flash-programming path was verified on real hardware:

- The MCU firmware gates are already open (`[0x200001D0]==2`, `[0x200001C4]==0`).
- The block is the **external SPI flash's block-protect (BP) bits**.
- Flash = Puya P25Q40-class (JEDEC `85 60 13`), SR1 `0x7C`, SR2 `0x1A`,
  `SRP0/SRP1 == 0` → software-clearable.
- Verified cycle: clear BP (volatile) → erase/program a 16-byte pattern at a
  spare sector → read back OK → erase → restore BP. Full 512-KiB before/after
  matched the backup byte-for-byte.

## What's included here

| File | What |
|---|---|
| `barrot_preflight.py` | **Read-only** probe (identity, signature, safe BUS_READs). No reset / write / patch / erase. |
| `docs/BR8051A02_SPI_FINDINGS.md` | Consolidated verified findings, VSC table, recommended lifecycle, safety. |
| `docs/SPI_REGISTER_MAP.md` | Offline-recovered SPI controller register map + ROM entry points. |

## What's deliberately NOT included

- **No stock Barrot firmware** (flash/ROM/SRAM dumps) — manufacturer copyright.
- **No device-unique data** (e.g. BD_ADDR).
- **No verbatim ROM code.** The docs describe addresses/behavior only.
- The **on-device unlock/program tooling** is added separately by the
  contributor who ran and verified it.

## ⚠️ Safety

Clearing BP and programming flash are **permanent** operations and can brick the
device (wrong SR value, QE disturbed → XIP-boot failure, power loss, or an
unexpected flash variant). `SRP0/SRP1 == 0` on the tested unit made the status
register software-writable, but this is **not guaranteed across units/variants**.
Always keep a full flash backup first. A contents backup cannot undo OTP/permanent
lock bits. Confirm the exact flash part from its datasheet before any WRSR.

## Scope

This validates a flash-programming path only. It does **not** fix the stock
`FLASH_WRITE`/`FLASH_ERASE` VSC handlers, and it does **not** provide any
USB-Audio / A2DP / PS5 firmware — that remains future work.
