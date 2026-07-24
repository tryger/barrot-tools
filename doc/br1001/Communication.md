# Communication
The bootloader exposes a UART interface which is accessed through defined commands.

> **Disclaimer:** This documentation was reverse engineered from the chip
> firmware. Some fields and behaviours are untested and may be inaccurate.

## Packet structure

|  Preamble | Seq Num | Length | Opcode |   Args   | Postamble | Checksum |
|:---------:|:-------:|:------:|:------:|:--------:|:---------:|:--------:|
| `0x10 0x02` |   1 B   |   1 B  |   1B   | _Length_ B | `0x10 0x03` |    1B    |

## Opcodes

All multi-byte integers on the wire are **big-endian**. Most commands reply
with a single BE32 `result` (negative = error); commands that return more are
noted.

| OPCODE | CMD | Args | Response |
|:------:|:----|:-----|:---------|
| 00h | ERASE | addr:BE32, len:BE32 | result:BE32 |
| 01h | ID / PROBE | cs, spi_freq:BE32, [2], granularity | magic:BE32, flash_id:BE32, sec_reg[16] |
| 02h | READ | addr:BE32, len:BE32 | len:BE32, data[len] |
| 03h | WRITE | addr:BE32, len:BE32, data[len] | result:BE32 |
| 05h | RUN / BOOT | target:BE32 | result:BE32 (0 before jump) |
| 06h | SPI_CFG | freq:BE32, mode, arg2, width:BE16 | result:BE32 |
| 08h | SET_VERIFY | flag | result:BE32 |
| 0Ah | GPIO_CS_CFG | pin, level | result:BE32 |
| 0Bh | PART_READ | part | addr:BE32, length:BE32 |
| 0Ch | PART_OPEN | part, addr:BE32, size:BE32 | addr:BE32 |
| 0Dh | PEEK | width(8/16/32), addr:BE32 | value:BE32 |
| 0Eh | POKE | width(8/16/32), addr:BE32, value:BE32 | result:BE32 |
| 10h | FLASH_CFG_CLR0 | — | result:BE32 |
| 11h | FLASH_CFG_CLR1 | — | result:BE32 |
| 12h | FLASH_CFG_2 | — | result:BE32 |
| 13h | FLASH_CFG_3 | — | result:BE32 |
| 90h | FLASH_TX_CMD | cmd, arg | result:BE32 |
| 91h | READ_FLASH_SR | — | sr:BE16, result:BE32 |
| 92h | WRITE_FLASH_SR | sr:BE16 | result:BE32 |
| 93h | ERASE_SECTOR | addr:BE32 | result:BE32 |
| 94h | FLASH_PROGRAM | addr:BE32, len:BE32 | result:BE32 |
| 95h | FLASH_SPI_CMD | cs, dir, reg_len, dma_len, cmd0:BE32, cmd1:BE32, [wdata] | result:BE32, [rdata if dir=1] |

The opcodes above are defined as Scapy packet classes in
[`barrot_tools/br1001/pkt.py`](../../src/barrot_tools/br1001/pkt.py).

Notes:
* READ/WRITE switch on `addr < 0x08000000`: below that is SPI-flash, at/above
  it is a direct memory copy (so `0x08000000` = bootrom, `0x20000000` = SRAM).
* ID `flash_id` is the JEDEC RDID (0x9F): `(manufacturer << 16) | device_id16`.
  Observed `0x00856013` = manufacturer `0x85` (PUYA) + device `0x6013`; `magic=0x66200400`.
* PART_READ returns `(addr, length)`. On the units seen: part `0x60`=0x3000/0x6edc,
  `0x61`=0x7b000/0x18, `0x62`=0x7c000/0x3000. Absent entries return `0xffffffff/0`.
  These partitions hold firmware/patch code, **not** an NVDS store — a full
  512 KB flash dump contains no `NVDS` magic. The `NVDS` tag format parsed by
  `barrot_tools.common.nvds` belongs to the BR8551 HCI/config family, not this ROM.
* 06h and 0Bh write the partition-table magic (0xAA55) to sector 1 if it is
  absent — avoid on an unprovisioned chip.
* 0Ch `part=0x62` erases the opened region.
## Partition 0x62 — ROM `cfg` store (HSE/TLV)

Partition `0x62` is the bootrom's **config store**. It is a wear-leveled,
append-only TLV log, **not** an NVDS blob. Reverse engineered from the ROM and
verified against a live chip. See `barrot_tools.br1001.cfg` for a parser (`cfg` CLI
subcommand).

Layout: the partition is split into N equal, sector-aligned **sections**
(N = 2 if size < 0x3000 else 3; e.g. 0x3000 → 3 × 0x1000 @ +0x0/+0x1000/+0x2000).
A valid mount needs ≥2 sections carrying the `HSE` magic.

Section header (4-byte little-endian word):

| bits | field |
|:----:|:------|
| 0–3   | flags (bit0=valid, bit1=full, …; nibble 0xF = erased/NIL) |
| 4–7   | section id (0..N-1; 0xF = NIL) |
| 8–31  | magic = `"HSE"` (0x455348) |

Entry: a 4-byte little-endian **tag word** followed by `length` payload bytes,
packed from offset 4 until a `0xFFFFFFFF` word (free space = end of log):

| bits | field |
|:----:|:------|
| 0–2   | state: `011`=VALID (live), `000`=DELETED (superseded), `111`=FREE (erased) |
| 3–11  | length = `(tag & 0xFFF) >> 3` (payload bytes) |
| 12–19 | key_id (config/NVDS tag id, e.g. `0x02`=DEVICE_NAME, `0x60..0x67`=BT link keys) |
| 20–31 | next-link (`0xFFF` = NIL) |

State polarity follows NOR-flash physics (bits only clear `1→0` without an erase):
a slot goes `111` (erased) → `011` (written/live) → `000` (superseded). A DELETED
entry's `next` points **forward** to its replacement; the live entry is the chain
tail (`next`=NIL), which the ROM asserts. The current value of a key is its VALID
entry.

Key **names** are looked up in `barrot_tools.common.nvds`'s tag table by id, assuming the
cfg key_id namespace matches the NVDS tag namespace. Only `0x02`=DEVICE_NAME (its
payload is an ASCII device-name string) and the `0x60..0x67` link-key range are
corroborated by the data; the other names are unverified best-effort labels.
