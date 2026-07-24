# Communication

Barrot chips (BR8051, BR8551, ...) expose a vendor-specific HCI command set
over USB. All subcommands share one HCI opcode (OGF=0x3F, OCF=0x80 → `0xFC80`)
and select the operation with a leading 2-byte command id.

> **Disclaimer:** This documentation was reverse engineered from the chip
> firmware. Some fields and behaviours are untested and may be inaccurate.

## Packet structure

| HCI opcode | Length | Cmd id (LE) | Args |
|:----------:|:------:|:-----------:|:----:|
| `0x80 0xfc` | 1 B | 2 B | _Length_ − 2 |

The reply is an HCI Command Complete event carrying a status byte, the echoed
command id, and the response body. Multi-byte integers are **little-endian**.

## Commands

Command ids were reverse engineered from the chip firmware (BR8051A02).

| ID | CMD | Args | Response |
|:--:|:----|:-----|:---------|
| 00h | RESET | reset_type | — |
| 01h | READ_CHIP_VERSION | — | magic[3], config_type, version:u32, fw_date:u32, esm_type:u32, run_mode:u32, features:u32, flash_id:u16 |
| 02h | WRITE_PATCH | offset:u16, data | — |
| 03h | READ_SIGNATURE | — | signature[32] |
| 04h | UART_TL_PARAM | — / data[18] | data[18] / — |
| 05h | BD_PARAM | — / bd_addr[6] | bd_addr[6] / — |
| 06h | RF_TX_CONTROL | mode, [power], [extra] | — |
| 07h | RF_FREQ_TRIM | — / trim[6] | trim[6] / — |
| 08h | RF_TEMPERATURE_COMP | temp | comp:u16 |
| 09h | PARAM_WRITE | tag_id, data | — |
| 0Ah | PARAM_READ | tag_id, length | tag_id, data[length] |
| 0Bh | PARAM_PURGE | — | — |
| 0Ch | CONFIG_WRITE | tag_id, data | — |
| 0Dh | CONFIG_READ | tag_id | tag_id, data |
| 0Eh | BUS_WRITE | addr:u32, data | — |
| 0Fh | BUS_READ | addr:u32, length | data[length] |
| 10h | FLASH_ERASE | addr:u32, length:u32 | — |
| 11h | FLASH_WRITE | addr:u32, data | — |
| 12h | FLASH_READ | addr:u32, length | data[length] |
| 13h | EEPROM_WRITE | addr:u32, data | — |
| 14h | EEPROM_READ | addr:u32, length | data[length] |
| 15h | RF_REG_WRITE | addr:u32, value:u32 | — |
| 16h | RF_REG_READ | addr:u32 | addr:u32, value:u32 |
| 17h | RF_TEST | descriptor[10..16] | — |
| 18h | RF_TEST_END | — | result[16] |
| 19h | PATCH_READ_RSSI_CAP | addr:u32, delay:u16 | — |
| 1Ah | PATCH_TEST | — | result:u16 |
| 1Bh | PATCH_END | enable | — |

The commands above are defined as Scapy packet classes in
[`barrot_tools/brt_hci_spec/pkt.py`](../../src/barrot_tools/brt_hci_spec/pkt.py).

* BUS/FLASH/EEPROM reads accept a 1-byte length of `1..0xF0`; the driver chunks
  larger reads (`bus_dump`, `flash_read`, `eeprom_dump`).
* `READ_CHIP_VERSION.version` packs the chip name in hex digits
  (`0x08051A02` → `BR8051A02`); see `info` and `BrtInfo.model`.

Safety-critical behaviour (verified live):
* **08h RF_TEMPERATURE_COMP** bricked the USB endpoint on every invocation.
  The packet class exists for completeness but no helper is exposed — do not send it.
* **0Dh CONFIG_READ tag_id=0xFF** hits a buggy ROM path (NULL deref) that hangs
  the chip until reset.
* **09h PARAM_WRITE** with a length-1 payload (tag id, no data) wipes the in-RAM
  BD address. `param_write()` rejects empty payloads.
* **07h RF_FREQ_TRIM** read and write bit-packings are asymmetric — writing back
  what a read returned corrupts the XO trim in RF regs 0xaa/0xab.
* **0Eh BUS_WRITE** verified live: RAM identical-write roundtrip, a single-chunk
  mutation with read-back, and a chunked (>0xF0) write, each restored afterwards.
* **11h FLASH_WRITE / 10h FLASH_ERASE** return status `0x00` but are silent no-ops. 
  The ROM runs the WREN + page-program / sector-erase sequence,
  but the SPI flash is write-protected so flash never changes, and the ROM does not
  read back to confirm. Unlocking requires a patch — see below.
