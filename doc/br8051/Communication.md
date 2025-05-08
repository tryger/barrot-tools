# Communication
The bootloader exposes a UART interface which is accessed through defined commands.

This is not tested, just extracted from somewhere code.

## Packet structure

|  Fixed | Length | Opcode (LE) | Args | 
|:------:|:------:|:-----------:|:------:|
| `0x01 0x80 0xfc`| 1B | 4 B | _Length_ - 4  |


## Opcodes

| OPCODE | CMD  |
|:------:|:----:|
| 00h | RESET |
| 01h | READ_CHIP_VERSION |
| 02h | WRITE_PATCH |
| 03h | READ_SIGNATURE |
| 04h | UART_TL_PARAM |
| 05h | BD_PARAM |
| 06h | RF_TX_CONTROL |
| 07h | RF_FREQ_TRIM |
| 08h | RF_TEMPERATURE_COMP |
| 09h | PARAM_WRITE |
| 0Ah | PARAM_READ |
| 0Bh | PARAM_PURGE |
| 0Ch | CONFIG_WRITE |
| 0Dh | CONFIG_READ |
| 0Eh | BUS_WRITE |
| 0Fh | BUS_READ |
| 10h | FLASH_ERASE |
| 11h | FLASH_WRITE |
| 12h | FLASH_READ |
| 13h | EEPROM_WRITE |
| 14h | EEPROM_READ |
| 15h | RF_REG_WRITE |
| 16h | RF_REG_READ |
| 17h | RF_TEST |
| 18h | RF_TEST_END |
| 30h | PATCH_READ_RSSI_CAP |
| 31h | PATCH_TEST |
| 32h | PATCH_EN |