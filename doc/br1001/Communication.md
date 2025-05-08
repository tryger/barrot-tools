# Communication
The bootloader exposes a UART interface which is accessed through defined commands.

## Packet structure

|  Preamble | Seq Num | Length | Opcode |   Args   | Postamble | Checksum |
|:---------:|:-------:|:------:|:------:|:--------:|:---------:|:--------:|
| `0x10 0x02` |   1 B   |   1 B  |   1B   | _Length_ B | `0x10 0x03` |    1B    |

## Opcodes
`-` means unknown
| OPCODE | CMD  |
|:------:|:----:|
|  00h  | ERASE |
|  01h  | ID    |
|  02h  | READ  |
|  03h  | WRITE |
|  05h  | UNK0  |
|  06h  | SPI_CFG |
|  08h  | -  |
|  0Bh  | PART_UNK0 |
|  0Ch  | PART_UNK1 |
|  0Dh  | LOAD  |
|  0Eh  | STORE |
|  10h  | - |
|  11h  | - |
|  12h  | - |
|  13h  | - |
|  91h  | READ_FLASH_STATUS_REG |
|  91h  | WRITE_FLASH_STATUS_REG |
|  93h  | - |
|  94h  | ERASE_SECTOR |
|  95h  | FLASH_SPI_CMD |