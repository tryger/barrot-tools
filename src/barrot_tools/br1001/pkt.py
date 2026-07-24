"""
BR1001 ROM-bootloader UART command/response packets.

Reverse engineered from the bootrom ``process_packet()`` dispatcher
(ARM Cortex-M, image base 0x08000000). Framing is documented in
doc/br1001/Communication.md; this module only models the per-opcode
argument/response bodies.

All multi-byte integers on the wire are BIG-ENDIAN, so scapy's default
network-order Int/Short fields are correct as-is. Most handlers reply with
a single BE32 ``result`` (negative => error); commands that return more
override that with their own response class.

``[untested]`` marks a layout derived from static analysis that has not
been exercised on hardware. Everything else was verified against a live
BR1001 in boot mode over UART.
"""

from enum import IntEnum

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteField, XByteField, XIntField, XShortField, ShortField,
    FieldLenField, StrLenField, StrField, StrFixedLenField,
)


class BR1001_OPCODES(IntEnum):
    ERASE = 0x00
    ID = 0x01
    READ = 0x02
    WRITE = 0x03
    RUN = 0x05
    SPI_CFG = 0x06
    SET_VERIFY = 0x08
    GPIO_CS_CFG = 0x0A
    PART_READ = 0x0B
    PART_OPEN = 0x0C
    PEEK = 0x0D
    POKE = 0x0E
    FLASH_CFG_CLR0 = 0x10
    FLASH_CFG_CLR1 = 0x11
    FLASH_CFG_2 = 0x12
    FLASH_CFG_3 = 0x13
    FLASH_TX_CMD = 0x90
    READ_FLASH_SR = 0x91
    WRITE_FLASH_SR = 0x92
    ERASE_SECTOR = 0x93
    FLASH_PROGRAM = 0x94
    FLASH_SPI_CMD = 0x95


class BR1001_Cmd(Packet):
    name = "BR1001 Command"
    fields_desc = [ByteField("opcode", 0)]


class BR1001_Rsp(Packet):
    name = "BR1001 Response"
    fields_desc = [ByteField("opcode", 0)]


# Shared response body: a single BE32 status word (< 0 => error code).
class BR1001_Rsp_Result(Packet):
    name = "BR1001 Result"
    fields_desc = [XIntField("result", 0)]


# --- 0x00 ERASE --- addr==0 forces a full chip erase.
class BR1001_Cmd_Erase(Packet):
    name = "BR1001 Erase"
    fields_desc = [XIntField("addr", 0), XIntField("len", 0)]

class BR1001_Rsp_Erase(Packet):
    name = "BR1001 Erase Response"
    fields_desc = [XIntField("result", 0)]

bind_layers(BR1001_Cmd, BR1001_Cmd_Erase, opcode=BR1001_OPCODES.ERASE)
bind_layers(BR1001_Rsp, BR1001_Rsp_Erase, opcode=BR1001_OPCODES.ERASE)


# --- 0x01 ID --- probe flash; returns magic, JEDEC id and security regs.
class BR1001_Cmd_Id(Packet):
    name = "BR1001 Id"
    fields_desc = [
        ByteField("cs", 0),
        XIntField("spi_freq", 0),
        XShortField("_reserved", 0),
        ByteField("granularity", 0),
    ]

class BR1001_Rsp_Id(Packet):
    name = "BR1001 Id Response"
    fields_desc = [
        XIntField("magic", 0),
        XIntField("jedec_id", 0),
        StrFixedLenField("sec_reg", b"\x00" * 16, length=16),
    ]

bind_layers(BR1001_Cmd, BR1001_Cmd_Id, opcode=BR1001_OPCODES.ID)
bind_layers(BR1001_Rsp, BR1001_Rsp_Id, opcode=BR1001_OPCODES.ID)


# --- 0x02 READ --- addr < 0x08000000 reads SPI flash, else direct memory.
class BR1001_Cmd_Read(Packet):
    name = "BR1001 Read"
    fields_desc = [XIntField("addr", 0), XIntField("len", 0)]

class BR1001_Rsp_Read(Packet):
    name = "BR1001 Read Response"
    fields_desc = [
        FieldLenField("len", None, fmt="I", length_of="data"),
        StrLenField("data", b"", length_from=lambda pkt: pkt.len),
    ]

bind_layers(BR1001_Cmd, BR1001_Cmd_Read, opcode=BR1001_OPCODES.READ)
bind_layers(BR1001_Rsp, BR1001_Rsp_Read, opcode=BR1001_OPCODES.READ)


# --- 0x03 WRITE --- addr < 0x08000000 writes flash (partition-aware), else RAM.
class BR1001_Cmd_Write(Packet):
    name = "BR1001 Write"
    fields_desc = [
        XIntField("addr", 0),
        FieldLenField("len", None, fmt="I", length_of="data"),
        StrField("data", b""),
    ]

bind_layers(BR1001_Cmd, BR1001_Cmd_Write, opcode=BR1001_OPCODES.WRITE)
bind_layers(BR1001_Rsp, BR1001_Rsp_Result, opcode=BR1001_OPCODES.WRITE)


# --- 0x05 RUN --- [untested] jump to the image at `target` (or reboot).
class BR1001_Cmd_Run(Packet):
    name = "BR1001 Run"
    fields_desc = [XIntField("target", 0)]

bind_layers(BR1001_Cmd, BR1001_Cmd_Run, opcode=BR1001_OPCODES.RUN)
bind_layers(BR1001_Rsp, BR1001_Rsp_Result, opcode=BR1001_OPCODES.RUN)


# --- 0x06 SPI_CFG --- [untested] reconfigure SPI-flash freq/mode.
# Also writes the sector-1 magic if absent -- avoid on an unprovisioned chip.
class BR1001_Cmd_Spi_Cfg(Packet):
    name = "BR1001 SPI Cfg"
    fields_desc = [
        XIntField("freq", 0),
        ByteField("mode", 0),
        ByteField("arg2", 0),
        XShortField("width", 0),
    ]

bind_layers(BR1001_Cmd, BR1001_Cmd_Spi_Cfg, opcode=BR1001_OPCODES.SPI_CFG)
bind_layers(BR1001_Rsp, BR1001_Rsp_Result, opcode=BR1001_OPCODES.SPI_CFG)


# --- 0x08 SET_VERIFY --- [untested] non-zero => WRITE reads back and compares.
class BR1001_Cmd_Set_Verify(Packet):
    name = "BR1001 Set Verify"
    fields_desc = [ByteField("flag", 0)]

bind_layers(BR1001_Cmd, BR1001_Cmd_Set_Verify, opcode=BR1001_OPCODES.SET_VERIFY)
bind_layers(BR1001_Rsp, BR1001_Rsp_Result, opcode=BR1001_OPCODES.SET_VERIFY)


# --- 0x0A GPIO_CS_CFG --- [untested] drive the flash chip-select GPIO.
class BR1001_Cmd_Gpio_Cs_Cfg(Packet):
    name = "BR1001 GPIO CS Cfg"
    fields_desc = [ByteField("pin", 0), ByteField("level", 0)]

bind_layers(BR1001_Cmd, BR1001_Cmd_Gpio_Cs_Cfg, opcode=BR1001_OPCODES.GPIO_CS_CFG)
bind_layers(BR1001_Rsp, BR1001_Rsp_Result, opcode=BR1001_OPCODES.GPIO_CS_CFG)


# --- 0x0B PART_READ --- partition-table entry. Absent entries return
# addr=0xffffffff/length=0. Also writes the sector-1 magic if absent, so
# avoid on an unprovisioned chip.
class BR1001_Cmd_Part_Read(Packet):
    name = "BR1001 Part Read"
    fields_desc = [ByteField("part", 0)]

class BR1001_Rsp_Part_Read(Packet):
    name = "BR1001 Part Read Response"
    fields_desc = [XIntField("addr", 0), XIntField("length", 0)]

bind_layers(BR1001_Cmd, BR1001_Cmd_Part_Read, opcode=BR1001_OPCODES.PART_READ)
bind_layers(BR1001_Rsp, BR1001_Rsp_Part_Read, opcode=BR1001_OPCODES.PART_READ)


# --- 0x0C PART_OPEN --- [untested] register a partition/region; part 0x62
# erases the region. Response is the (possibly reallocated) base addr.
class BR1001_Cmd_Part_Open(Packet):
    name = "BR1001 Part Open"
    fields_desc = [ByteField("part", 0), XIntField("addr", 0), XIntField("size", 0)]

class BR1001_Rsp_Part_Open(Packet):
    name = "BR1001 Part Open Response"
    fields_desc = [XIntField("addr", 0)]

bind_layers(BR1001_Cmd, BR1001_Cmd_Part_Open, opcode=BR1001_OPCODES.PART_OPEN)
bind_layers(BR1001_Rsp, BR1001_Rsp_Part_Open, opcode=BR1001_OPCODES.PART_OPEN)


# --- 0x0D PEEK --- width 8/16/32; value is zero-extended to BE32.
class BR1001_Cmd_Peek(Packet):
    name = "BR1001 Peek"
    fields_desc = [ByteField("width", 0), XIntField("addr", 0)]

class BR1001_Rsp_Peek(Packet):
    name = "BR1001 Peek Response"
    fields_desc = [XIntField("value", 0)]

bind_layers(BR1001_Cmd, BR1001_Cmd_Peek, opcode=BR1001_OPCODES.PEEK)
bind_layers(BR1001_Rsp, BR1001_Rsp_Peek, opcode=BR1001_OPCODES.PEEK)


# --- 0x0E POKE --- [untested] width 8/16/32; misaligned writes are ignored.
class BR1001_Cmd_Poke(Packet):
    name = "BR1001 Poke"
    fields_desc = [ByteField("width", 0), XIntField("addr", 0), XIntField("value", 0)]

bind_layers(BR1001_Cmd, BR1001_Cmd_Poke, opcode=BR1001_OPCODES.POKE)
bind_layers(BR1001_Rsp, BR1001_Rsp_Result, opcode=BR1001_OPCODES.POKE)


# --- 0x10..0x13 flash-config toggles --- [untested] no arguments.
class BR1001_Cmd_Empty(Packet):
    name = "BR1001 Empty Command"
    fields_desc = []

for _op in (BR1001_OPCODES.FLASH_CFG_CLR0, BR1001_OPCODES.FLASH_CFG_CLR1,
            BR1001_OPCODES.FLASH_CFG_2, BR1001_OPCODES.FLASH_CFG_3):
    bind_layers(BR1001_Cmd, BR1001_Cmd_Empty, opcode=_op)
    bind_layers(BR1001_Rsp, BR1001_Rsp_Result, opcode=_op)


# --- 0x90 FLASH_TX_CMD --- [untested] shift out one SPI opcode + one data byte.
class BR1001_Cmd_Flash_Tx_Cmd(Packet):
    name = "BR1001 Flash Tx Cmd"
    fields_desc = [XByteField("cmd", 0), XByteField("arg", 0)]

bind_layers(BR1001_Cmd, BR1001_Cmd_Flash_Tx_Cmd, opcode=BR1001_OPCODES.FLASH_TX_CMD)
bind_layers(BR1001_Rsp, BR1001_Rsp_Result, opcode=BR1001_OPCODES.FLASH_TX_CMD)


# --- 0x91 READ_FLASH_SR --- BE16 status register, then the BE32 result.
class BR1001_Cmd_Read_Flash_SR(Packet):
    name = "BR1001 Read Flash SR"
    fields_desc = []

class BR1001_Rsp_Read_Flash_SR(Packet):
    name = "BR1001 Read Flash SR Response"
    fields_desc = [ShortField("sr", 0), XIntField("result", 0)]

bind_layers(BR1001_Cmd, BR1001_Cmd_Read_Flash_SR, opcode=BR1001_OPCODES.READ_FLASH_SR)
bind_layers(BR1001_Rsp, BR1001_Rsp_Read_Flash_SR, opcode=BR1001_OPCODES.READ_FLASH_SR)


# --- 0x92 WRITE_FLASH_SR --- [untested]
class BR1001_Cmd_Write_Flash_SR(Packet):
    name = "BR1001 Write Flash SR"
    fields_desc = [ShortField("sr", 0)]

bind_layers(BR1001_Cmd, BR1001_Cmd_Write_Flash_SR, opcode=BR1001_OPCODES.WRITE_FLASH_SR)
bind_layers(BR1001_Rsp, BR1001_Rsp_Result, opcode=BR1001_OPCODES.WRITE_FLASH_SR)


# --- 0x93 ERASE_SECTOR --- [untested] erase the sector containing `addr`.
class BR1001_Cmd_Erase_Sector(Packet):
    name = "BR1001 Erase Sector"
    fields_desc = [XIntField("addr", 0)]

bind_layers(BR1001_Cmd, BR1001_Cmd_Erase_Sector, opcode=BR1001_OPCODES.ERASE_SECTOR)
bind_layers(BR1001_Rsp, BR1001_Rsp_Result, opcode=BR1001_OPCODES.ERASE_SECTOR)


# --- 0x94 FLASH_PROGRAM --- [untested] page-program flash.
class BR1001_Cmd_Flash_Program(Packet):
    name = "BR1001 Flash Program"
    fields_desc = [XIntField("addr", 0), XIntField("len", 0)]

bind_layers(BR1001_Cmd, BR1001_Cmd_Flash_Program, opcode=BR1001_OPCODES.FLASH_PROGRAM)
bind_layers(BR1001_Rsp, BR1001_Rsp_Result, opcode=BR1001_OPCODES.FLASH_PROGRAM)


# --- 0x95 FLASH_SPI_CMD --- [untested] raw SPI transfer. dir==1 => read
# (dma_len bytes appended to the response); otherwise data follows the two
# command words in the request.
class BR1001_Cmd_Flash_Spi_Cmd(Packet):
    name = "BR1001 Flash SPI Cmd"
    fields_desc = [
        ByteField("cs", 0),
        ByteField("dir", 0),
        ByteField("reg_len", 0),
        FieldLenField("dma_len", None, fmt="B", length_of="data"),
        XIntField("cmd0", 0),
        XIntField("cmd1", 0),
        StrLenField("data", b"", length_from=lambda pkt: 0 if pkt.dir == 1 else pkt.dma_len),
    ]

class BR1001_Rsp_Flash_Spi_Cmd(Packet):
    name = "BR1001 Flash SPI Cmd Response"
    fields_desc = [
        XIntField("result", 0),
        StrField("data", b""),
    ]

bind_layers(BR1001_Cmd, BR1001_Cmd_Flash_Spi_Cmd, opcode=BR1001_OPCODES.FLASH_SPI_CMD)
bind_layers(BR1001_Rsp, BR1001_Rsp_Flash_Spi_Cmd, opcode=BR1001_OPCODES.FLASH_SPI_CMD)
