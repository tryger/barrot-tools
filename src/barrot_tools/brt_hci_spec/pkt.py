"""
Barrot vendor-specific HCI command/response packets (OGF=0x3F, OCF=0x80).

Subcommand ids come from the ``brt_spec_cmd_tab`` table in rom.bin
(BR8051A02); ids 0x00..0x1B are populated. Multi-byte integers on the wire
are LITTLE-ENDIAN. Each subcommand wraps in ``HCI_Cmd_VSC_Barrot`` on the way out and
its reply parses as ``HCI_Evt_VSC_Barrot_Command_Complete`` inside an HCI Command Complete event.

``[untested]`` marks a ROM-derived layout that was not exercised against a
chip (typically write/RF-test paths whose effect could be permanent).
Everything else was verified live against a BR8051A02 (33fa:0010 / :0012).
"""

from enum import IntEnum

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteField, XLEShortField, XLEIntField, LEShortField,
    StrField, StrFixedLenField,
)
from scapy.layers.bluetooth import HCI_Command_Hdr, HCI_Event_Command_Complete


class BRT_HCI_VSC_CMD_ID(IntEnum):
    RESET = 0x00
    READ_CHIP_VERSION = 0x01
    WRITE_PATCH = 0x02
    READ_SIGNATURE = 0x03
    UART_TL_PARAM = 0x04
    BD_PARAM = 0x05
    RF_TX_CONTROL = 0x06
    RF_FREQ_TRIM = 0x07
    RF_TEMPERATURE_COMP = 0x08
    PARAM_WRITE = 0x09
    PARAM_READ = 0x0A
    PARAM_PURGE = 0x0B
    CONFIG_WRITE = 0x0C
    CONFIG_READ = 0x0D
    BUS_WRITE = 0x0E
    BUS_READ = 0x0F
    FLASH_ERASE = 0x10
    FLASH_WRITE = 0x11
    FLASH_READ = 0x12
    EEPROM_WRITE = 0x13
    EEPROM_READ = 0x14
    RF_REG_WRITE = 0x15
    RF_REG_READ = 0x16
    RF_TEST = 0x17
    RF_TEST_END = 0x18
    PATCH_READ_RSSI_CAP = 0x19
    PATCH_TEST = 0x1A
    PATCH_END = 0x1B


class BARROT_RESET_TYPE(IntEnum):
    HW = 0x00
    ROM = 0x01
    SW = 0x02
    SW_PATCH = 0x03
    HCI = 0x04


class BARROT_ERROR_CODE(IntEnum):
    SUCCESS = 0x00
    STATUS_ERROR = 0x01
    UNSUPPORT_TYPE = 0x02
    UNKNOWN_COMMAND = 0x03
    ERROR_PARAMETERS = 0x04
    UNALLOW_COMMAND = 0x05
    COM_ERROR = 0x06
    PARAM_PROCESS_ERROR = 0x07
    ERROR_EVENT_PARAM_LEN = 0x08
    DATA_MISMATCH = 0x09
    USER_CANCEL = 0x0A
    FILE_FORMAT_ERROR = 0x0B
    INTERNAL_FAILURE = 0x0C
    INVALID_PARAM_LENGTH = 0x12
    EVT_FORMAT_ERROR = 0xF0
    COMMAND_ERROR = 0xF1
    TIMEOUT = 0xF2
    SPEC_CMD_MISMATCH = 0xF3
    END = 0xF4


# Command wraps in HCI_Command_Hdr; the reply is an HCI Command Complete
# event carrying HCI_Evt_VSC_Barrot_Command_Complete with the echoed subcommand id.
class HCI_Cmd_VSC_Barrot(Packet):
    name = "Barrot HCI Vendor Specific Command"
    fields_desc = [XLEShortField("cmd", 0)]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Barrot, ogf=0x3f, ocf=0x80)


class HCI_Evt_VSC_Barrot_Command_Complete(Packet):
    name = "Barrot HCI Command Complete Event"
    fields_desc = [XLEShortField("cmd", 0)]

bind_layers(HCI_Event_Command_Complete, HCI_Evt_VSC_Barrot_Command_Complete, opcode=0xfc80)


# --- 0x00 RESET ---
class HCI_Cmd_VSC_Barrot_Reset(Packet):
    name = "Barrot HCI Reset"
    fields_desc = [ByteField("reset_type", 0)]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Reset, cmd=BRT_HCI_VSC_CMD_ID.RESET)


# --- 0x01 READ_CHIP_VERSION ---
class HCI_Cmd_VSC_Barrot_Read_Chip_Version(Packet):
    name = "Barrot HCI Read Chip Version"
    fields_desc = []

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Read_Chip_Version, cmd=BRT_HCI_VSC_CMD_ID.READ_CHIP_VERSION)

class HCI_Evt_VSC_Barrot_Read_Chip_Version_Response(Packet):
    name = "Barrot HCI Read Chip Version Response"
    fields_desc = [
        StrFixedLenField("magic", b"BRT", 3),
        ByteField("config_type", 0),
        XLEIntField("version", 0),
        XLEIntField("fw_date", 0),
        XLEIntField("esm_type", 0),
        XLEIntField("run_mode", 0),
        XLEIntField("features", 0),
        XLEShortField("flash_id", 0),
    ]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Read_Chip_Version_Response, cmd=BRT_HCI_VSC_CMD_ID.READ_CHIP_VERSION)


# --- 0x02 WRITE_PATCH --- offset then data; data size is the HCI param length.
class HCI_Cmd_VSC_Barrot_Write_Patch(Packet):
    name = "Barrot HCI Write Patch"
    fields_desc = [XLEShortField("offset", 0), StrField("data", b"")]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Write_Patch, cmd=BRT_HCI_VSC_CMD_ID.WRITE_PATCH)


# --- 0x03 READ_SIGNATURE --- 32-byte MAC of BRT signature constants.
class HCI_Cmd_VSC_Barrot_Read_Signature(Packet):
    name = "Barrot HCI Read Signature"
    fields_desc = []

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Read_Signature, cmd=BRT_HCI_VSC_CMD_ID.READ_SIGNATURE)

class HCI_Evt_VSC_Barrot_Read_Signature_Response(Packet):
    name = "Barrot HCI Read Signature Response"
    fields_desc = [StrFixedLenField("signature", b"\x00" * 32, 32)]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Read_Signature_Response, cmd=BRT_HCI_VSC_CMD_ID.READ_SIGNATURE)


# --- 0x04 UART_TL_PARAM --- empty payload reads (18B out); 18B writes [untested].
class HCI_Cmd_VSC_Barrot_Uart_Tl_Param(Packet):
    name = "Barrot HCI UART TL Param"
    fields_desc = [StrField("data", b"")]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Uart_Tl_Param, cmd=BRT_HCI_VSC_CMD_ID.UART_TL_PARAM)

class HCI_Evt_VSC_Barrot_Uart_Tl_Param_Response(Packet):
    name = "Barrot HCI UART TL Param Response"
    fields_desc = [StrField("data", b"")]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Uart_Tl_Param_Response, cmd=BRT_HCI_VSC_CMD_ID.UART_TL_PARAM)


# --- 0x05 BD_PARAM --- empty reads (6B BD addr, LE); 6B writes RAM [untested].
class HCI_Cmd_VSC_Barrot_Bd_Param(Packet):
    name = "Barrot HCI BD Param"
    fields_desc = [StrField("bd_addr", b"")]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Bd_Param, cmd=BRT_HCI_VSC_CMD_ID.BD_PARAM)

class HCI_Evt_VSC_Barrot_Bd_Param_Response(Packet):
    name = "Barrot HCI BD Param Response"
    fields_desc = [StrField("bd_addr", b"")]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Bd_Param_Response, cmd=BRT_HCI_VSC_CMD_ID.BD_PARAM)


# --- 0x06 RF_TX_CONTROL --- 1..3 bytes (mode, [power], [extra]). Enabling TX
# emits RF; not exposed via a helper except behind an explicit call.
class HCI_Cmd_VSC_Barrot_Rf_Tx_Control(Packet):
    name = "Barrot HCI RF TX Control"
    fields_desc = [StrField("data", b"")]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Rf_Tx_Control, cmd=BRT_HCI_VSC_CMD_ID.RF_TX_CONTROL)


# --- 0x07 RF_FREQ_TRIM --- empty reads (6B); 6B writes [untested].
# WARNING: read and write bit-packings are ASYMMETRIC -- writing back the
# bytes a read returned corrupts the XO trim in RF regs 0xaa/0xab.
class HCI_Cmd_VSC_Barrot_Rf_Freq_Trim(Packet):
    name = "Barrot HCI RF Freq Trim"
    fields_desc = [StrField("trim", b"")]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Rf_Freq_Trim, cmd=BRT_HCI_VSC_CMD_ID.RF_FREQ_TRIM)

class HCI_Evt_VSC_Barrot_Rf_Freq_Trim_Response(Packet):
    name = "Barrot HCI RF Freq Trim Response"
    fields_desc = [StrField("trim", b"")]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Rf_Freq_Trim_Response, cmd=BRT_HCI_VSC_CMD_ID.RF_FREQ_TRIM)


# --- 0x08 RF_TEMPERATURE_COMP --- WARNING: any invocation
# bricked the USB endpoint of the BR8051A02 tested. TBD.
class HCI_Cmd_VSC_Barrot_Rf_Temperature_Comp(Packet):
    name = "Barrot HCI RF Temperature Comp (DANGEROUS)"
    fields_desc = [ByteField("temp", 0)]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Rf_Temperature_Comp, cmd=BRT_HCI_VSC_CMD_ID.RF_TEMPERATURE_COMP)

class HCI_Evt_VSC_Barrot_Rf_Temperature_Comp_Response(Packet):
    name = "Barrot HCI RF Temperature Comp Response"
    fields_desc = [LEShortField("comp", 0)]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Rf_Temperature_Comp_Response, cmd=BRT_HCI_VSC_CMD_ID.RF_TEMPERATURE_COMP)


# --- 0x09 PARAM_WRITE --- byte0 = tag_id then data; tag_id=0xFF is the
# streamed form (offset LE, total LE, chunk).
# WARNING: a length-1 payload (tag id, no data) wipes the in-RAM BD address.
class HCI_Cmd_VSC_Barrot_Param_Write(Packet):
    name = "Barrot HCI Param Write"
    fields_desc = [ByteField("tag_id", 0), StrField("data", b"")]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Param_Write, cmd=BRT_HCI_VSC_CMD_ID.PARAM_WRITE)


# --- 0x0A PARAM_READ ---
class HCI_Cmd_VSC_Barrot_Param_Read(Packet):
    name = "Barrot HCI Param Read"
    fields_desc = [ByteField("tag_id", 0), ByteField("length", 0)]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Param_Read, cmd=BRT_HCI_VSC_CMD_ID.PARAM_READ)

class HCI_Evt_VSC_Barrot_Param_Read_Response(Packet):
    name = "Barrot HCI Param Read Response"
    fields_desc = [ByteField("tag_id", 0), StrField("data", b"")]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Param_Read_Response, cmd=BRT_HCI_VSC_CMD_ID.PARAM_READ)


# --- 0x0B PARAM_PURGE --- [untested] wipes all params (likely BD addr + trim).
class HCI_Cmd_VSC_Barrot_Param_Purge(Packet):
    name = "Barrot HCI Param Purge"
    fields_desc = []

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Param_Purge, cmd=BRT_HCI_VSC_CMD_ID.PARAM_PURGE)


# --- 0x0C CONFIG_WRITE --- tag_id then data (length must match the tag).
# The handler persists to flash NVDS, so a non-idempotent write mutates flash.
class HCI_Cmd_VSC_Barrot_Config_Write(Packet):
    name = "Barrot HCI Config Write"
    fields_desc = [ByteField("tag_id", 0), StrField("data", b"")]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Config_Write, cmd=BRT_HCI_VSC_CMD_ID.CONFIG_WRITE)


# --- 0x0D CONFIG_READ --- one tag_id in, [tag_id][data] out.
# WARNING: tag_id=0xFF hits a buggy ROM path (NULL deref) that hangs the chip.
class HCI_Cmd_VSC_Barrot_Config_Read(Packet):
    name = "Barrot HCI Config Read"
    fields_desc = [ByteField("tag_id", 0xff)]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Config_Read, cmd=BRT_HCI_VSC_CMD_ID.CONFIG_READ)

class HCI_Evt_VSC_Barrot_Config_Read_Response(Packet):
    name = "Barrot HCI Config Read Response"
    fields_desc = [StrField("data", b"")]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Config_Read_Response, cmd=BRT_HCI_VSC_CMD_ID.CONFIG_READ)


# --- 0x0E BUS_WRITE --- writes arbitrary memory.
class HCI_Cmd_VSC_Barrot_Bus_Write(Packet):
    name = "Barrot HCI Bus Write"
    fields_desc = [XLEIntField("address", 0), StrField("data", b"")]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Bus_Write, cmd=BRT_HCI_VSC_CMD_ID.BUS_WRITE)


# --- 0x0F BUS_READ --- length 1..0xF0.
class HCI_Cmd_VSC_Barrot_Bus_Read(Packet):
    name = "Barrot HCI Bus Read"
    fields_desc = [XLEIntField("address", 0), ByteField("length", 0)]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Bus_Read, cmd=BRT_HCI_VSC_CMD_ID.BUS_READ)

class HCI_Evt_VSC_Barrot_Bus_Read_Response(Packet):
    name = "Barrot HCI Bus Read Response"
    fields_desc = [StrField("data", b"")]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Bus_Read_Response, cmd=BRT_HCI_VSC_CMD_ID.BUS_READ)


# --- 0x10 FLASH_ERASE --- status 0 but a no-op: flash write-protected, like FLASH_WRITE.
# addr must be 4KB-aligned, len sector/block-sized; addr=len=0 = full-chip erase.
# Needs a WRITE_PATCH flash-unlock patch to take effect (WREN + WRSR clears BP). TODO.
class HCI_Cmd_VSC_Barrot_Flash_Erase(Packet):
    name = "Barrot HCI Flash Erase"
    fields_desc = [XLEIntField("address", 0), XLEIntField("length", 0)]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Flash_Erase, cmd=BRT_HCI_VSC_CMD_ID.FLASH_ERASE)


# --- 0x11 FLASH_WRITE --- status 0 but a no-op: SPI flash is write-protected (BP bits).
# Needs a WRITE_PATCH flash-unlock patch to take effect (WREN + WRSR clears BP). TODO.
class HCI_Cmd_VSC_Barrot_Flash_Write(Packet):
    name = "Barrot HCI Flash Write"
    fields_desc = [XLEIntField("address", 0), StrField("data", b"")]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Flash_Write, cmd=BRT_HCI_VSC_CMD_ID.FLASH_WRITE)


# --- 0x12 FLASH_READ ---
class HCI_Cmd_VSC_Barrot_Flash_Read(Packet):
    name = "Barrot HCI Flash Read"
    fields_desc = [XLEIntField("address", 0), ByteField("length", 0)]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Flash_Read, cmd=BRT_HCI_VSC_CMD_ID.FLASH_READ)

class HCI_Evt_VSC_Barrot_Flash_Read_Response(Packet):
    name = "Barrot HCI Flash Read Response"
    fields_desc = [StrField("data", b"")]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Flash_Read_Response, cmd=BRT_HCI_VSC_CMD_ID.FLASH_READ)


# --- 0x13 EEPROM_WRITE --- [untested] (EEPROM absent on some variants)
class HCI_Cmd_VSC_Barrot_Eeprom_Write(Packet):
    name = "Barrot HCI EEPROM Write"
    fields_desc = [XLEIntField("address", 0), StrField("data", b"")]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Eeprom_Write, cmd=BRT_HCI_VSC_CMD_ID.EEPROM_WRITE)


# --- 0x14 EEPROM_READ --- absent EEPROM returns INTERNAL_FAILURE.
class HCI_Cmd_VSC_Barrot_Eeprom_Read(Packet):
    name = "Barrot HCI EEPROM Read"
    fields_desc = [XLEIntField("address", 0), ByteField("length", 0)]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Eeprom_Read, cmd=BRT_HCI_VSC_CMD_ID.EEPROM_READ)

class HCI_Evt_VSC_Barrot_Eeprom_Read_Response(Packet):
    name = "Barrot HCI EEPROM Read Response"
    fields_desc = [StrField("data", b"")]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Eeprom_Read_Response, cmd=BRT_HCI_VSC_CMD_ID.EEPROM_READ)


# --- 0x15 RF_REG_WRITE --- [untested]
class HCI_Cmd_VSC_Barrot_Rf_Reg_Write(Packet):
    name = "Barrot HCI RF Register Write"
    fields_desc = [XLEIntField("address", 0), XLEIntField("value", 0)]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Rf_Reg_Write, cmd=BRT_HCI_VSC_CMD_ID.RF_REG_WRITE)


# --- 0x16 RF_REG_READ --- address must be < 0x100.
class HCI_Cmd_VSC_Barrot_Rf_Reg_Read(Packet):
    name = "Barrot HCI RF Register Read"
    fields_desc = [XLEIntField("address", 0)]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Rf_Reg_Read, cmd=BRT_HCI_VSC_CMD_ID.RF_REG_READ)

class HCI_Evt_VSC_Barrot_Rf_Reg_Read_Response(Packet):
    name = "Barrot HCI RF Register Read Response"
    fields_desc = [XLEIntField("address", 0), XLEIntField("value", 0)]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Rf_Reg_Read_Response, cmd=BRT_HCI_VSC_CMD_ID.RF_REG_READ)


# --- 0x17 RF_TEST --- [untested] 10..16 bytes of RF test descriptor.
class HCI_Cmd_VSC_Barrot_Rf_Test(Packet):
    name = "Barrot HCI RF Test"
    fields_desc = [StrField("data", b"")]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Rf_Test, cmd=BRT_HCI_VSC_CMD_ID.RF_TEST)


# --- 0x18 RF_TEST_END --- 16-byte result (rx_count LE, err_count LE, 8 misc).
class HCI_Cmd_VSC_Barrot_Rf_Test_End(Packet):
    name = "Barrot HCI RF Test End"
    fields_desc = []

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Rf_Test_End, cmd=BRT_HCI_VSC_CMD_ID.RF_TEST_END)

class HCI_Evt_VSC_Barrot_Rf_Test_End_Response(Packet):
    name = "Barrot HCI RF Test End Response"
    fields_desc = [StrFixedLenField("result", b"\x00" * 16, 16)]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Rf_Test_End_Response, cmd=BRT_HCI_VSC_CMD_ID.RF_TEST_END)


# --- 0x19 PATCH_READ_RSSI_CAP --- [untested]
class HCI_Cmd_VSC_Barrot_Patch_Read_Rssi_Cap(Packet):
    name = "Barrot HCI Patch Read RSSI Cap"
    fields_desc = [XLEIntField("address", 0), XLEShortField("delay", 0)]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Patch_Read_Rssi_Cap, cmd=BRT_HCI_VSC_CMD_ID.PATCH_READ_RSSI_CAP)


# --- 0x1A PATCH_TEST --- 2-byte LE result.
class HCI_Cmd_VSC_Barrot_Patch_Test(Packet):
    name = "Barrot HCI Patch Test"
    fields_desc = []

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Patch_Test, cmd=BRT_HCI_VSC_CMD_ID.PATCH_TEST)

class HCI_Evt_VSC_Barrot_Patch_Test_Response(Packet):
    name = "Barrot HCI Patch Test Response"
    fields_desc = [LEShortField("result", 0)]

bind_layers(HCI_Evt_VSC_Barrot_Command_Complete, HCI_Evt_VSC_Barrot_Patch_Test_Response, cmd=BRT_HCI_VSC_CMD_ID.PATCH_TEST)


# --- 0x1B PATCH_END --- 1 byte: 0 disables the patch override, !=0 enables.
class HCI_Cmd_VSC_Barrot_Patch_End(Packet):
    name = "Barrot HCI Patch End"
    fields_desc = [ByteField("enable", 0)]

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Patch_End, cmd=BRT_HCI_VSC_CMD_ID.PATCH_END)
