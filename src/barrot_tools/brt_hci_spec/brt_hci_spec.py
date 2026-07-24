from scapy.packet import Packet
from scapy.layers.bluetooth import HCI_Event_Command_Complete

from .pkt import (
    BRT_HCI_VSC_CMD_ID, BARROT_RESET_TYPE, BARROT_ERROR_CODE,
    HCI_Cmd_VSC_Barrot,
    HCI_Cmd_VSC_Barrot_Reset, HCI_Cmd_VSC_Barrot_Read_Chip_Version, HCI_Cmd_VSC_Barrot_Read_Signature,
    HCI_Cmd_VSC_Barrot_Write_Patch, HCI_Cmd_VSC_Barrot_Uart_Tl_Param, HCI_Cmd_VSC_Barrot_Bd_Param,
    HCI_Cmd_VSC_Barrot_Rf_Tx_Control, HCI_Cmd_VSC_Barrot_Rf_Freq_Trim, HCI_Cmd_VSC_Barrot_Param_Read,
    HCI_Cmd_VSC_Barrot_Param_Write, HCI_Cmd_VSC_Barrot_Param_Purge, HCI_Cmd_VSC_Barrot_Config_Read,
    HCI_Cmd_VSC_Barrot_Config_Write, HCI_Cmd_VSC_Barrot_Bus_Read, HCI_Cmd_VSC_Barrot_Bus_Write,
    HCI_Cmd_VSC_Barrot_Flash_Read, HCI_Cmd_VSC_Barrot_Flash_Write, HCI_Cmd_VSC_Barrot_Flash_Erase,
    HCI_Cmd_VSC_Barrot_Eeprom_Read, HCI_Cmd_VSC_Barrot_Eeprom_Write, HCI_Cmd_VSC_Barrot_Rf_Reg_Read,
    HCI_Cmd_VSC_Barrot_Rf_Reg_Write, HCI_Cmd_VSC_Barrot_Rf_Test, HCI_Cmd_VSC_Barrot_Rf_Test_End,
    HCI_Cmd_VSC_Barrot_Patch_Test, HCI_Cmd_VSC_Barrot_Patch_End, HCI_Cmd_VSC_Barrot_Patch_Read_Rssi_Cap,
    HCI_Evt_VSC_Barrot_Read_Chip_Version_Response, HCI_Evt_VSC_Barrot_Read_Signature_Response,
    HCI_Evt_VSC_Barrot_Uart_Tl_Param_Response, HCI_Evt_VSC_Barrot_Bd_Param_Response, HCI_Evt_VSC_Barrot_Rf_Freq_Trim_Response,
    HCI_Evt_VSC_Barrot_Param_Read_Response, HCI_Evt_VSC_Barrot_Bus_Read_Response, HCI_Evt_VSC_Barrot_Flash_Read_Response,
    HCI_Evt_VSC_Barrot_Eeprom_Read_Response, HCI_Evt_VSC_Barrot_Rf_Reg_Read_Response, HCI_Evt_VSC_Barrot_Config_Read_Response,
    HCI_Evt_VSC_Barrot_Patch_Test_Response, HCI_Evt_VSC_Barrot_Rf_Test_End_Response,
)
from .hci_transport import HciTransport, HciError, BARROT_USB_IDS
from .chip_info import BrtInfo
from ..common.chunked import read_chunked, write_chunked


# Per-region chunk limits.
FLASH_CHUNK_SIZE = 0xf0
WRITE_CHUNK_SIZE = 0x80
PATCH_CHUNK_SIZE = 0x80
BUS_CHUNK_SIZE = 0xf0
EEPROM_CHUNK_SIZE = 0xf0

# On-chip memory regions (Cortex-M3 BR8051/BR8551; from the SDK linker map).
ROM_BASE = 0x00000000
ROM_SIZE = 0x40000          # 256 KB mask ROM
RAM_BASE = 0x20000000
RAM_SIZE = 0x20000          # 128 KB SRAM
FLASH_BASE = 0x00000000
FLASH_SIZE = 0x80000        # 512 KB flash


class BrtHciSpec:
    """
    Driver for Barrot chips speaking the USB HCI vendor-specific command set
    (OGF=0x3F, OCF=0x80). Works with any chip exposing that family
    (BR8051, BR8551, ...). Use ``chip_info()`` to identify the device.

    Read-only / non-destructive subcommands are exposed as high-level
    methods. Destructive ones (writes, RF test mode, RF_TEMPERATURE_COMP)
    are kept behind explicit calls or omitted -- see barrot_tools.brt_hci_spec.pkt for
    the raw scapy classes if you need to send one by hand.
    """

    def __init__(self,
                 usb_ids: list[tuple[int, int]] = BARROT_USB_IDS,
                 verbose: bool = False,
                 *, transport: HciTransport | None = None) -> None:
        if transport is None:
            transport = HciTransport(usb_ids=usb_ids, verbose=verbose)
        self.transport = transport

    def close(self) -> None:
        self.transport.close()

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # --- command plumbing ---

    def sr1(self, pkt: Packet) -> Packet:
        """Send one command packet and return its parsed response event."""
        return self.transport.sr1(pkt)

    def _cmd(self, cmd_id: BRT_HCI_VSC_CMD_ID, payload: Packet | None = None) -> Packet:
        """Send a VSC command and return the status-checked response event."""
        pkt = HCI_Cmd_VSC_Barrot(cmd=int(cmd_id))
        if payload is not None:
            pkt = pkt / payload
        resp = self.sr1(pkt)
        if resp is None:
            raise HciError("No response from chip (sr1 timed out)")
        if HCI_Event_Command_Complete in resp:
            status = resp[HCI_Event_Command_Complete].status
            if status != 0:
                try:
                    name = BARROT_ERROR_CODE(status).name
                except ValueError:
                    name = f"0x{status:02x}"
                raise HciError(f"Command failed: {name} (0x{status:02x})")
        return resp

    def _flash_read(self, address: int, length: int) -> Packet:
        return self._cmd(BRT_HCI_VSC_CMD_ID.FLASH_READ, HCI_Cmd_VSC_Barrot_Flash_Read(address=address, length=length))

    def _flash_write(self, address: int, data: bytes) -> Packet:
        return self._cmd(BRT_HCI_VSC_CMD_ID.FLASH_WRITE, HCI_Cmd_VSC_Barrot_Flash_Write(address=address, data=data))

    def _bus_read(self, address: int, length: int) -> Packet:
        return self._cmd(BRT_HCI_VSC_CMD_ID.BUS_READ, HCI_Cmd_VSC_Barrot_Bus_Read(address=address, length=length))

    def _bus_write(self, address: int, data: bytes) -> Packet:
        return self._cmd(BRT_HCI_VSC_CMD_ID.BUS_WRITE, HCI_Cmd_VSC_Barrot_Bus_Write(address=address, data=data))

    def _eeprom_read(self, address: int, length: int) -> Packet:
        return self._cmd(BRT_HCI_VSC_CMD_ID.EEPROM_READ, HCI_Cmd_VSC_Barrot_Eeprom_Read(address=address, length=length))

    def _eeprom_write(self, address: int, data: bytes) -> Packet:
        return self._cmd(BRT_HCI_VSC_CMD_ID.EEPROM_WRITE, HCI_Cmd_VSC_Barrot_Eeprom_Write(address=address, data=data))

    # --- identity ---

    def chip_info(self) -> BrtInfo:
        r = self._cmd(BRT_HCI_VSC_CMD_ID.READ_CHIP_VERSION)[HCI_Evt_VSC_Barrot_Read_Chip_Version_Response]
        return BrtInfo(
            magic       = r.magic.decode("ascii", errors="replace"),
            config_type = r.config_type,
            version     = r.version,
            fw_date     = r.fw_date,
            esm_type    = r.esm_type,
            run_mode    = r.run_mode,
            features    = r.features,
            flash_id    = r.flash_id,
        )

    def signature_read(self) -> bytes:
        resp = self._cmd(BRT_HCI_VSC_CMD_ID.READ_SIGNATURE)
        return bytes(resp[HCI_Evt_VSC_Barrot_Read_Signature_Response].signature)

    def reset(self, reset_type: BARROT_RESET_TYPE = BARROT_RESET_TYPE.HCI) -> None:
        self._cmd(BRT_HCI_VSC_CMD_ID.RESET, HCI_Cmd_VSC_Barrot_Reset(reset_type=int(reset_type)))

    # --- named parameters ---

    def bd_addr_read(self) -> bytes:
        """Return the 6-byte BD address in chip byte order (little-endian)."""
        resp = self._cmd(BRT_HCI_VSC_CMD_ID.BD_PARAM, HCI_Cmd_VSC_Barrot_Bd_Param(bd_addr=b""))
        return bytes(resp[HCI_Evt_VSC_Barrot_Bd_Param_Response].bd_addr)

    def bd_addr_write(self, bd_addr_le: bytes) -> None:
        """Overwrite the in-RAM BD address (6 bytes, LE). A HW reset restores
        the NVDS-programmed value."""
        if len(bd_addr_le) != 6:
            raise ValueError(f"BD address must be 6 bytes, got {len(bd_addr_le)}")
        self._cmd(BRT_HCI_VSC_CMD_ID.BD_PARAM, HCI_Cmd_VSC_Barrot_Bd_Param(bd_addr=bd_addr_le))

    def uart_tl_param_read(self) -> bytes:
        resp = self._cmd(BRT_HCI_VSC_CMD_ID.UART_TL_PARAM, HCI_Cmd_VSC_Barrot_Uart_Tl_Param(data=b""))
        return bytes(resp[HCI_Evt_VSC_Barrot_Uart_Tl_Param_Response].data)

    def uart_tl_param_write(self, data: bytes) -> None:
        """Overwrite the in-RAM UART transport-layer parameter block (18 bytes)."""
        if len(data) != 18:
            raise ValueError(f"UART_TL_PARAM expects 18 bytes, got {len(data)}")
        self._cmd(BRT_HCI_VSC_CMD_ID.UART_TL_PARAM, HCI_Cmd_VSC_Barrot_Uart_Tl_Param(data=data))

    def rf_freq_trim_read(self) -> bytes:
        """6 bytes of packed RF crystal-trim bits (chip-specific layout)."""
        resp = self._cmd(BRT_HCI_VSC_CMD_ID.RF_FREQ_TRIM, HCI_Cmd_VSC_Barrot_Rf_Freq_Trim(trim=b""))
        return bytes(resp[HCI_Evt_VSC_Barrot_Rf_Freq_Trim_Response].trim)

    def rf_freq_trim_write(self, trim: bytes) -> None:
        """Overwrite RF crystal trim (6 bytes).

        WARNING: read and write bit layouts are asymmetric. Writing back the
        value from rf_freq_trim_read() corrupts the XO trim in RF regs
        0xaa/0xab; snapshot and restore those via rf_reg_read/rf_reg_write.
        """
        if len(trim) != 6:
            raise ValueError(f"RF_FREQ_TRIM expects 6 bytes, got {len(trim)}")
        self._cmd(BRT_HCI_VSC_CMD_ID.RF_FREQ_TRIM, HCI_Cmd_VSC_Barrot_Rf_Freq_Trim(trim=trim))

    def param_read(self, tag_id: int, length: int) -> bytes:
        """Read a single tag from the parameter store."""
        resp = self._cmd(BRT_HCI_VSC_CMD_ID.PARAM_READ, HCI_Cmd_VSC_Barrot_Param_Read(tag_id=tag_id, length=length))
        return bytes(resp[HCI_Evt_VSC_Barrot_Param_Read_Response].data)

    def param_write(self, tag_id: int, data: bytes) -> None:
        """Write a single (non-streamed) parameter tag."""
        if tag_id == 0xff:
            raise ValueError("tag_id=0xFF is the streaming form; use param_write_stream")
        if len(data) == 0:
            raise ValueError("a zero-length payload wipes the in-RAM BD address")
        self._cmd(BRT_HCI_VSC_CMD_ID.PARAM_WRITE, HCI_Cmd_VSC_Barrot_Param_Write(tag_id=tag_id, data=data))

    def param_write_stream(self, offset: int, total: int, chunk: bytes) -> None:
        """Streaming PARAM_WRITE (tag_id=0xFF), for large params."""
        payload = bytes([offset & 0xff, (offset >> 8) & 0xff,
                         total & 0xff, (total >> 8) & 0xff]) + chunk
        self._cmd(BRT_HCI_VSC_CMD_ID.PARAM_WRITE, HCI_Cmd_VSC_Barrot_Param_Write(tag_id=0xff, data=payload))

    def param_purge(self) -> None:
        """Wipe all parameters. DANGEROUS -- likely loses BD addr and trim."""
        self._cmd(BRT_HCI_VSC_CMD_ID.PARAM_PURGE, HCI_Cmd_VSC_Barrot_Param_Purge())

    def config_read(self, tag_id: int) -> bytes:
        """Read one config tag ([tag_id][data]). tag_id=0xFF is a buggy ROM
        path (NULL deref) -- do not pass it."""
        resp = self._cmd(BRT_HCI_VSC_CMD_ID.CONFIG_READ, HCI_Cmd_VSC_Barrot_Config_Read(tag_id=tag_id))
        return bytes(resp[HCI_Evt_VSC_Barrot_Config_Read_Response].data)

    def config_write(self, tag_id: int, data: bytes) -> None:
        """Write a config tag. The ROM validates length against the tag and
        persists to flash NVDS, so non-idempotent writes mutate flash."""
        self._cmd(BRT_HCI_VSC_CMD_ID.CONFIG_WRITE, HCI_Cmd_VSC_Barrot_Config_Write(tag_id=tag_id, data=data))

    # --- RF registers / test ---

    def rf_reg_read(self, address: int) -> tuple[int, int]:
        """Return (address, value); both 32-bit. Address must be < 0x100."""
        r = self._cmd(BRT_HCI_VSC_CMD_ID.RF_REG_READ, HCI_Cmd_VSC_Barrot_Rf_Reg_Read(address=address))[HCI_Evt_VSC_Barrot_Rf_Reg_Read_Response]
        return r.address, r.value

    def rf_reg_write(self, address: int, value: int) -> None:
        self._cmd(BRT_HCI_VSC_CMD_ID.RF_REG_WRITE, HCI_Cmd_VSC_Barrot_Rf_Reg_Write(address=address, value=value))

    def rf_tx_control(self, mode: int, power: int | None = None,
                      extra: int | None = None) -> None:
        """Drive the RF TX hook. mode=0xFF disables; any other value enables
        TX and emits RF -- only safe in a shielded setup."""
        if not 0 <= mode <= 0xff:
            raise ValueError("mode must fit in 1 byte")
        payload = bytes([mode])
        if power is not None:
            payload += bytes([power & 0xff])
            if extra is not None:
                payload += bytes([extra & 0xff])
        elif extra is not None:
            raise ValueError("extra requires power to be set")
        self._cmd(BRT_HCI_VSC_CMD_ID.RF_TX_CONTROL, HCI_Cmd_VSC_Barrot_Rf_Tx_Control(data=payload))

    def rf_test(self, payload: bytes) -> None:
        """Start an RF test (10..16 bytes). Pair with rf_test_end()."""
        if not 10 <= len(payload) <= 16:
            raise ValueError("RF_TEST payload must be 10..16 bytes")
        self._cmd(BRT_HCI_VSC_CMD_ID.RF_TEST, HCI_Cmd_VSC_Barrot_Rf_Test(data=payload))

    def rf_test_end(self) -> bytes:
        """Stop the RF test; return 16 bytes of result (rx/err counters, ...)."""
        return bytes(self._cmd(BRT_HCI_VSC_CMD_ID.RF_TEST_END, HCI_Cmd_VSC_Barrot_Rf_Test_End())[HCI_Evt_VSC_Barrot_Rf_Test_End_Response].result)

    # --- patch ---

    def patch_test(self) -> int:
        """Run the built-in patch-test routine. Returns the 16-bit result."""
        return self._cmd(BRT_HCI_VSC_CMD_ID.PATCH_TEST, HCI_Cmd_VSC_Barrot_Patch_Test())[HCI_Evt_VSC_Barrot_Patch_Test_Response].result

    def patch_end(self, enable: int) -> None:
        """Toggle the patch-override flag (0 = disable, !=0 = enable)."""
        self._cmd(BRT_HCI_VSC_CMD_ID.PATCH_END, HCI_Cmd_VSC_Barrot_Patch_End(enable=enable & 0xff))

    def patch_read_rssi_cap(self, address: int, delay_ms: int = 0x14) -> None:
        """Run the RSSI-capture patch routine. Touches flash -- destructive."""
        self._cmd(BRT_HCI_VSC_CMD_ID.PATCH_READ_RSSI_CAP,
                  HCI_Cmd_VSC_Barrot_Patch_Read_Rssi_Cap(address=address, delay=delay_ms))

    def patch_write(self, data: bytes) -> None:
        """Upload a patch blob in 128-byte chunks."""
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + PATCH_CHUNK_SIZE]
            self._cmd(BRT_HCI_VSC_CMD_ID.WRITE_PATCH, HCI_Cmd_VSC_Barrot_Write_Patch(offset=offset, data=chunk))
            offset += len(chunk)

    # --- bus (arbitrary memory) ---

    def bus_read(self, address: int, length: int) -> bytes:
        """Read memory (RAM/ROM/peripherals) in one chunk (length 1..0xF0)."""
        if not 1 <= length <= BUS_CHUNK_SIZE:
            raise ValueError(f"BUS_READ length must be 1..0x{BUS_CHUNK_SIZE:x} "
                             f"(use bus_dump for chunked reads)")
        return bytes(self._bus_read(address, length)[HCI_Evt_VSC_Barrot_Bus_Read_Response].data)

    def bus_write(self, address: int, data: bytes) -> None:
        """Write up to 0xF0 bytes to memory in one chunk."""
        if not 1 <= len(data) <= 0xf0:
            raise ValueError("BUS_WRITE payload length must be 1..0xF0")
        self._bus_write(address, data)

    def bus_dump(self, address: int, size: int) -> bytes:
        print(f"Reading {size} bytes from memory 0x{address:08x} via BUS_READ")
        return read_chunked(self._bus_read, HCI_Evt_VSC_Barrot_Bus_Read_Response, address, size, BUS_CHUNK_SIZE)

    def bus_write_chunked(self, address: int, data: bytes) -> None:
        write_chunked(self._bus_write, address, data, BUS_CHUNK_SIZE)

    def rom_dump(self, filepath: str) -> None:
        """Dump the full 256 KB mask ROM (0x00000000) via BUS_READ."""
        _save(self.bus_dump(ROM_BASE, ROM_SIZE), filepath)

    def ram_dump(self, filepath: str) -> None:
        """Dump the full 128 KB SRAM (0x20000000) via BUS_READ."""
        _save(self.bus_dump(RAM_BASE, RAM_SIZE), filepath)

    # --- eeprom ---

    def eeprom_read(self, address: int, length: int) -> bytes:
        """Read EEPROM in one chunk (length 1..0xF0). Absent EEPROM returns
        INTERNAL_FAILURE."""
        if not 1 <= length <= EEPROM_CHUNK_SIZE:
            raise ValueError(f"EEPROM_READ length must be 1..0x{EEPROM_CHUNK_SIZE:x} "
                             f"(use eeprom_dump for chunked reads)")
        return bytes(self._eeprom_read(address, length)[HCI_Evt_VSC_Barrot_Eeprom_Read_Response].data)

    def eeprom_write(self, address: int, data: bytes) -> None:
        """Write EEPROM. Variants without EEPROM return INTERNAL_FAILURE."""
        self._eeprom_write(address, data)

    def eeprom_dump(self, address: int, size: int) -> bytes:
        print(f"Reading {size} bytes from EEPROM 0x{address:08x}")
        return read_chunked(self._eeprom_read, HCI_Evt_VSC_Barrot_Eeprom_Read_Response, address, size, EEPROM_CHUNK_SIZE)

    # --- flash ---

    def flash_read(self, address: int, size: int) -> bytes:
        print(f"Reading {size} bytes from flash 0x{address:08x}")
        return read_chunked(self._flash_read, HCI_Evt_VSC_Barrot_Flash_Read_Response, address, size, FLASH_CHUNK_SIZE)

    def flash_write(self, address: int, data: bytes) -> None:
        print(f"Writing {len(data)} bytes to flash 0x{address:08x}")
        write_chunked(self._flash_write, address, data, WRITE_CHUNK_SIZE)

    def flash_erase(self, address: int, length: int) -> None:
        print(f"Erasing flash 0x{address:08x} length 0x{length:x}")
        self._cmd(BRT_HCI_VSC_CMD_ID.FLASH_ERASE, HCI_Cmd_VSC_Barrot_Flash_Erase(address=address, length=length))

    def flash_dump(self, address: int, size: int, filepath: str) -> None:
        _save(self.flash_read(address, size), filepath)

    def flash_write_file(self, address: int, filepath: str) -> None:
        with open(filepath, "rb") as f:
            self.flash_write(address, f.read())


def _save(data: bytes, filepath: str) -> None:
    with open(filepath, "wb") as f:
        f.write(data)
    print(f"Saved {len(data)} bytes to {filepath}")
