from scapy.packet import Packet

from . import cfg
from .pkt import (
    BR1001_OPCODES,
    BR1001_Cmd, BR1001_Cmd_Id, BR1001_Cmd_Read, BR1001_Cmd_Write,
    BR1001_Cmd_Erase, BR1001_Cmd_Read_Flash_SR, BR1001_Cmd_Part_Read,
    BR1001_Rsp_Id, BR1001_Rsp_Read, BR1001_Rsp_Erase,
    BR1001_Rsp_Read_Flash_SR, BR1001_Rsp_Part_Read,
)
from .br1001_transport import BR1001Transport
from ..common import nvds
from ..common.chunked import read_chunked, write_chunked


READ_CHUNK_SIZE = 0xf0
# WRITE args are addr(4) + len(4) + data and the frame length is one byte,
# so keep the data chunk well under 0xff - 9.
WRITE_CHUNK_SIZE = 0xf0

# On-chip regions reachable through READ (addr >= 0x08000000 = direct memory).
FLASH_BASE = 0x00000000
FLASH_SIZE = 0x80000        # 512 KB SPI flash
BOOTROM_BASE = 0x08000000
BOOTROM_SIZE = 0x80000
SRAM_BASE = 0x20000000
SRAM_SIZE = 0x20000         # 128 KB SRAM

# The ROM `cfg` store (HSE/TLV wear-leveled config) lives in this partition.
CFG_PARTITION = 0x62

# Partition ids accepted by PART_READ (0x0B): 0..7 and 0x60..0x67.
PART_IDS = tuple(range(0, 8)) + tuple(range(0x60, 0x68))


class BR1001:
    """
    Driver for the BR1001 ROM bootloader over UART.

    Call ``init()`` after construction to send the UART enable handshake.
    """

    def __init__(self, device: str, verbose: bool = False,
                 *, transport: BR1001Transport | None = None) -> None:
        if transport is None:
            transport = BR1001Transport(device, verbose=verbose)
        self.transport = transport

    def close(self) -> None:
        self.transport.close()

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def init(self) -> None:
        self.transport.init()

    def sr1(self, pkt: Packet) -> Packet:
        """Send one command packet and return its parsed response."""
        return self.transport.sr1(pkt)

    # --- raw commands (return the parsed response packet) ---

    def _read(self, addr: int, length: int) -> Packet:
        pkt = BR1001_Cmd(opcode=BR1001_OPCODES.READ) / BR1001_Cmd_Read(addr=addr, len=length)
        return self.sr1(pkt)

    def _write(self, addr: int, data: bytes) -> Packet:
        pkt = BR1001_Cmd(opcode=BR1001_OPCODES.WRITE) / BR1001_Cmd_Write(addr=addr, data=bytes(data))
        return self.sr1(pkt)

    def chip_id(self, cs: int = 0, spi_freq: int = 0, granularity: int = 0) -> Packet:
        """Probe the flash: returns the ID response (magic, JEDEC id, sec regs)."""
        pkt = BR1001_Cmd(opcode=BR1001_OPCODES.ID) / BR1001_Cmd_Id(
            cs=cs, spi_freq=spi_freq, granularity=granularity)
        return self.sr1(pkt)[BR1001_Rsp_Id]

    def flash_sr(self) -> int:
        """Read the flash status register value."""
        pkt = BR1001_Cmd(opcode=BR1001_OPCODES.READ_FLASH_SR) / BR1001_Cmd_Read_Flash_SR()
        return self.sr1(pkt)[BR1001_Rsp_Read_Flash_SR].sr

    def flash_erase(self) -> int:
        """Erase all flash. Returns the result code."""
        pkt = BR1001_Cmd(opcode=BR1001_OPCODES.ERASE) / BR1001_Cmd_Erase(addr=0, len=0)
        err = self.sr1(pkt)[BR1001_Rsp_Erase].result
        print(f"Erase status = 0x{err:08x}")
        return err

    # --- partitions ---

    def partition(self, part: int) -> tuple[int, int] | None:
        """Return ``(addr, length)`` of partition `part`, or None if absent."""
        pkt = BR1001_Cmd(opcode=BR1001_OPCODES.PART_READ) / BR1001_Cmd_Part_Read(part=part)
        rsp = self.sr1(pkt)[BR1001_Rsp_Part_Read]
        if rsp.addr == 0xffffffff or rsp.length == 0:
            return None
        return rsp.addr, rsp.length

    def partitions(self) -> dict[int, tuple[int, int]]:
        """Enumerate every present partition as ``{part: (addr, length)}``."""
        return {p: ext for p in PART_IDS if (ext := self.partition(p)) is not None}

    def partition_read(self, part: int) -> bytes:
        """Read the full contents of partition `part`."""
        ext = self.partition(part)
        if ext is None:
            raise ValueError(f"partition 0x{part:02x} not present")
        addr, length = ext
        return read_chunked(self._read, BR1001_Rsp_Read, addr, length, READ_CHUNK_SIZE)

    def partition_dump(self, part: int, filepath: str) -> tuple[int, int]:
        """Read partition `part` to `filepath`. Returns ``(addr, length)``."""
        ext = self.partition(part)
        if ext is None:
            raise ValueError(f"partition 0x{part:02x} not present")
        addr, length = ext
        print(f"Reading partition 0x{part:02x}: {length} bytes @ 0x{addr:08x} to {filepath}")
        data = read_chunked(self._read, BR1001_Rsp_Read, addr, length, READ_CHUNK_SIZE)
        with open(filepath, "wb") as f:
            f.write(data)
        return addr, length

    def cfg_read(self, part: int = CFG_PARTITION) -> list[cfg.CfgEntry]:
        """Read the ROM cfg store partition and parse its TLV entries."""
        return cfg.parse_cfg(self.partition_read(part))

    def cfg_current(self, part: int = CFG_PARTITION) -> dict[int, bytes]:
        """Return the current ``{key_id: value}`` config from the cfg store."""
        return cfg.current_config(self.partition_read(part))

    def partition_nvds(self, part: int) -> list[nvds.Tag]:
        """Read partition `part` and parse it as an NVDS tag store.

        BR1001 partitions hold firmware/patch code rather than NVDS, so this
        raises ValueError when no ``NVDS`` magic is present. Provided for
        partitions that do use the shared NVDS format (see barrot_tools.common.nvds).
        """
        return nvds.parse_nvds(self.partition_read(part))

    # --- bulk memory ---

    def mem_dump(self, addr: int, size: int, filepath: str) -> None:
        """Read `size` bytes from `addr` and save to file."""
        print(f"Reading {size} bytes from 0x{addr:08x} to {filepath}")
        data = read_chunked(self._read, BR1001_Rsp_Read, addr, size, READ_CHUNK_SIZE)
        with open(filepath, "wb") as f:
            f.write(data)

    def mem_write(self, addr: int, data: bytes) -> None:
        """Write `data` at `addr` (chunked, with progress).

        addr < 0x08000000 targets SPI flash (destructive); at/above it is a
        direct memory copy (e.g. 0x20000000 = SRAM).
        """
        print(f"Writing {len(data)} bytes to 0x{addr:08x}")
        write_chunked(self._write, addr, bytes(data), WRITE_CHUNK_SIZE)

    def flash_dump(self, filepath: str) -> None:
        self.mem_dump(FLASH_BASE, FLASH_SIZE, filepath)

    def bootloader_dump(self, filepath: str) -> None:
        self.mem_dump(BOOTROM_BASE, BOOTROM_SIZE, filepath)

    def sram_dump(self, filepath: str) -> None:
        self.mem_dump(SRAM_BASE, SRAM_SIZE, filepath)
