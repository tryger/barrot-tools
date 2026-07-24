import time

import serial
from scapy.packet import Packet

from .pkt import BR1001_Cmd, BR1001_Rsp


BAUDRATE = 115200


class BR1001Error(Exception):
    pass


class BR1001Transport:
    """
    Serial transport for the BR1001 ROM bootloader.

    Wire frame::

        0x10 0x02  seq  len  opcode  <escaped args>  0x10 0x03  checksum

    Raw 0x10 bytes in the args are doubled (escaped). The checksum is an XOR
    over seq, len, opcode and the unescaped args.
    """

    def __init__(self, device: str, baudrate: int = BAUDRATE,
                 verbose: bool = False) -> None:
        self.serial = serial.Serial(device, baudrate, timeout=2)
        self.verbose = verbose
        self.seq = 0x50
        self.checksum = 0

    def close(self) -> None:
        self.serial.close()

    def init(self) -> None:
        """Send the bootloader-enable handshake (0xdb 0xde)."""
        self.serial.write(b"\xdb\xde")
        if self.verbose:
            print("BR1001: UART interface enabled")
        time.sleep(0.5)

    def sr1(self, pkt: Packet) -> Packet:
        self._send(pkt)
        return self._recv()

    def _encode_byte(self, b: int) -> bytes:
        out = bytes([b])
        if b == 0x10:
            out += b"\x10"
        self.checksum ^= b
        return out

    def _send(self, pkt: Packet) -> None:
        opcode = int(pkt[BR1001_Cmd].opcode)
        args = bytes(pkt[BR1001_Cmd].payload)

        self.checksum = 0
        out = b"\x10\x02"
        out += self._encode_byte(self.seq)
        out += self._encode_byte((len(args) + 1) & 0xff)
        out += self._encode_byte(opcode)
        for b in args:
            self.checksum ^= b
        out += args.replace(b"\x10", b"\x10\x10")
        out += b"\x10\x03"
        out += self._encode_byte(self.checksum)

        if self.verbose:
            print(f"TX: {out.hex(' ')}")
        self.serial.write(out)

    def _recv_byte(self) -> int:
        bv = int.from_bytes(self.serial.read(1))
        if bv == 0x10:
            self.serial.read(1)
        self.checksum ^= bv
        return bv

    def _recv_args(self) -> bytes:
        args = b""
        while True:
            b = self.serial.read(1)
            if not b:
                raise BR1001Error("Unexpected end of packet")
            if b == b"\x10":
                b2 = self.serial.read(1)
                if b2 == b"\x03":
                    return args
            self.checksum ^= int.from_bytes(b)
            args += b

    def _recv(self) -> Packet:
        raw = self.serial.read(2)
        if raw != b"\x10\x02":
            raise BR1001Error(f"Preamble mismatch: {raw.hex()}")

        self.checksum = 0
        seq = self._recv_byte()
        length = self._recv_byte()
        opcode = self._recv_byte()
        args = self._recv_args()
        chk = self._recv_byte()

        if self.checksum != 0:
            raise BR1001Error("Checksum mismatch")

        if self.verbose:
            dump = b"\x10\x02" + bytes([seq, length, opcode]) + args + bytes([chk])
            print(f"RX: {dump.hex(' ')}")

        return BR1001_Rsp(bytes([opcode]) + args)
