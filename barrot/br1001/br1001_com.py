from .br1001_cmd import *

import serial
import time

def bytes_str(raw):
    return " ".join(f"{b:02x}" for b in raw)

'''
This class manages the communication of commands and response.
It does the encoding and decoding of packets.
'''

BAUDRATE = 115200

class BR1001_COM:
    def __init__(self, device, verbose=False):
        self.serial = serial.Serial(device, BAUDRATE, timeout=2)
        self.verbose = verbose
        
        # Fixed sequence 0x50 works for all packets, by the moment
        self.seq = 0x50

    def _encode_byte(self, b):
        '''
        Encode byte to send
        '''
        ret = bytes([b])
        if b == 0x10:
            ret += b"\x10"

        self.checksum = self.checksum ^ b
        return ret

    def _encode_cmd(self, cmd: BR1001_CMD):
        '''
        Encode BR1001_CMD to send 
        '''
        data = b"\x10\x02"

        self.checksum = 0

        data += self._encode_byte(self.seq)
        data += self._encode_byte((len(cmd.raw_args)+1) & 0xff)
        data += self._encode_byte(cmd.opcode)

        args = cmd.raw_args

        for b in args:
            self.checksum = self.checksum ^ b

        data += args.replace(b"\x10", b"\x10\x10")

        data += b"\x10\x03"

        data += self._encode_byte(self.checksum)

        return data

    def _recv_byte(self):
        '''
        Receive single byte
        '''
        b = self.serial.read(1)
        b = int.from_bytes(b)
        if b == 0x10:
            self.serial.read(1)
        self.checksum = self.checksum ^ b
        return b

    def _recv_args(self):
        '''
        Receive arguments for command until postamble (0x10 0x03) is found
        '''
        args = b""
        while True:
            b = self.serial.read(1)
            if b is None:
                raise Exception("End of packet unexpected")
            if b == b"\x10":
                b2 = self.serial.read(1)
                if b2 == b"\x03": # postamble found
                    return args
            
            self.checksum = self.checksum ^ int.from_bytes(b)
            args += b


    #
    # PUBLIC
    #
    def init(self):
        '''
        Enable bootloader UART interface
        '''
        self.serial.write(b"\xdb\xde")

        print("BR1001: UART interface enabled")
        time.sleep(0.5)

    def send_raw(self, data):
        '''
        Send raw data over serial interface
        '''
        self.serial.write(data)

        if self.verbose:
            print(f"TX: {bytes_str(data)}")

    def send(self, cmd: BR1001_CMD):
        '''
        Encode and send a command
        '''
        pkt = self._encode_cmd(cmd)

        self.send_raw(pkt)

    def recv(self):
        '''
        Receive packet
        '''
        raw = self.serial.read(2)
        if raw != b"\x10\x02":
            raise Exception("Error receiving packet. Preamble Missmatch")
        
        self.checksum = 0

        seq = self._recv_byte()
        raw += bytes([seq])
        length = self._recv_byte()
        raw += bytes([length])
        opcode = self._recv_byte()
        raw += bytes([opcode])
        args = self._recv_args()
        raw += args
        checksum = self._recv_byte()
        raw += bytes([checksum])
        
        # _recv_byte() updates checksum, so if checksums matches, self.checksum == 0
        if self.checksum != 0:
            raise Exception("Error receiving packet. Checksum Missmatch")
        
        if self.verbose:
            print(f"RX: {bytes_str(raw)}")

        rsp = BR1001_CMD.response(opcode, args)

        return rsp

    def send_recv(self, cmd: BR1001_CMD):
        self.send(cmd)
        return self.recv()