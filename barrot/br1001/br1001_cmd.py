from enum import IntEnum
import struct

'''
Opcode definitions
'''

class BR1001_OPCODES(IntEnum):
    ERASE = 0x00
    ID = 0x01
    READ = 0x02
    WRITE = 0x03
    _UNK0 = 0x05
    SPI_CFG = 0x06
    UNK1 = 0x08

    PART_UNK0 = 0x0B
    PART_UNK1 = 0x0C
    LOAD = 0x0D
    STORE = 0x0E

    _UNK2 = 0x10
    _UNK3 = 0x11
    _UNK4 = 0x12
    _UNK5 = 0x13

    READ_FLASH_SR = 0x91
    WRITE_FLASH_SR = 0x92
    _UNK6 = 0x93
    ERASE_SECTOR = 0x94
    FLASH_SPI_CMD = 0x95

'''
Command / Responses argument definition.

Following python's struct format.

Argument 'data' represents variable field length. Format is 's' and has to be the last argument.
'''

BR1001_COMMANDS = {
    BR1001_OPCODES.ERASE: {
        "cmd": {
            "addr": "I",
            "len": "I"
        },
        "rsp": {
            "result": "I"
        }
    },
    BR1001_OPCODES.READ: {
        "cmd": {
            "addr": "I",
            "len": "I"
        },
        "rsp": {
            "len": "I",
            "data": "s"
        }
    },
    BR1001_OPCODES.WRITE: {
        "cmd": {
            "addr": "I",
            "len": "I",
            "data": "s"
        },
        "rsp": {
            "len": "I"
        }
    },
    BR1001_OPCODES.PART_UNK0: {
        "cmd": {
            "part": "B"
        },
        "rsp": {
            "result": "I"
        }
    },
    BR1001_OPCODES.PART_UNK1: {
        "cmd": {
            "part": "B",
            "addr": "I",
            "size": "I"
        },
        "rsp": {
            "addr": "I"
        }
    },
    BR1001_OPCODES.LOAD: {
        "cmd": {
            "type": "B",
            "addr": "I"
        },
        "rsp": {
            "value": "I"
        }
    },
    BR1001_OPCODES.STORE: {
        "cmd": {
            "type": "B",
            "addr": "I",
            "value": "I"
        },
        "rsp": {}
    },

    BR1001_OPCODES.READ_FLASH_SR: {
        "cmd": {},
        "rsp": {
            "sr": "H"
        }
    }
}

'''
BR1001_CMD

Represents either a command or a response.
Args are passed in constructor in the form of kwargs.
Parse full raw arguments bytes calling response() classmethod

Example:
cmd = BR1001_CMD(BR1001_OPCODES.WRITE, addr=0x08000000, len=0x4, data=b"\xde\xad\xbe\xef")

...

rsp = BR1001_CMD.response(BR1001_OPCODES.WRITE, b"\x00\x00\x00\x04\xba\xdc\x0d\xee")
'''
class BR1001_CMD:
    def __init__(self, opcode: BR1001_OPCODES, _raw_args=None, **kwargs):
        if opcode not in BR1001_COMMANDS:
            raise ValueError(f"Unknown opcode: {opcode:#x}")

        self.opcode = opcode
        if _raw_args == None:
            self.is_response = False
            self.cmd_def = BR1001_COMMANDS[opcode]["cmd"]
            self.raw_args = self._encode_args(kwargs)
            self.args = kwargs
        else:
            self.is_response = True
            self.cmd_def = BR1001_COMMANDS[opcode]["rsp"]
            self.args = self._parse_args(_raw_args)

    def _encode_args(self, kwargs):
        fmt = ">" + "".join(self.cmd_def.values())
        keys = list(self.cmd_def.keys())
        values = [kwargs.get(k) for k in keys]

        if None in values:
            missing = keys[values.index(None)]
            raise ValueError(f"Missing input argument: {missing}")

        if 'data' in kwargs:
            data = kwargs['data']
            if isinstance(data, bytes):
                return struct.pack(fmt, *values) + data
            else:
                raise ValueError("Data must be a byte-like object.")
        
        return struct.pack(fmt, *values)

    def _parse_args(self, args):
        out_meta = self.cmd_def
        if not out_meta:
            return {}

        fmt = ">" + "".join(out_meta.values())
        keys = list(out_meta.keys())

        fixed_len = struct.calcsize(fmt)
        fixed = args[:fixed_len]
        unpacked = struct.unpack(fmt, fixed)

        result = dict(zip(keys, unpacked))

        if 'data' in keys:
            result['data'] = args[fixed_len-1:]

        return result

    @classmethod
    def response(cls, opcode, raw_args):
        if opcode != opcode:
            raise ValueError(f"Unexpected opcode in response: 0x{opcode:#x}")
        
        return cls(opcode, _raw_args=raw_args)
    
    def __repr__(self):
        mode = "Response" if self.is_response else "Command"
        return f"<BR1001_CMD {mode} opcode=0x{self.opcode:02X} args={self.args}>"