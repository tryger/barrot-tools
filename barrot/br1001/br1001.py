from .br1001_com import BR1001_COM
from .br1001_cmd import *

READ_CHUNK_SIZE = 0xf0

class BR1001:
    def __init__(self, device, verbose=False):
        self.com = BR1001_COM(device, verbose)

    def init(self):
        self.com.init()
    
    def read(self, addr, size, filepath):
        a = addr
        with open(filepath, "wb") as file:
            print(f"Reading {size} bytes from address 0x{addr:08x} to file {filepath}")
            while a < (addr + size):
                if (a + READ_CHUNK_SIZE) <= (addr + size):
                    chunk_size = READ_CHUNK_SIZE
                else:
                    chunk_size = (addr+size-a)
                cmd = BR1001_CMD(BR1001_OPCODES.READ, addr=a, len=chunk_size)

                rsp = self.com.send_recv(cmd)

                file.write(rsp.args["data"])
                file.flush()

                a += chunk_size

                progress = ((a - addr) / size) * 100
                print(f"Progress: {progress:.2f}%", end="\r")
        print("\nDONE")


    def read_flash(self, filepath):
        self.read(0x00000000, 0x80000, filepath)
    
    def read_bootloader(self, filepath):
        self.read(0x08000000, 0x80000, filepath)
    
    def read_sram(self, filepath):
        self.read(0x20000000, 0x20000, filepath)
    
    def erase_flash(self):
        cmd = BR1001_CMD(BR1001_OPCODES.ERASE, addr=0x0, len=0x0)
        rsp = self.com.send_recv(cmd)

        err = rsp.args["result"]
        print(f"Erase Status = {err:08x}")
        return err
    
    def flash_sr_read(self):
        cmd = BR1001_CMD(BR1001_OPCODES.READ_FLASH_SR)
        rsp = self.com.send_recv(cmd)

        print(rsp.args)



