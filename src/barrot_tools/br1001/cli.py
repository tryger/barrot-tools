import argparse
import sys

from .br1001 import BR1001, CFG_PARTITION
from .pkt import BR1001_Rsp_Id
from . import cfg


def _hexint(x: str) -> int:
    return int(x, 0)


def _payload(arg: str, from_file: bool) -> bytes:
    """A file path (--file) or an inline hex string."""
    if from_file:
        with open(arg, "rb") as f:
            return f.read()
    return bytes.fromhex(arg.replace(" ", ""))


def main() -> int:
    parser = argparse.ArgumentParser(description="BR1001 ROM bootloader tool (UART)")
    parser.add_argument("-d", "--device", required=True, help="Serial device, e.g. /dev/ttyUSB0")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print raw UART frames")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="Probe flash: magic, JEDEC id, security registers")
    sub.add_parser("partitions", help="List flash partitions (addr/length)")
    sub.add_parser("flash_erase", help="Erase the whole flash")

    p = sub.add_parser("flash_dump", help="Dump the full flash to file")
    p.add_argument("filepath")
    p = sub.add_parser("bootloader_dump", help="Dump the bootrom region to file")
    p.add_argument("filepath")
    p = sub.add_parser("sram_dump", help="Dump SRAM to file")
    p.add_argument("filepath")

    p = sub.add_parser("mem_read", help="Read addr..addr+size to file")
    p.add_argument("addr", type=_hexint)
    p.add_argument("size", type=_hexint)
    p.add_argument("filepath")

    p = sub.add_parser("mem_write", help="Write hex bytes (or a --file) to addr")
    p.add_argument("addr", type=_hexint)
    p.add_argument("data", help="Hex bytes (e.g. deadbeef), or a path with --file")
    p.add_argument("--file", action="store_true", help="Treat data as a file path")

    p = sub.add_parser("partition_dump", help="Dump a partition to file")
    p.add_argument("part", type=_hexint)
    p.add_argument("filepath")

    p = sub.add_parser("cfg", help="Dump the ROM cfg store (partition 0x62)")
    p.add_argument("--part", type=_hexint, default=CFG_PARTITION)

    args = parser.parse_args()

    br = None
    try:
        br = BR1001(args.device, args.verbose)
        br.init()
        _dispatch(br, args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    finally:
        if br is not None:
            try:
                br.close()
            except Exception:
                pass
    return 0


def _dispatch(br: BR1001, args) -> None:
    if args.command == "info":
        rsp = br.chip_id()
        manuf = (rsp.jedec_id >> 16) & 0xff
        device = rsp.jedec_id & 0xffff
        print(f"  magic:    0x{rsp.magic:08x}")
        print(f"  JEDEC id: 0x{rsp.jedec_id:06x} (manufacturer 0x{manuf:02x}, device 0x{device:04x})")
        print(f"  sec_reg:  {rsp.sec_reg.hex(' ')}")

    elif args.command == "partitions":
        parts = br.partitions()
        if not parts:
            print("No partitions present")
        for part, (addr, length) in parts.items():
            print(f"  part 0x{part:02x}: addr=0x{addr:08x} length=0x{length:x} ({length} bytes)")

    elif args.command == "flash_erase":
        br.flash_erase()

    elif args.command == "flash_dump":
        br.flash_dump(args.filepath)
    elif args.command == "bootloader_dump":
        br.bootloader_dump(args.filepath)
    elif args.command == "sram_dump":
        br.sram_dump(args.filepath)

    elif args.command == "mem_read":
        br.mem_dump(args.addr, args.size, args.filepath)
    elif args.command == "mem_write":
        br.mem_write(args.addr, _payload(args.data, args.file))

    elif args.command == "partition_dump":
        br.partition_dump(args.part, args.filepath)

    elif args.command == "cfg":
        cfg.render(br.partition_read(args.part))


if __name__ == "__main__":
    sys.exit(main())
