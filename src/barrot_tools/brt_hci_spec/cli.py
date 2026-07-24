import argparse
import sys

from .brt_hci_spec import BrtHciSpec
from .pkt import BARROT_RESET_TYPE
from .hci_transport import HciError
from ..common import nvds


def _hexint(x: str) -> int:
    return int(x, 0)


def _hexbytes(s: str) -> bytes:
    cleaned = s.replace(":", "").replace(" ", "").replace(",", "").strip()
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    return bytes.fromhex(cleaned)


def _hexdump(b: bytes, group: int = 16) -> str:
    return "\n".join(b[i:i + group].hex(" ") for i in range(0, len(b), group))


def _parse_mac(s: str) -> bytes:
    """Parse "aa:bb:cc:dd:ee:ff" (or 12 hex digits) into 6-byte chip-LE order."""
    cleaned = s.replace(":", "").replace("-", "").replace(".", "").strip()
    if len(cleaned) != 12:
        raise ValueError(f"BD address must be 6 bytes; got {s!r}")
    return bytes(reversed(bytes.fromhex(cleaned)))


def _format_mac(bd_le: bytes) -> str:
    return ":".join(f"{b:02x}" for b in reversed(bd_le))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Barrot HCI VSC tool (BR8051, BR8551, ...)",
        epilog="""Examples:
  br-hci info
  br-hci bd_addr                       read the BD address
  br-hci bd_addr aa:bb:cc:dd:ee:ff     set the BD address (RAM only)
  br-hci rom_dump rom.bin
  br-hci flash_dump flash.bin
  br-hci config_dump
  br-hci bus_read 0x20000544 0x80 cmd_tab.bin
""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--verbose", action="store_true", help="Print raw HCI packets")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="Print chip version information")
    sub.add_parser("signature", help="Print the chip signature")
    sub.add_parser("patch_test", help="Run the chip patch-test routine")

    p = sub.add_parser("reset", help="Reset the chip")
    p.add_argument("type", nargs="?", default="hci",
                   choices=[t.name.lower() for t in BARROT_RESET_TYPE])

    p = sub.add_parser("bd_addr", help="Read the BD address, or set it (RAM only)")
    p.add_argument("mac", nargs="?", help="New MAC: aa:bb:cc:dd:ee:ff or 12 hex digits")

    p = sub.add_parser("uart_tl_param", help="Read UART transport-layer params (18 B), or write them")
    p.add_argument("data", nargs="?", help="18-byte hex blob to write")

    p = sub.add_parser("rf_freq_trim", help="Read RF crystal trim (6 B), or write it")
    p.add_argument("data", nargs="?", help="6-byte hex blob to write")

    p = sub.add_parser("rf_reg_read", help="Read an RF register (addr < 0x100)")
    p.add_argument("addr", type=_hexint)
    p = sub.add_parser("rf_reg_write", help="Write an RF register (32-bit value)")
    p.add_argument("addr", type=_hexint)
    p.add_argument("value", type=_hexint)

    p = sub.add_parser("param_read", help="Read a tag from the parameter store")
    p.add_argument("tag", type=_hexint)
    p.add_argument("length", type=_hexint)
    p = sub.add_parser("param_write", help="Write a non-streaming param tag")
    p.add_argument("tag", type=_hexint)
    p.add_argument("data", help="Hex bytes to write")

    p = sub.add_parser("patch_end", help="Toggle the patch-override flag")
    p.add_argument("enable", type=_hexint)

    p = sub.add_parser("bus_read", help="Read memory via BUS_READ (chunked)")
    p.add_argument("addr", type=_hexint)
    p.add_argument("size", type=_hexint)
    p.add_argument("filepath", nargs="?", help="Output file, else hex to stdout")
    p = sub.add_parser("bus_write", help="Write memory via BUS_WRITE")
    p.add_argument("addr", type=_hexint)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--hex", dest="hex_data", help="Hex bytes to write")
    g.add_argument("--file", dest="filepath", help="File to write")

    p = sub.add_parser("eeprom_read", help="Read EEPROM (chunked; may be unsupported)")
    p.add_argument("addr", type=_hexint)
    p.add_argument("size", type=_hexint)
    p.add_argument("filepath", nargs="?", help="Output file, else hex to stdout")
    p = sub.add_parser("eeprom_write", help="Write EEPROM (may be unsupported)")
    p.add_argument("addr", type=_hexint)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--hex", dest="hex_data", help="Hex bytes to write")
    g.add_argument("--file", dest="filepath", help="File to write")

    p = sub.add_parser("flash_dump", help="Dump the full flash (0x80000) to file")
    p.add_argument("filepath")
    p = sub.add_parser("rom_dump", help="Dump the 256 KB mask ROM (0x00000000) to file")
    p.add_argument("filepath")
    p = sub.add_parser("ram_dump", help="Dump the 128 KB SRAM (0x20000000) to file")
    p.add_argument("filepath")

    p = sub.add_parser("flash_read", help="Read a flash region to file")
    p.add_argument("addr", type=_hexint)
    p.add_argument("size", type=_hexint)
    p.add_argument("filepath")
    p = sub.add_parser("flash_write", help="Write a file to flash")
    p.add_argument("addr", type=_hexint)
    p.add_argument("filepath")
    p = sub.add_parser("flash_erase", help="Erase a flash region")
    p.add_argument("addr", type=_hexint)
    p.add_argument("length", type=_hexint)

    p = sub.add_parser("config_read", help="Read a single config tag")
    p.add_argument("--tag", type=_hexint, required=True)
    p.add_argument("filepath", nargs="?", help="Output file, else hex to stdout")
    p = sub.add_parser("config_dump", help="Read the NVDS partition and pretty-print it")
    p.add_argument("--addr", type=_hexint, default=0x7E000)
    p.add_argument("--size", type=_hexint, default=0x1000)
    p.add_argument("--save", help="Also write the raw NVDS bytes to this file")
    p.add_argument("--raw", action="store_true", help="Hexdump every tag")

    args = parser.parse_args()
    try:
        with BrtHciSpec(verbose=args.verbose) as chip:
            _dispatch(chip, args)
    except (HciError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def _dispatch(chip: BrtHciSpec, args) -> None:
    if args.command == "info":
        print(chip.chip_info())

    elif args.command == "signature":
        print(chip.signature_read().hex(" "))

    elif args.command == "patch_test":
        print(f"0x{chip.patch_test():04x}")

    elif args.command == "reset":
        chip.reset(BARROT_RESET_TYPE[args.type.upper()])
        print("Reset sent.")

    elif args.command == "bd_addr":
        if args.mac is None:
            print(_format_mac(chip.bd_addr_read()))
        else:
            bd_le = _parse_mac(args.mac)
            chip.bd_addr_write(bd_le)
            print(f"Wrote {_format_mac(bd_le)}; chip now reports {_format_mac(chip.bd_addr_read())}")

    elif args.command == "uart_tl_param":
        if args.data is None:
            print(chip.uart_tl_param_read().hex(" "))
        else:
            chip.uart_tl_param_write(_hexbytes(args.data))
            print(f"Read-back: {chip.uart_tl_param_read().hex(' ')}")

    elif args.command == "rf_freq_trim":
        if args.data is None:
            print(chip.rf_freq_trim_read().hex(" "))
        else:
            chip.rf_freq_trim_write(_hexbytes(args.data))
            print(f"Read-back: {chip.rf_freq_trim_read().hex(' ')}")

    elif args.command == "rf_reg_read":
        addr, value = chip.rf_reg_read(args.addr)
        print(f"0x{addr:08x} = 0x{value:08x}")
    elif args.command == "rf_reg_write":
        chip.rf_reg_write(args.addr, args.value)
        _, back = chip.rf_reg_read(args.addr)
        print(f"Wrote 0x{args.value:08x} to 0x{args.addr:08x}; read-back: 0x{back:08x}")

    elif args.command == "param_read":
        print(_hexdump(chip.param_read(args.tag, args.length)))
    elif args.command == "param_write":
        blob = _hexbytes(args.data)
        chip.param_write(args.tag, blob)
        print(f"Wrote tag 0x{args.tag:02x} ({len(blob)} bytes).")

    elif args.command == "patch_end":
        chip.patch_end(args.enable)
        print(f"patch_end(enable={args.enable}) sent.")

    elif args.command in ("bus_read", "eeprom_read"):
        dump = chip.bus_dump if args.command == "bus_read" else chip.eeprom_dump
        data = dump(args.addr, args.size)
        _write_or_print(data, args.filepath)

    elif args.command in ("bus_write", "eeprom_write"):
        blob = _hexbytes(args.hex_data) if args.hex_data is not None else open(args.filepath, "rb").read()
        if args.command == "bus_write":
            chip.bus_write_chunked(args.addr, blob)
        else:
            chip.eeprom_write(args.addr, blob)
        print(f"Wrote {len(blob)} bytes to 0x{args.addr:08x}.")

    elif args.command == "flash_dump":
        chip.flash_dump(0x00000000, 0x80000, args.filepath)
    elif args.command == "rom_dump":
        chip.rom_dump(args.filepath)
    elif args.command == "ram_dump":
        chip.ram_dump(args.filepath)

    elif args.command == "flash_read":
        _save(chip.flash_read(args.addr, args.size), args.filepath)
    elif args.command == "flash_write":
        chip.flash_write_file(args.addr, args.filepath)
    elif args.command == "flash_erase":
        chip.flash_erase(args.addr, args.length)
        print("Done.")

    elif args.command == "config_read":
        if args.tag == 0xff:
            raise ValueError("tag 0xFF triggers a buggy ROM path (NULL deref)")
        _write_or_print(chip.config_read(args.tag), args.filepath)

    elif args.command == "config_dump":
        data = chip.flash_read(args.addr, args.size)
        try:
            nvds.find_nvds(data)
        except ValueError:
            raise ValueError(f"no NVDS magic in 0x{args.size:x} bytes at 0x{args.addr:08x}")
        if args.save:
            _save(data, args.save)
        nvds.render(data, raw=args.raw)


def _write_or_print(data: bytes, filepath: str | None) -> None:
    if filepath:
        _save(data, filepath)
    else:
        print(_hexdump(data))


def _save(data: bytes, filepath: str) -> None:
    with open(filepath, "wb") as f:
        f.write(data)
    print(f"Saved {len(data)} bytes to {filepath}")


if __name__ == "__main__":
    sys.exit(main())
