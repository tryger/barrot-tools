import argparse
from barrot import BR1001

def main():
    parser = argparse.ArgumentParser(description="BR1001 Flash Tool CLI",
                                     epilog="""
Example:
  Read entire flash:
    python br1001_cli.py -d /dev/ttyUSB0 read_flash flash_dump.bin

  Read bootloader region:
    python br1001_cli.py -d /dev/ttyUSB0 read_bootloader bootloader.bin

  Read SRAM:
    python br1001_cli.py -d /dev/ttyUSB0 read_sram sram_dump.bin

  Read custom memory:
    python br1001_cli.py -d /dev/ttyUSB0 read 0x20000000 0x1000 output.bin

  Erase entire flash memory:
    python br1001_cli.py -d /dev/ttyUSB0 erase_flash
""",
                formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-d", "--device", required=True, help="Device path (e.g., /dev/ttyUSB0 or COM3)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    # read_flash
    parser_read_flash = subparsers.add_parser("read_flash", help="Read entire flash to file")
    parser_read_flash.add_argument("filepath", help="Path to save the flash data")

    # read_bootloader
    parser_read_bl = subparsers.add_parser("read_bootloader", help="Read bootloader region to file")
    parser_read_bl.add_argument("filepath", help="Path to save the bootloader data")

    # read_sram
    parser_read_sram = subparsers.add_parser("read_sram", help="Read SRAM region to file")
    parser_read_sram.add_argument("filepath", help="Path to save the SRAM data")

    # read custom
    parser_read = subparsers.add_parser("read", help="Read custom address and size to file")
    parser_read.add_argument("addr", type=lambda x: int(x, 0), help="Start address (e.g., 0x20000000)")
    parser_read.add_argument("size", type=lambda x: int(x, 0), help="Size in bytes")
    parser_read.add_argument("filepath", help="Output file path")

    # erase_flash
    subparsers.add_parser("erase_flash", help="Erase the flash memory")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    br = BR1001(args.device, args.verbose)
    br.init()

    if args.command == "read_flash":
        br.read_flash(args.filepath)
    elif args.command == "read_bootloader":
        br.read_bootloader(args.filepath)
    elif args.command == "read_sram":
        br.read_sram(args.filepath)
    elif args.command == "read":
        br.read(args.addr, args.size, args.filepath)
    elif args.command == "erase_flash":
        br.erase_flash()

if __name__ == "__main__":
    main()
