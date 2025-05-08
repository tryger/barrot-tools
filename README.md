# Barrot Tools

This repository contains tooling for interacting with Barrot chips via their built-in bootloader. All supported commands have been documented through reverse engineering the bootloader firmware.

## Barrot Bootloader
Barrot chips include a bootloader in ROM that can be accessed via a UART interface. The bootloader allows communication with a command interface that enables full access to internal flash and full memory.

The bootloader also opens a BLE interface for firmware update with name HS_OTA. This is pending to reverse engineer but seems to be using some code from Nordic SDK.

## Dumping memory
Currently, only reading flash and memory from BR1001 chip is implemented. This is done with `br1001_cli.py`.

### Entering Bootloader Mode

- Power up the chip keeping BOOT pin pulled down to GND
- Connect to UART pins RX/TX at baudrate 115200

![BOOT to GND](doc/img/boot.png)

### Examples
Dump internal flash

`br1001_cli.py -d /dev/ttyUSB0 read_flash flash.bin`

Dump bootloader

`br1001_cli.py -d /dev/ttyUSB0 read_bootloader bootloader.bin`

Dump memory region memory

`python br1001_cli.py -d /dev/ttyUSB0 read 0x40000000 0x10000 out.bin`

# TODO
- Add support for BR8051. Documentation of interface and commands in doc section
- Document and implement more commands
- Reverse engineer interaction via BLE interface


# Contributing
Pull requests and issues are welcome!