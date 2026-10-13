#!/usr/bin/env python3
"""Read-only BR8051A02 preflight. Requires pyusb and Homebrew libusb.
No reset, RAM write, patch upload, erase, or flash write is implemented.
Usage: python3 barrot_preflight.py --out preflight.json
"""
import argparse
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
import usb.core
import usb.util
import usb.backend.libusb1

SAFE_READS = {
    'firmware_gates': (0x200001C4, 16),
    'hal_table': (0x20000358, 76),
    'xip_state': (0x20000400, 4),
    'vsc_handlers': (0x20000544, 112),
    'patch_control': (0x2000053C, 8),
    'allocator_control': (0x20001A28, 48),
    'candidate_slot': (0x2000E900, 192),
    'spi_base': (0x2000BFFC, 4),
    'patch_prefix': (0x2000C000, 128),
    'system_xip_select': (0x90000010, 4),
    'system_xip_control': (0x90000020, 4),
}

def command(dev, ep, cid, payload=b'', trace=None):
    if cid not in (1, 3, 15):
        raise ValueError('Only identity, signature and BUS_READ are implemented')
    params = struct.pack('<H', cid) + payload
    if trace: trace('control_transfer_started', cid)
    dev.ctrl_transfer(0x20, 0, 0, 0, struct.pack('<HB', 0xFC80, len(params)) + params, timeout=1500)
    if trace: trace('control_transfer_completed', cid)
    pending = bytearray()
    for _ in range(32):
        if trace: trace('interrupt_response_wait', cid)
        pending.extend(dev.read(ep, 255, timeout=2000))
        if trace: trace('interrupt_data_received', cid)
        while len(pending) >= 2 and len(pending) >= 2 + pending[1]:
            event, length = pending[:2]
            body = bytes(pending[2:2+length])
            del pending[:2+length]
            if event == 14 and len(body) >= 6 and struct.unpack_from('<H', body, 1)[0] == 0xFC80:
                if struct.unpack_from('<H', body, 4)[0] != cid:
                    raise RuntimeError('Unexpected echoed subcommand; stop rather than mix responses')
                if body[3]:
                    raise RuntimeError(f'VSC status {body[3]:#x}')
                return body[6:]
    raise RuntimeError('No matching Command Complete')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error('Output exists; choose a new path to preserve earlier evidence')
    report = {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'reads': {},
              'flash_status_captured': False, 'device_mutations': [], 'transport_trace': []}
    def trace(stage, cid):
        report['transport_trace'].append({'stage': stage, 'subcommand': f'{cid:#04x}'})
    def read_command(dev, ep, cid, payload=b''):
        return command(dev, ep, cid, payload, trace=trace)
    dev = None
    claimed = False
    try:
        backend = usb.backend.libusb1.get_backend()
        if backend is None and Path('/opt/homebrew/lib/libusb-1.0.dylib').exists():
            backend = usb.backend.libusb1.get_backend(find_library=lambda _: '/opt/homebrew/lib/libusb-1.0.dylib')
        if backend is None:
            raise RuntimeError('libusb backend unavailable')
        devices = list(usb.core.find(find_all=True, backend=backend))
        report['visible_usb_ids'] = [f'{d.idVendor:04x}:{d.idProduct:04x}' for d in devices]
        matches = [d for d in devices if d.idVendor == 0x33FA and d.idProduct == 0x0012]
        if len(matches) != 1:
            raise RuntimeError(f'Expected one 33fa:0012 dongle; found {len(matches)}')
        dev = matches[0]
        # Inspect the existing configuration; do not reset or set_configuration.
        cfg = dev.get_active_configuration()
        intf = cfg[(0, 0)]
        ep = usb.util.find_descriptor(intf, custom_match=lambda e: (e.bEndpointAddress & 0x80) and (e.bmAttributes & 3) == 3)
        if ep is None:
            raise RuntimeError('Interrupt IN endpoint not found')
        usb.util.claim_interface(dev, 0)
        claimed = True
        info = read_command(dev, ep.bEndpointAddress, 1)
        report['identity_hex'] = info.hex()
        if len(info) < 26 or struct.unpack_from('<I', info, 4)[0] != 0x08051A02:
            raise RuntimeError('Unexpected chip identity')
        report['reported_flash_id'] = f'{struct.unpack_from("<H", info, 24)[0]:04x}'
        report['signature_hex'] = read_command(dev, ep.bEndpointAddress, 3).hex()
        for name, (address, length) in SAFE_READS.items():
            data = read_command(dev, ep.bEndpointAddress, 15, struct.pack('<IB', address, length))
            if len(data) != length:
                raise RuntimeError(f'Short read: {name}')
            report['reads'][name] = {'address': f'{address:#010x}', 'hex': data.hex(),
                                    'words_le': [f'{w:#010x}' for w in struct.unpack('<'+'I'*(length//4), data)]}
        report['ok'] = True
    except Exception as exc:
        report['ok'] = False
        report['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        if dev is not None:
            if claimed:
                try:
                    usb.util.release_interface(dev, 0)
                except usb.core.USBError:
                    pass
            usb.util.dispose_resources(dev)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report.get('ok') else 1

if __name__ == '__main__':
    raise SystemExit(main())
