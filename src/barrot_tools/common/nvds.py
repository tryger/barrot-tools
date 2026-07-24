"""
NVDS (Non-Volatile Data Store) parser for Barrot config / param dumps.

Layout:

    Header  : "NVDS" (4 bytes)
    Entry[] : [tag_id (1B)] [status (1B)] [length (1B)] [data (length B)]
    End     : 0xFF padding (erased flash)
"""

import struct
import sys
from dataclasses import dataclass


# ----------------------------------------------------------------------
# Tag table
# ----------------------------------------------------------------------

# (tag_id, name, expected_len_or_None)
_TAGS: list[tuple[int, str, int | None]] = [
    (0x02, "DEVICE_NAME",            248),
    (0x03, "IN_OTA_MODE",            1),
    (0x04, "OTA_NOT_COMPLETE",       1),
    (0x07, "LPCLK_DRIFT",            2),
    (0x08, "LPCLK_JITTER",           1),
    (0x0D, "EXT_WAKEUP_TIME",        2),
    (0x0E, "OSC_WAKEUP_TIME",        2),
    (0x0F, "RM_WAKEUP_TIME",         2),
    (0x10, "UART_CONFIG",            4),
    (0x11, "SLEEP_ENABLE",           1),
    (0x12, "EXT_WAKEUP_ENABLE",      1),
    (0x13, "SP_PRIVATE_KEY_P192",    24),
    (0x14, "SP_PUBLIC_KEY_P192",     48),
    (0x15, "ACTIVITY_MOVE_CONFIG",   1),
    (0x16, "SCAN_EXT_ADV",           1),
    (0x17, "SCHED_SCAN_DUR",         2),
    (0x2C, "SYNC_CONFIG",            2),
    (0x2D, "PCM_SETTINGS",           8),
    (0x2E, "SLEEP_ALGO_DUR",         None),
    (0x2F, "TRACER_CONFIG",          4),
    (0x30, "DIAG_BT_HW",             4),
    (0x31, "DIAG_BLE_HW",            4),
    (0x32, "DIAG_SW",                4),
    (0x33, "DIAG_DM_HW",             4),
    (0x34, "DIAG_PLF",               4),
    (0x37, "IDCSEL_PLF",             4),
    (0x3A, "RSSI_HIGH_THR",          1),
    (0x3B, "RSSI_LOW_THR",           1),
    (0x3C, "RSSI_INTERF_THR",        1),
    (0x3E, "RF_BTIPT_VERSION",       1),
    (0x3F, "RF_BTIPT_XO_SETTING",    1),
    (0x80, "LE_PRIVATE_KEY_P256",    32),
    (0x81, "LE_PUBLIC_KEY_P256",     64),
    (0x82, "LE_DBG_FIXED_P256_KEY",  1),
    (0x83, "SP_PRIVATE_KEY_P256",    32),
    (0x84, "SP_PUBLIC_KEY_P256",     64),
    (0x85, "LE_CODED_PHY_500",       1),
    (0x86, "PRIORITY_INFO",          58),
    (0x87, "BTBLECORE_VERSION",      1),
    (0x88, "COMPANY_ID",             2),
    (0x89, "RF_PARAM",               None),
    (0x8A, "BB_PARAM",               None),
    (0x90, "CONFIG_SYS",             None),
    (0x91, "CONFIG_GPIO",            None),
    (0x92, "CONFIG_RF",              None),
    (0x93, "CONFIG_LMLL",            None),  # contains BT address
    (0x94, "CONFIG_TL",              None),
    (0x95, "CONFIG_HOST",            None),
    (0x96, "CONFIG_CR",              None),
]

_TAG_BY_ID: dict[int, tuple[str, int | None]] = {
    tid: (name, expected) for tid, name, expected in _TAGS
}


def tag_name(tag_id: int) -> str:
    if tag_id in _TAG_BY_ID:
        return _TAG_BY_ID[tag_id][0]
    if 0x60 <= tag_id <= 0x67:
        return f"BT_LINK_KEY_{tag_id - 0x60}"
    if 0x70 <= tag_id <= 0x7F:
        return f"BLE_LINK_KEY_{tag_id - 0x70}"
    if 0xA0 <= tag_id <= 0xBF:
        return f"APP_SPECIFIC_{tag_id - 0xA0:02X}"
    return "UNKNOWN"


# ----------------------------------------------------------------------
# Pretty-printers for known tags
# ----------------------------------------------------------------------

def _fmt_bd_addr(data: bytes) -> str:
    """LMLL config carries the 6-byte BT address LSB-first."""
    if len(data) < 6:
        return ""
    addr = data[:6][::-1]
    return ":".join(f"{b:02X}" for b in addr)


def _fmt_string(data: bytes) -> str:
    s = data.split(b"\x00", 1)[0]
    try:
        return s.decode("utf-8")
    except UnicodeDecodeError:
        return s.decode("latin-1", errors="replace")


def _fmt_uint(data: bytes) -> str:
    if len(data) == 1:
        return f"{data[0]} (0x{data[0]:02x})"
    if len(data) == 2:
        v = struct.unpack("<H", data)[0]
        return f"{v} (0x{v:04x})"
    if len(data) == 4:
        v = struct.unpack("<I", data)[0]
        return f"{v} (0x{v:08x})"
    return ""


PRETTY = {
    0x02: ("device name", _fmt_string),
    0x88: ("company id",  _fmt_uint),
    0x93: ("BT address",  _fmt_bd_addr),
}


# ----------------------------------------------------------------------
# Parser
# ----------------------------------------------------------------------

@dataclass
class Tag:
    offset: int
    tag_id: int
    status: int
    length: int
    data: bytes

    @property
    def name(self) -> str:
        return tag_name(self.tag_id)


def find_nvds(buf: bytes) -> int:
    """Return offset of "NVDS" magic, or raise ValueError."""
    idx = buf.find(b"NVDS")
    if idx < 0:
        raise ValueError("NVDS header not found")
    return idx


def parse_nvds(buf: bytes) -> list[Tag]:
    """Walk the NVDS tag stream starting at the first "NVDS" magic."""
    start = find_nvds(buf) + 4
    tags: list[Tag] = []
    i = start
    while i + 3 <= len(buf):
        tag_id = buf[i]
        status = buf[i + 1]
        length = buf[i + 2]
        if tag_id == 0xFF:
            break  # erased flash
        if i + 3 + length > len(buf):
            break  # truncated
        data = bytes(buf[i + 3 : i + 3 + length])
        tags.append(Tag(offset=i, tag_id=tag_id, status=status, length=length, data=data))
        i += 3 + length
    return tags


def hexdump(data: bytes, indent: str = "    ", width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{off:04x}  {hexs:<{width*3}}  {ascii_}")
    return "\n".join(lines)


def render(buf: bytes, raw: bool = False, out=sys.stdout) -> None:
    """Parse `buf` and print a human-readable report to `out`."""
    nvds_off = find_nvds(buf)
    tags = parse_nvds(buf)
    print(f"NVDS header at offset 0x{nvds_off:04x}, {len(tags)} tags", file=out)
    print(file=out)

    for t in tags:
        flag_str = "OK" if t.status == 0 else f"status=0x{t.status:02x}"
        header = (f"@0x{t.offset:04x}  tag=0x{t.tag_id:02x} "
                  f"({t.name})  len={t.length}  {flag_str}")
        print(header, file=out)

        pretty = PRETTY.get(t.tag_id)
        if pretty and not raw:
            label, fn = pretty
            print(f"    {label}: {fn(t.data)}", file=out)
        else:
            print(hexdump(t.data), file=out)
        print(file=out)
