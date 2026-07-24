"""
Parser for the BR1001 ROM ``cfg`` store (partition id 0x62).

Reverse engineered from the bootrom `cfg_manage_mount` / `cfg_manage_update_section_info`
(``..\\hardware\\cfg\\cfg_manage.c``). The partition is a wear-leveled,
append-only TLV log split into N equal, sector-aligned sections
(N = 2 if the partition is smaller than 0x3000, else 3). Each section is
independent redundancy; a mount needs at least two sections carrying the
``HSE`` magic.

Section header (4-byte little-endian word)::

    [0:3]   flags   bit0=valid, bit1=full, ...   (0xF nibble => erased/NIL)
    [4:7]   section id (0..N-1; 0xF = NIL)
    [8:31]  magic = b"HSE" (0x455348)

Entry / tag word (4-byte little-endian header, then ``length`` payload bytes)::

    [0:2]   state   011=VALID(live), 000=DELETED(superseded), 111=FREE (erased => end)
    [3:11]  length  payload length in bytes  (len = (tag & 0xFFF) >> 3)
    [12:19] key_id  8-bit config/NVDS tag id (e.g. 0x02 = DEVICE_NAME)
    [20:31] next    12-bit intra-section link (0xFFF = NIL)

State polarity follows NOR-flash physics (bits only clear 1->0 without an
erase): a slot is erased (111), written live (011), then superseded (000).
A DELETED entry's ``next`` points forward to the replacement entry; a live
entry is the chain tail (next = NIL), which the ROM asserts. The *current*
value of a key is therefore its VALID entry.
"""

import struct
from dataclasses import dataclass
from enum import IntEnum

from ..common import nvds

CFG_MAGIC = 0x455348  # "HSE"
SECTION_SIZE = 0x1000
TAG_NIL = 0xFFF


class EntryState(IntEnum):
    DELETED = 0b000   # superseded; `next` links to the replacement entry
    VALID = 0b011     # live/current value (chain tail, next = NIL)
    FREE = 0b111      # erased slot (0xFFFFFFFF) => end of log


@dataclass
class CfgEntry:
    section: int
    offset: int          # absolute offset within the partition buffer
    key_id: int
    state: EntryState
    length: int
    next: int
    data: bytes

    @property
    def name(self) -> str:
        return nvds.tag_name(self.key_id)


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _section_count(size: int) -> int:
    return 2 if size < 0x3000 else 3


def parse_cfg(buf: bytes, section_size: int = SECTION_SIZE) -> list[CfgEntry]:
    """Walk every section and return all entries (VALID, DELETED and the
    trailing FREE terminator are all skipped/stopped on appropriately)."""
    entries: list[CfgEntry] = []
    nsec = _section_count(len(buf))
    for sec in range(nsec):
        so = sec * section_size
        if so + 4 > len(buf):
            break
        hdr = _u32(buf, so)
        if hdr >> 8 != CFG_MAGIC:
            continue  # unformatted / erased section
        pos = so + 4
        end = so + section_size
        while pos + 4 <= end:
            tag = _u32(buf, pos)
            if tag == 0xFFFFFFFF:
                break  # free space => end of log for this section
            length = (tag & 0xFFF) >> 3
            key_id = (tag >> 12) & 0xFF
            nxt = (tag >> 20) & 0xFFF
            raw_state = tag & 0b111
            try:
                state = EntryState(raw_state)
            except ValueError:
                break  # corrupt / partially-written tag
            data = bytes(buf[pos + 4: pos + 4 + length])
            entries.append(CfgEntry(sec, pos, key_id, state, length, nxt, data))
            pos += 4 + length
    return entries


def current_config(buf: bytes, section_size: int = SECTION_SIZE) -> dict[int, bytes]:
    """Return ``{key_id: data}`` for the current (last VALID) value of each key."""
    cur: dict[int, bytes] = {}
    for e in parse_cfg(buf, section_size):
        if e.state == EntryState.VALID:
            cur[e.key_id] = e.data
    return cur


def render(buf: bytes, out=None) -> None:
    import sys
    out = out or sys.stdout
    entries = parse_cfg(buf)
    print(f"cfg store: {len(entries)} entries across sections", file=out)
    for e in entries:
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in e.data)
        print(f"  sec{e.section} +{e.offset:04x} key=0x{e.key_id:02x} ({e.name}) "
              f"{e.state.name:8s} len={e.length:3d}  {e.data.hex(' ')}  |{asc}|", file=out)
    cur = current_config(buf)
    print(f"\ncurrent config ({len(cur)} keys):", file=out)
    for key_id, data in cur.items():
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in data)
        print(f"  0x{key_id:02x} ({nvds.tag_name(key_id)}): {data.hex(' ')}  |{asc}|", file=out)
