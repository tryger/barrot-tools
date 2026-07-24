"""
Shared bulk read/write helpers used by both chip family drivers.
Small progress bar + chunked-loop primitives.
"""

from collections.abc import Callable
from scapy.packet import Packet


_BAR_WIDTH = 40


def _progress(current: int, total: int, label: str = "") -> None:
    pct = current / total
    filled = int(_BAR_WIDTH * pct)
    bar = "#" * filled + "-" * (_BAR_WIDTH - filled)
    suffix = f" {label}" if label else ""
    print(f"\r  [{bar}] {current}/{total} ({pct*100:.1f}%){suffix}",
          end="", flush=True)


def _progress_done() -> None:
    print()


def read_chunked(read_fn: Callable[[int, int], Packet],
                 response_cls: type[Packet],
                 address: int, size: int,
                 chunk_size: int) -> bytes:
    """
    Read `size` bytes starting at `address` by issuing `read_fn(addr, n)`
    repeatedly in chunks of at most `chunk_size`. Concatenates each
    response's `.data` field (parsed from `response_cls`).
    """
    data = b""
    offset = 0
    while offset < size:
        n = min(chunk_size, size - offset)
        resp = read_fn(address + offset, n)
        data += bytes(resp[response_cls].data)
        offset += n
        _progress(offset, size)
    _progress_done()
    return data


def write_chunked(write_fn: Callable[[int, bytes], Packet],
                  address: int, data: bytes,
                  chunk_size: int) -> None:
    """
    Write `data` starting at `address` by issuing `write_fn(addr, chunk)`
    in chunks of at most `chunk_size`.
    """
    offset = 0
    total = len(data)
    while offset < total:
        chunk = data[offset:offset + chunk_size]
        write_fn(address + offset, chunk)
        offset += len(chunk)
        _progress(offset, total)
    _progress_done()
