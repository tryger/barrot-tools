from dataclasses import dataclass
from datetime import datetime

def _parse_fw_date(raw: int) -> datetime:
    """
    Decode fw_date_num from its decimal YYMMDDHHNN encoding.

    The value is stored as a plain decimal integer where each pair of
    digits encodes a date/time component (2-digit year, month, day,
    hour, minute), e.g. 2005191223 → 2020-05-19 12:23.
    """
    mn = raw % 100;  raw //= 100
    hh = raw % 100;  raw //= 100
    dd = raw % 100;  raw //= 100
    mo = raw % 100;  raw //= 100
    yy = raw % 100
    return datetime(2000 + yy, mo, dd, hh, mn)


@dataclass
class BrtInfo:
    """Parsed chip version response from READ_CHIP_VERSION."""

    magic:       str   # "BRT"
    config_type: int
    version:     int
    fw_date:     int   # (decimal YYMMDDHHNN)
    esm_type:    int
    run_mode:    int
    features:    int
    flash_id:    int

    @property
    def fw_datetime(self) -> datetime:
        """fw_date decoded as a datetime object."""
        return _parse_fw_date(self.fw_date)

    @property
    def model(self) -> str:
        """
        The version field packs the chip name in hex digits.
        """
        return f"BR{self.version:X}"

    def __str__(self) -> str:
        return (
            f"  magic       : {self.magic}\n"
            f"  config_type : 0x{self.config_type:02x}\n"
            f"  model       : {self.model} (0x{self.version:08x})\n"
            f"  fw_date     : 0x{self.fw_date} ({self.fw_datetime:%d-%m-%Y %H:%M})\n"
            f"  esm_type    : 0x{self.esm_type:08x}\n"
            f"  run_mode    : 0x{self.run_mode:08x}\n"
            f"  features    : 0x{self.features:08x}\n"
            f"  flash_id    : 0x{self.flash_id:04x}"
        )
