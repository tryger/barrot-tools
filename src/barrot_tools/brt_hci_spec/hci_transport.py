import signal
from typing import Any

import usbbluetooth
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr
from scapy.packet import Packet


BARROT_USB_IDS: list[tuple[int, int]] = [
    (0x33fa, 0x0010),
    (0x33fa, 0x0012),
]


class HciError(Exception):
    pass


class HciTransport:
    """
    USB HCI H4 transport for Barrot chips.

    Wraps a bare VSC command packet in ``HCI_Hdr / HCI_Command_Hdr`` and
    sends it over scapy's UsbBluetoothSocket.
    """

    DEFAULT_TIMEOUT = 2.0

    def __init__(self, usb_ids: list[tuple[int, int]] = BARROT_USB_IDS,
                 verbose: bool = False,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        device = self._find_device(usb_ids)
        self.socket = UsbBluetoothSocket(device)
        self.verbose = verbose
        self.timeout = timeout

    @staticmethod
    def _find_device(usb_ids: list[tuple[int, int]]) -> Any:
        for dev in usbbluetooth.list_controllers():
            if (dev.vendor_id, dev.product_id) in usb_ids:
                return dev
        id_list = ", ".join(f"0x{v:04x}:0x{p:04x}" for v, p in usb_ids)
        raise HciError(f"No USB Bluetooth device found. Tried: {id_list}")

    def close(self) -> None:
        self.socket.close()

    def sr1(self, pkt: Packet) -> Packet:
        full = HCI_Hdr() / HCI_Command_Hdr() / pkt
        if self.verbose:
            full.show2()

        def _alarm(*_):
            raise TimeoutError(f"no response within {self.timeout}s")

        prev = signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, self.timeout)
        try:
            resp = self.socket.sr1(full, verbose=0)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, prev)

        if self.verbose and resp is not None:
            resp.show()
        return resp
