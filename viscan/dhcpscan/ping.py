import socket

from scapy.packet import Packet

from typing import Optional

from ..common.fingerprinter import FingerPrinter, EnsembleFingerPrinter
from ..common.decorators import override
from .base import DHCPBaseScanner, DHCPRequester, DHCPSoliciter


class DHCPReplyFingerPrinter(FingerPrinter, DHCPBaseScanner):
    requester: DHCPRequester

    fp_names = ['reply']

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.requester = DHCPRequester(**kwargs)

    @override(FingerPrinter)
    def scan(self):
        self.requester.retrieve()

    @override(FingerPrinter)
    def parse_fps(self) -> list[Optional[Packet]]:
        return [self.requester.result]


class DHCPAdvertiseFingerPrinter(FingerPrinter, DHCPBaseScanner):
    soliciter: DHCPSoliciter

    fp_names = ['advertise']

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.soliciter = DHCPSoliciter(**kwargs)

    @override(FingerPrinter)
    def scan(self):
        self.soliciter.retrieve()

    @override(FingerPrinter)
    def parse_fps(self) -> list[Optional[Packet]]:
        return [self.soliciter.result]


class DHCPPinger(EnsembleFingerPrinter, DHCPBaseScanner):
    fp_types = [DHCPReplyFingerPrinter, DHCPAdvertiseFingerPrinter]

    def __init__(self, sock: Optional[socket.socket] = None, **kwargs):
        sock = sock if sock is not None else self.get_sock()
        super().__init__(sock=sock, **kwargs)


if __name__ == '__main__':
    DHCPPinger.main()
