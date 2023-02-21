import select
import socket
import logging

from typing import Tuple

from ..base import (
    BaseScanner,
    GenericScanMixin,
    StatelessScanMixin,
    StatefulScanMixin,
)

DgramPkt = Tuple[str, int, bytes]


class DgramScanner(GenericScanMixin[DgramPkt, DgramPkt], BaseScanner):
    sock: socket.socket

    logger = logging.getLogger('dgram_scanner')

    def __init__(self, sock: socket.socket, **kwargs):
        self.sock = sock
        super().__init__(**kwargs)

    def send_pkt(self, pkt: DgramPkt):
        addr, port, buf = pkt
        self.sock.sendto(buf, (addr, port))

    def receiver(self):
        while not self.done:
            rlist, _, _ = select.select([self.sock], [], [], 1)
            if rlist:
                buf, addrport = self.sock.recvfrom(4096)
                addr, port = '', 0
                if len(addrport) >= 1:
                    addr = addrport[0]
                if len(addrport) >= 2:
                    port = addrport[1]
                self.add_result((addr, port, buf))


class DgramStatelessScanner(StatelessScanMixin, DgramScanner):
    pass


class DgramStatefulScanner(StatefulScanMixin, DgramScanner):
    pass
