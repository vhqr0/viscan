import select
import socket
import logging

from typing import Optional, Tuple

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

    sock_family: int = socket.AF_INET6
    sock_type: int = socket.SOCK_RAW
    sock_proto: int = socket.IPPROTO_ICMPV6

    def __init__(self, sock: Optional[socket.socket] = None, **kwargs):
        if sock is None:
            sock = self.get_sock()
            self.prepare_sock(sock)
        self.sock = sock
        super().__init__(**kwargs)

    def get_sock(self) -> socket.socket:
        return socket.socket(self.sock_family, self.sock_type, self.sock_proto)

    def prepare_sock(self, sock: socket.socket):
        sock.setblocking(False)

    def send_pkt(self, pkt: DgramPkt):
        addr, port, buf = pkt
        self.sock.sendto(buf, (addr, port))

    def receive_loop(self):
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
