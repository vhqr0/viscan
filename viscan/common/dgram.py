import select
import socket

from typing import Optional

from .base import SRScanner
from .decorators import override
from .icmp6_utils import (
    ICMP6Filter,
    ICMP6_ECHO_REP,
)

Pkt = tuple[str, int, bytes]


class DgramScanner(SRScanner[Pkt, Pkt]):
    sock: socket.socket

    sock_family: int = socket.AF_INET6
    sock_type: int = -1
    sock_proto: int = -1

    def __init__(self, sock: Optional[socket.socket] = None, **kwargs):
        super().__init__(**kwargs)
        self.sock = sock if sock is not None else self.get_sock()

    def get_sock(self) -> socket.socket:
        sock = socket.socket(self.sock_family, self.sock_type, self.sock_proto)
        sock.setblocking(False)
        return sock

    @override(SRScanner)
    def send_pkt(self, pkt: Pkt):
        addr, port, buf = pkt
        self.sock.sendto(buf, (addr, port))

    @override(SRScanner)
    def recv(self):
        while not self.scan_done:
            rlist, _, _ = select.select([self.sock], [], [], 1)
            if rlist:
                buf, addrport = self.sock.recvfrom(4096)
                addr, port = '', 0
                if len(addrport) >= 1:
                    addr = addrport[0]
                if len(addrport) >= 2:
                    port = addrport[1]
                self.append_recv_pkt((addr, port, buf))


class ICMP6Scanner(DgramScanner):
    sock_type = socket.SOCK_RAW
    sock_proto = socket.IPPROTO_ICMPV6

    icmp6_whitelist: list[int] = [ICMP6_ECHO_REP]

    @override(DgramScanner)
    def get_sock(self) -> socket.socket:
        sock = super().get_sock()
        icmp6_filter = ICMP6Filter()
        icmp6_filter.setblockall()
        for icmp6_type in self.icmp6_whitelist:
            icmp6_filter.setpass(icmp6_type)
        icmp6_filter.setsockopt(sock)
        return sock


class UDPScanner(DgramScanner):
    sock_type = socket.SOCK_DGRAM

    udp_addr: tuple[str, int] = ('::', 0)

    @override(DgramScanner)
    def get_sock(self) -> socket.socket:
        sock = super().get_sock()
        sock.bind(self.udp_addr)
        return sock
