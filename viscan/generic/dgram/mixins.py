import select
import socket

from typing import Tuple, List

from ...utils.icmp6_filter import (
    ICMP6Filter,
    ICMP6_ECHO_REP,
)
from ..base import GenericScanMixin
from .scanners import MixinForDgramScanner

DgramPkt = Tuple[str, int, bytes]


class DgramScanMixin(GenericScanMixin[DgramPkt, DgramPkt],
                     MixinForDgramScanner):
    # override GenericScanMixin
    def send_pkt(self, pkt: DgramPkt):
        addr, port, buf = pkt
        self.sock.sendto(buf, (addr, port))

    # override GenericScanMixin
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


class SockMixin(MixinForDgramScanner):
    sock_family: int = socket.AF_INET6
    sock_type: int = -1
    sock_proto: int = -1

    def get_sock_family(self):
        return self.sock_family

    def get_sock_type(self):
        return self.sock_type

    def get_sock_proto(self):
        return self.sock_proto

    # override mixin DgramScanner
    def get_sock(self) -> socket.socket:
        sock = socket.socket(family=self.get_sock_family(),
                             type=self.get_sock_type(),
                             proto=self.get_sock_proto())
        self.prepare_sock(sock)
        return sock

    def prepare_sock(self, sock: socket.socket):
        sock.setblocking(False)


class ICMP6SockMixin(SockMixin):
    # override SockMixin
    sock_type = socket.SOCK_RAW
    sock_proto = socket.IPPROTO_ICMPV6

    icmp6_whitelist: List[int] = [ICMP6_ECHO_REP]

    def get_icmp6_whitelist(self):
        return self.icmp6_whitelist

    # override SockMixin
    def prepare_sock(self, sock: socket.socket):
        icmp6_filter = ICMP6Filter()
        icmp6_filter.setblockall()
        for icmp6_type in self.get_icmp6_whitelist():
            icmp6_filter.setpass(icmp6_type)
        icmp6_filter.setsockopt(sock)
        super().prepare_sock(sock)


class UDPSockMixin(SockMixin):
    # override SockMixin
    sock_type = socket.SOCK_DGRAM

    udp_addr: Tuple[str, int] = ('::', 0)

    def get_udp_addr(self):
        return self.udp_addr

    # override SockMixin
    def prepare_sock(self, sock: socket.socket):
        sock.bind(self.get_udp_addr())
        super().prepare_sock(sock)