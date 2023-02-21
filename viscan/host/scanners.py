import random
import struct
import socket
import logging

import scapy.all as sp

from typing import Optional, Tuple, List

from ..generic import DgramStatelessScanner
from ..utils.icmp6_filter import ICMP6Filter, ICMP6_ECHOREP


class HostScanner(DgramStatelessScanner):
    targets: List[str]
    ieid: int

    logger = logging.getLogger('host_scanner')

    def __init__(self,
                 targets: List[str],
                 sock: Optional[socket.socket] = None,
                 **kwargs):
        if sock is None:
            sock = socket.socket(family=socket.AF_INET6,
                                 type=socket.SOCK_RAW,
                                 proto=socket.IPPROTO_ICMPV6)
            self.prepare_sock(sock)
        self.targets = targets
        self.ieid = random.getrandbits(16)
        super().__init__(sock=sock, **kwargs)

    @staticmethod
    def prepare_sock(sock: socket.socket):
        sock.setblocking(False)
        icmp6_filter = ICMP6Filter()
        icmp6_filter.setblockall()
        icmp6_filter.setpass(ICMP6_ECHOREP)
        icmp6_filter.setsockopt(sock)

    def get_pkts(self) -> List[Tuple[str, int, bytes]]:
        pkts = []
        for seq, target in enumerate(self.targets):
            pkt = sp.ICMPv6EchoRequest(id=self.ieid,
                                       seq=seq,
                                       data=random.randbytes(
                                           random.randint(20, 40)))
            pkts.append((target, 0, sp.raw(pkt)))
        return pkts

    def lfilter(self, pkt: Tuple[str, int, bytes]) -> bool:
        ieid, = struct.unpack_from('!H', buffer=pkt[2], offset=4)
        return ieid == self.ieid

    def parse(self) -> List[Tuple[str, bool]]:
        results = [(target, False) for target in self.targets]
        for pkt in self.results:
            try:
                addr, _, buf = pkt
                seq, = struct.unpack_from('!H', buffer=buf, offset=6)
                if seq <= len(results) and addr == results[seq][0]:
                    results[seq] = (addr, True)
            except Exception as e:
                self.logger.warning('except while parsing: %s', e)
        return results
