import random
import struct
import socket
import logging

from typing import Tuple, List

from ..generic import DgramStatelessScanner
from ..utils.icmp6_filter import (
    ICMP6Filter,
    ICMP6_ECHOREQ,
    ICMP6_ECHOREP,
)


class HostScanner(DgramStatelessScanner):
    targets: List[str]
    ieid: int

    logger = logging.getLogger('host_scanner')

    def __init__(self, targets: List[str], **kwargs):
        self.targets = targets
        self.ieid = random.getrandbits(16)
        super().__init__(**kwargs)

    def prepare_sock(self, sock: socket.socket):
        icmp6_filter = ICMP6Filter()
        icmp6_filter.setblockall()
        icmp6_filter.setpass(ICMP6_ECHOREP)
        icmp6_filter.setsockopt(sock)
        super().prepare_sock(sock)

    def get_pkts(self) -> List[Tuple[str, int, bytes]]:
        pkts = []
        for seq, target in enumerate(self.targets):
            buf = struct.pack('!BBHHH', ICMP6_ECHOREQ, 0, 0, self.ieid, seq)
            buf += random.randbytes(random.randint(20, 40))
            pkts.append((target, 0, buf))
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
