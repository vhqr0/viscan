import random
import struct
import logging

from typing import Tuple, List

from ..generic import DgramScanner, DgramScanMixin, ICMP6SockMixin
from ..utils.icmp6_filter import ICMP6_ECHO_REQ


class HostScanner(ICMP6SockMixin, DgramScanMixin, DgramScanner):
    targets: List[str]
    ieid: int

    # override
    logger = logging.getLogger('host_scanner')

    def __init__(self, targets: List[str], **kwargs):
        self.targets = targets
        self.ieid = random.getrandbits(16)
        super().__init__(**kwargs)

    # override
    def get_pkts(self) -> List[Tuple[str, int, bytes]]:
        pkts = []
        for seq, target in enumerate(self.targets):
            buf = struct.pack('!BBHHH', ICMP6_ECHO_REQ, 0, 0, self.ieid, seq)
            buf += random.randbytes(random.randint(20, 40))
            pkts.append((target, 0, buf))
        return pkts

    # override
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
