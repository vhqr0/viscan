import random
import logging

import scapy.all as sp

from typing import Tuple, List

from ..generic import PcapStatelessScanner


class PortScanner(PcapStatelessScanner):
    targets: List[Tuple[str, int]]
    port: int

    logger = logging.getLogger('port_scanner')

    def __init__(self, targets: List[Tuple[str, int]], **kwargs):
        super().__init__(**kwargs)

    def get_pkts(self) -> List[sp.IPv6]:
        pkts = []
        for target in self.targets:
            pkt = sp.IPv6(dst=target[0]) / \
                sp.TCP(sport=self.port,
                       dport=target[1],
                       seq=random.getrandbits(32),
                       flags='S',
                       window=1024,
                       options=[('MSS', 1460)])
            pkts.append(pkt)
        return pkts

    def get_filter(self) -> str:
        return f'ip6 and tcp dst port {self.port}'

    def parse(self) -> List[Tuple[str, int, str]]:
        results = []
        for result in self.results:
            try:
                pkt = sp.Ether(result)
                ippkt = pkt[sp.IPv6]
                tcppkt = ippkt[sp.TCP]
                flags = tcppkt.flags
                if 'R' in flags:
                    results.append((ippkt.src, tcppkt.sport, 'closed'))
                elif 'S' in flags and 'A' in flags:
                    results.append((ippkt.src, tcppkt.sport, 'open'))
                else:
                    raise ValueError('invalid tcp flags')
            except Exception as e:
                self.logger.warning('except while parsing: %s', e)
        return results
