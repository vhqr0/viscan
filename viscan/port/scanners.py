import random
import logging

import scapy.all as sp

from typing import Any, Tuple, List, Mapping

from ..generic.pcap import PcapScanner, PcapScanMixin, FilterMixin


class PortScanner(FilterMixin, PcapScanMixin, PcapScanner):
    targets: List[Tuple[str, int]]
    port: int

    # override PcapScanner
    logger = logging.getLogger('port_scanner')
    # override FilterMixin
    filter_template = 'ip6 and tcp dst port {port}'

    def __init__(self, targets: List[Tuple[str, int]], **kwargs):
        self.targets = targets
        self.port = random.getrandbits(16)
        super().__init__(**kwargs)

    # override PcapScanMixin
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

    # override FilterMixin
    def get_filter_context(self) -> Mapping[str, Any]:
        return {'port': self.port}

    def parse(self) -> List[Tuple[str, int, str]]:
        results = []
        for result in self.results:
            try:
                ippkt = sp.Ether(result)[sp.IPv6]
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
