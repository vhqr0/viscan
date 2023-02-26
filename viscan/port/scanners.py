import sys
import random
import logging

import scapy.all as sp

from typing import Any, Tuple, List, Mapping, Dict
from argparse import Namespace

from ..generic.base import FinalResultMixin, GenericMainMixin
from ..generic.pcap import PcapScanner, PcapScanMixin, FilterMixin
from ..utils.decorators import override
from ..utils.generators import AddrPortGenerator


class PortScanner(GenericMainMixin, FinalResultMixin[List[Tuple[str, int,
                                                                str]]],
                  FilterMixin, PcapScanMixin, PcapScanner):
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

    @override(PcapScanMixin)
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

    @override(FilterMixin)
    def get_filter_context(self) -> Mapping[str, Any]:
        return {'port': self.port}

    @override(FinalResultMixin)
    def parse(self):
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
        self.final_result = results

    @override(FinalResultMixin)
    def print(self):
        for addr, port, state in self.final_result:
            print(f'[{addr}]:{port}\t{state}')

    @classmethod
    @override(GenericMainMixin)
    def add_scan_kwargs(cls, raw_args: Namespace, scan_kwargs: Dict[str, Any]):
        super().add_scan_kwargs(raw_args, scan_kwargs)

        ports = raw_args.ports.split(',')
        addrs = raw_args.targets

        if not addrs:
            for line in sys.stdin:
                line = line.strip()
                if len(line) == 0 or line[0] == '#':
                    continue
                addrs.append(line)

        scan_kwargs['targets'] = AddrPortGenerator(addrs, ports).addrports
