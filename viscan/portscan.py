import random

import scapy.layers.l2 as l2
import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6

from typing import Any
from argparse import Namespace

from .common.base import ResultParser, MainRunner
from .common.pcap import PcapScanner
from .common.decorators import override
from .common.generators import AddrPortGenerator


class PortScanner(ResultParser[list[tuple[str, int, str]]], PcapScanner,
                  MainRunner):
    targets: list[tuple[str, int]]
    port: int

    def __init__(self, targets: list[tuple[str, int]], **kwargs):
        super().__init__(**kwargs)
        self.targets = targets
        self.port = random.getrandbits(16)

    @override(ResultParser)
    def parse(self):
        results = [(addr, port, 'filtered') for addr, port in self.targets]
        for buf in self.recv_pkts:
            try:
                pkt = l2.Ether(buf)
                ippkt = pkt[inet6.IPv6]
                tcppkt = ippkt[inet.TCP]
                seq = tcppkt.ack - 1
                if seq <= len(results) and \
                   ippkt.src == results[seq][0] and \
                   tcppkt.sport == results[seq][1]:
                    flags = tcppkt.flags
                    if 'R' in flags:
                        results[seq] = (ippkt.src, tcppkt.sport, 'closed')
                    elif 'S' in flags and 'A' in flags:
                        results[seq] = (ippkt.src, tcppkt.sport, 'open')
            except Exception as e:
                self.logger.debug('except while parsing: %s', e)
        self.result = results

    @override(ResultParser)
    def show(self):
        assert self.result is not None
        for addr, port, state in self.result:
            print(f'[{addr}]:{port}\t{state}')

    @override(PcapScanner)
    def get_filter(self) -> str:
        return f'ip6 and tcp dst port {self.port}'

    @override(PcapScanner)
    def get_pkts(self) -> list[inet6.IPv6]:
        pkts = []
        for seq, target in enumerate(self.targets):
            pkt = inet6.IPv6(dst=target[0], fl=random.getrandbits(20)) / \
                inet.TCP(sport=self.port,
                         dport=target[1],
                         seq=seq,
                         flags='S',
                         window=1024,
                         options=[('MSS', 1460)])
            pkts.append(pkt)
        return pkts

    @override(PcapScanner)
    def send(self):
        self.send_pkts_with_timewait()

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        ports = args.ports.split(',')
        addrs = args.targets
        kwargs['targets'] = AddrPortGenerator(addrs, ports).addrports
        return kwargs


if __name__ == '__main__':
    PortScanner.main()
