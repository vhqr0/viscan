import random

import scapy.layers.l2 as l2
import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6
import scapy.layers.dns as dns

from typing import Any
from argparse import Namespace

from ..common.base import MainRunner
from ..common.pcap import PcapScanner
from ..common.decorators import override
from ..common.generators import AddrGenerator
from .base import RouteSubTracer, RouteTracer


class DNSRouteSubTracer(RouteSubTracer, PcapScanner, MainRunner):
    target: str
    target_port: int
    target_name: str

    filter_template = 'ip6 and ' \
        '(' \
        ' icmp6[icmp6type]==icmp6-timeexceeded or ' \
        ' icmp6[icmp6type]==icmp6-destinationunreach or ' \
        ' (udp dst port {} and udp src port {} and ip6 src {})' \
        ')'

    def __init__(self,
                 target: str,
                 target_port: int = 53,
                 target_name: str = 'www.google.com',
                 **kwargs):
        super().__init__(**kwargs)
        self.target = target
        self.target_port = target_port
        self.target_name = target_name

    @override(RouteSubTracer)
    def parse(self):
        for buf in self.recv_pkts:
            try:
                pkt = l2.Ether(buf)
                ippkt = pkt[inet6.IPv6]
                if inet.UDP in ippkt:
                    self.result = (ippkt.src, 'arrived', True)
                    return
                res = self.get_iperr(ippkt)
                if res is not None:
                    err, reason, arrived = res
                    if err.dst == self.target:
                        self.result = (ippkt.src, reason, arrived)
                        return
            except Exception as e:
                self.logger.debug('except while parsing: %s', e)
        raise RuntimeError('no response')

    @override(PcapScanner)
    def get_filter(self) -> str:
        return self.filter_template.format(self.port, self.target_port,
                                           self.target)

    @override(PcapScanner)
    def get_pkt(self) -> inet6.IPv6:
        pkt = inet6.IPv6(dst=self.target,
                         fl=random.getrandbits(20),
                         hlim=self.hop) / \
            inet.UDP(sport=self.port, dport=self.target_port) / \
            dns.DNS(qd=dns.DNSQR(qname=self.target_name, qtype='AAAA'))
        return pkt

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['target'] = AddrGenerator.resolve(args.targets[0])
        if len(args.targets) >= 2:
            kwargs['target_name'] = args.targets[1]
        if len(args.targets) >= 3:
            kwargs['target_port'] = int(args.targets[2])
        return kwargs


class DNSRouteTracer(RouteTracer, DNSRouteSubTracer):
    sub_tracer_type = DNSRouteSubTracer


if __name__ == '__main__':
    DNSRouteTracer.main()
