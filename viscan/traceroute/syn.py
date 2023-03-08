import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6

from typing import Any
from argparse import Namespace

from ..common.base import MainRunner
from ..common.pcap import PcapScanner
from ..common.decorators import override, auto_add_logger
from ..common.generators import AddrGenerator
from .base import RouteSubTracer, RouteTracer


@auto_add_logger
class SYNRouteSubTracer(RouteSubTracer, PcapScanner, MainRunner):
    target: str
    target_port: int

    filter_template = 'ip6 and ' \
        '('\
        ' icmp6[icmp6type]==icmp6-timeexceeded or' \
        ' (tcp dst port {} and tcp src port {} and ip6 src {})' \
        ')'

    def __init__(self, target: str, target_port: int = 53, **kwargs):
        super().__init__(**kwargs)
        self.target = target
        self.target_port = target_port

    @override(RouteSubTracer)
    def parse(self):
        for pkt in self.recv_pkts:
            try:
                if inet.TCP in pkt:
                    self.result = (pkt.src, True)
                    return
                # TODO: deeper analysis
                self.result = (pkt.src, False)
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
        pkt = inet6.IPv6(dst=self.target, hlim=self.hop) / \
            inet.TCP(sport=self.port, dport=self.target_port, flags='S')
        return pkt

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['target'] = AddrGenerator.resolve(args.targets[0])
        kwargs['port'] = int(args.targets[1]) \
            if len(args.targets) >= 2 else 53
        return kwargs


@auto_add_logger
class SYNRouteTracer(RouteTracer, SYNRouteSubTracer):
    sub_tracer_type = SYNRouteSubTracer


if __name__ == '__main__':
    SYNRouteTracer.main()
