import random

import scapy.layers.l2 as l2
import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6
import scapy.layers.dhcp6 as dhcp6

from typing import Any, Optional
from argparse import Namespace

from ..common.base import MainRunner
from ..common.pcap import PcapScanner
from ..common.decorators import override
from ..common.generators import AddrGenerator
from .base import RouteSubTracer, RouteTracer


class DHCPRouteSubTracer(RouteSubTracer, PcapScanner, MainRunner):
    target: str
    linkaddr: str

    filter_template = 'ip6 and ' \
        '(' \
        ' icmp6[icmp6type]==icmp6-timeexceeded or ' \
        ' icmp6[icmp6type]==icmp6-destinationunreach or ' \
        ' (udp dst port 547 and udp src port 547 and ip6 src {})' \
        ')'

    def __init__(self, target: str, linkaddr: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.target = target
        self.linkaddr = linkaddr if linkaddr is not None else target

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
        return self.filter_template.format(self.target)

    @override(PcapScanner)
    def get_pkt(self) -> inet6.IPv6:
        msg = dhcp6.DHCP6_Solicit(trid=random.getrandbits(16)) / \
            dhcp6.DHCP6OptClientId(
                duid=dhcp6.DUID_LL(lladdr=random.randbytes(6))) / \
            dhcp6.DHCP6OptOptReq() / \
            dhcp6.DHCP6OptElapsedTime() / \
            dhcp6.DHCP6OptIA_NA(iaid=random.getrandbits(32)) / \
            dhcp6.DHCP6OptIA_TA(iaid=random.getrandbits(32)) / \
            dhcp6.DHCP6OptIA_PD(iaid=random.getrandbits(32))
        pkt = inet6.IPv6(dst=self.target,
                         fl=random.getrandbits(20),
                         hlim=self.hop) / \
            inet.UDP(sport=547, dport=547) / \
            dhcp6.DHCP6_RelayForward(linkaddr=self.linkaddr) / \
            dhcp6.DHCP6OptRelayMsg(message=msg)
        return pkt

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['target'] = AddrGenerator.resolve(args.targets[0])
        if len(args.targets) >= 2:
            kwargs['linkaddr'] = AddrGenerator.resolve(args.targets[1])
        return kwargs


class DHCPRouteTracer(RouteTracer, DHCPRouteSubTracer):
    sub_tracer_type = DHCPRouteSubTracer


if __name__ == '__main__':
    DHCPRouteTracer.main()
