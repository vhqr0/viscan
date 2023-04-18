import random

import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6

from ...common.decorators import override
from ..base import OSFingerPrinter, OSScanner

Pad4 = inet6.PadN(optdata=b'\x00\x00\x00\x00')


class NmapU1FingerPrinter(OSFingerPrinter):
    fp_names = ['U1']
    filter_template = 'ip6 src {} and ' \
        'icmp6[icmp6type]==icmp6-destinationunreach and ' \
        'icmp6[icmp6code]==4'

    @override(OSFingerPrinter)
    def get_filter(self) -> str:
        return self.filter_template.format(self.target)

    @override(OSFingerPrinter)
    def get_pkts(self) -> list[inet6.IPv6]:
        pkts = []
        for _ in range(3):
            pkt = inet6.IPv6(dst=self.target, fl=random.getrandbits(20)) / \
                inet.UDP(sport=self.port, dport=random.getrandbits(16)) / \
                random.randbytes(random.randint(20, 40))
            pkts.append(pkt)
        return pkts


class NmapIE1FingerPrinter(OSFingerPrinter):
    fp_names = ['IE1']
    filter_template = 'ip6 src {} and ' \
        'icmp6[icmp6type]==icmp6-echoreply and ' \
        'icmp6[4:2]=={}'

    @override(OSFingerPrinter)
    def get_filter(self) -> str:
        return self.filter_template.format(self.target, self.port)

    @override(OSFingerPrinter)
    def get_pkt(self) -> inet6.IPv6:
        pkt = inet6.IPv6(dst=self.target, fl=random.getrandbits(20)) / \
            inet6.IPv6ExtHdrHopByHop(options=[Pad4]) / \
            inet6.ICMPv6EchoRequest(
                code=128 + random.getrandbits(7),
                id=self.port,
                seq=random.getrandbits(16),
                data=random.randbytes(random.randint(20, 40)))
        return pkt


class NmapIE2FingerPrinter(OSFingerPrinter):
    fp_names = ['IE2']

    # TODO: icmpv6 parameter problem need deeper analysis
    filter_template = 'ip6 src {} and ' \
        '(' \
        ' (icmp6[icmp6type]==icmp6-echoreply and icmp6[4:2]=={}) or ' \
        ' icmp6[icmp6type]==icmp6-parameterproblem' \
        ')'

    @override(OSFingerPrinter)
    def get_filter(self) -> str:
        return self.filter_template.format(self.target, self.port)

    @override(OSFingerPrinter)
    def get_pkt(self) -> inet6.IPv6:
        pkt = inet6.IPv6(dst=self.target, fl=random.getrandbits(20)) / \
            inet6.IPv6ExtHdrHopByHop(options=[Pad4]) / \
            inet6.IPv6ExtHdrDestOpt(options=[Pad4]) / \
            inet6.IPv6ExtHdrRouting() / \
            inet6.IPv6ExtHdrHopByHop(options=[Pad4]) / \
            inet6.ICMPv6EchoRequest(
                id=self.port,
                seq=random.getrandbits(16),
                data=random.randbytes(random.randint(20, 40)))
        return pkt


class NmapICMPOSScanner(OSScanner):
    fp_types = [
        NmapU1FingerPrinter,
        NmapIE1FingerPrinter,
        NmapIE2FingerPrinter,
    ]


if __name__ == '__main__':
    NmapICMPOSScanner.main()
