import random
import scapy.all as sp

from typing import List

from ....utils.decorators import override
from ...base import OSBaseScanner
from .mixins import NmapICMPScanMixin

Pad4 = sp.PadN(optdata=b'\x00\x00\x00\x00')


class NmapU1Scanner(NmapICMPScanMixin, OSBaseScanner):
    # override NmapICMPScanMixin
    filter_template = 'ip6 src {target} and ' \
        'icmp6[icmp6type]==icmp6-destinationunreach and ' \
        'icmp6[icmp6code]==4'
    fp_names = ['U1']

    @override(NmapICMPScanMixin)
    def get_pkts(self) -> List[sp.IPv6]:
        pkts = []
        for _ in range(3):
            pkt = sp.IPv6(dst=self.target) / \
                sp.UDP(sport=self.port, dport=random.getrandbits(16)) / \
                random.randbytes(random.randint(20, 40))
            pkts.append(pkt)
        return pkts


class NmapIE1Scanner(NmapICMPScanMixin, OSBaseScanner):
    # override NmapICMPScanMixin
    fp_names = ['IE1']

    @override(NmapICMPScanMixin)
    def get_pkts(self) -> List[sp.IPv6]:
        pkt = sp.IPv6(dst=self.target) / \
            sp.IPv6ExtHdrHopByHop(options=[Pad4]) / \
            sp.ICMPv6EchoRequest(code=128 + random.getrandbits(7),
                                 id=self.port,
                                 seq=random.getrandbits(16),
                                 data=random.randbytes(random.randint(20, 40)))
        return [pkt]


class NmapIE2Scanner(NmapICMPScanMixin, OSBaseScanner):

    # override NmapICMPScanMixin
    # Notice: icmpv6 parameter problem need deeper analysis
    filter_template = 'ip6 src {target} and ' \
        '(' \
        ' (icmp6[icmp6type]==icmp6-echoreply and icmp6[4:2]=={port}) or ' \
        ' icmp6[icmp6type]==icmp6-parameterproblem' \
        ')'
    fp_names = ['IE2']

    # TODO: deeper analysis
    # def parse(self) -> List[Optional[bytes]]:
    #     pass

    @override(NmapICMPScanMixin)
    def get_pkts(self) -> List[sp.IPv6]:
        pkt = sp.IPv6(dst=self.target) / \
            sp.IPv6ExtHdrHopByHop(options=[Pad4]) / \
            sp.IPv6ExtHdrDestOpt(options=[Pad4]) / \
            sp.IPv6ExtHdrRouting() / \
            sp.IPv6ExtHdrHopByHop(options=[Pad4]) / \
            sp.ICMPv6EchoRequest(id=self.port,
                                 seq=random.getrandbits(16),
                                 data=random.randbytes(random.randint(20, 40)))
        return [pkt]
