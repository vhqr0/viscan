import random

import scapy.all as sp

from typing import List

from ..base import OSScanner

Pad4 = sp.PadN(optdata=b'\x00\x00\x00\x00')


class NmapU1Scanner(OSScanner):
    port: int

    filter_tpl = 'ip6 src {} and ' \
        'icmp6[icmp6type]==icmp6-destinationunreach and ' \
        'icmp6[icmp6code]==4'

    def __init__(self, **kwargs):
        self.port = random.getrandbits(16)
        super().__init__(**kwargs)

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.target)

    def get_pkts(self) -> List[sp.IPv6]:
        pkts = []
        for _ in range(3):
            pkt = sp.IPv6(dst=self.target) / \
                sp.UDP(sport=self.port, dport=random.getrandbits(16)) / \
                random.randbytes(random.randint(20, 40))
            pkts.append(pkt)
        return pkts


class IE1Scanner(OSScanner):
    ieid: int

    filter_tpl = 'ip6 src {} and ' \
        'icmp6[icmp6type]==icmp6-echoreply and ' \
        'icmp6[4:2]=={}'

    def __init__(self, **kwargs):
        self.ieid = random.getrandbits(16)
        super().__init__(**kwargs)

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.target, self.ieid)

    def get_pkts(self) -> List[sp.IPv6]:
        pkt = sp.IPv6(dst=self.target) / \
            sp.IPv6ExtHdrHopByHop(options=[Pad4]) / \
            sp.ICMPv6EchoRequest(code=128 + random.getrandbits(7),
                                 id=self.ieid,
                                 seq=random.getrandbits(16),
                                 data=random.randbytes(random.randint(20, 40)))
        return [pkt]


class IE2Scanner(OSScanner):
    ieid: int

    # Notice: icmpv6 parameter problem need deeper analysis
    filter_tpl = 'ip6 src {} and ' \
        '(' \
        ' (icmp6[icmp6type]==icmp6-echoreply and icmp6[4:2]=={}) or ' \
        ' icmp6[icmp6type]==icmp6-parameterproblem' \
        ')'

    def __init__(self, **kwargs):
        self.ieid = random.getrandbits(16)
        super().__init__(**kwargs)

    # TODO: deeper analysis
    # def parse(self) -> Optional[bytes]:
    #     pass

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.target, self.ieid)

    def get_pkts(self) -> List[sp.IPv6]:
        pkt = sp.IPv6(dst=self.target) / \
            sp.IPv6ExtHdrHopByHop(options=[Pad4]) / \
            sp.IPv6ExtHdrDestOpt(options=[Pad4]) / \
            sp.IPv6ExtHdrRouting() / \
            sp.IPv6ExtHdrHopByHop(options=[Pad4]) / \
            sp.ICMPv6EchoRequest(id=self.ieid,
                                 seq=random.getrandbits(16),
                                 data=random.randbytes(random.randint(20, 40)))
        return [pkt]
