import random
import logging

import scapy.all as sp

from typing import Optional, List

from ..base import OSScanner


class NmapTCPBaseScanner(OSScanner):
    target_port: int
    port: int

    logger = logging.getLogger('tcp_scanner')

    filter_tpl = 'ip6 and ' \
        'tcp dst port {} and ' \
        'tcp src port {}'

    def __init__(self, target_port: Optional[int], **kwargs):
        if target_port is None:
            raise ValueError('target port is None')
        self.target_port = target_port
        self.port = random.getrandbits(16)
        super().__init__(**kwargs)

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.port, self.target_port)


class NmapTCPOpenScanner(NmapTCPBaseScanner):

    def __init__(self, open_port: Optional[int] = None, **kwargs):
        super().__init__(open_port, **kwargs)


class NmapTCPClosedScanner(NmapTCPBaseScanner):

    def __init__(self, closed_port: Optional[int] = None, **kwargs):
        super().__init__(closed_port, **kwargs)


class NmapTECNScanner(NmapTCPOpenScanner):

    def get_pkts(self) -> List[sp.IPv6]:
        pkt = sp.IPv6(dst=self.target) / \
            sp.TCP(sport=self.port,
                   dport=self.target_port,
                   seq=random.getrandbits(32),
                   flags='SEC',  # SYN ECE CWR
                   window=3,
                   urgptr=0xf7f5,
                   options=[
                       ('WScale', 10),
                       ('NOP', None),
                       ('MSS', 1460),
                       ('SAckOK', b''),
                       ('NOP', None),
                       ('NOP', None),
                   ])
        return [pkt]


class _NmapTCPFlagsWindowMixin:
    target: str
    target_port: int
    port: int

    flags = ''
    window = 0

    def get_pkts(self) -> List[sp.IPv6]:
        pkt = sp.IPv6(dst=self.target) / \
            sp.TCP(sport=self.port,
                   dport=self.target_port,
                   seq=random.getrandbits(32),
                   flags=self.flags,
                   window=self.window)
        return [pkt]


class NmapT2Scanner(_NmapTCPFlagsWindowMixin, NmapTCPOpenScanner):
    window = 128


class NmapT3Scanner(_NmapTCPFlagsWindowMixin, NmapTCPOpenScanner):
    flags = 'FSPU'
    window = 256


class NmapT4Scanner(_NmapTCPFlagsWindowMixin, NmapTCPOpenScanner):
    flags = 'A'
    window = 1024


class NmapT5Scanner(_NmapTCPFlagsWindowMixin, NmapTCPClosedScanner):
    flags = 'S'
    window = 31337


class NmapT6Scanner(_NmapTCPFlagsWindowMixin, NmapTCPClosedScanner):
    flags = 'A'
    window = 32768


class NmapT7Scanner(_NmapTCPFlagsWindowMixin, NmapTCPClosedScanner):
    flags = 'FPU'
    window = 65535
