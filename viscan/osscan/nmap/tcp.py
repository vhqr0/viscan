import random

import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6

from typing import Optional

from ...common.decorators import override
from ..base import OSFingerPrinter


class NmapTCPFingerPrinter(OSFingerPrinter):
    target_port: int

    filter_template = 'ip6 and ' \
        'tcp dst port {} and ' \
        'tcp src port {}'

    def __init__(self, target_port: Optional[int], **kwargs):
        super().__init__(**kwargs)
        if target_port is None:
            raise ValueError('no target port specified')
        self.target_port = target_port

    @override(OSFingerPrinter)
    def get_filter(self) -> str:
        return self.filter_template.format(self.port, self.target_port)


class NmapTCPOpenPortFingerPrinter(NmapTCPFingerPrinter):

    def __init__(self, open_port: Optional[int] = None, **kwargs):
        super().__init__(target_port=open_port, **kwargs)


class NmapTCPClosedPortFingerPrinter(NmapTCPFingerPrinter):

    def __init__(self, closed_port: Optional[int] = None, **kwargs):
        super().__init__(target_port=closed_port, **kwargs)


class NmapTECNFingerPrinter(NmapTCPOpenPortFingerPrinter):
    fp_names = ['TECN']

    @override(NmapTCPOpenPortFingerPrinter)
    def get_pkt(self) -> inet6.IPv6:
        pkt = inet6.IPv6(dst=self.target) / \
            inet.TCP(sport=self.port,
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


class NmapTCPSender(NmapTCPFingerPrinter):
    flags: str = ''
    window: int = 0

    @override(NmapTCPFingerPrinter)
    def get_pkt(self) -> inet6.IPv6:
        pkt = inet6.IPv6(dst=self.target) / \
            inet.TCP(sport=self.port,
                     dport=self.target_port,
                     seq=random.getrandbits(32),
                     flags=self.flags,
                     window=self.window)
        return pkt


class NmapT2FingerPrinter(NmapTCPSender, NmapTCPOpenPortFingerPrinter):
    fp_names = ['T2']
    window = 128


class NmapT3FingerPrinter(NmapTCPSender, NmapTCPOpenPortFingerPrinter):
    fp_names = ['T3']
    flags = 'FSPU'
    window = 256


class NmapT4FingerPrinter(NmapTCPSender, NmapTCPOpenPortFingerPrinter):
    fp_names = ['T4']
    flags = 'A'
    window = 1024


class NmapT5FingerPrinter(NmapTCPSender, NmapTCPClosedPortFingerPrinter):
    fp_names = ['T5']
    flags = 'S'
    window = 31337


class NmapT6FingerPrinter(NmapTCPSender, NmapTCPClosedPortFingerPrinter):
    fp_names = ['T6']
    flags = 'A'
    window = 32768


class NmapT7FingerPrinter(NmapTCPSender, NmapTCPClosedPortFingerPrinter):
    fp_names = ['T7']
    flags = 'FPU'
    window = 65535
