import random

from scapy.packet import Packet
import scapy.layers.l2 as l2
import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6

from typing import Optional

from ...common.decorators import override
from ..base import OSFingerPrinter, OSScanner


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
        pkt = inet6.IPv6(dst=self.target, fl=random.getrandbits(20)) / \
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
        return pkt


class NmapT1FingerPrinter(NmapTCPOpenPortFingerPrinter):
    fps: list[Optional[inet6.IPv6]]

    fp_names = [f'S{j+1}#{i+1}' for i in range(3) for j in range(6)]

    tcp_args = [
        # S1
        (1, [
            ('WScale', 10),
            ('NOP', None),
            ('MSS', 1460),
            ('Timestamp', (0xffffffff, 0)),
            ('SAckOK', b''),
        ]),
        # S2
        (63, [
            ('MSS', 1400),
            ('WScale', 0),
            ('SAckOK', b''),
            ('Timestamp', (0xffffffff, 0)),
            ('EOL', None),
        ]),
        # S3
        (4, [
            ('Timestamp', (0xffffffff, 0)),
            ('NOP', None),
            ('NOP', None),
            ('WScale', 5),
            ('NOP', None),
            ('MSS', 640),
        ]),
        # S4
        (4, [
            ('SAckOK', b''),
            ('Timestamp', (0xffffffff, 0)),
            ('WScale', 10),
            ('EOL', None),
        ]),
        # S5
        (16, [
            ('MSS', 536),
            ('SAckOK', b''),
            ('Timestamp', (0xffffffff, 0)),
            ('WScale', 10),
            ('EOL', None),
        ]),
        # S6
        (512, [
            ('MSS', 265),
            ('SAckOK', b''),
            ('Timestamp', (0xffffffff, 0)),
        ]),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.send_interval = 0.1  # force 0.1s
        self.fps = [None for _ in range(18)]

    @override(NmapTCPOpenPortFingerPrinter)
    def parse_fps(self) -> list[Optional[Packet]]:
        return self.fps

    @override(NmapTCPOpenPortFingerPrinter)
    def get_pkts(self) -> list[inet6.IPv6]:
        pkts = []
        for seq, arg in enumerate(self.tcp_args):
            window, opts = arg
            pkt = inet6.IPv6(dst=self.target, fl=random.getrandbits(20)) / \
                inet.TCP(sport=self.port,
                         dport=self.target_port,
                         seq=seq,
                         flags='S',
                         window=window,
                         options=opts)
            pkts.append(pkt)
        return pkts

    @override(NmapTCPOpenPortFingerPrinter)
    def send(self):
        for i in range(3):
            self.send_pkts_with_timewait()
            for buf in self.recv_pkts:
                pkt = l2.Ether(buf)
                ippkt = pkt[inet6.IPv6]
                tcppkt = ippkt[inet.TCP]
                seq = tcppkt.ack - 1
                if seq < 6:
                    self.fps[6 * i + seq] = ippkt


class NmapTCPSender(NmapTCPFingerPrinter):
    flags: str = ''
    window: int = 0

    @override(NmapTCPFingerPrinter)
    def get_pkt(self) -> inet6.IPv6:
        pkt = inet6.IPv6(dst=self.target, fl=random.getrandbits(20)) / \
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


class NmapTCPOSScanner(OSScanner):
    fp_types = [
        NmapTECNFingerPrinter,
        NmapT1FingerPrinter,
        NmapT2FingerPrinter,
        NmapT3FingerPrinter,
        NmapT4FingerPrinter,
        NmapT5FingerPrinter,
        NmapT6FingerPrinter,
        NmapT7FingerPrinter,
    ]


if __name__ == '__main__':
    NmapTCPOSScanner.main()
