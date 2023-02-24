import random

import scapy.all as sp

from typing import Optional, List

from ....utils.decorators import override
from ...base import OSBaseScanner
from .mixins import NmapTCPScanMixin, NmapTCPScanWithFlagsWindowMixin


class NmapTCPBaseScanner(NmapTCPScanMixin, OSBaseScanner):

    def __init__(self, target_port: Optional[int], **kwargs):
        if target_port is None:
            raise ValueError('target port is None')
        self.target_port = target_port
        super().__init__(**kwargs)


class NmapTCPOpenScanner(NmapTCPBaseScanner):

    def __init__(self, open_port: Optional[int] = None, **kwargs):
        super().__init__(target_port=open_port, **kwargs)


class NmapTCPClosedScanner(NmapTCPBaseScanner):

    def __init__(self, closed_port: Optional[int] = None, **kwargs):
        super().__init__(target_port=closed_port, **kwargs)


class NmapTECNScanner(NmapTCPOpenScanner):
    # override
    fp_names = ['TECN']

    @override(NmapTCPOpenScanner)
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


class NmapT1Scanner(NmapTCPOpenScanner):
    initial_seq: int
    syn_round: int
    syn_results: List[List[bytes]]

    # override
    fp_names = [
        'S1#1',
        'S2#1',
        'S3#1',
        'S4#1',
        'S5#1',
        'S6#1',
        'S1#2',
        'S2#2',
        'S3#2',
        'S4#2',
        'S5#2',
        'S6#2',
        'S1#3',
        'S2#3',
        'S3#3',
        'S4#3',
        'S5#3',
        'S6#3',
    ]

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
        self.initial_seq = random.getrandbits(31)
        super().__init__(**kwargs)
        self.interval = 0.1  # force 0.1s

    @override(NmapTCPOpenScanner)
    def get_pkts(self) -> List[sp.IPv6]:
        pkts = []
        for i, arg in enumerate(self.tcp_args):
            window, opts = arg
            pkt = sp.IPv6(dst=self.target) / \
                sp.TCP(sport=self.port,
                       dport=self.target_port,
                       seq=self.initial_seq+i,
                       flags='S',
                       window=window,
                       options=opts)
            pkts.append(pkt)
        return pkts

    @override(NmapTCPOpenScanner)
    def prepare_pkts(self) -> bool:
        if self.syn_round >= 0:
            self.syn_results[self.syn_round] = self.results
            self.results = []  # Notice: new list

        self.syn_round += 1
        if self.syn_round >= 3:
            return False

        self.pkts_prepared = False
        return super().prepare_pkts()

    @override(NmapTCPOpenScanner)
    def parse(self) -> List[Optional[bytes]]:
        results: List[Optional[bytes]] = [None for _ in range(18)]
        for i in range(3):
            for buf in self.syn_results[i]:
                ippkt = sp.Ether(buf)[sp.IPv6]
                tcppkt = ippkt[sp.TCP]
                j = tcppkt.ack - self.initial_seq - 1
                if 0 <= j < 6:
                    results[6 * i + j] = sp.raw(ippkt)
                else:
                    self.logger.warning('invalid ack number')
        return results

    @override(NmapTCPOpenScanner)
    def init_send_loop(self):
        self.syn_round = -1
        self.syn_results = [[] for _ in range(3)]
        super().init_send_loop()


class NmapT2Scanner(NmapTCPScanWithFlagsWindowMixin, NmapTCPOpenScanner):
    fp_names = ['T2']
    window = 128


class NmapT3Scanner(NmapTCPScanWithFlagsWindowMixin, NmapTCPOpenScanner):
    fp_names = ['T3']
    flags = 'FSPU'
    window = 256


class NmapT4Scanner(NmapTCPScanWithFlagsWindowMixin, NmapTCPOpenScanner):
    fp_names = ['T4']
    flags = 'A'
    window = 1024


class NmapT5Scanner(NmapTCPScanWithFlagsWindowMixin, NmapTCPClosedScanner):
    fp_names = ['T5']
    flags = 'S'
    window = 31337


class NmapT6Scanner(NmapTCPScanWithFlagsWindowMixin, NmapTCPClosedScanner):
    fp_names = ['T6']
    flags = 'A'
    window = 32768


class NmapT7Scanner(NmapTCPScanWithFlagsWindowMixin, NmapTCPClosedScanner):
    fp_names = ['T7']
    flags = 'FPU'
    window = 65535