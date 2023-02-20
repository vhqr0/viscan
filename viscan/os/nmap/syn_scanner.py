import random
import base64

import scapy.all as sp

from typing import Optional, Dict, List

from .tcp_scanners import NmapTCPOpenScanner


class NmapSynScanner(NmapTCPOpenScanner):
    initial_seq: int
    syn_round: int
    syn_results: List[List[bytes]]

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
        self.syn_round = -1
        self.syn_results = [[] for _ in range(3)]
        super().__init__(**kwargs)
        self.interval = 0.1  # force 0.1s

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

    def prepare_pkts(self) -> bool:
        if self.syn_round >= 0:
            self.syn_results[self.syn_round] = self.results
            self.results = []

        self.syn_round += 1
        if self.syn_round >= 3:
            return False

        self.pkts_prepared = False
        return super().prepare_pkts()

    def parse(self) -> List[Optional[bytes]]:
        results: List[Optional[bytes]] = [None for _ in range(18)]
        for i in range(3):
            for buf in self.syn_results[i]:
                ippkt = sp.Ether(buf)[sp.IPv6]
                tcppkt = ippkt[sp.TCP]
                j = tcppkt.ack - self.initial_seq - 1
                if 0 <= j < 6:
                    results[3 * i + j] = sp.raw(ippkt)
                else:
                    self.logger.warning('invalid ack number')
        return results
