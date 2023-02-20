import random
import logging

import scapy.all as sp

from typing import Optional, List

from ...generic import PcapStatefulScanner


class NmapSynScanner(PcapStatefulScanner):
    target: str
    target_port: int
    port: int
    initial_seq: int
    syn_round: int
    syn_results: List[List[bytes]]

    logger = logging.getLogger('syn_scanner')

    filter_tpl = 'ip6 and ' \
        'tcp dst port {} and ' \
        'tcp src port {}'

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

    def __init__(self,
                 target: str,
                 open_port: Optional[int] = None,
                 closed_port: Optional[int] = None,
                 **kwargs):
        if open_port is None:
            raise ValueError('target port is None')
        self.target = target
        self.target_port = open_port
        self.port = random.getrandbits(16)
        self.initial_seq = random.getrandbits(31)
        self.syn_round = -1
        self.syn_results = [[] for _ in range(3)]
        super().__init__(**kwargs)

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.port, self.target_port)

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

    def parse(self) -> List[List[Optional[bytes]]]:
        results: List[List[Optional[bytes]]] = [[None for _ in range(6)]
                                                for _ in range(3)]

        for i in range(3):
            for buf in self.syn_results[i]:
                ippkt = sp.Ether(buf)[sp.IPv6]
                tcppkt = ippkt[sp.TCP]
                j = tcppkt.ack - self.initial_seq - 1
                if 0 <= j < 6:
                    results[i][j] = sp.raw(ippkt)
                else:
                    self.logger.warning('invalid ack number')

        return results
