import random
import struct
import socket
import logging

from typing import Any, Optional, Tuple, List, Dict
from argparse import Namespace

from ..defaults import TRACEROUTE_LIMIT
from ..generic.base import FinalResultMixin, GenericMainMixin
from ..generic.dgram import DgramScanner, DgramScanMixin, ICMP6SockMixin
from ..utils.decorators import override
from ..utils.argparser import GenericScanArgParser
from ..utils.generators import AddrGenerator
from ..utils.icmp6_filter import (
    ICMP6_TIME_EXCEEDED,
    ICMP6_ECHO_REQ,
    ICMP6_ECHO_REP,
)


class TracerouteScanner(GenericMainMixin,
                        FinalResultMixin[List[Optional[str]]], ICMP6SockMixin,
                        DgramScanMixin, DgramScanner):
    target: str
    limit: int
    ieid: int
    tr_round: int
    tr_results: List[Optional[str]]

    # override DgramScanner
    logger = logging.getLogger('traceroute_scanner')
    # override DgramScanMixin
    stateless = False
    # override ICMP6SockMixin
    icmp6_whitelist = [ICMP6_ECHO_REP, ICMP6_TIME_EXCEEDED]

    def __init__(self, target: str, limit: int = TRACEROUTE_LIMIT, **kwargs):
        self.target = target
        self.limit = limit
        self.ieid = random.getrandbits(16)
        super().__init__(**kwargs)

    @override(DgramScanMixin)
    def get_pkts(self) -> List[Tuple[str, int, bytes]]:
        buf = struct.pack('!BBHHH', ICMP6_ECHO_REQ, 0, 0, self.ieid,
                          self.tr_round)
        return [(self.target, 0, buf)]

    @override(DgramScanMixin)
    def prepare_pkts(self):

        arrived = False

        if self.tr_round != 0:
            if self.results:
                for pkt in self.results:
                    addr, _, buf = pkt
                    ietype, _, _, ieid, seq = \
                        struct.unpack_from('!BBHHH', buffer=buf, offset=0)
                    if ietype == ICMP6_ECHO_REP:  # arrived
                        if ieid == self.ieid and seq == self.tr_round:
                            arrived = True
                            self.tr_results.append(addr)
                            break
                    if ietype == ICMP6_TIME_EXCEEDED:  # continue
                        # TODO: deeper analysis
                        self.tr_results.append(addr)
                        break
                else:  # no useful results
                    self.tr_results.append(None)
                self.results.clear()
            else:  # no results
                self.tr_results.append(None)

        self.tr_round += 1
        if arrived or self.tr_round >= self.limit:
            return False

        self.pkts_prepared = False
        return super().prepare_pkts()

    @override(DgramScanMixin)
    def send_pkt(self, pkt: Tuple[str, int, bytes]):
        addr, _, buf = pkt
        cmsg = [(socket.IPPROTO_IPV6, socket.IPV6_HOPLIMIT,
                 struct.pack('@I', self.tr_round))]
        self.sock.sendmsg([buf], cmsg, 0, (addr, 0))

    @override(DgramScanMixin)
    def init_send_loop(self):
        self.tr_round = 0
        self.tr_results = []
        super().init_send_loop()

    @override(FinalResultMixin)
    def parse(self):
        self.final_result = self.tr_results

    @override(FinalResultMixin)
    def print(self):
        for i, addr in enumerate(self.final_result):
            print(f'{i+1}\t{addr}')

    @classmethod
    @override(GenericMainMixin)
    def get_argparser(self, *args, **kwargs) -> GenericScanArgParser:
        parser = super().get_argparser(*args, **kwargs)
        parser.add_limit_dwim(TRACEROUTE_LIMIT)
        return parser

    @classmethod
    @override(GenericMainMixin)
    def add_scan_kwargs(cls, raw_args: Namespace, scan_kwargs: Dict[str, Any]):
        super().add_scan_kwargs(raw_args, scan_kwargs)
        scan_kwargs['limit'] = raw_args.limit_dwim
        scan_kwargs['target'] = AddrGenerator.resolve(raw_args.targets[0])
