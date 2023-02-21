import random
import struct
import socket
import logging

from typing import Optional, Tuple, List

from ..defaults import TRACEROUTE_LIMIT
from ..generic import DgramStatefulScanner
from ..utils.icmp6_filter import (
    ICMP6Filter,
    ICMP6_TIME_EXCEEDED,
    ICMP6_ECHO_REQ,
    ICMP6_ECHO_REP,
)


class TracerouteScanner(DgramStatefulScanner):
    target: str
    limit: int
    ieid: int
    tr_round: int
    tr_results: List[Optional[str]]

    logger = logging.getLogger('traceroute_scanner')

    def __init__(self, target: str, limit: int = TRACEROUTE_LIMIT, **kwargs):
        self.target = target
        self.limit = limit
        self.ieid = random.getrandbits(16)
        self.tr_round = 0
        self.tr_results = []
        super().__init__(**kwargs)

    def get_pkts(self) -> List[Tuple[str, int, bytes]]:
        buf = struct.pack('!BBHHH', ICMP6_ECHO_REQ, 0, 0, self.ieid,
                          self.tr_round)
        return [(self.target, 0, buf)]

    def prepare_pkts(self):
        if self.tr_round >= self.limit:
            return False

        if self.tr_round != 0:

            if self.results:
                for pkt in self.results:
                    addr, _, buf = pkt
                    ietype, _, _, ieid, seq = \
                        struct.unpack_from('!BBHHH', buffer=buf, offset=0)
                    if ietype == ICMP6_ECHO_REP:  # arrive
                        if ieid == self.ieid and seq == self.tr_round:
                            self.tr_results.append(addr)
                            self.results.clear()
                            self.tr_round += 1
                            return False
                    if ietype == ICMP6_TIME_EXCEEDED:  # continue
                        buf = buf[8:]
                        if buf == self.pkts[0][:len(buf)]:
                            self.tr_results.append(addr)
                            self.results.clear()
                            self.tr_round += 1
                            if self.tr_round >= self.limit:
                                return False
                            self.pkts_prepared = False
                            return super().prepare_pkts()
                self.tr_results.clear()  # receive but useless

            self.tr_results.append(None)

        self.tr_round += 1
        if self.tr_round >= self.limit:
            return False

        self.pkts_prepared = False
        return super().prepare_pkts()

    def send_pkt(self, pkt: Tuple[str, int, bytes]):
        addr, _, buf = pkt
        cmsg = [(socket.IPPROTO_IPV6, socket.IPV6_HOPLIMIT,
                 struct.pack('@I', self.tr_round))]
        self.sock.sendmsg([buf], cmsg, 0, (addr, 0))

    def prepare_sock(self, sock: socket.socket):
        icmp6_filter = ICMP6Filter()
        icmp6_filter.setblockall()
        icmp6_filter.setpass(ICMP6_TIME_EXCEEDED)
        icmp6_filter.setpass(ICMP6_ECHO_REP)
        icmp6_filter.setsockopt(sock)
        super().prepare_sock(sock)