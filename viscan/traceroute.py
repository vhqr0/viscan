import random
import struct
import socket
import logging

from typing import Any, Optional
from argparse import Namespace

from .defaults import TRACEROUTE_LIMIT
from .common.base import ResultParser, MainRunner
from .common.dgram import ICMP6Scanner
from .common.decorators import override
from .common.argparser import ScanArgParser
from .common.icmp6_filter import (
    ICMP6_TIME_EXCEEDED,
    ICMP6_ECHO_REQ,
    ICMP6_ECHO_REP,
)


class TracePinger(ResultParser[Optional[tuple[str, bool]]], ICMP6Scanner):
    target: str
    hop: int
    port: int

    def __init__(self, hop: int, target: str, **kwargs):
        super().__init__(**kwargs)
        self.hop = hop
        self.target = target
        self.port = random.getrandbits(16)

    def ping(self) -> Optional[tuple[str, bool]]:
        for _ in range(self.retry):
            try:
                self.scan_and_parse()
                if self.result is not None:
                    break
            except Exception:
                pass
        return self.result

    @override(ResultParser)
    def parse(self):
        for pkt in self.recv_pkts:
            try:
                addr, _, buf = pkt
                t, _, _, port, seq = \
                    struct.unpack_from('!BBHHH', buffer=buf, offset=0)
                if t == ICMP6_ECHO_REP and \
                   addr == self.target and \
                   port == self.port and \
                   seq == self.hop:
                    self.result = (addr, True)
                    return
                if t == ICMP6_TIME_EXCEEDED:
                    self.result = (addr, False)
                    return
            except Exception as e:
                self.logger.warning('except while parsing: %s', e)
        raise RuntimeError('no response')

    @override(ICMP6Scanner)
    def get_pkt(self):
        buf = struct.pack('!BBHHH', ICMP6_ECHO_REQ, 0, 0, self.port, self.hop)
        return (self.target, 0, buf)

    @override(ICMP6Scanner)
    def send_pkt(self, pkt: tuple[str, int, bytes]):
        addr, _, buf = pkt
        cmsg = [(socket.IPPROTO_IPV6, socket.IPV6_HOPLIMIT,
                 struct.pack('@I', self.hop))]
        self.sock.sendmsg([buf], cmsg, 0, (addr, 0))

    @override(ICMP6Scanner)
    def send_reset(self):
        super().send_reset()
        self.result = None

    @override(ICMP6Scanner)
    def send(self):
        self.send_pkts_with_timewait()


class TraceRouter(ResultParser[list[Optional[str]]], ICMP6Scanner, MainRunner):
    limit: int
    pinger: TracePinger

    logger = logging.getLogger('tracerouter')

    icmp6_whitelist = [ICMP6_ECHO_REP, ICMP6_TIME_EXCEEDED]

    def __init__(self, limit: int = TRACEROUTE_LIMIT, **kwargs):
        super().__init__(**kwargs)
        self.limit = limit
        kwargs['sock'] = self.sock  # override if exists
        self.pinger = TracePinger(1, **kwargs)

    @override(ICMP6Scanner)
    def scan_and_parse(self):
        results: list[Optional[str]] = []
        while self.pinger.hop <= self.limit:
            result = self.pinger.ping()
            if result is None:
                results.append(None)
            else:
                addr, arrived = result
                results.append(addr)
                if arrived:
                    break
        self.result = results

    @override(ResultParser)
    def show(self):
        for i, addr in enumerate(self.result):
            print(f'{i+1}\t{addr}')

    @classmethod
    @override(MainRunner)
    def get_argparser(cls, *args, **kwargs) -> ScanArgParser:
        parser = super().get_argparser(*args, **kwargs)
        parser.add_limit_dwim(TRACEROUTE_LIMIT)
        return parser

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['limit'] = args.limit_dwim
        kwargs['target'] = args.targets[0]
        return kwargs


if __name__ == '__main__':
    TraceRouter.main()
