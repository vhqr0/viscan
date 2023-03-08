import struct
import socket

from typing import Any, Optional
from argparse import Namespace

from ..common.base import MainRunner
from ..common.dgram import ICMP6Scanner
from ..common.decorators import override, auto_add_logger
from ..common.generators import AddrGenerator
from ..common.icmp6_utils import (
    ICMP6_TIME_EXCEEDED,
    ICMP6_ECHO_REQ,
    ICMP6_ECHO_REP,
)
from .base import RouteSubTracer, RouteTracer


@auto_add_logger
class PingRouteSubTracer(RouteSubTracer, ICMP6Scanner):
    target: str

    icmp6_whitelist = [ICMP6_ECHO_REP, ICMP6_TIME_EXCEEDED]

    def __init__(self, target: str, **kwargs):
        super().__init__(**kwargs)
        self.target = target

    @override(RouteSubTracer)
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
                    # TODO: deeper analysis
                    self.result = (addr, False)
                    return
            except Exception as e:
                self.logger.debug('except while parsing: %s', e)
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


@auto_add_logger
class PingRouteTracer(RouteTracer, PingRouteSubTracer, MainRunner):
    sub_tracer_type = PingRouteSubTracer

    def __init__(self, sock: Optional[socket.socket] = None, **kwargs):
        sock = sock if sock is not None else self.get_sock()
        super().__init__(sock=sock, **kwargs)

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['target'] = AddrGenerator.resolve(args.targets[0])
        return kwargs


if __name__ == '__main__':
    PingRouteTracer.main()
