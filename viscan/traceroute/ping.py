import struct
import socket

from typing import Any, Optional
from argparse import Namespace

from ..common.base import MainRunner
from ..common.dgram import ICMP6Scanner
from ..common.decorators import override
from ..common.generators import AddrGenerator
from ..common.icmp6_utils import (
    ICMP6_DEST_UNREACH,
    ICMP6_TIME_EXCEEDED,
    ICMP6_ECHO_REQ,
    ICMP6_ECHO_REP,
)
from .base import RouteSubTracer, RouteTracer


class PingRouteSubTracer(RouteSubTracer, ICMP6Scanner, MainRunner):
    target: str

    icmp6_whitelist = [ICMP6_ECHO_REP, ICMP6_DEST_UNREACH, ICMP6_TIME_EXCEEDED]

    def __init__(self, target: str, **kwargs):
        super().__init__(**kwargs)
        self.target = target

    @override(RouteSubTracer)
    def parse(self):
        for pkt in self.recv_pkts:
            try:
                addr, _, buf = pkt
                t, code, _, port, seq = \
                    struct.unpack_from('!BBHHH', buffer=buf, offset=0)
                # don't check addr
                if t == ICMP6_ECHO_REP and \
                   port == self.port and \
                   seq == self.hop:
                    self.result = (addr, 'arrived', True)
                    return
                if t in (ICMP6_DEST_UNREACH, ICMP6_TIME_EXCEEDED) and \
                   socket.inet_ntop(socket.AF_INET6, buf[32:48]) \
                   == self.target:
                    arrived = False
                    if t == ICMP6_DEST_UNREACH:
                        if code == 0:
                            reason = 'dest route'
                        elif code == 1:
                            reason = 'dest prohibited'
                        elif code == 3:
                            reason = 'dest addr'
                        elif code == 4:
                            reason = 'dest port'
                        else:
                            reason = 'dest unknown'
                        arrived = True
                    else:
                        reason = 'time exceeded'
                    self.result = (addr, reason, arrived)
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

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['target'] = AddrGenerator.resolve(args.targets[0])
        return kwargs


class PingRouteTracer(RouteTracer, PingRouteSubTracer):
    sub_tracer_type = PingRouteSubTracer

    def __init__(self, sock: Optional[socket.socket] = None, **kwargs):
        sock = sock if sock is not None else self.get_sock()
        super().__init__(sock=sock, **kwargs)


if __name__ == '__main__':
    PingRouteTracer.main()
