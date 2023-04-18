import random
import struct
import functools
import ipaddress

from typing import Any
from argparse import Namespace

from .defaults import (
    DELIMIT_LIMIT,
    DELIMIT_WINDOW,
)
from .common.base import ResultParser, MainRunner, BaseScanner
from .common.dgram import ICMP6Scanner
from .common.decorators import override
from .common.argparser import ScanArgParser
from .common.generators import AddrGenerator
from .common.icmp6_utils import ICMP6_ECHO_REQ


class SubDelimiter(ResultParser[bool], ICMP6Scanner):
    target: str
    port: int

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.port = random.getrandbits(16)

    def ping(self, target: str) -> bool:
        self.target = target
        try:
            self.scan_and_parse()
            assert self.result is not None
            return self.result
        except Exception:
            return False

    @override(ICMP6Scanner)
    def parse(self):
        for pkt in self.recv_pkts:
            addr, _, buf = pkt
            if addr != self.target:
                continue
            try:
                port, = struct.unpack_from('!H', buffer=buf, offset=4)
                if port == self.port:
                    self.result = True
                    return
            except Exception as e:
                self.logger.debug('except while parsing: %s', e)
        raise RuntimeError('no response')

    @override(ICMP6Scanner)
    def get_pkt(self) -> tuple[str, int, bytes]:
        buf = struct.pack('!BBHHH', ICMP6_ECHO_REQ, 0, 0, self.port, 0)
        return (self.target, 0, buf)

    @override(ICMP6Scanner)
    def send_reset(self):
        super().send_reset()
        self.result = None

    @override(ICMP6Scanner)
    def send(self):
        self.send_pkts_with_retry()


class Delimiter(ResultParser[tuple[int, int]], MainRunner, BaseScanner):
    target: str
    limit: int
    window: int
    sub_delimiter: SubDelimiter

    def __init__(self,
                 target: str,
                 limit: int = DELIMIT_LIMIT,
                 window: int = DELIMIT_WINDOW,
                 **kwargs):
        super().__init__(**kwargs)
        self.target = target
        self.limit = limit
        self.window = window
        self.sub_delimiter = SubDelimiter(**kwargs)

    @functools.cache
    def ping(self, addr: int):
        return self.sub_delimiter.ping(str(ipaddress.IPv6Address(addr)))

    def search(self, beg: int, end: int, find_below: bool) -> int:
        while beg < end:
            i = (beg + end) // 2
            responsed = False
            for i in range(max(beg, i - self.window),
                           min(end, i + self.window)):
                if self.ping(i):
                    responsed = True
                    break
            if find_below:
                if responsed:
                    end = i - 1
                else:
                    beg = i + 1
            else:
                if responsed:
                    beg = i + 1
                else:
                    end = i - 1
        return end

    @override(ResultParser)
    def get_jsonable(self) -> tuple[str, str]:
        assert self.result is not None
        return (str(ipaddress.IPv6Address(self.result[0])),
                str(ipaddress.IPv6Address(self.result[1])))

    @override(ResultParser)
    def show(self):
        a, b = self.get_jsonable()
        print(f'{a}-{b}')

    @override(BaseScanner)
    def scan_and_parse(self):
        try:
            iface = ipaddress.IPv6Interface(self.target)
            net = iface.network.supernet(self.limit)
            m = int(iface.ip)
            ll = int(net.network_address)
            hl = int(net.broadcast_address)
            ll = self.search(ll, m, True)
            hl = self.search(m, hl, False)
            self.result = (ll, hl)
        except Exception as e:
            self.logger.error('error while scanning: %s', e)
            raise

    @classmethod
    @override(MainRunner)
    def get_argparser(cls, *args, **kwargs) -> ScanArgParser:
        parser = super().get_argparser(*args, **kwargs)
        parser.add_limit_dwim(DELIMIT_LIMIT)
        parser.add_window_dwim(DELIMIT_WINDOW)
        return parser

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['limit'] = args.limit_dwim
        kwargs['window'] = args.window_dwim
        kwargs['target'] = AddrGenerator.resolve(args.targets[0])
        return kwargs


if __name__ == '__main__':
    Delimiter.main()
