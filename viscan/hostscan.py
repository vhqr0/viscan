import random
import struct

from typing import Any
from argparse import Namespace

from .common.base import ResultParser, MainRunner
from .common.dgram import ICMP6Scanner
from .common.decorators import override
from .common.generators import AddrGenerator
from .common.icmp6_utils import ICMP6_ECHO_REQ


class HostScanner(ResultParser[list[tuple[str, bool]]], ICMP6Scanner,
                  MainRunner):
    targets: list[str]
    port: int

    def __init__(self, targets: list[str], **kwargs):
        super().__init__(**kwargs)
        self.targets = targets
        self.port = random.getrandbits(16)

    @override(ResultParser)
    def parse(self):
        results = [(target, False) for target in self.targets]
        for pkt in self.recv_pkts:
            try:
                addr, _, buf = pkt
                port, seq = struct.unpack_from('!HH', buffer=buf, offset=4)
                if port == self.port and \
                   seq <= len(results) and \
                   addr == results[seq][0]:
                    results[seq] = (addr, True)
            except Exception as e:
                self.logger.debug('except while parsing: %s', e)
        self.result = results

    @override(ResultParser)
    def show(self):
        assert self.result is not None
        for addr, state in self.result:
            print(f'{addr}\t{state}')

    @override(ICMP6Scanner)
    def get_pkts(self) -> list[tuple[str, int, bytes]]:
        pkts = []
        for seq, target in enumerate(self.targets):
            buf = struct.pack('!BBHHH', ICMP6_ECHO_REQ, 0, 0, self.port, seq)
            pkts.append((target, 0, buf))
        return pkts

    @override(ICMP6Scanner)
    def send(self):
        self.send_pkts_with_timewait()

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['targets'] = list(AddrGenerator(args.targets).addrs)
        return kwargs


if __name__ == '__main__':
    HostScanner.main()
