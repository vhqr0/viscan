import random
import struct

from typing import Any
from argparse import Namespace

from .common.base import ResultParser, MainRunner
from .common.dgram import ICMP6Scanner
from .common.decorators import override
from .common.generators import AddrGenerator
from .common.icmp6_filter import ICMP6_ECHO_REQ


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
                seq, = struct.unpack_from('!H', buffer=buf, offset=6)
                if seq <= len(results) and addr == results[seq][0]:
                    results[seq] = (addr, True)
            except Exception as e:
                self.logger.warning('except while parsing: %s', e)
        self.result = results

    @override(ResultParser)
    def print(self):
        for addr, state in self.result:
            print(f'{addr}\t{state}')

    @override(ICMP6Scanner)
    def get_pkts(self) -> list[tuple[str, int, bytes]]:
        pkts = []
        for seq, target in enumerate(self.targets):
            buf = struct.pack('!BBHHH', ICMP6_ECHO_REQ, 0, 0, self.port, seq)
            buf += random.randbytes(random.randint(20, 40))
            pkts.append((target, 0, buf))
        return pkts

    @override(ICMP6Scanner)
    def send(self):
        self.send_pkts_with_timewait()

    @override(ICMP6Scanner)
    def recv_filter(self, pkt: tuple[str, int, bytes]) -> bool:
        try:
            _, _, buf = pkt
            port, = struct.unpack_from('!H', buffer=buf, offset=4)
            return port == self.port
        except Exception:
            return False

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['limit'] = args.limit_dwim
        kwargs['target'] = list(AddrGenerator(args.targets).addrs)
        return kwargs


if __name__ == '__main__':
    HostScanner.main()