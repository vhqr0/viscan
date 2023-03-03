import random

from scapy.packet import Packet
import scapy.layers.l2 as l2
import scapy.layers.inet6 as inet6

from typing import Any, Optional
from argparse import Namespace

from ..common.base import MainRunner
from ..common.fingerprinter import FingerPrinter, EnsembleFingerPrinter
from ..common.pcap import PcapScanner
from ..common.decorators import override
from ..common.generators import AddrGenerator


class OSFingerPrinter(FingerPrinter, PcapScanner, MainRunner):
    target: str
    open_port: Optional[int]
    closed_port: Optional[int]
    port: int

    def __init__(self,
                 target: str,
                 open_port: Optional[int] = None,
                 closed_port: Optional[int] = None,
                 **kwargs):
        super().__init__(**kwargs)
        self.target = target
        self.open_port = open_port
        self.closed_port = closed_port
        self.port = random.getrandbits(16)

    @override(PcapScanner)
    def send(self):
        self.send_pkts_with_retry()

    @override(FingerPrinter)
    def parse_fps(self) -> list[Optional[Packet]]:
        if len(self.recv_pkts) == 0:
            return [None]
        else:
            return [l2.Ether(self.recv_pkts[0])[inet6.IPv6]]

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        kwargs = super().parse_args(args)
        kwargs['open_port'] = args.open_port
        kwargs['closed_port'] = args.closed_port
        kwargs['target'] = AddrGenerator.resolve(args.targets[0])
        return kwargs


class OSScanner(EnsembleFingerPrinter, OSFingerPrinter):
    pass
