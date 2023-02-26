import random
import base64
import logging

import scapy.all as sp

from typing import Any, Type, Optional, List, Dict
from argparse import Namespace

from ...generic.base import BaseScanner, FinalResultMixin, GenericMainMixin
from ...generic.pcap import PcapScanner, MixinForPcapScanner
from ...utils.decorators import override
from ...utils.generators import AddrGenerator


class MixinForOSBaseScanner(FinalResultMixin[List[Optional[sp.IPv6]]],
                            MixinForPcapScanner):
    target: str
    open_port: Optional[int]
    closed_port: Optional[int]
    port: int  # ieid for icmp, port for tcp/udp

    def update_fp(self, fp: Dict[str, Optional[sp.IPv6]]):
        super().update_fp(fp)


class OSBaseScanner(PcapScanner, MixinForOSBaseScanner):

    # override PcapScanner
    logger = logging.getLogger('os_scanner')

    def __init__(self,
                 target: str,
                 open_port: Optional[int] = None,
                 closed_port: Optional[int] = None,
                 **kwargs):
        self.target = target
        self.open_port = open_port
        self.closed_port = closed_port
        self.port = random.getrandbits(16)
        super().__init__(**kwargs)

    @override(MixinForOSBaseScanner)
    def update_fp(self, fp: Dict[str, Optional[sp.IPv6]]):
        raise NotImplementedError


class OSBaseFingerPrinter(GenericMainMixin,
                          FinalResultMixin[Dict[str, Optional[sp.IPv6]]],
                          BaseScanner):
    kwargs: Dict[str, Any]
    results: Dict[str, Optional[sp.IPv6]]

    # override BaseScanner
    logger = logging.getLogger('os_finger_printer')

    scanner_clses: List[Type[OSBaseScanner]] = []

    def __init__(self, output_file: Optional[str] = None, **kwargs):
        super().__init__(output_file=output_file)
        self.kwargs = kwargs
        self.results = dict()

    @override(BaseScanner)
    def scan(self):
        self.results.clear()

        for scanner_cls in self.scanner_clses:
            try:
                scanner = scanner_cls(**self.kwargs)
                scanner.scan()
                scanner.parse()
                scanner.update_fp(self.results)
            except Exception as e:
                self.logger.error('except while scanning: %s', e)

    @override(FinalResultMixin)
    def parse(self):
        self.final_result = self.results

    @override(FinalResultMixin)
    def print(self):
        for name, pkt in self.final_result.items():
            if pkt is None:
                print(f'{name}: None')
            else:
                print(f'{name}: {pkt.summary()}')

    @override(FinalResultMixin)
    def to_jsonable(self) -> Dict[str, Optional[str]]:
        results: Dict[str, Optional[str]] = dict()
        for name, pkt in self.final_result.items():
            if pkt is None:
                results[name] = None
            else:
                results[name] = base64.b64encode(sp.raw(pkt)).decode()
        return results

    @classmethod
    @override(GenericMainMixin)
    def add_scan_kwargs(cls, raw_args: Namespace, scan_kwargs: Dict[str, Any]):
        super().add_scan_kwargs(raw_args, scan_kwargs)
        scan_kwargs['open_port'] = raw_args.open_port
        scan_kwargs['closed_port'] = raw_args.closed_port
        scan_kwargs['target'] = AddrGenerator.resolve(raw_args.targets[0])
