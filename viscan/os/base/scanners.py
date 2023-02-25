import random
import base64
import logging

import scapy.all as sp

from typing import Any, Type, Optional, List, Dict

from ...generic.base import BaseScanner, FinalResultMixin
from ...generic.pcap import PcapScanner, MixinForPcapScanner
from ...utils.decorators import override


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


class OSBaseFingerPrinter(FinalResultMixin[Dict[str, Optional[sp.IPv6]]],
                          BaseScanner):
    kwargs: Dict[str, Any]
    results: Dict[str, Optional[sp.IPv6]]

    # override BaseScanner
    logger = logging.getLogger('os_finger_printer')

    scanner_clses: List[Type[OSBaseScanner]] = []

    def __init__(self, **kwargs):
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
            print(f'name: {name}')
            if pkt is None:
                print(None)
            else:
                pkt.show()

    @override(FinalResultMixin)
    def to_jsonable(self) -> Dict[str, Optional[str]]:
        results: Dict[str, Optional[str]] = dict()
        for name, pkt in self.final_result.items():
            if pkt is None:
                results[name] = None
            else:
                results[name] = base64.b64encode(sp.raw(pkt)).decode()
        return results
