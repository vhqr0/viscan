import base64
import logging

import scapy.all as sp

from typing import Any, Type, Optional, List, Dict

from ..generic.base import BaseScanner
from ..generic.pcap import PcapScanner, PcapScanMixin, FilterMixin


class OSBaseScanner(FilterMixin, PcapScanMixin, PcapScanner):
    target: str
    open_port: Optional[int]
    closed_port: Optional[int]

    # override PcapScanner
    logger = logging.getLogger('os_scanner')
    # override PcapScanMixin
    stateless = False

    fp_names: List[str] = []

    def __init__(self,
                 target: str,
                 open_port: Optional[int] = None,
                 closed_port: Optional[int] = None,
                 **kwargs):
        self.target = target
        self.open_port = open_port
        self.closed_port = closed_port
        super().__init__(**kwargs)

    def parse(self) -> List[Optional[bytes]]:
        if not self.results:
            return [None]
        return [sp.raw(sp.Ether(self.results[0])[sp.IPv6])]

    def update_fp(self, fp: Dict[str, Optional[str]]):
        if len(self.fp_names) == 0:
            raise NotImplementedError
        try:
            results = self.parse()
            for name, result in zip(self.fp_names, results):
                if result is None:
                    fp[name] = None
                else:
                    fp[name] = base64.b64encode(result).decode()
        except Exception as e:
            self.logger.error('except while parsing: %s', e)


class OSBaseFingerPrinter(BaseScanner):
    kwargs: Dict[str, Any]
    results: Dict[str, Optional[str]]

    # override BaseScanner
    logger = logging.getLogger('os_finger_printer')

    scanner_clses: List[Type[OSBaseScanner]] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.results = dict()

    # override BaseScanner
    def scan(self):
        self.results.clear()

        for scanner_cls in self.scanner_clses:
            try:
                scanner = scanner_cls(**self.kwargs)
                scanner.scan()
                scanner.update_fp(self.results)
            except Exception as e:
                self.logger.error('except while scanning: %s', e)
