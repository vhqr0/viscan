import logging

from typing import Any, Type, Optional, List, Dict

from ...generic.base import BaseScanner
from ...generic.pcap import PcapScanner, MixinForPcapScanner
from ...utils.decorators import override


class MixinForOSBaseScanner(MixinForPcapScanner):
    target: str
    open_port: Optional[int]
    closed_port: Optional[int]

    def parse(self) -> List[Optional[bytes]]:
        return super().parse()

    def update_fp(self, fp: Dict[str, Optional[str]]):
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
        super().__init__(**kwargs)


class OSBaseFingerPrinter(BaseScanner):
    kwargs: Dict[str, Any]
    results: Dict[str, Optional[str]]

    # override BaseScanner
    logger = logging.getLogger('os_finger_printer')

    scanner_clses: List[Type[OSBaseScanner]] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.results = dict()

    def parse(self) -> Dict[str, Optional[str]]:
        return self.results

    @override(BaseScanner)
    def scan(self):
        self.results.clear()

        for scanner_cls in self.scanner_clses:
            try:
                scanner = scanner_cls(**self.kwargs)
                scanner.scan()
                scanner.update_fp(self.results)
            except Exception as e:
                self.logger.error('except while scanning: %s', e)
