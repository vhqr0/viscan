import logging

from typing import Optional, Type, Any, Dict, List

from ..base import OSScanner
from .syn_scanner import NmapSynScanner
from .tcp_scanners import (
    NmapTECNScanner,
    NmapT2Scanner,
    NmapT3Scanner,
    NmapT4Scanner,
    NmapT5Scanner,
    NmapT6Scanner,
    NmapT7Scanner,
)
from .icmp_scanners import NmapU1Scanner, NmapIE1Scanner, NmapIE2Scanner


class NmapScanner:
    kwargs: Dict[str, Any]
    results: Dict[str, Optional[str]]

    logger = logging.getLogger('nmap_scanner')

    scanner_clses: List[Type[OSScanner]] = [
        NmapSynScanner,
        NmapTECNScanner,
        NmapT2Scanner,
        NmapT3Scanner,
        NmapT4Scanner,
        NmapT5Scanner,
        NmapT6Scanner,
        NmapT7Scanner,
        NmapU1Scanner,
        NmapIE1Scanner,
        NmapIE2Scanner,
    ]

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.results = dict()

    def scan(self):
        self.results.clear()

        for scanner_cls in self.scanner_clses:
            try:
                scanner = scanner_cls(**self.kwargs)
                scanner.scan()
                scanner.update_fp(self.results)
            except Exception as e:
                self.logger.error('except while scanning: %s', e)
