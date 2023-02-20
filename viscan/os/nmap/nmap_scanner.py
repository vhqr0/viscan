import base64
import logging

from typing import Optional, Type, Any, Mapping, Dict

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

    scanner_clses_map: Mapping[str, Type[OSScanner]] = {
        'TECN': NmapTECNScanner,
        'T2': NmapT2Scanner,
        'T3': NmapT3Scanner,
        'T4': NmapT4Scanner,
        'T5': NmapT5Scanner,
        'T6': NmapT6Scanner,
        'T7': NmapT7Scanner,
        'U1': NmapU1Scanner,
        'IE1': NmapIE1Scanner,
        'IE2': NmapIE2Scanner,
    }

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.results = dict()

    def scan(self):
        self.results.clear()

        try:
            syn_scanner = NmapSynScanner(**self.kwargs)
            syn_scanner.scan()
            syn_results = syn_scanner.parse()
            for i in range(3):
                for j, fp in enumerate(syn_results[i]):
                    name = f'S{j+1}#{i+1}'
                    if fp is None:
                        self.results[name] = None
                    else:
                        self.results[name] = base64.b64encode(fp).decode()
        except Exception as e:
            self.logger.error('except while scanning: %s', e)

        for name, scanner_cls in self.scanner_clses_map.items():
            try:
                scanner = scanner_cls(**self.kwargs)
                scanner.scan()
                fp = scanner.parse()
                if fp is None:
                    self.results[name] = None
                else:
                    self.results[name] = base64.b64encode(fp).decode()
            except Exception as e:
                self.logger.error('except while scanning: %s', e)
