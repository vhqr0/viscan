import base64

from scapy.packet import Packet

from typing import Any, Optional

from .base import ResultParser, BaseScanner
from .decorators import override


class FingerPrinter(ResultParser[dict[str, Optional[Packet]]], BaseScanner):
    fp_names: list[str] = []

    def parse_fps(self) -> list[Optional[Packet]]:
        raise NotImplementedError

    @override(ResultParser)
    def parse(self):
        results = dict()
        pkts = self.parse_fps()
        for name, pkt in zip(self.fp_names, pkts):
            results[name] = pkt
        self.result = results

    @override(ResultParser)
    def get_jsonable(self) -> dict[str, Any]:
        assert self.result is not None
        results: dict[str, Any] = dict()
        for name, pkt in self.result.items():
            if pkt is None:
                results[name] = None
            else:
                results[name] = base64.b64encode(bytes(pkt)).decode()
        return results

    @override(ResultParser)
    def show(self):
        assert self.result is not None
        for name, pkt in self.result.items():
            if pkt is None:
                print(f'{name}\tNone')
            else:
                print(f'{name}\t{pkt.summary()}')


class EnsembleFingerPrinter(FingerPrinter):
    kwargs: dict[str, Any]

    fp_types: list[type[FingerPrinter]] = []

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.kwargs = kwargs

    @override(FingerPrinter)
    def scan_and_parse(self):
        results: dict[str, Optional[Packet]] = dict()
        for fp_type in self.fp_types:
            try:
                scanner = fp_type(**self.kwargs)
                scanner.scan_and_parse()
                assert scanner.result is not None
                for name, pkt in scanner.result.items():
                    results[name] = pkt
            except Exception as e:
                self.logger.debug('except while scanning: %s', e)
        self.result = results
