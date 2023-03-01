import base64

import scapy.all as sp

from typing import Optional, List, Dict

from ...generic.pcap import PcapScanMixin
from ...utils.decorators import override
from .scanners import MixinForOSBaseScanner


class OSScanMixin(PcapScanMixin, MixinForOSBaseScanner):

    # override PcapScanMixin
    stateless = False

    fp_names: List[str] = []

    @override(MixinForOSBaseScanner)
    def update_fp(self, fp: Dict[str, Optional[sp.IPv6]]):
        try:
            for name, pkt in zip(self.fp_names, self.final_result):
                fp[name] = pkt
        except Exception as e:
            self.logger.error('except while parsing: %s', e)

    @override(MixinForOSBaseScanner)
    def parse(self):
        if len(self.results) == 0:
            self.final_result = [None]
        else:
            self.final_result = [sp.Ether(self.results[0])[sp.IPv6]]

    @override(MixinForOSBaseScanner)
    def print(self):
        for name, pkt in zip(self.fp_names, self.final_result):
            if pkt is None:
                print(f'{name}: None')
            else:
                print(f'{name}: {pkt.summary()}')

    @override(MixinForOSBaseScanner)
    def to_jsonable(self) -> Dict[str, Optional[str]]:
        results: Dict[str, Optional[str]] = dict()
        for name, pkt in zip(self.fp_names, self.final_result):
            if pkt is None:
                results[name] = None
            else:
                results[name] = base64.b64encode(sp.raw(pkt)).decode()
        return results
