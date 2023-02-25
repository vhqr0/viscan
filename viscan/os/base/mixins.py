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
        if len(self.fp_names) == 0:
            raise NotImplementedError
        try:
            for name, result in zip(self.fp_names, self.final_result):
                fp[name] = result
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
        for pkt in self.final_result:
            if pkt is None:
                print(None)
            else:
                pkt.show()

    @override(MixinForOSBaseScanner)
    def to_jsonable(self) -> List[Optional[str]]:
        results: List[Optional[str]] = []
        for pkt in self.results:
            if pkt is None:
                results.append(None)
            else:
                results.append(base64.b64encode(sp.raw(pkt)).decode())
        return results
