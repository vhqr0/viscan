import base64

import scapy.all as sp

from typing import Optional, List, Dict

from ...generic.pcap import PcapScanMixin, FilterMixin
from ...utils.decorators import override
from .scanners import MixinForOSBaseScanner


class OSScanMixin(FilterMixin, PcapScanMixin, MixinForOSBaseScanner):

    # override PcapScanMixin
    stateless = False

    fp_names: List[str] = []

    @override(MixinForOSBaseScanner)
    def parse(self) -> List[Optional[bytes]]:
        if not self.results:
            return [None]
        return [sp.raw(sp.Ether(self.results[0])[sp.IPv6])]

    @override(MixinForOSBaseScanner)
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
