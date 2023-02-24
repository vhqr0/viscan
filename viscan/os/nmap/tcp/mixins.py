import random

import scapy.all as sp

from typing import Any, List, Mapping

from ....generic.pcap import FilterMixin
from ....utils.decorators import override
from ...base import OSScanMixin


class NmapTCPScanMixin(FilterMixin, OSScanMixin):
    target_port: int

    # override FilterMixin
    filter_template = 'ip6 and ' \
        'tcp dst port {port} and ' \
        'tcp src port {target_port}'

    @override(FilterMixin)
    def get_filter_context(self) -> Mapping[str, Any]:
        return {'port': self.port, 'target_port': self.target_port}


class NmapTCPScanWithFlagsWindowMixin(NmapTCPScanMixin):
    flags: str = ''
    window: int = 0

    @override(NmapTCPScanMixin)
    def get_pkts(self) -> List[sp.IPv6]:
        pkt = sp.IPv6(dst=self.target) / \
            sp.TCP(sport=self.port,
                   dport=self.target_port,
                   seq=random.getrandbits(32),
                   flags=self.flags,
                   window=self.window)
        return [pkt]
