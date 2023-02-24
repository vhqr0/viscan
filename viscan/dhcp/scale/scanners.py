import logging

import scapy.layers.dhcp6 as dhcp6

from typing import Optional, Tuple, List

from ...defaults import (
    DHCP_SCALE_COUNT,
    DHCP_SCALE_LOSSRATE,
)
from ...utils.decorators import override
from ..base import DHCPScanMixin, DHCPBaseScanner


class DHCPScaler(DHCPScanMixin, DHCPBaseScanner):
    count: int
    lossrate: float

    # override DHCPBaseScanner
    logger = logging.getLogger('dhcp_scaler')

    def __init__(self,
                 count: int = DHCP_SCALE_COUNT,
                 lossrate: float = DHCP_SCALE_LOSSRATE,
                 **kwargs):
        self.count = count
        self.lossrate = lossrate
        super().__init__(**kwargs)

    def parse(self) -> List[Tuple[Optional[str], Optional[str], Optional[str]]]:
        results: List[Tuple[Optional[str], Optional[str], Optional[str]]] = \
            [(None, None, None) for _ in range(self.count)]
        for pkt in self.results:
            _, _, buf = pkt
            msg = self.parse_msg(buf)
            if not isinstance(msg, dhcp6.DHCP6_Advertise):
                continue
            trid = msg.trid
            if trid >= self.count:
                continue
            results[trid] = (
                self.get_na(msg),
                self.get_ta(msg),
                self.get_pd(msg),
            )
        return results

    @override(DHCPScanMixin)
    def get_pkts(self) -> List[Tuple[str, int, bytes]]:
        pkts = []
        for trid in range(self.count):
            buf = self.build_solicit(trid=trid)
            pkts.append((self.target, 547, buf))
        return pkts
