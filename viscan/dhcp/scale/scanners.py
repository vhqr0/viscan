import ipaddress
import logging

import scapy.layers.dhcp6 as dhcp6

from typing import Any, Optional, Tuple, List, Dict

from ...defaults import (
    DHCP_SCALE_COUNT,
    DHCP_SCALE_LOSSRATE,
)
from ...utils.decorators import override
from ..base import DHCPScanMixin, DHCPBaseScanner
from .scale import scale


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

    def scale(
            self,
            addrs: List[Optional[str]]) -> Optional[Tuple[str, str, str, str]]:
        addrs = [addr for addr in addrs if addr is not None]
        if len(addrs) <= self.count / 2:
            return None
        addrs_int = [int(ipaddress.IPv6Address(addr)) for addr in addrs]
        t, a1, a2, d = scale(addrs_int)
        return t, str(ipaddress.IPv6Address(a1)), \
            str(ipaddress.IPv6Address(a2)), str(ipaddress.IPv6Address(d))

    def parse(self) -> Dict[str, Any]:
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
        return {
            'na_scale': self.scale([addrs[0] for addrs in results]),
            'ta_scale': self.scale([addrs[1] for addrs in results]),
            'pd_scale': self.scale([addrs[2] for addrs in results]),
            'results': results,
        }

    @override(DHCPScanMixin)
    def get_pkts(self) -> List[Tuple[str, int, bytes]]:
        pkts = []
        for trid in range(self.count):
            buf = self.build_solicit(trid=trid)
            pkts.append((self.target, 547, buf))
        return pkts
